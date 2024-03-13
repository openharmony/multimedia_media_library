/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MultiStagesCaptureManager"

#include "multistages_capture_manager.h"

#include "database_adapter.h"
#include "exif_utils.h"
#include "medialibrary_command.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_tracer.h"
#include "media_log.h"
#include "multistages_capture_dfx_first_visit.h"
#include "multistages_capture_dfx_request_policy.h"
#include "multistages_capture_dfx_total_time.h"
#include "multistages_capture_dfx_trigger_ratio.h"
#include "request_policy.h"
#include "result_set_utils.h"

using namespace std;
#ifdef ABILITY_CAMERA_SUPPORT
using namespace OHOS::CameraStandard;
#endif
namespace OHOS {
namespace Media {

MultiStagesPhotoInfo::MultiStagesPhotoInfo(int32_t fileId, const std::string &id, int32_t quality)
    : photoId(id), photoQuality(quality), fileId(fileId) {}

MultiStagesPhotoInfo::MultiStagesPhotoInfo()
    : photoId(""), photoQuality(static_cast<int32_t>(MultiStagesPhotoQuality::FULL)), fileId(0) {}

MultiStagesCaptureManager::MultiStagesCaptureManager()
{
    deferredProcSession_ = make_shared<DeferredProcessingAdapter>();
}

MultiStagesCaptureManager::~MultiStagesCaptureManager() {}

MultiStagesCaptureManager& MultiStagesCaptureManager::GetInstance()
{
    static MultiStagesCaptureManager instance;
    return instance;
}

bool MultiStagesCaptureManager::Init()
{
    SyncWithDeferredProcSession();
    return true;
}

void MultiStagesCaptureManager::AddPhotoInProgress(int32_t fileId, const string &photoId, bool isTrashed)
{
    fileId2PhotoId_.emplace(fileId, photoId);
    PhotoState state = PhotoState::NORMAL;
    if (isTrashed) {
        state = PhotoState::TRASHED;
    }
    photoIdInProcess_.emplace(photoId, make_shared<LowQualityPhotoInfo>(fileId, state));
}

// 1. RestoreImage,从回收站恢复,isTrashed=false, state TRASHED => NORMAL
// 2. 删除到回收站,isTrashed=false, state NORMAL => TRASHED
void MultiStagesCaptureManager::UpdatePhotoInProgress(const string &photoId)
{
    if (photoIdInProcess_.count(photoId) == 0) {
        MEDIA_INFO_LOG("photo id (%{public}s) not in progress", photoId.c_str());
        return;
    }
    shared_ptr<LowQualityPhotoInfo> photo = photoIdInProcess_.at(photoId);
    photo->state = (photo->state == PhotoState::NORMAL) ? PhotoState::TRASHED : PhotoState::NORMAL;
    photoIdInProcess_[photoId] = photo;
}

void MultiStagesCaptureManager::RemovePhotoInProgress(const string &photoId, bool isRestorable)
{
    if (!isRestorable) {
        if (photoIdInProcess_.count(photoId) == 0) {
            MEDIA_INFO_LOG("photo id (%{public}s) not in progress.", photoId.c_str());
            return;
        }
        int32_t fileId = photoIdInProcess_.at(photoId)->fileId;
        fileId2PhotoId_.erase(fileId);
        photoIdInProcess_.erase(photoId);
        return;
    }

    UpdatePhotoInProgress(photoId);
}

bool MultiStagesCaptureManager::IsPhotoInProgress(const string &photoId)
{
    if (photoId.empty() || photoIdInProcess_.find(photoId) == photoIdInProcess_.end()) {
        return false;
    }
    return true;
}

void MultiStagesCaptureManager::HandleMultiStagesOperation(MediaLibraryCommand &cmd,
    const NativeRdb::ValuesBucket &valuesBucket)
{
    switch (cmd.GetOprnType()) {
        case OperationType::PROCESS_IMAGE: {
            ProcessImage(valuesBucket);
            MultiStagesCaptureDfxTriggerRatio::GetInstance().SetTrigger(MultiStagesCaptureTriggerType::THIRD_PART);
            break;
        }
        case OperationType::ADD_IMAGE: {
            MEDIA_DEBUG_LOG("calling addImage");
            UpdateLowQualityDbInfo(cmd);
            auto values = cmd.GetValueBucket();
            string photoId = "";
            ValueObject valueObject;
            if (values.GetObject(PhotoColumn::PHOTO_ID, valueObject)) {
                valueObject.GetString(photoId);
            }
            int32_t deferredProcType = -1;
            if (values.GetObject(PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, valueObject)) {
                valueObject.GetInt(deferredProcType);
            }
            int32_t fileId = 0;
            if (values.GetObject(MediaColumn::MEDIA_ID, valueObject)) {
                valueObject.GetInt(fileId);
            }
            AddImage(fileId, photoId, deferredProcType);
            MultiStagesCaptureDfxTotalTime::GetInstance().AddStartTime(photoId);
            MultiStagesCaptureDfxTriggerRatio::GetInstance().SetTrigger(MultiStagesCaptureTriggerType::AUTO);
            break;
        }
        case OperationType::SET_LOCATION: {
            MEDIA_DEBUG_LOG("calling setLocation");
            break;
        }
        default:
            break;
    }
}

void MultiStagesCaptureManager::UpdateLowQualityDbInfo(MediaLibraryCommand &cmd)
{
    MediaLibraryCommand cmdLocal (OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    auto values = cmd.GetValueBucket();
    values.PutInt(MEDIA_DATA_DB_PHOTO_QUALITY, static_cast<int32_t>(MultiStagesPhotoQuality::LOW));
    values.PutInt(MEDIA_DATA_DB_DIRTY, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
    cmdLocal.SetValueBucket(values);
    cmdLocal.GetAbsRdbPredicates()->SetWhereClause(cmd.GetAbsRdbPredicates()->GetWhereClause());
    cmdLocal.GetAbsRdbPredicates()->SetWhereArgs(cmd.GetAbsRdbPredicates()->GetWhereArgs());
    auto result = DatabaseAdapter::Update(cmdLocal);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("update failed");
    }
}

void MultiStagesCaptureManager::UpdateLocation(int32_t fileId, const string &path, double longitude, double latitude)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    string where = MEDIA_DATA_DB_ID + " = ? ";
    vector<string> whereArgs { fileId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    ValuesBucket values;
    values.PutDouble(MEDIA_DATA_DB_LATITUDE, latitude);
    values.PutDouble(MEDIA_DATA_DB_LONGITUDE, longitude);
    cmd.SetValueBucket(values);

    auto result = DatabaseAdapter::Update(cmd);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("update fail fileId: %{public}d", fileId);
    }

    // update exif info
    ExifUtils::WriteGpsExifInfo(path, longitude, latitude);
}

void MultiStagesCaptureManager::AddImageInternal(int32_t fileId, const string &photoId, int32_t deferredProcType,
    bool discardable)
{
    AddPhotoInProgress(fileId, photoId, discardable);

    #ifdef ABILITY_CAMERA_SUPPORT
    DpsMetadata metadata;
    metadata.Set(CameraStandard::DEFERRED_PROCESSING_TYPE_KEY, deferredProcType);
    deferredProcSession_->AddImage(photoId, metadata, discardable);
    #endif
}

void MultiStagesCaptureManager::AddImage(int32_t fileId, const string &photoId, int32_t deferredProcType)
{
    if (photoId.empty()) {
        MEDIA_ERR_LOG("photo is empty");
        return;
    }
    MEDIA_INFO_LOG("enter photoId: %{public}s, deferredProcType: %{public}d", photoId.c_str(), deferredProcType);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = MEDIA_DATA_DB_PHOTO_ID + " = ? ";
    vector<string> whereArgs { photoId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MEDIA_DATA_DB_DATE_TRASHED };
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    bool isTrashed = GetInt32Val(MEDIA_DATA_DB_DATE_TRASHED, resultSet) > 0;

    AddImageInternal(fileId, photoId, deferredProcType, isTrashed);
}

void MultiStagesCaptureManager::SyncWithDeferredProcSession()
{
    MEDIA_INFO_LOG("enter");
    // 进程重启场景，媒体库需要和延时子服务同步
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = MEDIA_DATA_DB_PHOTO_ID + " is not null and " + MEDIA_DATA_DB_PHOTO_QUALITY + " > 0";
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    vector<string> columns { MEDIA_DATA_DB_ID, MEDIA_DATA_DB_PHOTO_ID, MEDIA_DATA_DB_DATE_TRASHED,
        MEDIA_DATA_DB_DEFERRED_PROC_TYPE };
    
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != 0) {
        MEDIA_ERR_LOG("result set is empty");
        return;
    }

    MediaLibraryTracer tracer;
    tracer.Start("MultiStagesCaptureManager::SyncWithDeferredProcSession");

    deferredProcSession_->BeginSynchronize();
    do {
        unique_lock<mutex> lock(deferredProcMutex_, try_to_lock);
        int32_t fileId = GetInt32Val(MEDIA_DATA_DB_ID, resultSet);
        string photoId = GetStringVal(MEDIA_DATA_DB_PHOTO_ID, resultSet);
        bool isTrashed = GetInt32Val(MEDIA_DATA_DB_DATE_TRASHED, resultSet) > 0;
        if (setOfDeleted_.find(fileId) != setOfDeleted_.end()) {
            MEDIA_INFO_LOG("remove image, fileId: %{public}d, photoId: %{public}s", fileId, photoId.c_str());
            deferredProcSession_->RemoveImage(photoId);
            continue;
        }
        MEDIA_INFO_LOG("AddImage fileId: %{public}d, photoId: %{public}s", fileId, photoId.c_str());
        int32_t deferredProcType = GetInt32Val(MEDIA_DATA_DB_DEFERRED_PROC_TYPE, resultSet);
        AddImageInternal(fileId, photoId, deferredProcType, isTrashed);
    } while (!resultSet->GoToNextRow());
    
    deferredProcSession_->EndSynchronize();
    MEDIA_INFO_LOG("exit");
}

bool MultiStagesCaptureManager::CancelProcessRequest(const string &photoId)
{
    if (!IsPhotoInProgress(photoId)) {
        MEDIA_ERR_LOG("photoId is empty or not in process");
        return false;
    }

    unique_lock<mutex> lock(deferredProcMutex_, try_to_lock);
    auto isCancelSucc = deferredProcSession_->CancelProcessImage(photoId);
    MEDIA_INFO_LOG("cancel request %{public}d", isCancelSucc);

    return true;
}

void MultiStagesCaptureManager::RemoveImage(const string &photoId, bool isRestorable)
{
    if (!IsPhotoInProgress(photoId)) {
        MEDIA_ERR_LOG("photoId is empty or not in process ");
        return;
    }

    unique_lock<mutex> lock(deferredProcMutex_, try_to_lock);
    RemovePhotoInProgress(photoId, isRestorable);
    deferredProcSession_->RemoveImage(photoId, isRestorable);
}

void MultiStagesCaptureManager::RemoveImages(const AbsRdbPredicates &predicates, bool isRestorable)
{
    vector<shared_ptr<MultiStagesPhotoInfo>> photosInfo = GetPhotosInfo(predicates);
    for (auto photo : photosInfo) {
        if (photo->photoId.empty() || photo->photoQuality == static_cast<int32_t>(MultiStagesPhotoQuality::FULL)) {
            MEDIA_DEBUG_LOG("photoId is empty or full quality");
            continue;
        }

        RemoveImage(photo->photoId, isRestorable);
    }
}

void MultiStagesCaptureManager::RestoreImages(const AbsRdbPredicates &predicates)
{
    vector<shared_ptr<MultiStagesPhotoInfo>> photosInfo = GetPhotosInfo(predicates);
    for (auto photo : photosInfo) {
        if (photo->photoId.empty() || photo->photoQuality == static_cast<int32_t>(MultiStagesPhotoQuality::FULL)) {
            MEDIA_DEBUG_LOG("photoId is empty or full quality ");
            continue;
        }

        unique_lock<mutex> lock(deferredProcMutex_, try_to_lock);
        UpdatePhotoInProgress(photo->photoId);
        deferredProcSession_->RestoreImage(photo->photoId);
    }
}

void MultiStagesCaptureManager::ProcessImage(const NativeRdb::ValuesBucket &valuesBucket)
{
    int fileId = -1;
    ValueObject valueObject;
    if (valuesBucket.GetObject(PhotoColumn::MEDIA_ID, valueObject)) {
        valueObject.GetInt(fileId);
    }
    string photoId = fileId2PhotoId_[fileId];
    if (photoId.size() == 0) {
        MEDIA_ERR_LOG("processimage image id is invalid, fileId: %{public}d", fileId);
        return;
    }

    int32_t deliveryMode = -1;
    if (valuesBucket.GetObject("delivery_mode", valueObject)) {
        valueObject.GetInt(deliveryMode);
    }
    string appName = "";
    if (valuesBucket.GetObject("app_name", valueObject)) {
        valueObject.GetString(appName);
    }
    MultiStagesCaptureDfxTriggerRatio::GetInstance().SetTrigger(MultiStagesCaptureTriggerType::THIRD_PART);
    MultiStagesCaptureDfxRequestPolicy::GetInstance().SetPolicy(appName, static_cast<RequestPolicy>(deliveryMode));
    MultiStagesCaptureDfxFirstVisit::GetInstance().Report(photoId);
    MEDIA_INFO_LOG("processimage, pkg name: %{public}s, photoid %{public}s, mode: %{public}d", appName.c_str(),
        photoId.c_str(), deliveryMode);
    if (deliveryMode == static_cast<int32_t>(RequestPolicy::HIGH_QUALITY_MODE) ||
        deliveryMode == static_cast<int32_t>(RequestPolicy::BALANCE_MODE)) {
        deferredProcSession_->ProcessImage(appName, photoId);
    }
}

vector<shared_ptr<MultiStagesPhotoInfo>> MultiStagesCaptureManager::GetPhotosInfo(const AbsRdbPredicates &predicates)
{
    vector<shared_ptr<MultiStagesPhotoInfo>> photos;
    if (predicates.GetTableName() != PhotoColumn::PHOTOS_TABLE) {
        return photos;
    }

    AbsRdbPredicates predicatesNew(predicates.GetTableName());
    string where = predicates.GetWhereClause() + " AND " + PhotoColumn::PHOTO_QUALITY + "=" +
        to_string(static_cast<int32_t>(MultiStagesPhotoQuality::LOW));
    predicatesNew.SetWhereClause(where);
    predicatesNew.SetWhereArgs(predicates.GetWhereArgs());
    vector<string> columns { MediaColumn::MEDIA_ID, MEDIA_DATA_DB_PHOTO_ID, MEDIA_DATA_DB_PHOTO_QUALITY };
    auto resultSet = MediaLibraryRdbStore::Query(predicatesNew, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        return photos;
    }

    do {
        shared_ptr<MultiStagesPhotoInfo> photoInfo = make_shared<MultiStagesPhotoInfo>();
        photoInfo->photoId = GetStringVal(MEDIA_DATA_DB_PHOTO_ID, resultSet);
        photoInfo->photoQuality = GetInt32Val(MEDIA_DATA_DB_PHOTO_QUALITY, resultSet);
        photoInfo->fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        photos.push_back(photoInfo);
    } while (!resultSet->GoToNextRow());

    return photos;
}

bool MultiStagesCaptureManager::IsPhotoDeleted(const std::string &photoId)
{
    if (!IsPhotoInProgress(photoId)) {
        return false;
    }

    return true;
}
} // namespace Media
} // namespace OHOS