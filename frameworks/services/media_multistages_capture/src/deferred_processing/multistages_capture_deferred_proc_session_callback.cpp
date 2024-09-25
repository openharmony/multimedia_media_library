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

#define MLOG_TAG "MultiStagesCaptureDeferredProcSessionCallback"

#include "multistages_capture_deferred_proc_session_callback.h"

#include "database_adapter.h"
#include "file_utils.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "media_log.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_tracer.h"
#include "multistages_capture_manager.h"
#include "multistages_capture_dfx_result.h"
#include "multistages_capture_dfx_total_time.h"
#include "multistages_capture_request_task_manager.h"
#include "result_set_utils.h"
#include "media_change_effect.h"

using namespace std;
using namespace OHOS::CameraStandard;

namespace OHOS {
namespace Media {
MultiStagesCaptureDeferredProcSessionCallback::MultiStagesCaptureDeferredProcSessionCallback()
{}

MultiStagesCaptureDeferredProcSessionCallback::~MultiStagesCaptureDeferredProcSessionCallback()
{}

void MultiStagesCaptureDeferredProcSessionCallback::NotifyIfTempFile(shared_ptr<NativeRdb::ResultSet> resultSet)
{
    if (resultSet == nullptr) {
        MEDIA_WARN_LOG("resultSet is nullptr");
        return;
    }
    int32_t isTemp = GetInt32Val(PhotoColumn::PHOTO_IS_TEMP, resultSet);
    if (!isTemp) {
        return;
    }
    string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    string filePath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    int32_t mediaType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
    string extrUri = MediaFileUtils::GetExtraUri(displayName, filePath);
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    auto notifyUri = MediaFileUtils::GetUriByExtrConditions(ML_FILE_URI_PREFIX + MediaFileUri::GetMediaTypeUri(
        static_cast<MediaType>(mediaType), MEDIA_API_VERSION_V10) + "/", to_string(fileId), extrUri);

    auto watch = MediaLibraryNotify::GetInstance();
    if (watch != nullptr) {
        watch->Notify(notifyUri, NOTIFY_UPDATE);
    }
}

int32_t MultiStagesCaptureDeferredProcSessionCallback::UpdatePhotoQuality(const string &photoId)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdatePhotoQuality " + photoId);
    MediaLibraryCommand updateCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    NativeRdb::ValuesBucket updateValues;
    updateValues.PutInt(PhotoColumn::PHOTO_QUALITY, static_cast<int32_t>(MultiStagesPhotoQuality::FULL));
    updateCmd.SetValueBucket(updateValues);
    updateCmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_ID, photoId);
    int32_t updatePhotoQualityResult = DatabaseAdapter::Update(updateCmd);

    updateCmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_IS_TEMP, false);
    updateCmd.GetAbsRdbPredicates()->NotEqualTo(PhotoColumn::PHOTO_SUBTYPE,
        to_string(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)));
    NativeRdb::ValuesBucket updateValuesDirty;
    updateValuesDirty.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));
    updateCmd.SetValueBucket(updateValuesDirty);
    auto isDirtyResult = DatabaseAdapter::Update(updateCmd);
    if (isDirtyResult < 0) {
        MEDIA_WARN_LOG("update dirty flag fail, photoId: %{public}s", photoId.c_str());
    }

    return updatePhotoQualityResult;
}

void MultiStagesCaptureDeferredProcSessionCallback::UpdateCEAvailable(const string& photoId)
{
    MediaLibraryCommand updateCEAvailableCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    NativeRdb::ValuesBucket updateCEAvailable;
    updateCEAvailableCmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_ID, photoId);
    updateCEAvailable.PutInt(PhotoColumn::PHOTO_CE_AVAILABLE,
        static_cast<int32_t>(CloudEnhancementAvailableType::SUPPORT));
    updateCEAvailableCmd.SetValueBucket(updateCEAvailable);
    auto ceAvailableResult = DatabaseAdapter::Update(updateCEAvailableCmd);
    if (ceAvailableResult < 0) {
        MEDIA_WARN_LOG("update CE available fail, photoId: %{public}s", photoId.c_str());
        return;
    }
}

int32_t QuerySubType(const string &photoId)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { photoId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { PhotoColumn::PHOTO_SUBTYPE };
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        MEDIA_ERR_LOG("result set is empty, photoId: %{public}s", photoId.c_str());
        return static_cast<int32_t>(PhotoSubType::CAMERA);
    }
    int32_t subType = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
    return subType == 0 ? static_cast<int32_t>(PhotoSubType::CAMERA) : subType;
}

void MultiStagesCaptureDeferredProcSessionCallback::OnError(const string &imageId, const DpsErrorCode error)
{
    switch (error) {
        case ERROR_SESSION_SYNC_NEEDED:
            MultiStagesCaptureManager::GetInstance().SyncWithDeferredProcSession();
            break;
        case ERROR_IMAGE_PROC_INVALID_PHOTO_ID:
        case ERROR_IMAGE_PROC_FAILED: {
            MultiStagesCaptureManager::GetInstance().RemoveImage(imageId, false);
            UpdatePhotoQuality(imageId);
            MEDIA_ERR_LOG("error %{public}d, photoid: %{public}s", static_cast<int32_t>(error), imageId.c_str());
            break;
        }
        default:
            break;
    }

    if (error != ERROR_SESSION_SYNC_NEEDED) {
        MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(error));
    }
}

void MultiStagesCaptureDeferredProcSessionCallback::OnProcessImageDone(const std::string &imageId,
    std::shared_ptr<Media::Picture> picture, bool isCloudEnhancementAvailable)
{
    MediaLibraryTracer tracer;
    tracer.Start("OnProcessImageDone " + imageId);
    if (picture == nullptr || picture->GetMainPixel() == nullptr) {
        tracer.Finish();
        MEDIA_ERR_LOG("OnProcessImageDone picture is null");
        return;
    }
    // 1. 分段式拍照已经处理完成，保存全质量图
    MEDIA_INFO_LOG("yuv photoid: %{public}s, isCloudEnhancementAvailable: %{public}s enter", imageId.c_str(),
        isCloudEnhancementAvailable?"true":"false");
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { imageId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_EDIT_TIME,
        PhotoColumn::PHOTO_SUBTYPE,  MediaColumn::MEDIA_MIME_TYPE};
    tracer.Start("Query");
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        tracer.Finish();
        MEDIA_INFO_LOG("result set is empty.");
        // 高质量图先上来，直接保存
        MultiStagesCaptureManager::GetInstance().DealHighQualityPicture(imageId, std::move(picture), false);
        MultiStagesCaptureDfxTotalTime::GetInstance().RemoveStartTime(imageId);
        MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(MultiStagesCaptureResultErrCode::SQL_ERR));
        return;
    }
    tracer.Finish();
    string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    bool isEdited = (GetInt64Val(PhotoColumn::PHOTO_EDIT_TIME, resultSet) > 0);
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    string mime_type = GetStringVal(MediaColumn::MEDIA_MIME_TYPE, resultSet);
    MultiStagesCaptureManager::GetInstance().SaveLowQualityPicture(imageId);
    // 裸picture落盘处理
    int ret = MediaLibraryPhotoOperations::ProcessMultistagesPhotoForPicture(isEdited,
        data, picture, fileId, mime_type);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Save high quality image failed. ret: %{public}d, errno: %{public}d", ret, errno);
        MultiStagesCaptureDfxResult::Report(imageId,
            static_cast<int32_t>(MultiStagesCaptureResultErrCode::SAVE_IMAGE_FAIL));
        return;
    }
    MultiStagesCaptureManager::GetInstance().DealHighQualityPicture(imageId, std::move(picture), isEdited);

    // 2. 更新数据库 photoQuality 到高质量
    int32_t subType = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
    UpdatePhotoQuality(imageId);
    // 3. update cloud enhancement available
    if (isCloudEnhancementAvailable) {
        UpdateCEAvailable(imageId);
    }

    MediaLibraryObjectUtils::ScanFileAsync(data, to_string(fileId), MediaLibraryApi::API_10);

    MultiStagesCaptureDfxTotalTime::GetInstance().Report(imageId);
    MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(MultiStagesCaptureResultErrCode::SUCCESS));

    // delete raw file
    MultiStagesCaptureManager::GetInstance().RemoveImage(imageId, false);
    MEDIA_INFO_LOG("yuv success photoid: %{public}s", imageId.c_str());
}

void MultiStagesCaptureDeferredProcSessionCallback::OnDeliveryLowQualityImage(const std::string &imageId,
    std::shared_ptr<Media::Picture> picture)
{
    MEDIA_INFO_LOG("photoid: %{public}s", imageId.c_str());
    if (picture != nullptr && picture->GetMainPixel() != nullptr) {
        MEDIA_INFO_LOG("OnDeliveryLowQualityImage picture is not null");
    } else {
        MEDIA_INFO_LOG("OnDeliveryLowQualityImage picture is null");
        return;
    }
    MediaLibraryTracer tracer;
    tracer.Start("OnDeliveryLowQualityImage " + imageId);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    int slashIndex = imageId.rfind("/");
    string where = "";
    vector<string> whereArgs;
    string photoId = "";
    if (slashIndex != string::npos) {
        string fileId = MediaFileUtils::GetIdFromUri(imageId);
        where = PhotoColumn::MEDIA_ID + " = ? ";
        whereArgs = { fileId };
        photoId = fileId + "_";
    } else {
        where = PhotoColumn::PHOTO_ID + " = ? ";
        whereArgs = { imageId };
        photoId = imageId;
    }
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_EDIT_TIME,
        PhotoColumn::PHOTO_SUBTYPE, PhotoColumn::PHOTO_QUALITY};
    tracer.Start("Query");
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        tracer.Finish();
        MEDIA_INFO_LOG("result set is empty");
        return;
    }
    tracer.Finish();
    int32_t photoQuality = GetInt32Val(PhotoColumn::PHOTO_QUALITY, resultSet);
    string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    bool isEdited = (GetInt64Val(PhotoColumn::PHOTO_EDIT_TIME, resultSet) > 0);
    MultiStagesCaptureManager::GetInstance().DealLowQualityPicture(imageId, std::move(picture), isEdited);
    MEDIA_INFO_LOG("save low quality image end");
}

void MultiStagesCaptureDeferredProcSessionCallback::OnProcessImageDone(const string &imageId, const uint8_t *addr,
    const long bytes, bool isCloudEnhancementAvailable)
{
    CHECK_AND_RETURN_LOG((addr != nullptr) && (bytes != 0), "addr is nullptr or bytes(%{public}ld) is 0", bytes);
    CHECK_AND_RETURN_LOG(MultiStagesCaptureRequestTaskManager::IsPhotoInProcess(imageId),
        "this photo was delete or err photoId: %{public}s", imageId.c_str());
    MediaLibraryTracer tracer;
    tracer.Start("OnProcessImageDone " + imageId);

    // 1. 分段式拍照已经处理完成，保存全质量图
    MEDIA_INFO_LOG("photoid: %{public}s, bytes: %{public}ld, isCloudEnhancementAvailable: %{public}s enter",
        imageId.c_str(), bytes, isCloudEnhancementAvailable?"true":"false");
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { imageId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_EDIT_TIME,
        PhotoColumn::MEDIA_NAME, PhotoColumn::MEDIA_TYPE, PhotoColumn::PHOTO_IS_TEMP };
    tracer.Start("Query");
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        tracer.Finish();
        MEDIA_INFO_LOG("result set is empty");
        MultiStagesCaptureDfxTotalTime::GetInstance().RemoveStartTime(imageId);
        MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(MultiStagesCaptureResultErrCode::SQL_ERR));
        return;
    }
    tracer.Finish();
    string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    bool isEdited = (GetInt64Val(PhotoColumn::PHOTO_EDIT_TIME, resultSet) > 0);
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    int ret = MediaLibraryPhotoOperations::ProcessMultistagesPhoto(isEdited, data, addr, bytes, fileId);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Save high quality image failed. ret: %{public}d, errno: %{public}d", ret, errno);
        MultiStagesCaptureDfxResult::Report(imageId,
            static_cast<int32_t>(MultiStagesCaptureResultErrCode::SAVE_IMAGE_FAIL));
        return;
    }

    // 2. 更新数据库 photoQuality 到高质量
    UpdatePhotoQuality(imageId);
    // 3. update cloud enhancement avaiable
    if (isCloudEnhancementAvailable) {
        UpdateCEAvailable(imageId);
    }

    MediaLibraryObjectUtils::ScanFileAsync(data, to_string(fileId), MediaLibraryApi::API_10);
    NotifyIfTempFile(resultSet);

    MultiStagesCaptureDfxTotalTime::GetInstance().Report(imageId);
    MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(MultiStagesCaptureResultErrCode::SUCCESS));

    // delete raw file
    MultiStagesCaptureManager::GetInstance().RemoveImage(imageId, false);
    MEDIA_INFO_LOG("success photoid: %{public}s", imageId.c_str());
}

void MultiStagesCaptureDeferredProcSessionCallback::OnStateChanged(const DpsStatusCode state)
{
    MEDIA_INFO_LOG("status: %{public}d", state);
}
} // namespace Media
} // namespace OHOS