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

#define MLOG_TAG "MultiStagesCaptureDeferredPhotoProcSessionCallback"

#include "multistages_capture_deferred_photo_proc_session_callback.h"

#include <sstream>

#include "database_adapter.h"
#include "file_utils.h"
#include "media_exif.h"
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
#include "exif_metadata.h"

using namespace std;
using namespace OHOS::CameraStandard;

constexpr int32_t ORIENTATION_0 = 1;
constexpr int32_t ORIENTATION_90 = 6;
constexpr int32_t ORIENTATION_180 = 3;
constexpr int32_t ORIENTATION_270 = 8;

static const std::unordered_map<int, int> ORIENTATION_MAP = {
    {0, ORIENTATION_0},
    {90, ORIENTATION_90},
    {180, ORIENTATION_180},
    {270, ORIENTATION_270}
};

namespace OHOS {
namespace Media {
MultiStagesCaptureDeferredPhotoProcSessionCallback::MultiStagesCaptureDeferredPhotoProcSessionCallback()
{}

MultiStagesCaptureDeferredPhotoProcSessionCallback::~MultiStagesCaptureDeferredPhotoProcSessionCallback()
{}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::NotifyIfTempFile(shared_ptr<NativeRdb::ResultSet> resultSet)
{
    if (resultSet == nullptr) {
        MEDIA_WARN_LOG("resultSet is nullptr");
        return;
    }
    string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    string filePath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    int32_t mediaType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    resultSet->Close();

    auto watch = MediaLibraryNotify::GetInstance();
    if (watch != nullptr) {
        string extrUri = MediaFileUtils::GetExtraUri(displayName, filePath);
        auto notifyUri = MediaFileUtils::GetUriByExtrConditions(ML_FILE_URI_PREFIX + MediaFileUri::GetMediaTypeUri(
            static_cast<MediaType>(mediaType), MEDIA_API_VERSION_V10) + "/", to_string(fileId), extrUri);
        MEDIA_DEBUG_LOG("notify %{public}s", MediaFileUtils::GetUriWithoutDisplayname(notifyUri).c_str());
        watch->Notify(MediaFileUtils::GetUriWithoutDisplayname(notifyUri), NOTIFY_UPDATE);
    }
}

int32_t MultiStagesCaptureDeferredPhotoProcSessionCallback::UpdatePhotoQuality(const string &photoId)
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

void MultiStagesCaptureDeferredPhotoProcSessionCallback::UpdateCEAvailable(const string& photoId)
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
    resultSet->Close();
    return subType == 0 ? static_cast<int32_t>(PhotoSubType::CAMERA) : subType;
}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::OnError(const string &imageId, const DpsErrorCode error)
{
    switch (error) {
        case ERROR_SESSION_SYNC_NEEDED:
            MultiStagesPhotoCaptureManager::GetInstance().SyncWithDeferredProcSession();
            break;
        case ERROR_IMAGE_PROC_INVALID_PHOTO_ID:
        case ERROR_IMAGE_PROC_FAILED: {
            MultiStagesPhotoCaptureManager::GetInstance().RemoveImage(imageId, false);
            UpdatePhotoQuality(imageId);
            MEDIA_ERR_LOG("error %{public}d, photoid: %{public}s", static_cast<int32_t>(error), imageId.c_str());
            break;
        }
        default:
            break;
    }

    if (error != ERROR_SESSION_SYNC_NEEDED) {
        MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(error),
            static_cast<int32_t>(MultiStagesCaptureMediaType::Photo));
    }
}

std::shared_ptr<NativeRdb::ResultSet> QueryPhotoData(const std::string &imageId)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { imageId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_EDIT_TIME,
        MediaColumn::MEDIA_MIME_TYPE, PhotoColumn::PHOTO_SUBTYPE, PhotoColumn::MEDIA_TYPE, PhotoColumn::PHOTO_IS_TEMP,
        PhotoColumn::PHOTO_ORIENTATION};
    return DatabaseAdapter::Query(cmd, columns);
}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::ProcessAndSaveHighQualityImage(
    const std::string& imageId, std::shared_ptr<Media::Picture> picture,
    std::shared_ptr<NativeRdb::ResultSet> resultSet, bool isCloudEnhancementAvailable)
{
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        MEDIA_INFO_LOG("resultset is empty.");
        return;
    }
    string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    bool isEdited = (GetInt64Val(PhotoColumn::PHOTO_EDIT_TIME, resultSet) > 0);
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    string mimeType = GetStringVal(MediaColumn::MEDIA_MIME_TYPE, resultSet);
    int32_t orientation = GetInt32Val(PhotoColumn::PHOTO_ORIENTATION, resultSet);
    if (orientation != 0) {
        auto metadata = picture->GetExifMetadata();
        if (metadata == nullptr) {
            MEDIA_ERR_LOG("metadata is null");
            return;
        }
        auto imageSourceOrientation = ORIENTATION_MAP.find(orientation);
        if (imageSourceOrientation == ORIENTATION_MAP.end()) {
            MEDIA_ERR_LOG("imageSourceOrientation value is invalid.");
            return;
        }
        metadata->SetValue(PHOTO_DATA_IMAGE_ORIENTATION, std::to_string(imageSourceOrientation->second));
    }

    // 裸picture落盘处理
    int ret = MediaLibraryPhotoOperations::ProcessMultistagesPhotoForPicture(isEdited, data, picture, fileId, mimeType);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Save high quality image failed. ret: %{public}d, errno: %{public}d", ret, errno);
        MultiStagesCaptureDfxResult::Report(imageId,
            static_cast<int32_t>(MultiStagesCaptureResultErrCode::SAVE_IMAGE_FAIL),
            static_cast<int32_t>(MultiStagesCaptureMediaType::Photo));
        return;
    }

    MultiStagesPhotoCaptureManager::GetInstance().DealHighQualityPicture(imageId, std::move(picture), isEdited);
    UpdateHighQualityPictureInfo(imageId, isCloudEnhancementAvailable);
    MediaLibraryObjectUtils::ScanFileAsync(data, to_string(fileId), MediaLibraryApi::API_10);
    NotifyIfTempFile(resultSet);

    MultiStagesCaptureDfxTotalTime::GetInstance().Report(imageId);
    MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(MultiStagesCaptureResultErrCode::SUCCESS),
        static_cast<int32_t>(MultiStagesCaptureMediaType::Photo));

    // delete raw file
    MultiStagesPhotoCaptureManager::GetInstance().RemoveImage(imageId, false);
    MEDIA_INFO_LOG("MultistagesCapture yuv success photoid: %{public}s", imageId.c_str());
}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::OnProcessImageDone(const std::string &imageId,
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
    tracer.Start("Query");
    auto resultSet = QueryPhotoData(imageId);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        tracer.Finish();
        MEDIA_INFO_LOG("result set is empty.");
        // 高质量图先上来，直接保存
        MultiStagesPhotoCaptureManager::GetInstance().DealHighQualityPicture(imageId, std::move(picture), false);
        return;
    }
    tracer.Finish();
    int32_t isTemp = GetInt32Val(PhotoColumn::PHOTO_IS_TEMP, resultSet);
    if (isTemp) {
        MultiStagesPhotoCaptureManager::GetInstance().DealHighQualityPicture(imageId, std::move(picture), false);
        UpdateHighQualityPictureInfo(imageId, isCloudEnhancementAvailable);
        return;
    }
    ProcessAndSaveHighQualityImage(imageId, picture, resultSet, isCloudEnhancementAvailable);
}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::GetCommandByImageId(const std::string &imageId,
    MediaLibraryCommand &cmd)
{
    size_t slashIndex = imageId.rfind("/");
    string where = "";
    vector<string> whereArgs;
    if (slashIndex != string::npos) {
        string fileId = MediaFileUtils::GetIdFromUri(imageId);
        where = PhotoColumn::MEDIA_ID + " = ? ";
        whereArgs = { fileId };
    }
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::UpdateHighQualityPictureInfo(const std::string &imageId,
    bool isCloudEnhancementAvailable)
{
    // 2. 更新数据库 photoQuality 到高质量
    UpdatePhotoQuality(imageId);
    // 3. update cloud enhancement avaiable
    if (isCloudEnhancementAvailable) {
        UpdateCEAvailable(imageId);
    }
}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::OnDeliveryLowQualityImage(const std::string &imageId,
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
    GetCommandByImageId(imageId, cmd);
    vector<string> columns { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_EDIT_TIME,
        PhotoColumn::PHOTO_SUBTYPE, PhotoColumn::PHOTO_ID};
    tracer.Start("Query");
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        tracer.Finish();
        MEDIA_INFO_LOG("result set is empty");
        return;
    }
    tracer.Finish();
    string photoId = GetStringVal(PhotoColumn::PHOTO_ID, resultSet);
    string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    bool isEdited = (GetInt64Val(PhotoColumn::PHOTO_EDIT_TIME, resultSet) > 0);
    resultSet->Close();
    MultiStagesPhotoCaptureManager::GetInstance().DealLowQualityPicture(photoId, std::move(picture), isEdited);
    MEDIA_INFO_LOG("save low quality image end");
}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::OnProcessImageDone(const string &imageId, const uint8_t *addr,
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
        MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(MultiStagesCaptureResultErrCode::SQL_ERR),
            static_cast<int32_t>(MultiStagesCaptureMediaType::Photo));
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
            static_cast<int32_t>(MultiStagesCaptureResultErrCode::SAVE_IMAGE_FAIL),
            static_cast<int32_t>(MultiStagesCaptureMediaType::Photo));
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
    MultiStagesCaptureDfxResult::Report(imageId, static_cast<int32_t>(MultiStagesCaptureResultErrCode::SUCCESS),
        static_cast<int32_t>(MultiStagesCaptureMediaType::Photo));

    // delete raw file
    MultiStagesPhotoCaptureManager::GetInstance().RemoveImage(imageId, false);
    MEDIA_INFO_LOG("success photoid: %{public}s", imageId.c_str());
}

void MultiStagesCaptureDeferredPhotoProcSessionCallback::OnStateChanged(const DpsStatusCode state)
{
    MEDIA_INFO_LOG("status: %{public}d", state);
}
} // namespace Media
} // namespace OHOS