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
    int32_t updatePhotoIdResult = DatabaseAdapter::Update(updateCmd);

    updateCmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_IS_TEMP, false);
    updateCmd.GetAbsRdbPredicates()->NotEqualTo(PhotoColumn::PHOTO_SUBTYPE,
        to_string(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)));
    NativeRdb::ValuesBucket updateValuesDirty;
    updateValuesDirty.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));
    updateCmd.SetValueBucket(updateValuesDirty);
    auto isTempResult = DatabaseAdapter::Update(updateCmd);
    if (isTempResult < 0) {
        MEDIA_WARN_LOG("update temp flag fail, photoId: %{public}s", photoId.c_str());
    }

    return updatePhotoIdResult;
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

void MultiStagesCaptureDeferredProcSessionCallback::OnProcessImageDone(const string &imageId, const uint8_t *addr,
    const long bytes)
{
    if (addr == nullptr || bytes == 0) {
        MEDIA_ERR_LOG("addr is nullptr or bytes(%{public}ld) is 0", bytes);
        return;
    }

    if (!MultiStagesCaptureRequestTaskManager::IsPhotoInProcess(imageId)) {
        MEDIA_ERR_LOG("this photo was delete or err photoId: %{public}s", imageId.c_str());
        return;
    }
    MediaLibraryTracer tracer;
    tracer.Start("OnProcessImageDone " + imageId);

    // 1. 分段式拍照已经处理完成，保存全质量图
    MEDIA_INFO_LOG("photoid: %{public}s, bytes: %{public}ld enter", imageId.c_str(), bytes);
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
    NotifyIfTempFile(resultSet);
    MediaLibraryObjectUtils::ScanFileAsync(data, to_string(fileId), MediaLibraryApi::API_10);

    // 2. 更新数据库 photoQuality 到高质量
    UpdatePhotoQuality(imageId);

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