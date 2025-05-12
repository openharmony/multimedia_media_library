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

#define MLOG_TAG "MultiStagesCaptureDeferredVideoProcSessionCallback"

#include "multistages_capture_deferred_video_proc_session_callback.h"

#include "media_log.h"
#include "database_adapter.h"
#include "multistages_capture_dfx_result.h"
#include "multistages_capture_dfx_total_time.h"
#include "multistages_capture_manager.h"
#include "medialibrary_object_utils.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS::CameraStandard;

namespace OHOS {
namespace Media {
MultiStagesCaptureDeferredVideoProcSessionCallback::MultiStagesCaptureDeferredVideoProcSessionCallback()
{}
 
MultiStagesCaptureDeferredVideoProcSessionCallback::~MultiStagesCaptureDeferredVideoProcSessionCallback()
{}

int32_t MultiStagesCaptureDeferredVideoProcSessionCallback::UpdateVideoQuality(
    const std::string &videoId, bool isSuccess, bool isDirtyNeedUpdate)
{
    MediaLibraryCommand updateCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    NativeRdb::ValuesBucket updateValues;
    if (isDirtyNeedUpdate) {
        updateValues.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_FDIRTY));
    }

    int32_t subType = MultiStagesCaptureManager::QuerySubType(videoId);
    if (subType == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        updateValues.PutInt(PhotoColumn::STAGE_VIDEO_TASK_STATUS,
            isSuccess ? static_cast<int32_t>(StageVideoTaskStatus::STAGE_TASK_SUCCESS) :
            static_cast<int32_t>(StageVideoTaskStatus::STAGE_TASK_FAIL));
    } else {
        updateValues.PutInt(PhotoColumn::PHOTO_QUALITY, static_cast<int32_t>(MultiStagesPhotoQuality::FULL));
    }

    updateCmd.SetValueBucket(updateValues);
    updateCmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_ID, videoId);
    return DatabaseAdapter::Update(updateCmd);
}
 
void MultiStagesCaptureDeferredVideoProcSessionCallback::OnProcessVideoDone(const std::string& videoId,
    const sptr<IPCFileDescriptor> ipcFd)
{
    CHECK_AND_RETURN_LOG(!videoId.empty(), "OnProcessVideoDone, videoId is empty");
    MEDIA_INFO_LOG("OnProcessVideoDone, videoId: %{public}s", videoId.c_str());

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { videoId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_EDIT_TIME,
        PhotoColumn::STAGE_VIDEO_TASK_STATUS, PhotoColumn::PHOTO_POSITION, PhotoColumn::MOVING_PHOTO_EFFECT_MODE };
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        MEDIA_INFO_LOG("result set is empty");
        MultiStagesCaptureDfxTotalTime::GetInstance().RemoveStartTime(videoId);
        // When subType query failed, default mediaType is Video
        MultiStagesCaptureDfxResult::Report(videoId, static_cast<int32_t>(MultiStagesCaptureResultErrCode::SQL_ERR),
            static_cast<int32_t>(MultiStagesCaptureMediaType::VIDEO));
        return;
    }

    bool isMovingPhoto = (GetInt32Val(PhotoColumn::STAGE_VIDEO_TASK_STATUS, resultSet) ==
        static_cast<int32_t>(StageVideoTaskStatus::STAGE_TASK_DELIVERED));
    int32_t mediaType = isMovingPhoto ? static_cast<int32_t>(MultiStagesCaptureMediaType::MOVING_PHOTO_VIDEO) :
        static_cast<int32_t>(MultiStagesCaptureMediaType::VIDEO);
    string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    bool isEdited = (GetInt64Val(PhotoColumn::PHOTO_EDIT_TIME, resultSet) > 0);
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    bool isDirtyNeedUpdate = (GetInt32Val(PhotoColumn::PHOTO_POSITION, resultSet) !=
        static_cast<int32_t>(PhotoPositionType::LOCAL));
    resultSet->Close();

    bool isMovingPhotoEffectMode = GetInt64Val(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, resultSet) > 0;
    int ret = MediaLibraryPhotoOperations::ProcessMultistagesVideo(isEdited, isMovingPhoto, isMovingPhotoEffectMode,
        data);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Save 110 quality video failed. ret: %{public}d, errno: %{public}d", ret, errno);
        MultiStagesCaptureDfxResult::Report(videoId,
            static_cast<int32_t>(MultiStagesCaptureResultErrCode::SAVE_VIDEO_FAIL), mediaType);
        return;
    }

    MediaLibraryObjectUtils::ScanFileAsync(data, to_string(fileId), MediaLibraryApi::API_10);

    UpdateVideoQuality(videoId, true, isDirtyNeedUpdate);

    MultiStagesCaptureDfxTotalTime::GetInstance().Report(videoId, mediaType);
    MultiStagesCaptureDfxResult::Report(videoId,
        static_cast<int32_t>(MultiStagesCaptureResultErrCode::SUCCESS), mediaType);

    MultiStagesVideoCaptureManager::GetInstance().RemoveVideo(videoId, false);
    MEDIA_INFO_LOG("OnProcessVideoDone, success videoid: %{public}s", videoId.c_str());
}

void MultiStagesCaptureDeferredVideoProcSessionCallback::VideoFaileProcAsync(AsyncTaskData *data)
{
    auto *taskData = static_cast<VideoFaileProcTaskData *>(data);
    CHECK_AND_RETURN_LOG(taskData != nullptr, "taskData is null");
    MEDIA_INFO_LOG("Enter OnError, errorCode: %{public}d", taskData->errorCode_);
    switch (taskData->errorCode_) {
        case ERROR_SESSION_SYNC_NEEDED:
            MultiStagesVideoCaptureManager::GetInstance().SyncWithDeferredVideoProcSession();
            break;
        case ERROR_VIDEO_PROC_INVALID_VIDEO_ID:
        case ERROR_VIDEO_PROC_FAILED: {
            MultiStagesVideoCaptureManager::GetInstance().RemoveVideo(taskData->videoId_, false);
            UpdateVideoQuality(taskData->videoId_, false);
            MEDIA_ERR_LOG("error %{public}d, videoId: %{public}s", static_cast<int32_t>(taskData->errorCode_),
                taskData->videoId_.c_str());
            break;
        }
        default:
            break;
    }

    if (taskData->errorCode_ != ERROR_SESSION_SYNC_NEEDED) {
        int32_t mediaType = (MultiStagesCaptureManager::QuerySubType(taskData->videoId_) ==
            static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) ?
            static_cast<int32_t>(MultiStagesCaptureMediaType::MOVING_PHOTO_VIDEO) :
            static_cast<int32_t>(MultiStagesCaptureMediaType::VIDEO);
        MultiStagesCaptureDfxResult::Report(taskData->videoId_, static_cast<int32_t>(taskData->errorCode_), mediaType);
    }
}

void MultiStagesCaptureDeferredVideoProcSessionCallback::AsyncOnErrorProc(const std::string& videoId,
    const CameraStandard::DpsErrorCode errorCode)
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_LOG(asyncWorker != nullptr, "Can not get asyncWorker");

    AsyncTaskData* taskData = new (std::nothrow) VideoFaileProcTaskData(videoId, errorCode);
    CHECK_AND_RETURN_LOG(taskData != nullptr, "Failed to new taskData");

    shared_ptr<MediaLibraryAsyncTask> asyncTask =
        make_shared<MediaLibraryAsyncTask>(VideoFaileProcAsync, taskData);
    CHECK_AND_RETURN_LOG(asyncTask != nullptr, "Can not get asyncWorker");

    MEDIA_INFO_LOG("AsyncOnErrorProc add task success");
    asyncWorker->AddTask(asyncTask, false);
}

void MultiStagesCaptureDeferredVideoProcSessionCallback::OnError(const std::string& videoId,
    const CameraStandard::DpsErrorCode errorCode)
{
    AsyncOnErrorProc(videoId, errorCode);
}

void MultiStagesCaptureDeferredVideoProcSessionCallback::OnStateChanged(const CameraStandard::DpsStatusCode state)
{
    MEDIA_INFO_LOG("status: %{public}d", state);
}
} // namespace Media
} // namespace OHOS