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

#define MLOG_TAG "MultiStagesVideoCaptureManager"

#include "multistages_video_capture_manager.h"

#include <fcntl.h>
#include <string>

#include "database_adapter.h"
#include "dfx_utils.h"
#include "directory_ex.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_command.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "moving_photo_file_utils.h"
#include "multistages_capture_dfx_total_time.h"
#include "result_set_utils.h"

using namespace std;
#ifdef ABILITY_CAMERA_SUPPORT
using namespace OHOS::CameraStandard;
#endif

using namespace OHOS::NativeRdb;
namespace OHOS {
namespace Media {
MultiStagesVideoCaptureManager::MultiStagesVideoCaptureManager()
{
    deferredProcSession_ = make_shared<DeferredVideoProcessingAdapter>();
}

MultiStagesVideoCaptureManager::~MultiStagesVideoCaptureManager() {}

MultiStagesVideoCaptureManager& MultiStagesVideoCaptureManager::GetInstance()
{
    static MultiStagesVideoCaptureManager instance;
    return instance;
}

void MultiStagesVideoCaptureManager::AddVideoInternal(const std::string &videoId,
    const std::string &filePath, bool isMovingPhoto)
{
#ifdef ABILITY_CAMERA_SUPPORT
    MEDIA_INFO_LOG("AddVideoInternal filePath = %{public}s", filePath.c_str());

    string absSrcFilePath;
    string videoPath = filePath;
    if (isMovingPhoto) {
        videoPath = MovingPhotoFileUtils::GetSourceMovingPhotoVideoPath(filePath);
        if (!MediaFileUtils::IsFileExists(videoPath)) {
            videoPath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(filePath);
        }
    }
    if (!PathToRealPath(videoPath, absSrcFilePath)) {
        MEDIA_ERR_LOG("file is not real path, file path: %{private}s", videoPath.c_str());
        return;
    }

    MEDIA_INFO_LOG("AddVideoInternal, file path: %{public}s", DfxUtils::GetSafePath(absSrcFilePath).c_str());
    const mode_t fileMode = 0644;
    int srcFd = open(absSrcFilePath.c_str(), O_RDONLY);
    if (srcFd < 0) {
        MEDIA_ERR_LOG("open file fail, srcFd = %{public}d, errno:%{public}d", srcFd, errno);
        return;
    }

    string dirPath = filePath.substr(0, filePath.rfind('/'));
    char realDirPath[PATH_MAX] = {0};
    if (realpath(dirPath.c_str(), realDirPath) == nullptr) {
        MEDIA_ERR_LOG("check dirPath fail, dirPath = %{public}s", dirPath.c_str());
        close(srcFd);
        return;
    }

    if (isMovingPhoto) {
        videoPath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(filePath);
    }

    string tempPath = realDirPath + videoPath.substr(videoPath.rfind('/'),
        videoPath.rfind('.') - videoPath.rfind('/')) + "_tmp" + videoPath.substr(videoPath.rfind('.'));
    MEDIA_INFO_LOG("AddVideoInternal tempPath = %{public}s", tempPath.c_str());
    int dstFd = open(tempPath.c_str(), O_CREAT|O_WRONLY|O_TRUNC, fileMode);
    if (dstFd < 0) {
        MEDIA_ERR_LOG("open file fail, dstFd = %{public}d, errno:%{public}d", dstFd, errno);
        close(srcFd);
        return;
    }
    
    deferredProcSession_->AddVideo(videoId, srcFd, dstFd);
    MultiStagesCaptureDfxTotalTime::GetInstance().AddStartTime(videoId);
#endif
}

void MultiStagesVideoCaptureManager::AddVideo(const std::string &videoId,
    const std::string &fileId, const std::string &filePath)
{
    if (videoId.empty()) {
        MEDIA_ERR_LOG("videoId is empty");
        return;
    }
    if (fileId.empty()) {
        MEDIA_ERR_LOG("fileId is empty");
        return;
    }
    if (filePath.empty()) {
        MEDIA_ERR_LOG("filePath is empty");
        return;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    string where = MEDIA_DATA_DB_ID + " = ? ";
    vector<string> whereArgs { fileId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_PHOTO_ID, videoId);
    values.PutInt(MEDIA_DATA_DB_PHOTO_QUALITY, static_cast<int32_t>(MultiStagesPhotoQuality::LOW));
    cmd.SetValueBucket(values);

    auto result = DatabaseAdapter::Update(cmd);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("AddVideo update fail fileId: %{public}s", fileId.c_str());
        return;
    }
    MEDIA_INFO_LOG("AddVideo update success fileId: %{public}s", fileId.c_str());

    AddVideoInternal(videoId, filePath);
}

bool MultiStagesVideoCaptureManager::Init()
{
    SyncWithDeferredVideoProcSessionInternal();
    return true;
}

void MultiStagesVideoCaptureManager::SyncWithDeferredVideoProcSessionInternal()
{
    MEDIA_INFO_LOG("SyncWithDeferredVideoProcSessionInternal enter");

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = MEDIA_DATA_DB_PHOTO_ID + " IS NOT NULL AND " +
        "((" + MEDIA_DATA_DB_PHOTO_QUALITY + " > 0 AND (" + MEDIA_DATA_DB_MEDIA_TYPE + " = " +
        to_string(static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)) + ") OR (" +
        MEDIA_DATA_DB_PHOTO_QUALITY + " = 0 AND " + MEDIA_DATA_DB_STAGE_VIDEO_TASK_STATUS + " IN (" +
        to_string(static_cast<int32_t>(StageVideoTaskStatus::STAGE_TASK_TO_DELIVER)) + ", " +
        to_string(static_cast<int32_t>(StageVideoTaskStatus::STAGE_TASK_DELIVERED)) + "))))";
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    vector<string> columns { MEDIA_DATA_DB_PHOTO_ID, MEDIA_DATA_DB_FILE_PATH,
                            MEDIA_DATA_DB_DATE_TRASHED, MEDIA_DATA_DB_STAGE_VIDEO_TASK_STATUS };

    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != 0) {
        MEDIA_ERR_LOG("result set is empty");
        return;
    }

    deferredProcSession_->BeginSynchronize();
    do {
        string videoId = GetStringVal(MEDIA_DATA_DB_PHOTO_ID, resultSet);
        string filePath = GetStringVal(MEDIA_DATA_DB_FILE_PATH, resultSet);
        bool isMovingPhoto = GetInt32Val(MEDIA_DATA_DB_STAGE_VIDEO_TASK_STATUS, resultSet) > 0;
        bool isTrashed = GetInt64Val(MEDIA_DATA_DB_DATE_TRASHED, resultSet) > 0;
        AddVideoInternal(videoId, filePath, isMovingPhoto);

        if (isTrashed) {
            RemoveVideo(videoId, true);
        }
    } while (!resultSet->GoToNextRow());

    deferredProcSession_->EndSynchronize();
    MEDIA_INFO_LOG("SyncWithDeferredVideoProcSessionInternal exit");
}

static void SyncWithDeferredVideoProcSessionAsync(AsyncTaskData *data)
{
    MultiStagesVideoCaptureManager::GetInstance().SyncWithDeferredVideoProcSessionInternal();
}

void MultiStagesVideoCaptureManager::SyncWithDeferredVideoProcSession()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_INFO_LOG("can not get async worker");
        return;
    }

    shared_ptr<MediaLibraryAsyncTask> asyncTask =
        make_shared<MediaLibraryAsyncTask>(SyncWithDeferredVideoProcSessionAsync, nullptr);
    if (asyncTask == nullptr) {
        MEDIA_ERR_LOG("SyncWithDeferredVideoProcSession create task fail");
        return;
    }
    MEDIA_INFO_LOG("SyncWithDeferredVideoProcSession add task success");
    asyncWorker->AddTask(asyncTask, false);
}

void MultiStagesVideoCaptureManager::RemoveVideo(const std::string &videoId, const bool restorable)
{
    MEDIA_INFO_LOG("RemoveVideo videoId = %{public}s, restorable = %{public}s",
        videoId.c_str(), restorable ? "true" : "false");

    deferredProcSession_->RemoveVideo(videoId, restorable);

    if (restorable) {
        return;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { videoId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_SUBTYPE };
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_INFO_LOG("result set is empty");
        return;
    }

    string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet) ==
        static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        data = MovingPhotoFileUtils::GetMovingPhotoVideoPath(data);
    }
    int ret = MediaLibraryPhotoOperations::RemoveTempVideo(data);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete temp video file failed. ret: %{public}d, errno: %{public}d", ret, errno);
    }
}

void MultiStagesVideoCaptureManager::RemoveVideo(const std::string &videoId, const std::string &mediaFilePath,
    const int32_t &photoSubType, const bool restorable)
{
    MEDIA_INFO_LOG("RemoveVideo videoId = %{public}s, restorable = %{public}s",
        videoId.c_str(), restorable ? "true" : "false");

    deferredProcSession_->RemoveVideo(videoId, restorable);
    if (restorable) {
        return;
    }
    string data = mediaFilePath;
    if (photoSubType == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        data = MovingPhotoFileUtils::GetMovingPhotoVideoPath(data);
    }
    int ret = MediaLibraryPhotoOperations::RemoveTempVideo(data);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete temp video file failed. ret: %{public}d, errno: %{public}d", ret, errno);
    }
}

void MultiStagesVideoCaptureManager::RestoreVideo(const std::string &videoId)
{
    deferredProcSession_->RestoreVideo(videoId);
}

static int32_t UpdateIsTempAndDirty(int32_t fileId, int32_t subType)
{
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::MEDIA_ID, fileId);

    ValuesBucket values;
    values.Put(PhotoColumn::PHOTO_IS_TEMP, false);
    values.Put(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));

    int32_t updateRows = MediaLibraryRdbStore::UpdateWithDateTime(values, predicates);
    CHECK_AND_RETURN_RET_LOG(updateRows >= 0, E_ERR, "update temp flag fail.");
    return updateRows;
}

int32_t MultiStagesVideoCaptureManager::SaveCameraVideo(const SaveCameraPhotoDto &dto)
{
    MediaLibraryTracer tracer;
    tracer.Start("MultiStagesVideoCaptureManager::SaveCameraVideo");
    MEDIA_INFO_LOG("MultistagesCapture, start save fileId: %{public}d", dto.fileId);

    int32_t ret = UpdateIsTempAndDirty(dto.fileId, dto.photoSubType);
    if (dto.path.empty()) {
        MEDIA_ERR_LOG("path is empty.");
        return E_ERR;
    }
    MediaLibraryAssetOperations::ScanFile(dto.path, false, true, true, dto.fileId);
    MEDIA_INFO_LOG("MultistagesCapture Success, fileId: %{public}d, ret: %{public}d", dto.fileId, ret);
    return ret;
}
} // Media
} // OHOS