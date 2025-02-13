/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MultiStagesMovingPhotoCaptureManager"

#include "multistages_moving_photo_capture_manager.h"
#include "multistages_video_capture_manager.h"

#include "media_log.h"
#include "moving_photo_file_utils.h"
#include "database_adapter.h"
#include "medialibrary_rdbstore.h"
#include "result_set_utils.h"
#include "userfilemgr_uri.h"

using namespace std;
#ifdef ABILITY_CAMERA_SUPPORT
using namespace OHOS::CameraStandard;
#endif

namespace OHOS {
namespace Media {
MultiStagesMovingPhotoCaptureManager::MultiStagesMovingPhotoCaptureManager() {}

MultiStagesMovingPhotoCaptureManager::~MultiStagesMovingPhotoCaptureManager() {}

static int32_t UpdateMultStagesMovingPhotoVideoTaskStatus(const std::string &photoId, StageVideoTaskStatus taskStatus)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { photoId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    NativeRdb::ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_STAGE_VIDEO_TASK_STATUS, to_string(static_cast<int32_t>(taskStatus)));
    cmd.SetValueBucket(values);

    auto result = DatabaseAdapter::Update(cmd);
    return result;
}

void MultiStagesMovingPhotoCaptureManager::SaveMovingPhotoVideoFinished(const std::string &photoId)
{
    int32_t ret = UpdateMultStagesMovingPhotoVideoTaskStatus(photoId, StageVideoTaskStatus::STAGE_TASK_TO_DELIVER);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK,
        "Stage video task status update fail photoId: %{public}s", photoId.c_str());
    AddVideoFromMovingPhoto(photoId);
}

void MultiStagesMovingPhotoCaptureManager::AddVideoFromMovingPhoto(const std::string &photoId)
{
    MEDIA_INFO_LOG("Enter AddVideoFromMovingPhoto, photoId: %{public}s", photoId.c_str());
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    string where = PhotoColumn::PHOTO_ID + " = ? ";
    vector<string> whereArgs { photoId };
    cmd.GetAbsRdbPredicates()->SetWhereClause(where);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    vector<string> columns { MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_QUALITY,
        PhotoColumn::STAGE_VIDEO_TASK_STATUS, PhotoColumn::PHOTO_SUBTYPE };
    auto resultSet = DatabaseAdapter::Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("result set is empty");
        return;
    }

    int32_t subType = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
    if (subType != static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        MEDIA_ERR_LOG("task must be moving photo.");
        return;
    }

    int32_t photoQuality = GetInt32Val(PhotoColumn::PHOTO_QUALITY, resultSet);
    if (photoQuality != static_cast<int32_t>(MultiStagesPhotoQuality::FULL)) {
        MEDIA_INFO_LOG("photo multi stage task not yet.");
        return;
    }

    int32_t stageVideoTaskStatus = GetInt32Val(PhotoColumn::STAGE_VIDEO_TASK_STATUS, resultSet);
    if (stageVideoTaskStatus != static_cast<int32_t>(StageVideoTaskStatus::STAGE_TASK_TO_DELIVER)) {
        MEDIA_INFO_LOG("moving photo video saving not yet.");
        return;
    }

    string data = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    string videoPath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(data);
    MultiStagesVideoCaptureManager::GetInstance().AddVideoInternal(photoId, videoPath);
    UpdateMultStagesMovingPhotoVideoTaskStatus(photoId, StageVideoTaskStatus::STAGE_TASK_DELIVERED);
    MEDIA_INFO_LOG("Moving photo mulit stage video task has been delivered");
}
} // Media
} // OHOS