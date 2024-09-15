/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MovingPhotoProcessor"

#include "moving_photo_processor.h"

#include "abs_rdb_predicates.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "moving_photo_file_utils.h"
#include "parameters.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "values_bucket.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static constexpr int32_t MOVING_PHOTO_PROCESS_NUM = 100;
static constexpr int32_t DIRTY_NOT_UPLOADING = -1;
static constexpr int32_t DEFAULT_EXTRA_DATA_SIZE = MIN_STANDARD_SIZE;

static const string MOVING_PHOTO_PROCESS_FLAG = "multimedia.medialibrary.cloneFlag";

bool MovingPhotoProcessor::isProcessing_ = false;

static void StopCloudSync()
{
    string currentTime = to_string(MediaFileUtils::UTCTimeSeconds());
    MEDIA_DEBUG_LOG("Stop cloud sync for processing moving photo: %{public}s", currentTime.c_str());
    bool retFlag = system::SetParameter(MOVING_PHOTO_PROCESS_FLAG, currentTime);
    if (!retFlag) {
        MEDIA_ERR_LOG("Failed to set parameter, retFlag: %{public}d", retFlag);
    }
}

static void StartCloudSync()
{
    MEDIA_DEBUG_LOG("Reset parameter for cloud sync");
    bool retFlag = system::SetParameter(MOVING_PHOTO_PROCESS_FLAG, "0");
    if (!retFlag) {
        MEDIA_ERR_LOG("Failed to set parameter for cloud sync, retFlag: %{public}d", retFlag);
    }
}

void MovingPhotoProcessor::StartProcess()
{
    MEDIA_DEBUG_LOG("Start processing moving photo task");
    auto resultSet = QueryMovingPhoto();
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query moving photo");
        return;
    }

    MovingPhotoDataList dataList;
    ParseMovingPhotoData(resultSet, dataList);
    if (dataList.movingPhotos.empty()) {
        MEDIA_DEBUG_LOG("No moving photo need to be processed");
        return;
    }

    isProcessing_ = true;
    StopCloudSync();
    CompatMovingPhoto(dataList);
    StartCloudSync();
}

void MovingPhotoProcessor::StopProcess()
{
    if (isProcessing_) {
        isProcessing_ = false;
        StartCloudSync();
    }
}

shared_ptr<NativeRdb::ResultSet> MovingPhotoProcessor::QueryMovingPhoto()
{
    const vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::PHOTO_SUBTYPE,
        PhotoColumn::MOVING_PHOTO_EFFECT_MODE,
        PhotoColumn::MEDIA_SIZE,
        PhotoColumn::MEDIA_FILE_PATH,
    };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::PHOTO_DIRTY, DIRTY_NOT_UPLOADING)
        ->And()
        ->BeginWrap()
        ->EqualTo(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO))
        ->Or()
        ->EqualTo(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY))
        ->EndWrap()
        ->And()
        ->EqualTo(PhotoColumn::PHOTO_IS_TEMP, 0)
        ->EqualTo(PhotoColumn::MEDIA_TIME_PENDING, 0)
        ->EqualTo(PhotoColumn::PHOTO_QUALITY, static_cast<int32_t>(MultiStagesPhotoQuality::FULL))
        ->Limit(MOVING_PHOTO_PROCESS_NUM);
    return MediaLibraryRdbStore::Query(predicates, columns);
}

void MovingPhotoProcessor::ParseMovingPhotoData(shared_ptr<NativeRdb::ResultSet>& resultSet,
    MovingPhotoDataList& dataList)
{
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId = get<int32_t>(
            ResultSetUtils::GetValFromColumn(PhotoColumn::MEDIA_ID, resultSet, TYPE_INT32));
        int32_t subtype = get<int32_t>(
            ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_SUBTYPE, resultSet, TYPE_INT32));
        int32_t effectMode = get<int32_t>(
            ResultSetUtils::GetValFromColumn(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, resultSet, TYPE_INT32));
        int64_t size = get<int64_t>(
            ResultSetUtils::GetValFromColumn(PhotoColumn::MEDIA_SIZE, resultSet, TYPE_INT64));
        std::string path = get<std::string>(
            ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));

        MovingPhotoData movingPhotoData;
        movingPhotoData.fileId = fileId;
        movingPhotoData.subtype = subtype;
        movingPhotoData.effectMode = effectMode;
        movingPhotoData.size = size;
        movingPhotoData.path = path;
        dataList.movingPhotos.push_back(movingPhotoData);
    }
}

void MovingPhotoProcessor::UpdateMovingPhotoData(const MovingPhotoData& movingPhotoData)
{
    ValuesBucket values;
    string whereClause = PhotoColumn::MEDIA_ID + " = ? AND " + PhotoColumn::PHOTO_DIRTY + " = ?";
    vector<string> whereArgs = { to_string(movingPhotoData.fileId), to_string(DIRTY_NOT_UPLOADING) };
    values.PutInt(PhotoColumn::PHOTO_SUBTYPE, movingPhotoData.subtype);
    values.PutLong(PhotoColumn::MEDIA_SIZE, movingPhotoData.size);
    values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyTypes::TYPE_NEW));
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is null");
        return;
    }
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        MEDIA_ERR_LOG("rdbStorePtr is null");
        return;
    }
    if (!isProcessing_) {
        MEDIA_INFO_LOG("stop updateing moving photo data");
        return;
    }
    int32_t updateCount = 0;
    int32_t result = rdbStorePtr->Update(updateCount, PhotoColumn::PHOTOS_TABLE, values, whereClause, whereArgs);
    if (result != NativeRdb::E_OK || updateCount <= 0) {
        MEDIA_ERR_LOG("Update failed. result: %{public}d, updateCount: %{public}d", result, updateCount);
        return;
    }
}

static string GetDefaultExtraData()
{
    static string defaultExtraData = "v3_f0               0:0                 LIVE_10000000       ";
    return defaultExtraData;
}

int32_t MovingPhotoProcessor::GetUpdatedMovingPhotoData(const MovingPhotoData& currentData,
    MovingPhotoData& newData)
{
    newData = currentData;
    string imagePath = currentData.path;
    string videoPath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(imagePath);
    string extraDataPath = MovingPhotoFileUtils::GetMovingPhotoExtraDataPath(imagePath);
    size_t imageSize = 0;
    size_t videoSize = 0;
    size_t extraSize = 0;
    if (!MediaFileUtils::GetFileSize(imagePath, imageSize) || imageSize == 0) {
        MEDIA_WARN_LOG("Failed to get image of moving photo, id: %{public}d", currentData.fileId);
        newData.size = -1; // set abnormal size to -1 if original size is 0
        newData.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
        return E_OK;
    }

    if (!MediaFileUtils::GetFileSize(videoPath, videoSize) || videoSize == 0) {
        MEDIA_WARN_LOG("Failed to get video of moving photo, id: %{public}d", currentData.fileId);
        newData.size = imageSize;
        newData.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
        return E_OK;
    }

    if (MediaFileUtils::GetFileSize(extraDataPath, extraSize) && extraSize > 0) {
        newData.size = imageSize + videoSize + extraSize;
        return E_OK;
    }
    string extraDataDir = MovingPhotoFileUtils::GetMovingPhotoExtraDataDir(imagePath);
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateDirectory(extraDataDir), E_HAS_FS_ERROR,
        "Cannot create dir %{private}s, errno:%{public}d", extraDataDir.c_str(), errno);
    if (!MediaFileUtils::IsFileExists(extraDataPath) && MediaFileUtils::CreateAsset(extraDataPath) != E_OK) {
        MEDIA_ERR_LOG("Failed to create extraData:%{private}s, errno:%{public}d", extraDataPath.c_str(), errno);
        return E_HAS_FS_ERROR;
    }
    if (!MediaFileUtils::WriteStrToFile(extraDataPath, GetDefaultExtraData())) {
        MEDIA_ERR_LOG("Failed to write extraData, errno:%{public}d", errno);
        return E_HAS_FS_ERROR;
    }
    newData.size = imageSize + videoSize + DEFAULT_EXTRA_DATA_SIZE;
    return E_OK;
}

void MovingPhotoProcessor::CompatMovingPhoto(const MovingPhotoDataList& dataList)
{
    MEDIA_INFO_LOG("Start processing %{public}zu moving photos", dataList.movingPhotos.size());
    for (const auto& movingPhoto : dataList.movingPhotos) {
        if (!isProcessing_) {
            MEDIA_INFO_LOG("stop compating moving photo");
            return;
        }
        MovingPhotoData newData;
        if (GetUpdatedMovingPhotoData(movingPhoto, newData) != E_OK) {
            MEDIA_INFO_LOG("Failed to get updated data of moving photo, id: %{public}d", movingPhoto.fileId);
            continue;
        }
        UpdateMovingPhotoData(newData);
    }
}
} // namespace Media
} // namespace OHOS
