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
#define MAP_UPLOAD_CHECKERLOG_TAG "MapUploadChecker"

#include "map_code_upload_checker.h"
#include "media_column.h"
#include "photo_map_code_column.h"
#include "photo_map_code_operation.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "thumbnail_const.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "result_set_utils.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_photo_operations.h"
#include "moving_photo_file_utils.h"
#include "medialibrary_subscriber.h"
#include "scanner_map_code_utils.h"
#include <sys/stat.h>

namespace OHOS {
namespace Media {
using namespace std;
using namespace NativeRdb;

const std::int32_t BATCH_SIZE = 500;

const int SCANMAP_DEFAULT_VERSION = 0;
const int SCANMAP_CURRENT_VERSION = 1;

const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
const std::string NO_MAPCODE_PHOTO_NUMBER = "no_mapcode_photo_number";
const std::string NO_PHOTO_BUT_MAPCODE_NUMBER = "no_origin_but_lcd_photo_number";
const std::string SCANMAP_VERSION = "scanmap_version";

static constexpr double DOUBLE_EPSILON = 1e-15;
static constexpr double MAX_LATITUDE_EPSILON = 1e-15 + 90.0;
static constexpr double MAX_LONGITUDE_EPSILON = 1e-15 + 180.0;

std::mutex MapCodeUploadChecker::mutex_;

const std::string SQL_PHOTOS_TABLE_QUERY_POSTION_PHOTO = "SELECT"
                                                                   " COUNT( * ) AS Count "
                                                                   "FROM"
                                                                   " Photos "
                                                                   "WHERE"
                                                                   " latitude <> 0"
                                                                   " AND longitude <> 0"
                                                                   " AND file_id > ?;";

const std::string SQL_PHOTOS_TABLE_QUERY_PHOTO = "SELECT"
                                                                   " file_id,"
                                                                   " latitude,"
                                                                   " longitude "
                                                                   "FROM"
                                                                   " Photos "
                                                                   "WHERE"
                                                                   " latitude <> 0"
                                                                   " AND longitude <> 0"
                                                                   " AND file_id > ?"
                                                                   " LIMIT ?;";

void MapCodeUploadChecker::HandleMapCodeInfos(const std::vector<CheckedMapCodeInfo> &photoInfos, int32_t &curFileId)
{
    MEDIA_INFO_LOG("MapCodeUploadChecker::HandleMapCodeInfos start");
    for (const CheckedMapCodeInfo &photoInfo : photoInfos) {
        CHECK_AND_BREAK_INFO_LOG(MedialibrarySubscriber::IsCurrentStatusOn(), "current status is off, break");
        curFileId = photoInfo.fileId;
        NativeRdb::ValuesBucket mapValue;
        std::string whereMapClause = PhotoMapCodeColumn::MAPCODE_FILE_ID + " = ?";
        std::vector<std::string> whereMapArgs = { to_string(curFileId)};

        // 数据入库点
        int32_t fileId = photoInfo.fileId;
        double longitude = photoInfo.longitude;
        double latitude = photoInfo.latitude;
        const std::string mapTableName = PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE;

        if (fileId > 0 && fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
            fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
            PhotoMapData photoMapData(fileId, latitude, longitude);
            PhotoMapCodeOperation::GetPhotoMapCode(photoMapData, PhotoMapType::QUERY_AND_INSERT);
        }
    }
}

std::vector<CheckedMapCodeInfo> MapCodeUploadChecker::QueryMapCodeInfo(int32_t startFileId)
{
    MEDIA_INFO_LOG("MapCodeUploadChecker::QueryMapCodeInfo start");
    std::vector<CheckedMapCodeInfo> photoInfos;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, photoInfos,
        "MapCodeUploadChecker::QueryMapCodeInfo Failed to get rdbstore!");

    const std::vector<NativeRdb::ValueObject> bindArgs = {startFileId, BATCH_SIZE};
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_PHOTO, bindArgs);
    bool cond = resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK;
    CHECK_AND_RETURN_RET_LOG(cond, photoInfos,
        "MapCodeUploadChecker::QueryMapCodeInfo resultSet is null or count is 0");

    do {
        CheckedMapCodeInfo photoInfo;
        photoInfo.fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID,
            resultSet, TYPE_INT32));
        photoInfo.latitude = get<double>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_LATITUDE,
            resultSet, TYPE_DOUBLE));
        photoInfo.longitude = get<double>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_LONGITUDE,
            resultSet, TYPE_DOUBLE));
        photoInfos.push_back(photoInfo);
    } while (MedialibrarySubscriber::IsCurrentStatusOn() && resultSet->GoToNextRow() == NativeRdb::E_OK);
    MEDIA_INFO_LOG("MapCodeUploadChecker::QueryMapCodeInfo end photoInfos size %{public}zu", photoInfos.size());
    resultSet->Close();
    return photoInfos;
}

int32_t MapCodeUploadChecker::QueryMapCodeCount(int32_t startFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "Failed to get rdbStore.");
    const std::vector<NativeRdb::ValueObject> bindArgs = {startFileId};
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_POSTION_PHOTO, bindArgs);
    if (resultSet == nullptr) {
        return E_ERR;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("MapCodeUploadChecker::QueryMapCodeCount resultSet is null or count is 0");
        resultSet->Close();
        return E_OK;
    }
    int32_t ret = get<int32_t>(ResultSetUtils::GetValFromColumn("Count", resultSet, TYPE_INT32));
    resultSet->Close();
    return ret;
}

void MapCodeUploadChecker::HandleMapCodePhoto()
{
    MEDIA_INFO_LOG("MapCodeUploadChecker::HandleMapCodePhoto start handle no mapcode photo!");
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "MapCodeUploadChecker::HandleMapCodePhoto get preferences \
        error: %{public}d", errCode);
    int32_t curFileId = prefs->GetInt(NO_MAPCODE_PHOTO_NUMBER, 0);
    MEDIA_DEBUG_LOG("MapCodeUploadChecker::HandleMapCodePhoto start id: %{public}d", curFileId);
    std::vector<CheckedMapCodeInfo> photoInfos = QueryMapCodeInfo(curFileId);
    while (MedialibrarySubscriber::IsCurrentStatusOn() && photoInfos.size() > 0) {
        HandleMapCodeInfos(photoInfos, curFileId);
        prefs->PutInt(NO_MAPCODE_PHOTO_NUMBER, curFileId);
        prefs->FlushSync();
        photoInfos = QueryMapCodeInfo(curFileId);
    }
    MEDIA_DEBUG_LOG("end handle no origin photo! cost: %{public}"
        PRId64, MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    return;
}

bool MapCodeUploadChecker::RepairNoMapCodePhoto()
{
    MEDIA_INFO_LOG("MapCodeUploadChecker::RepairNoMapCodePhoto In");
    std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
    if (!(lock.try_lock())) {
        MEDIA_WARN_LOG("MapCodeUploadChecker::RepairNoMapCodePhoto Repairing no mapCode \
            photos has started, skipping this operation");
        return false;
    }

    MEDIA_DEBUG_LOG("MapCodeUploadChecker::RepairNoMapCodePhoto start repair no map code photo!");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("MapCodeUploadChecker::RepairNoMapCodePhoto get preferences error: %{public}d",
            errCode);
        return false;
    }
    int scanmapVersion = prefs->GetInt(SCANMAP_VERSION, SCANMAP_DEFAULT_VERSION);
    MEDIA_DEBUG_LOG("MapCodeUploadChecker::RepairNoMapCodePhoto scanmap version: %{public}d", scanmapVersion);
    if (scanmapVersion < SCANMAP_CURRENT_VERSION) {
        prefs->PutInt(NO_MAPCODE_PHOTO_NUMBER, 0);
        prefs->PutInt(SCANMAP_VERSION, SCANMAP_CURRENT_VERSION);
        prefs->FlushSync();
    }
    HandleMapCodePhoto();
    MEDIA_DEBUG_LOG("end RepairNoMapCodePhoto no origin photo!");
    return true;
}
}  // namespace Media
}  // namespace OHOS
