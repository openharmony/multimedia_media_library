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

#define MLOG_TAG "MediaLibraryCloudUploadChecker"

#include "cloud_upload_checker.h"

#include <sys/stat.h>

#include "media_file_utils.h"
#include "media_file_uri.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "thumbnail_const.h"
#include "media_column.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "result_set_utils.h"
#include "thumbnail_const.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_photo_operations.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace NativeRdb;
const std::string BATCH_SIZE = "500";
const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
const std::string NO_ORIGIN_PHOTO_NUMBER = "no_origin_photo_number";
const std::string NO_ORIGIN_BUT_LCD_PHOTO_NUMBER = "no_origin_but_lcd_photo_number";
const std::string NO_DETAIL_TIME = "no_detail_time";
static const std::string SQL_PHOTOS_TABLE_QUERY_NO_ORIGIN_BUT_LCD_COUNT = "\
    SELECT \
        COUNT(*) AS Count \
    FROM Photos \
    WHERE dirty = 100 AND \
        thumbnail_ready >= 3 AND \
        lcd_visit_time >= 2 AND \
        date_trashed = 0 AND \
        file_id > ? \
    LIMIT 500;";
static const std::string SQL_PHOTOS_TABLE_QUERY_NO_ORIGIN_BUT_LCD_PHOTO = "\
    SELECT \
        file_id, data \
    FROM Photos \
    WHERE dirty = 100 AND \
        thumbnail_ready >= 3 AND \
        lcd_visit_time >= 2 AND \
        date_trashed = 0 AND \
        file_id > ? \
    LIMIT 500;";

static const std::string SQL_REPAIR_DETAIL_TIME =
    " UPDATE Photos "
    " SET detail_time = ("
    " CASE"
    "   WHEN date_taken / 10000000000 == 0 THEN strftime( '%Y:%m:%d %H:%M:%S', date_taken, 'unixepoch', 'localtime' )"
    "   ELSE strftime( '%Y:%m:%d %H:%M:%S', date_taken / 1000, 'unixepoch', 'localtime' )"
    " END ) "
    " WHERE"
    " CASE"
    "   WHEN date_taken / 10000000000 == 0 THEN strftime( '%Y:%m:%d %H:%M:%S', date_taken, 'unixepoch', 'localtime' )"
    "   <> detail_time"
    "   ELSE strftime( '%Y:%m:%d %H:%M:%S', date_taken / 1000, 'unixepoch', 'localtime' ) <> detail_time "
    " END ;";

static const int32_t NO_ORIGIN_NO_LCD = 101;

void CloudUploadChecker::HandleNoOriginPhoto()
{
    MEDIA_INFO_LOG("start handle no origin photo!");
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    int32_t curFileId = prefs->GetInt(NO_ORIGIN_PHOTO_NUMBER, 0);
    MEDIA_INFO_LOG("start file id: %{public}d", curFileId);
    while (GetPhotoCount(curFileId) > 0) {
        MEDIA_INFO_LOG("start handle origin photo start: %{public}d", curFileId);
        int32_t nextFileId = curFileId;
        std::vector<CheckedPhotoInfo> photoInfos = QueryPhotoInfo(curFileId, nextFileId);
        HandlePhotoInfos(photoInfos);
        curFileId = nextFileId + 1;
        prefs->PutInt(NO_ORIGIN_PHOTO_NUMBER, curFileId);
        prefs->FlushSync();
    }
    MEDIA_INFO_LOG("end handle no origin photo!");
    return;
}

void CloudUploadChecker::HandlePhotoInfos(std::vector<CheckedPhotoInfo> photoInfos)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr");
    std::vector<std::string> noLcdList;
    vector<int32_t> repairedIdList;
    for (CheckedPhotoInfo &photoInfo : photoInfos) {
        if (MediaFileUtils::IsFileExists(photoInfo.path)) {
            continue;
        }
        string lcdPath = GetThumbnailPath(photoInfo.path, THUMBNAIL_LCD_SUFFIX);
        if (MediaFileUtils::IsFileExists(lcdPath)) {
            MEDIA_INFO_LOG("lcd path exists but origin failed not, file_id: %{public}d", photoInfo.fileId);
            bool ret = MediaFileUtils::CopyFileUtil(lcdPath, photoInfo.path);
            if (!ret) {
                MEDIA_ERR_LOG(
                    "copy lcd to origin photo failed, file_id: %{public}d, ret: %{public}d", photoInfo.fileId, ret);
                continue;
            }
            struct stat fst{};
            if (stat(photoInfo.path.c_str(), &fst) != 0) {
                MEDIA_ERR_LOG("stat syscall failed, file_id=%{public}d, errno=%{public}d", photoInfo.fileId, errno);
                continue;
            }
            RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
            predicates.EqualTo(MediaColumn::MEDIA_ID, photoInfo.fileId);
            ValuesBucket values;
            values.PutLong(MediaColumn::MEDIA_SIZE, static_cast<int64_t>(fst.st_size));
            int32_t updateCount = 0;
            auto err = rdbStore->Update(updateCount, values, predicates);
            if (err != NativeRdb::E_OK) {
                MEDIA_ERR_LOG("repair from lcd failed, file_id=%{public}d, err=%{public}d", photoInfo.fileId, err);
                continue;
            }
            repairedIdList.emplace_back(photoInfo.fileId);
        } else {
            noLcdList.push_back(to_string(photoInfo.fileId));
        }
    }
    RecordRepairIdList(repairedIdList);
    UpdateDirty(noLcdList, NO_ORIGIN_NO_LCD);
}

void CloudUploadChecker::UpdateDirty(std::vector<std::string> idList, int32_t dirtyType)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "Failed to get rdbstore!");
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(MediaColumn::MEDIA_ID, idList);
    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_DIRTY, dirtyType);
    int32_t updateCount = 0;
    int32_t err = rdbStore->Update(updateCount, values, predicates);
    MEDIA_INFO_LOG("dirty: %{public}d, idList size: %{public}d, update size: %{public}d, err: %{public}d", dirtyType,
        static_cast<int32_t>(idList.size()), updateCount, err);
}

int32_t CloudUploadChecker::GetPhotoCount(int32_t startFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, 0, "Failed to get rdbstore!");
    std::string queryCount = " COUNT(*) AS Count";
    std::string sql = GetQuerySql(startFileId, queryCount);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(sql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is null or count is 0");
        return 0;
    }
    int32_t count = get<int32_t>(ResultSetUtils::GetValFromColumn("Count", resultSet, TYPE_INT32));
    return count;
}

std::string CloudUploadChecker::GetQuerySql(int32_t startFileId, std::string mediaColumns)
{
    const std::string sql = "SELECT " + mediaColumns + " FROM Photos WHERE dirty = 1 AND thumbnail_ready >= 3 AND " +
        "lcd_visit_time >= 2 AND date_trashed = 0 AND file_id > " + to_string(startFileId) + " LIMIT " + BATCH_SIZE;
    return sql;
}

std::vector<CheckedPhotoInfo> CloudUploadChecker::QueryPhotoInfo(int32_t startFileId, int32_t &outFileId)
{
    std::vector<CheckedPhotoInfo> photoInfos;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, photoInfos, "Failed to get rdbstore!");
    const std::string mediaColumns = Media::PhotoColumn::MEDIA_ID + ", " + Media::PhotoColumn::MEDIA_FILE_PATH;
    std::string sql = GetQuerySql(startFileId, mediaColumns);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(sql);
    bool cond = (resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK);
    CHECK_AND_RETURN_RET_LOG(cond, photoInfos, "resultSet is null or count is 0");
    int32_t fileId = startFileId;
    do {
        CheckedPhotoInfo photoInfo;
        std::string path =
            get<std::string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));
        if (path.empty()) {
            MEDIA_WARN_LOG("Failed to get data path");
            continue;
        }
        fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
        photoInfo.fileId = fileId;
        photoInfo.path = path;
        photoInfos.push_back(photoInfo);
    } while ((resultSet->GoToNextRow() == NativeRdb::E_OK));
    outFileId = fileId;
    return photoInfos;
}

void CloudUploadChecker::RecordRepairIdList(const vector<int32_t>& repairedIdList)
{
    string idList;
    for (int32_t fileId : repairedIdList) {
        idList.append("|");
        idList.append(to_string(fileId));
    }
    MEDIA_INFO_LOG("Record repaired file_id list: %{public}s", idList.c_str());
}

int32_t CloudUploadChecker::QueryLcdPhotoCount(int32_t startFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "Failed to get rdbStore.");
    const std::vector<NativeRdb::ValueObject> bindArgs = { startFileId };
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_NO_ORIGIN_BUT_LCD_COUNT, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK, 0,
        "resultSet is null or count is 0");
    int32_t count = get<int32_t>(ResultSetUtils::GetValFromColumn("Count", resultSet, TYPE_INT32));
    return count;
}

void CloudUploadChecker::QueryLcdAndRepair(int32_t startFileId, int32_t &outFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr");
    const std::vector<NativeRdb::ValueObject> bindArgs = { startFileId };
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_NO_ORIGIN_BUT_LCD_PHOTO, bindArgs);
    CHECK_AND_RETURN_LOG(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK,
        "resultSet is null or count is 0");
    int32_t fileId = startFileId;
    vector<int32_t> repairedIdList;
    do {
        std::string path =
            get<std::string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));
        if (path.empty()) {
            MEDIA_WARN_LOG("Failed to get data path");
            continue;
        }
        if (MediaFileUtils::IsFileExists(path)) {
            continue;
        }
        fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
        string lcdPath = GetThumbnailPath(path, THUMBNAIL_LCD_SUFFIX);
        if (MediaFileUtils::IsFileExists(lcdPath)) {
            bool ret = MediaFileUtils::CopyFileUtil(lcdPath, path);
            CHECK_AND_PRINT_LOG(ret, "copy lcd to origin photo failed, file_id: %{public}d", fileId);
            repairedIdList.emplace_back(fileId);
        }

        RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
        predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
        ValuesBucket values;
        values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyTypes::TYPE_NEW));
        struct stat fst{};
        if (stat(path.c_str(), &fst) == 0) {
            values.PutLong(MediaColumn::MEDIA_SIZE, static_cast<int64_t>(fst.st_size));
        } else {
            MEDIA_ERR_LOG("stat syscall failed, file_id=%{public}d, errno=%{public}d", fileId, errno);
        }
        int32_t updateCount = 0;
        int32_t err = rdbStore->Update(updateCount, values, predicates);
        MEDIA_INFO_LOG(
            "repair from lcd: file_id=%{public}d,dirty=100,path=%{public}s,count=%{public}d,err=%{public}d",
            fileId, path.c_str(), updateCount, err);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    outFileId = fileId;
    RecordRepairIdList(repairedIdList);
}

void CloudUploadChecker::RepairNoOriginButLcd()
{
    MEDIA_INFO_LOG("start repair no origin but lcd photo!");
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    int32_t curFileId = prefs->GetInt(NO_ORIGIN_BUT_LCD_PHOTO_NUMBER, 0);
    MEDIA_INFO_LOG("start file id: %{public}d", curFileId);
    while (QueryLcdPhotoCount(curFileId) > 0) {
        MEDIA_INFO_LOG("start repair origin photo, current file_id: %{public}d", curFileId);
        int32_t nextFileId = curFileId;
        QueryLcdAndRepair(curFileId, nextFileId);
        curFileId = nextFileId + 1;
        prefs->PutInt(NO_ORIGIN_BUT_LCD_PHOTO_NUMBER, curFileId);
        prefs->FlushSync();
    }
    MEDIA_INFO_LOG("end repair no origin but lcd photo!");
    return;
}

void CloudUploadChecker::RepairNoDetailTime()
{
    MEDIA_INFO_LOG("start repair detail time");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "Failed to get rdbstore!");
    int32_t err = rdbStore->ExecuteSql(SQL_REPAIR_DETAIL_TIME);
    CHECK_AND_RETURN_LOG(err == NativeRdb::E_OK, "Failed to RepairNoDetailTime: %{public}d", err);
    MEDIA_INFO_LOG("end repair detail time!");
}
} // namespace Media
} // namespace OHOS