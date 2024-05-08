/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "backup_database_utils.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
const size_t MIN_GARBLE_SIZE = 2;
const size_t GARBLE_START = 1;
int32_t BackupDatabaseUtils::InitDb(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &dbName,
    const std::string &dbPath, const std::string &bundleName, bool isMediaLibrary, int32_t area)
{
    NativeRdb::RdbStoreConfig config(dbName);
    config.SetPath(dbPath);
    config.SetBundleName(bundleName);
    config.SetReadConSize(CONNECT_SIZE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    if (area != DEFAULT_AREA_VERSION) {
        config.SetArea(area);
    }
    if (isMediaLibrary) {
        config.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
        config.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);
    }
    int32_t err;
    RdbCallback cb;
    rdbStore = NativeRdb::RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, cb, err);
    return err;
}

std::string BackupDatabaseUtils::CloudSyncTriggerFunc(const std::vector<std::string> &args)
{
    return "";
}

std::string BackupDatabaseUtils::IsCallerSelfFunc(const std::vector<std::string> &args)
{
    return "false";
}

int32_t BackupDatabaseUtils::QueryInt(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &sql,
    const std::string &column)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdb_ is nullptr, Maybe init failed.");
        return 0;
    }
    auto resultSet = rdbStore->QuerySql(sql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val(column, resultSet);
    return result;
}

int32_t BackupDatabaseUtils::Update(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, int32_t &changeRows,
    NativeRdb::ValuesBucket &valuesBucket, std::unique_ptr<NativeRdb::AbsRdbPredicates> &predicates)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdb_ is nullptr, Maybe init failed.");
        return E_FAIL;
    }
    return rdbStore->Update(changeRows, valuesBucket, *predicates);
}

int32_t BackupDatabaseUtils::InitGarbageAlbum(std::shared_ptr<NativeRdb::RdbStore> galleryRdb,
    std::set<std::string> &cacheSet, std::unordered_map<std::string, std::string> &nickMap)
{
    if (galleryRdb == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr, Maybe init failed.");
        return E_FAIL;
    }

    const string querySql = "SELECT nick_dir, nick_name FROM garbage_album where type = 0";
    auto resultSet = galleryRdb->QuerySql(QUERY_GARBAGE_ALBUM);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int32_t count = -1;
    int32_t err = resultSet->GetRowCount(count);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get count, err: %{public}d", err);
        return E_FAIL;
    }
    MEDIA_INFO_LOG("garbageCount: %{public}d", count);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t type;
        resultSet->GetInt(INDEX_TYPE, type);
        if (type == NICK) {
            string nickName;
            string nickDir;
            resultSet->GetString(INDEX_NICK_DIR, nickDir);
            resultSet->GetString(INDEX_NICK_NAME, nickName);
            nickMap[nickDir] = nickName;
        } else {
            string cacheDir;
            resultSet->GetString(INDEX_CACHE_DIR, cacheDir);
            cacheSet.insert(cacheDir);
        }
    }
    MEDIA_INFO_LOG("add map success!");
    resultSet->Close();
    return E_OK;
}

int32_t BackupDatabaseUtils::QueryGalleryAllCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_ALL_COUNT = "SELECT count(1) AS count FROM gallery_media";
    return QueryInt(galleryRdb, QUERY_GALLERY_ALL_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryImageCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_IMAGE_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE media_type = 1 AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_IMAGE_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryVideoCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_VIDEO_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE media_type = 3 AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_VIDEO_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryHiddenCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_HIDDEN_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE local_media_id = -4 AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_HIDDEN_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryTrashedCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_TRASHED_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE local_media_id = 0 AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_TRASHED_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryCloneCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_CLONE_COUNT =
        string("SELECT count(1) AS count FROM gallery_media WHERE local_media_id = -3 AND _size > 0 ") +
        "AND (storage_id IN (0, 65537)) AND relative_bucket_id NOT IN ( " +
        "SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1)";
    return QueryInt(galleryRdb, QUERY_GALLERY_CLONE_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGallerySDCardCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_SD_CARD_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE storage_id NOT IN (0, 65537) AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_SD_CARD_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryScreenVideoCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_SCRENN_VIDEO_COUNT =
        "SELECT count(1) AS count FROM gallery_media \
        WHERE local_media_id = -3 AND bucket_id = 1028075469 AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_SCRENN_VIDEO_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryCloudCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_CLOUD_COUNT =
        "SELECT count(1) AS count FROM gallery_media \
        WHERE local_media_id = -1 AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_CLOUD_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryExternalImageCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb)
{
    static string QUERY_EXTERNAL_IMAGE_COUNT =
        "SELECT count(1) AS count FROM files WHERE  media_type = 1 AND _size > 0";
    return QueryInt(externalRdb, QUERY_EXTERNAL_IMAGE_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryExternalVideoCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb)
{
    static string QUERY_EXTERNAL_VIDEO_COUNT =
        "SELECT count(1) AS count FROM files WHERE  media_type = 3 AND _size > 0";
    return QueryInt(externalRdb, QUERY_EXTERNAL_VIDEO_COUNT, CUSTOM_COUNT);
}

std::shared_ptr<NativeRdb::ResultSet> BackupDatabaseUtils::GetQueryResultSet(
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &querySql)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return nullptr;
    }
    return rdbStore->QuerySql(querySql);
}

std::unordered_map<std::string, std::string> BackupDatabaseUtils::GetColumnInfoMap(
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName)
{
    std::unordered_map<std::string, std::string> columnInfoMap;
    std::string querySql = "SELECT name, type FROM pragma_table_info('" + tableName + "')";
    auto resultSet = GetQueryResultSet(rdbStore, querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr");
        return columnInfoMap;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string columnName = GetStringVal(PRAGMA_TABLE_NAME, resultSet);
        std::string columnType = GetStringVal(PRAGMA_TABLE_TYPE, resultSet);
        if (columnName.empty() || columnType.empty()) {
            MEDIA_ERR_LOG("Empty column name or type: %{public}s, %{public}s", columnName.c_str(), columnType.c_str());
            continue;
        }
        columnInfoMap[columnName] = columnType;
    }
    return columnInfoMap;
}

void BackupDatabaseUtils::UpdateUniqueNumber(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, int32_t number,
    const std::string &type)
{
    const string updateSql =
        "UPDATE UniqueNumber SET unique_number = " + to_string(number) + " WHERE media_type = '" + type + "'";
    int32_t erroCode = rdbStore->ExecuteSql(updateSql);
    if (erroCode < 0) {
        MEDIA_ERR_LOG("execute update unique number failed, ret=%{public}d", erroCode);
    }
}

int32_t BackupDatabaseUtils::QueryUniqueNumber(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const std::string &type)
{
    const string querySql = "SELECT unique_number FROM UniqueNumber WHERE media_type = '" + type + "'";
    return QueryInt(rdbStore, querySql, UNIQUE_NUMBER);
}

std::string BackupDatabaseUtils::GarbleInfoName(const string &infoName)
{
    std::string garbledInfoName = infoName;
    if (infoName.size() <= MIN_GARBLE_SIZE) {
        return garbledInfoName;
    }
    size_t garbledSize = infoName.size() - MIN_GARBLE_SIZE;
    garbledInfoName.replace(GARBLE_START, garbledSize, GARBLE);
    return garbledInfoName;
}

int32_t BackupDatabaseUtils::QueryExternalAudioCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb)
{
    static string QUERY_EXTERNAL_AUDIO_COUNT = "SELECT count(1) as count FROM files WHERE media_type = 2 AND _size > 0 \
        AND _data LIKE '/storage/emulated/0/Music%'";
    return QueryInt(externalRdb, QUERY_EXTERNAL_AUDIO_COUNT, CUSTOM_COUNT);
}
} // namespace Media
} // namespace OHOS