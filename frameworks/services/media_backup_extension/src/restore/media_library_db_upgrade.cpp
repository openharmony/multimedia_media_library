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
#include "media_library_db_upgrade.h"

#include <string>
#include <vector>

#include "dfx_transaction.h"
#include "rdb_store.h"
#include "media_log.h"
#include "album_plugin_table_event_handler.h"
#include "db_upgrade_utils.h"
#include "medialibrary_rdb_transaction.h"
#include "photo_album_update_date_modified_operation.h"
#include "photo_day_month_year_operation.h"

namespace OHOS::Media {
namespace DataTransfer {
/**
 * @brief Upgrade the database, before data restore or clone.
 */
int32_t MediaLibraryDbUpgrade::OnUpgrade(NativeRdb::RdbStore &store)
{
    int32_t ret = NativeRdb::E_OK;
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::OnUpgrade start");
    ret = this->UpgradeAlbumPlugin(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->UpgradePhotoAlbum(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->UpgradePhotos(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->UpgradePhotoMap(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->MergeAlbumFromOldBundleNameToNewBundleName(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->UpgradePhotosBelongsToAlbum(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->ExecSqlWithRetry([&]() {
        return PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(store);
    });
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::OnUpgrade end");
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDbUpgrade::ExecSqlWithRetry(std::function<int32_t()> execSql)
{
    int currentTime = 0;
    int32_t busyRetryTime = 0;
    int32_t err = NativeRdb::E_OK;
    while (busyRetryTime < MAX_BUSY_TRY_TIMES && currentTime <= MAX_TRY_TIMES) {
        err = execSql();
        if (err == NativeRdb::E_OK) {
            break;
        } else if (err == NativeRdb::E_SQLITE_LOCKED) {
            std::this_thread::sleep_for(std::chrono::milliseconds(TRANSACTION_WAIT_INTERVAL));
            currentTime++;
            MEDIA_ERR_LOG("ExecuteSqlInternal busy, ret:%{public}d, time:%{public}d", err, currentTime);
        } else if (err == NativeRdb::E_SQLITE_BUSY || err == NativeRdb::E_DATABASE_BUSY) {
            busyRetryTime++;
            MEDIA_ERR_LOG("ExecuteSqlInternal busy, ret:%{public}d, busyRetryTime:%{public}d", err, busyRetryTime);
        } else {
            MEDIA_ERR_LOG("ExecuteSqlInternal faile, ret = %{public}d", err);
            break;
        }
    }
    return err;
}

int32_t MediaLibraryDbUpgrade::MergeAlbumFromOldBundleNameToNewBundleName(NativeRdb::RdbStore &store)
{
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::MergeAlbumFromOldBundleNameToNewBundleName start");
    int32_t ret = NativeRdb::E_OK;
    std::vector<NativeRdb::ValueObject> args;
    for (auto &executeSql : SQL_MERGE_ALBUM_FROM_OLD_BUNDLE_NAME_TO_NEW_BUNDLE_NAME) {
        ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(executeSql); });
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "Media_Restore: executeSql failed, sql: %{public}s", executeSql.c_str());
    }
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::MergeAlbumFromOldBundleNameToNewBundleName end");
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDbUpgrade::UpgradePhotosBelongsToAlbum(NativeRdb::RdbStore &store)
{
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::UpgradePhotosBelongsToAlbum start");
    int32_t ret = NativeRdb::E_OK;
    std::vector<NativeRdb::ValueObject> args;
    for (const auto &executeSql : this->SQL_PHOTOS_NEED_TO_BELONGS_TO_ALBUM) {
        ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(executeSql); });
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "Media_Restore: executeSql failed, sql: %{public}s", executeSql.c_str());
    }
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::UpgradePhotosBelongsToAlbum end");
    return NativeRdb::E_OK;
}

/**
 * @brief Upgrade album_plugin table.
 */
int32_t MediaLibraryDbUpgrade::UpgradeAlbumPlugin(NativeRdb::RdbStore &store)
{
    CHECK_AND_RETURN_RET(!(this->dbUpgradeUtils_.IsTableExists(store, "album_plugin")), NativeRdb::E_OK);
    AlbumPluginTableEventHandler handler;
    return handler.OnUpgrade(store, 0, 0);
}

/**
 * @brief Upgrade PhotoAlbum table.
 */
int32_t MediaLibraryDbUpgrade::UpgradePhotoAlbum(NativeRdb::RdbStore &store)
{
    int32_t ret = NativeRdb::E_OK;
    ret = this->dbUpgradeUtils_.DropAllTriggers(store, "PhotoAlbum");
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->dbUpgradeUtils_.DropAllUniqueIndex(store, "PhotoAlbum");
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->AddlPathColumn(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);
    return this->UpdatelPathColumn(store);
}

/**
 * @brief Upgrade the lpath column in PhotoAlbum table.
 */
int32_t MediaLibraryDbUpgrade::UpdatelPathColumn(NativeRdb::RdbStore &store)
{
    std::string executeSql = this->SQL_PHOTO_ALBUM_TABLE_UPDATE_LPATH_COLUMN;
    std::vector<NativeRdb::ValueObject> args;
    int32_t ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(executeSql); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Media_Restore: MediaLibraryDbUpgrade::UpdatelPathColumn failed, ret=%{public}d, sql=%{public}s",
            ret,
            executeSql.c_str());
        return ret;
    }
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::UpdatelPathColumn success");
    return ret;
}

/**
 * @brief Add owner_album_id column to Photos table.
 */
int32_t MediaLibraryDbUpgrade::AddOwnerAlbumIdColumn(NativeRdb::RdbStore &store)
{
    if (this->dbUpgradeUtils_.IsColumnExists(store, "Photos", "owner_album_id")) {
        return NativeRdb::E_OK;
    }

    std::vector<NativeRdb::ValueObject> args;
    std::string sql = this->SQL_PHOTOS_TABLE_ADD_OWNER_ALBUM_ID;
    int32_t ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(sql, args); });
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK,
        "Media_Restore: MediaLibraryDbUpgrade::AddOwnerAlbumIdColumn failed, ret=%{public}d, sql=%{public}s",
        ret, sql.c_str());
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::AddOwnerAlbumIdColumn success");
    return ret;
}

/**
 * @brief Add lpath column to PhotoAlbum table.
 */
int32_t MediaLibraryDbUpgrade::AddlPathColumn(NativeRdb::RdbStore &store)
{
    CHECK_AND_RETURN_RET(!(this->dbUpgradeUtils_.IsColumnExists(store, "PhotoAlbum", "lpath")), NativeRdb::E_OK);
    std::vector<NativeRdb::ValueObject> args;
    std::string sql = this->SQL_PHOTO_ALBUM_TABLE_ADD_LPATH_COLUMN;
    return ExecSqlWithRetry([&]() { return store.ExecuteSql(sql, args); });
}

/**
 * @brief Move the single relationship from PhotoMap table to Photos table, stored in owner_album_id.
 */
int32_t MediaLibraryDbUpgrade::MoveSingleRelationshipToPhotos(NativeRdb::RdbStore &store)
{
    std::vector<std::string> executeSqls = {this->SQL_TEMP_PHOTO_MAP_TABLE_DROP, this->SQL_TEMP_PHOTO_MAP_TABLE_CREATE};
    executeSqls.insert(executeSqls.end(),
        this->SQL_TEMP_PHOTO_MAP_TABLE_CREATE_INDEX_ARRAY.begin(),
        this->SQL_TEMP_PHOTO_MAP_TABLE_CREATE_INDEX_ARRAY.end());
    executeSqls.push_back(this->SQL_PHOTOS_TABLE_UPDATE_ALBUM_ID);
    executeSqls.push_back(this->SQL_PHOTO_MAP_TABLE_DELETE_SINGLE_RELATIONSHIP);
    executeSqls.push_back(this->SQL_TEMP_PHOTO_MAP_TABLE_DROP);
    int ret = NativeRdb::E_OK;
    MEDIA_INFO_LOG("MoveSingleRelationshipToPhotos begin");
    auto [errCode, transaction] = store.CreateTransaction(OHOS::NativeRdb::Transaction::DEFERRED);
    DfxTransaction reporter{__func__};
    if (errCode != NativeRdb::E_OK || transaction == nullptr) {
        reporter.ReportError(DfxTransaction::AbnormalType::CREATE_ERROR, errCode);
        MEDIA_ERR_LOG("transaction failed, err:%{public}d", errCode);
        return errCode;
    }
    for (const std::string &executeSql : executeSqls) {
        auto res = transaction->Execute(executeSql);
        ret = res.first;
        if (ret != NativeRdb::E_OK) {
            reporter.ReportError(DfxTransaction::AbnormalType::EXECUTE_ERROR, ret);
            MEDIA_ERR_LOG("Media_Restore: MoveSingleRelationshipToPhotos failed, ret=%{public}d, sql=%{public}s",
                ret,
                executeSql.c_str());
            transaction->Rollback();
            return ret;
        }
    }
    ret = transaction->Commit();
    if (ret != NativeRdb::E_OK) {
        reporter.ReportError(DfxTransaction::AbnormalType::COMMIT_ERROR, ret);
        MEDIA_ERR_LOG("MoveSingleRelationshipToPhotos: tans finish fail!, ret:%{public}d", ret);
        transaction->Rollback();
    } else {
        reporter.ReportIfTimeout();
    }
    return NativeRdb::E_OK;
}

/**
 * @brief Upgrade Photos table.
 */
int32_t MediaLibraryDbUpgrade::UpgradePhotos(NativeRdb::RdbStore &store)
{
    int32_t ret = NativeRdb::E_OK;
    ret = this->dbUpgradeUtils_.DropAllTriggers(store, "Photos");
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->AddOwnerAlbumIdColumn(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = ExecSqlWithRetry([&]() { return PhotoDayMonthYearOperation::UpdatePhotosDate(store); });
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret, "update photos date failed, ret=%{public}d", ret);

    return NativeRdb::E_OK;
}

/**
 * @brief Upgrade PhotoMap table.
 */
int32_t MediaLibraryDbUpgrade::UpgradePhotoMap(NativeRdb::RdbStore &store)
{
    int32_t ret = NativeRdb::E_OK;
    ret = this->dbUpgradeUtils_.DropAllTriggers(store, "PhotoMap");
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);

    ret = this->MoveSingleRelationshipToPhotos(store);
    CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, ret);
    return NativeRdb::E_OK;
}
}  // namespace DataTransfer
}  // namespace OHOS::Media