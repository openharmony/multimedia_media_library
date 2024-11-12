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

#include "rdb_store.h"
#include "media_log.h"
#include "album_plugin_table_event_handler.h"
#include "db_upgrade_utils.h"

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
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    ret = this->UpgradePhotoAlbum(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    ret = this->UpgradePhotos(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    ret = this->UpgradePhotoMap(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    ret = this->MergeAlbumFromOldBundleNameToNewBundleName(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    ret = this->UpgradePhotosBelongsToAlbum(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::OnUpgrade end");
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDbUpgrade::MergeAlbumFromOldBundleNameToNewBundleName(NativeRdb::RdbStore &store)
{
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::MergeAlbumFromOldBundleNameToNewBundleName start");
    int32_t ret = NativeRdb::E_OK;
    for (const auto &executeSql : this->SQL_MERGE_ALBUM_FROM_OLD_BUNDLE_NAME_TO_NEW_BUNDLE_NAME) {
        ret = store.ExecuteSql(executeSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Restore: executeSql failed, sql: %{public}s", executeSql.c_str());
            return ret;
        }
    }
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::MergeAlbumFromOldBundleNameToNewBundleName end");
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDbUpgrade::UpgradePhotosBelongsToAlbum(NativeRdb::RdbStore &store)
{
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::UpgradePhotosBelongsToAlbum start");
    int32_t ret = NativeRdb::E_OK;
    for (const auto &executeSql : this->SQL_PHOTOS_NEED_TO_BELONGS_TO_ALBUM) {
        ret = store.ExecuteSql(executeSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Restore: executeSql failed, sql: %{public}s", executeSql.c_str());
            return ret;
        }
    }
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::UpgradePhotosBelongsToAlbum end");
    return NativeRdb::E_OK;
}

/**
 * @brief Upgrade album_plugin table.
 */
int32_t MediaLibraryDbUpgrade::UpgradeAlbumPlugin(NativeRdb::RdbStore &store)
{
    if (this->dbUpgradeUtils_.IsTableExists(store, "album_plugin")) {
        return NativeRdb::E_OK;
    }
    AlbumPluginTableEventHandler handler;
    return handler.OnUpgrade(store, 0, 0);
}

/**
 * @brief Upgrade PhotoAlbum table.
 */
int32_t MediaLibraryDbUpgrade::UpgradePhotoAlbum(NativeRdb::RdbStore &store)
{
    int32_t ret = NativeRdb::E_OK;
    ret = this->AddlPathColumn(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    ret = this->DropPhotoAlbumTrigger(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    return this->UpdatelPathColumn(store);
}

/**
 * @brief Drop PhotoAlbum trigger.
 */
int32_t MediaLibraryDbUpgrade::DropPhotoAlbumTrigger(NativeRdb::RdbStore &store)
{
    std::vector<std::string> executeSqls = this->SQL_PHOTO_ALBUM_TABLE_DROP_TRIGGER;
    int ret = NativeRdb::E_OK;
    store.BeginTransaction();
    for (const std::string &executeSql : executeSqls) {
        ret = store.ExecuteSql(executeSql);
        if (ret != NativeRdb::E_OK) {
            store.RollBack();
            MEDIA_ERR_LOG(
                "Media_Restore: DropPhotoAlbumTrigger failed, ret=%{public}d, sql=%{public}s", ret, executeSql.c_str());
            return ret;
        }
    }
    store.Commit();
    return NativeRdb::E_OK;
}

/**
 * @brief Upgrade the lpath column in PhotoAlbum table.
 */
int32_t MediaLibraryDbUpgrade::UpdatelPathColumn(NativeRdb::RdbStore &store)
{
    std::string executeSql = this->SQL_PHOTO_ALBUM_TABLE_UPDATE_LPATH_COLUMN;
    int32_t ret = store.ExecuteSql(executeSql);
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
    std::string sql = this->SQL_PHOTOS_TABLE_ADD_OWNER_ALBUM_ID;
    int32_t ret = store.ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG(
            "Media_Restore: MediaLibraryDbUpgrade::AddOwnerAlbumIdColumn failed, ret=%{public}d, sql=%{public}s",
            ret,
            sql.c_str());
    }
    MEDIA_INFO_LOG("Media_Restore: MediaLibraryDbUpgrade::AddOwnerAlbumIdColumn success");
    return ret;
}

/**
 * @brief Add lpath column to PhotoAlbum table.
 */
int32_t MediaLibraryDbUpgrade::AddlPathColumn(NativeRdb::RdbStore &store)
{
    if (this->dbUpgradeUtils_.IsColumnExists(store, "PhotoAlbum", "lpath")) {
        return NativeRdb::E_OK;
    }
    std::string sql = this->SQL_PHOTO_ALBUM_TABLE_ADD_LPATH_COLUMN;
    return store.ExecuteSql(sql);
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
    executeSqls.insert(executeSqls.end(),
        this->SQL_PHOTOS_TABLE_DROP_TRIGGER_ARRAY.begin(),
        this->SQL_PHOTOS_TABLE_DROP_TRIGGER_ARRAY.end());
    executeSqls.push_back(this->SQL_PHOTOS_TABLE_UPDATE_ALBUM_ID);
    executeSqls.insert(executeSqls.end(),
        this->SQL_PHOTO_MAP_TABLE_DROP_TRIGGER_ARRAY.begin(),
        this->SQL_PHOTO_MAP_TABLE_DROP_TRIGGER_ARRAY.end());
    executeSqls.push_back(this->SQL_PHOTO_MAP_TABLE_DELETE_SINGLE_RELATIONSHIP);
    executeSqls.push_back(this->SQL_TEMP_PHOTO_MAP_TABLE_DROP);
    int ret = NativeRdb::E_OK;
    store.BeginTransaction();
    for (const std::string &executeSql : executeSqls) {
        ret = store.ExecuteSql(executeSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Media_Restore: MoveSingleRelationshipToPhotos failed, ret=%{public}d, sql=%{public}s",
                ret,
                executeSql.c_str());
            store.RollBack();
            return ret;
        }
    }
    store.Commit();
    return NativeRdb::E_OK;
}

/**
 * @brief Upgrade Photos table.
 */
int32_t MediaLibraryDbUpgrade::UpgradePhotos(NativeRdb::RdbStore &store)
{
    int32_t ret = NativeRdb::E_OK;
    ret = this->AddOwnerAlbumIdColumn(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    return NativeRdb::E_OK;
}

/**
 * @brief Upgrade PhotoMap table.
 */
int32_t MediaLibraryDbUpgrade::UpgradePhotoMap(NativeRdb::RdbStore &store)
{
    int32_t ret = NativeRdb::E_OK;
    ret = this->MoveSingleRelationshipToPhotos(store);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    return NativeRdb::E_OK;
}
}  // namespace DataTransfer
}  // namespace OHOS::Media