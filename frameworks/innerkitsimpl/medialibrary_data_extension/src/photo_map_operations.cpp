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
#define MLOG_TAG "PhotoMapOperation"

#include "photo_map_operations.h"

#include "media_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "value_object.h"

namespace OHOS::Media {
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

int32_t PhotoMapOperations::AddSingleAsset(const DataShareValuesBucket &value)
{
    /**
     * Build insert sql:
     * INSERT INTO PhotoMap (map_album, map_asset) SELECT
     * ?, ?
     * WHERE
     *     (NOT EXISTS (SELECT * FROM PhotoMap WHERE map_album = ? AND map_asset = ?))
     *     AND (EXISTS (SELECT file_id FROM Files WHERE file_id = ?))
     *     AND (EXISTS (SELECT album_id FROM PhotoAlbum WHERE album_id = ? AND album_type = ? AND album_subtype = ?));
     */
    static const string INSERT_MAP_SQL = "INSERT INTO " + PhotoMap::TABLE +
        " (" + PhotoMap::ALBUM_ID + ", " + PhotoMap::ASSET_ID + ") " +
        "SELECT ?, ? WHERE " +
        "(NOT EXISTS (SELECT * FROM " + PhotoMap::TABLE + " WHERE " +
            PhotoMap::ALBUM_ID + " = ? AND " + PhotoMap::ASSET_ID + " = ?)) " +
        "AND (EXISTS (SELECT " + MediaColumn::MEDIA_ID + " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
            MediaColumn::MEDIA_ID + " = ?)) " +
        "AND (EXISTS (SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE +
            " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = ? AND " + PhotoAlbumColumns::ALBUM_TYPE + " = ? AND " +
            PhotoAlbumColumns::ALBUM_SUBTYPE + " = ?));";
    bool isValid = false;
    int32_t albumId = value.Get(PhotoMap::ALBUM_ID, isValid);
    if (!isValid) {
        return -EINVAL;
    }
    string assetUri = value.Get(PhotoMap::ASSET_ID, isValid);
    if (!isValid) {
        return -EINVAL;
    }

    string assetId = MediaFileUri::GetPhotoId(assetUri);
    if (assetId.empty()) {
        return -EINVAL;
    }
    vector<ValueObject> bindArgs;
    bindArgs.emplace_back(albumId);
    bindArgs.emplace_back(assetId);
    bindArgs.emplace_back(albumId);
    bindArgs.emplace_back(assetId);
    bindArgs.emplace_back(assetId);
    bindArgs.emplace_back(albumId);
    bindArgs.emplace_back(PhotoAlbumType::USER);
    bindArgs.emplace_back(PhotoAlbumSubType::USER_GENERIC);
    int errCode =  MediaLibraryRdbStore::ExecuteForLastInsertedRowId(INSERT_MAP_SQL, bindArgs);
    auto watch = MediaLibraryNotify::GetInstance();
    if (errCode > 0) {
        watch->Notify(MediaFileUtils::Encode(assetUri), NotifyType::NOTIFY_ALBUM_ADD_ASSERT, albumId);
    }
    return errCode;
}

int32_t PhotoMapOperations::AddPhotoAssets(const vector<DataShareValuesBucket> &values)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    TransactionOperations op(rdbStore->GetRaw());
    int32_t changedRows = 0;
    int32_t err = op.Start();
    if (err != E_OK) {
        return E_HAS_DB_ERROR;
    }
    for (const auto &value : values) {
        auto ret = AddSingleAsset(value);
        if (ret == E_HAS_DB_ERROR) {
            return ret;
        }
        if (ret > 0) {
            changedRows++;
        }
    }
    op.Finish();
    if (!values.empty()) {
        bool isValid = false;
        int32_t albumId = values[0].Get(PhotoMap::ALBUM_ID, isValid);
        if (!isValid) {
            MEDIA_WARN_LOG("Ignore failure on get album id, album updation possibly would be lost");
            return changedRows;
        }
        MediaLibraryRdbUtils::UpdateUserAlbumInternal(rdbStore->GetRaw(), { to_string(albumId) });
    }

    return changedRows;
}

int32_t PhotoMapOperations::RemovePhotoAssets(RdbPredicates &predicates)
{
    vector<string> whereArgs = predicates.GetWhereArgs();
    MediaLibraryRdbStore::ReplacePredicatesUriToId(predicates);
    int deleteRow = MediaLibraryRdbStore::Delete(predicates);
    if (deleteRow <= 0) {
        return deleteRow;
    }

    string strAlbumId = predicates.GetWhereArgs()[0];
    if (strAlbumId.empty()) {
        MEDIA_ERR_LOG("Failed to get albumId");
        return deleteRow;
    }
    int32_t albumId = atoi(strAlbumId.c_str());

    auto watch = MediaLibraryNotify::GetInstance();
    for (size_t i = 1; i < whereArgs.size(); i++) {
        watch->Notify(MediaFileUtils::Encode(whereArgs[i]), NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, albumId);
    }
    MediaLibraryRdbUtils::UpdateUserAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), { strAlbumId });
    return deleteRow;
}

shared_ptr<ResultSet> PhotoMapOperations::QueryPhotoAssets(const RdbPredicates &rdbPredicate,
    const vector<string> &columns)
{
    return MediaLibraryRdbStore::Query(rdbPredicate, columns);
}
} // namespace OHOS::Media