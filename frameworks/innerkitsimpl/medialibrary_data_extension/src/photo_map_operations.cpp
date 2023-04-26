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
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "value_object.h"

namespace OHOS::Media {
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

int32_t AddSingleAsset(const DataShareValuesBucket &value, vector<ValueObject> &bindArgs)
{
    /**
     * Build insert sql:
     * INSERT INTO PhotoMap (map_album, map_asset) SELECT
     * ?, ?
     * WHERE
     *     (NOT EXISTS (SELECT * FROM PhotoMap WHERE map_album = ? AND map_asset = ?))
     *     AND (EXISTS (SELECT file_id FROM Files WHERE file_id = ? AND data_trashed = 0))
     *     AND (EXISTS (SELECT album_id FROM PhotoAlbum WHERE album_id = ? AND album_type = ? AND album_subtype = ?));
     */
    static const string insertSql = "INSERT INTO " + PhotoMap::TABLE +
        " (" + PhotoMap::ALBUM_ID + ", " + PhotoMap::ASSET_ID + ") " +
        "SELECT ?, ? WHERE " +
        "(NOT EXISTS (SELECT * FROM " + PhotoMap::TABLE + " WHERE " +
            PhotoMap::ALBUM_ID + " = ? AND " + PhotoMap::ASSET_ID + " = ?)) " +
        "AND (EXISTS (SELECT " + MediaColumn::MEDIA_ID + " FROM " + MEDIALIBRARY_TABLE + " WHERE " +
            MediaColumn::MEDIA_ID + " = ? AND " + MediaColumn::MEDIA_DATE_TRASHED + " = 0)) " +
        "AND (EXISTS (SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE +
            " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = ? AND " + PhotoAlbumColumns::ALBUM_TYPE + " = ? AND " +
            PhotoAlbumColumns::ALBUM_SUBTYPE + " = ?));";

    bool isValid = false;
    int32_t albumId = value.Get(PhotoMap::ALBUM_ID, isValid);
    if (!isValid) {
        return -EINVAL;
    }
    int32_t assetId = value.Get(PhotoMap::ASSET_ID, isValid);
    if (!isValid) {
        return -EINVAL;
    }
    bindArgs.emplace_back(albumId);
    bindArgs.emplace_back(assetId);
    bindArgs.emplace_back(albumId);
    bindArgs.emplace_back(assetId);
    bindArgs.emplace_back(assetId);
    bindArgs.emplace_back(albumId);
    bindArgs.emplace_back(PhotoAlbumType::USER);
    bindArgs.emplace_back(PhotoAlbumSubType::USER_GENERIC);
    int errCode =  MediaLibraryRdbStore::ExecuteForLastInsertedRowId(insertSql, bindArgs);
    auto watch = MediaLibraryNotify::GetInstance();
    if ((errCode > 0) && (watch != nullptr)) {
        watch->Notify(MEDIALIBRARY_PHOTO_URI + "/" + to_string(assetId),
            NotifyType::NOTIFY_ALBUM_ADD_ASSERT, albumId);
    }
    return errCode;
}

int32_t PhotoMapOperations::AddPhotoAssets(const vector<DataShareValuesBucket> &values)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    int32_t changedRows = 0;
    vector<ValueObject> bindArgs;
    rdbStore->BeginTransaction();
    for (const auto &value : values) {
        bindArgs.clear();
        auto ret = AddSingleAsset(value, bindArgs);
        if (ret == E_HAS_DB_ERROR) {
            rdbStore->RollBack();
            return ret;
        }
        if (ret > 0) {
            changedRows++;
        }
    }
    rdbStore->Commit();
    return changedRows;
}

int32_t PhotoMapOperations::RemovePhotoAssets(RdbPredicates &predicates)
{
    int deleteRow = MediaLibraryRdbStore::Delete(predicates);
    string strAlbumId = predicates.GetWhereArgs()[0];
    if (strAlbumId.empty()) {
        MEDIA_ERR_LOG("Failed to get albumId");
        return deleteRow;
    }
    auto watch = MediaLibraryNotify::GetInstance();
    for (size_t i = 1; i < predicates.GetWhereArgs().size(); i++) {
        if ((deleteRow > 0) && (watch != nullptr)) {
            watch->Notify(MEDIALIBRARY_PHOTO_URI + "/" + predicates.GetWhereArgs()[i],
                NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, atoi(strAlbumId.c_str()));
        }
    }
    return deleteRow;
}

shared_ptr<ResultSet> PhotoMapOperations::QueryPhotoAssets(const RdbPredicates &rdbPredicate,
    const vector<string> &columns)
{
    return MediaLibraryRdbStore::Query(rdbPredicate, columns);
}
} // namespace OHOS::Media