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
#include "vision_column.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "vision_album_column.h"
#include "vision_face_tag_column.h"
#include "vision_photo_map_column.h"
#include "dfx_manager.h"
#include "dfx_const.h"

namespace OHOS::Media {
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

static int32_t AddSingleAsset(const DataShareValuesBucket &value, vector<string> &notifyUris)
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
    if (errCode > 0) {
        notifyUris.push_back(assetUri);
    }
    return errCode;
}

static int32_t InsertAnalysisAsset(const DataShareValuesBucket &value)
{
    /**
     * Build insert sql:
     * INSERT INTO AnalysisPhotoMap (map_album, map_asset) SELECT
     * ?, ?
     * WHERE
     *     (NOT EXISTS (SELECT * FROM AnalysisPhotoMap WHERE map_album = ? AND map_asset = ?))
     *     AND (EXISTS (SELECT file_id FROM Photos WHERE file_id = ?))
     *     AND (EXISTS (SELECT album_id FROM AnalysisAlbum WHERE album_id = ?));
     */
    static const string INSERT_MAP_SQL = "INSERT INTO " + ANALYSIS_PHOTO_MAP_TABLE +
        " (" + PhotoMap::ALBUM_ID + ", " + PhotoMap::ASSET_ID + ") " +
        "SELECT ?, ? WHERE " +
        "(NOT EXISTS (SELECT * FROM " + ANALYSIS_PHOTO_MAP_TABLE + " WHERE " +
            PhotoMap::ALBUM_ID + " = ? AND " + PhotoMap::ASSET_ID + " = ?)) " +
        "AND (EXISTS (SELECT " + MediaColumn::MEDIA_ID + " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
            MediaColumn::MEDIA_ID + " = ?)) " +
        "AND (EXISTS (SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + ANALYSIS_ALBUM_TABLE +
            " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = ? ));";
    bool isValid = false;
    int32_t albumId = value.Get(PhotoMap::ALBUM_ID, isValid);
    if (!isValid) {
        return -EINVAL;
    }
    int32_t assetId = value.Get(PhotoMap::ASSET_ID, isValid);
    if (!isValid) {
        return -EINVAL;
    }
    vector<ValueObject> bindArgs = { albumId, assetId, albumId, assetId, assetId, albumId};
    return  MediaLibraryRdbStore::ExecuteForLastInsertedRowId(INSERT_MAP_SQL, bindArgs);
}

int32_t PhotoMapOperations::AddPhotoAssets(const vector<DataShareValuesBucket> &values)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    vector<string> notifyUris;
    TransactionOperations op(rdbStore->GetRaw());
    int32_t changedRows = 0;
    int32_t err = op.Start();
    if (err != E_OK) {
        return E_HAS_DB_ERROR;
    }
    for (const auto &value : values) {
        auto ret = AddSingleAsset(value, notifyUris);
        if (ret == E_HAS_DB_ERROR) {
            return ret;
        }
        if (ret > 0) {
            changedRows++;
        }
    }
    op.Finish();
    if (values.empty()) {
        return changedRows;
    }

    bool isValid = false;
    int32_t albumId = values[0].Get(PhotoMap::ALBUM_ID, isValid);
    if (!isValid || albumId <= 0) {
        MEDIA_WARN_LOG("Ignore failure on get album id when add assets. isValid: %{public}d, albumId: %{public}d",
            isValid, albumId);
        return changedRows;
    }
    MediaLibraryRdbUtils::UpdateUserAlbumInternal(rdbStore->GetRaw(), { to_string(albumId) });

    auto watch = MediaLibraryNotify::GetInstance();
    for (const auto &uri : notifyUris) {
        watch->Notify(MediaFileUtils::Encode(uri), NotifyType::NOTIFY_ALBUM_ADD_ASSET, albumId);
    }

    return changedRows;
}

static int32_t GetPortraitAlbumIds(const string &albumId, vector<string> &portraitAlbumIds)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_HAS_DB_ERROR;
    }
    const std::string queryPortraitAlbumIds = "SELECT " + ALBUM_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " +
        GROUP_TAG + " IN(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE " + ALBUM_ID + " = " + albumId + " AND " + ALBUM_SUBTYPE + " = " + to_string(PORTRAIT) +")";

    auto resultSet = uniStore->QuerySql(queryPortraitAlbumIds);
    if (resultSet == nullptr) {
        return E_DB_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        portraitAlbumIds.push_back(to_string(GetInt32Val(ALBUM_ID, resultSet)));
    }
    return E_OK;
}

int32_t PhotoMapOperations::AddAnaLysisPhotoAssets(const vector<DataShareValuesBucket> &values)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    if (values.empty()) {
        return 0;
    }
    TransactionOperations op(rdbStore->GetRaw());
    int32_t changedRows = 0;
    int32_t err = op.Start();
    if (err != E_OK) {
        return E_HAS_DB_ERROR;
    }
    for (const auto &value : values) {
        int ret =  InsertAnalysisAsset(value);
        if (ret == E_HAS_DB_ERROR) {
            return ret;
        }
        if (ret > 0) {
            changedRows++;
        }
    }
    op.Finish();
    bool isValid = false;
    vector<string> albumIdList;
    for (const auto &value : values) {
        int32_t albumId = value.Get(PhotoMap::ALBUM_ID, isValid);
        if (!isValid || albumId <= 0) {
            MEDIA_WARN_LOG("Ignore failure on get album id when add assets. isValid: %{public}d, albumId: %{public}d",
                isValid, albumId);
            continue;
        }
        albumIdList.push_back(to_string(albumId));
    }
    std::unordered_map<int32_t, int32_t> updateResult;
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore->GetRaw(), updateResult, albumIdList);
    return changedRows;
}

static void GetDismissAssetsPredicates(NativeRdb::RdbPredicates &rdbPredicate, vector<string> &updateAlbumIds,
    PhotoAlbumSubType subtype, const string &strAlbumId, const vector<string> &assetsArray)
{
    if (subtype == PhotoAlbumSubType::PORTRAIT) {
        GetPortraitAlbumIds(strAlbumId, updateAlbumIds);
        rdbPredicate.In(MAP_ALBUM, updateAlbumIds);
        rdbPredicate.And()->In(MAP_ASSET, assetsArray);
    } else {
        rdbPredicate.EqualTo(MAP_ALBUM, strAlbumId);
        rdbPredicate.And()->In(MAP_ASSET, assetsArray);
        updateAlbumIds.push_back(strAlbumId);
    }
}

int32_t PhotoMapOperations::DismissAssets(NativeRdb::RdbPredicates &predicates)
{
    vector<string> whereArgsUri = predicates.GetWhereArgs();
    MediaLibraryRdbStore::ReplacePredicatesUriToId(predicates);
    
    const vector<string> &whereArgsId = predicates.GetWhereArgs();
    if (whereArgsId.size() == 0 || whereArgsUri.size() == 0) {
        MEDIA_ERR_LOG("No fileAsset to delete");
        return E_INVALID_ARGUMENTS;
    }
    string strAlbumId = whereArgsId[0];
    if (strAlbumId.empty()) {
        MEDIA_ERR_LOG("Failed to get albumId");
        return E_INVALID_ARGUMENTS;
    }

    int32_t albumId = atoi(strAlbumId.c_str());
    if (albumId <= 0) {
        MEDIA_WARN_LOG("Ignore failure on get album id when remove assets, album updating would be lost");
        return E_INVALID_ARGUMENTS;
    }
    string strSubtype = whereArgsId[whereArgsId.size() - 1];
    int32_t subtype = atoi(strSubtype.c_str());
    if (subtype != PhotoAlbumSubType::CLASSIFY && subtype != PhotoAlbumSubType::PORTRAIT) {
        MEDIA_ERR_LOG("Invalid album subtype: %{public}d", subtype);
        return E_INVALID_ARGUMENTS;
    }

    vector<string> assetsArray;
    for (size_t i = 1; i < whereArgsId.size() - 1; i++) {
        assetsArray.push_back(whereArgsId[i]);
    }
    vector<string> updateAlbumIds;
    NativeRdb::RdbPredicates rdbPredicate {ANALYSIS_PHOTO_MAP_TABLE};
    GetDismissAssetsPredicates(rdbPredicate, updateAlbumIds,
        static_cast<PhotoAlbumSubType>(subtype), strAlbumId, assetsArray);
    int deleteRow = MediaLibraryRdbStore::Delete(rdbPredicate);
    if (deleteRow <= 0) {
        return deleteRow;
    }

    std::unordered_map<int32_t, int32_t> updateResult;
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), updateResult, updateAlbumIds,
        assetsArray);
    auto watch = MediaLibraryNotify::GetInstance();
    for (size_t i = 1; i < whereArgsUri.size() - 1; i++) {
        watch->Notify(MediaFileUtils::Encode(whereArgsUri[i]), NotifyType::NOTIFY_ALBUM_DISMISS_ASSET, albumId);
    }
    return deleteRow;
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
    if (albumId <= 0) {
        MEDIA_WARN_LOG("Ignore failure on get album id when remove assets, album updating would be lost");
        return deleteRow;
    }
    MediaLibraryRdbUtils::UpdateUserAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), { strAlbumId });

    auto watch = MediaLibraryNotify::GetInstance();
    for (size_t i = 1; i < whereArgs.size(); i++) {
        watch->Notify(MediaFileUtils::Encode(whereArgs[i]), NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, albumId);
    }
    std::unordered_map<int32_t, int32_t> updateResult;
    DfxManager::GetInstance()->HandleDeleteBehavior(DfxType::ALBUM_REMOVE_PHOTOS, deleteRow, updateResult, whereArgs);
    return deleteRow;
}

shared_ptr<OHOS::NativeRdb::ResultSet> PhotoMapOperations::QueryPhotoAssets(const RdbPredicates &rdbPredicate,
    const vector<string> &columns)
{
    return MediaLibraryRdbStore::Query(rdbPredicate, columns);
}
} // namespace OHOS::Media