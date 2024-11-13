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

#include "media_analysis_helper.h"
#include "media_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_analysis_album_operations.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_db_const.h"
#include "medialibrary_data_manager.h"
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
#include "vision_image_face_column.h"
#include "vision_photo_map_column.h"
#include "dfx_manager.h"
#include "dfx_const.h"

namespace OHOS::Media {
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

constexpr int32_t ALBUM_IS_REMOVED = 1;

static int32_t InsertAnalysisAsset(const DataShareValuesBucket &value,
    std::shared_ptr<TransactionOperations> trans)
{
    if (trans == nullptr) {
        MEDIA_ERR_LOG("transactionOperations is null");
        return -EINVAL;
    }
    /**
     * Build insert sql:
     * INSERT INTO AnalysisPhotoMap (map_album, map_asset) SELECT
     * ?, ?
     * WHERE
     *     (NOT EXISTS (SELECT * FROM AnalysisPhotoMap WHERE map_album = ? AND map_asset = ?))
     *     AND (EXISTS (SELECT file_id FROM Photos WHERE file_id = ?))
     *     AND (EXISTS (SELECT album_id FROM AnalysisAlbum WHERE album_id = ?));
     */
    static const std::string INSERT_MAP_SQL = "INSERT OR IGNORE INTO " + ANALYSIS_PHOTO_MAP_TABLE +
        " (" + PhotoMap::ALBUM_ID + ", " + PhotoMap::ASSET_ID + ") " +
        "SELECT ?, ? WHERE " +
        "(NOT EXISTS (SELECT 1 FROM " + ANALYSIS_PHOTO_MAP_TABLE + " WHERE " +
            PhotoMap::ALBUM_ID + " = ? AND " + PhotoMap::ASSET_ID + " = ?)) " +
        "AND (EXISTS (SELECT 1 FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
            MediaColumn::MEDIA_ID + " = ?)) " +
        "AND (EXISTS (SELECT 1 FROM " + ANALYSIS_ALBUM_TABLE +
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
    return trans->ExecuteForLastInsertedRowId(INSERT_MAP_SQL, bindArgs);
}

int32_t PhotoMapOperations::AddPhotoAssets(const vector<DataShareValuesBucket> &values)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    int32_t changedRows = 0;
    vector<int32_t> updateIds;
    if (!values.empty()) {
        bool isValid = false;
        int32_t albumId = values[0].Get(PhotoColumn::PHOTO_OWNER_ALBUM_ID, isValid);
        if (!isValid || albumId <= 0) {
            MEDIA_WARN_LOG("Ignore failure on get album id when add assets. isValid: %{public}d, albumId: %{public}d",
                isValid, albumId);
            return changedRows;
        }

        changedRows = MediaLibraryRdbUtils::UpdateOwnerAlbumId(rdbStore, values, updateIds);
        MediaLibraryRdbUtils::UpdateUserAlbumInternal(rdbStore, { to_string(albumId) });
        MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore, {
            to_string(PhotoAlbumSubType::IMAGE), to_string(PhotoAlbumSubType::VIDEO),
            to_string(PhotoAlbumSubType::FAVORITE)
        });

        MEDIA_INFO_LOG("AddPhotoAssets idToUpdateIndex size: %{public}zu", updateIds.size());
        if (!updateIds.empty()) {
            vector<string> idToUpdateIndex;
            for (size_t i = 0; i < updateIds.size(); i++) {
                idToUpdateIndex.push_back(to_string(updateIds[i]));
            }
            MediaAnalysisHelper::AsyncStartMediaAnalysisService(
                static_cast<int32_t>(MediaAnalysisProxy::ActivateServiceType::START_UPDATE_INDEX), idToUpdateIndex);
        }

        auto watch = MediaLibraryNotify::GetInstance();
        for (const auto &id : updateIds) {
            string notifyUri = PhotoColumn::PHOTO_URI_PREFIX + to_string(id);
            watch->Notify(MediaFileUtils::Encode(notifyUri), NotifyType::NOTIFY_ALBUM_ADD_ASSET, albumId);
            watch->Notify(MediaFileUtils::Encode(notifyUri), NotifyType::NOTIFY_ALBUM_ADD_ASSET,
                watch->GetAlbumIdBySubType(PhotoAlbumSubType::IMAGE));
            watch->Notify(MediaFileUtils::Encode(notifyUri), NotifyType::NOTIFY_ALBUM_ADD_ASSET,
                watch->GetAlbumIdBySubType(PhotoAlbumSubType::VIDEO));
            watch->Notify(MediaFileUtils::Encode(notifyUri), NotifyType::NOTIFY_ALBUM_ADD_ASSET,
                watch->GetAlbumIdBySubType(PhotoAlbumSubType::FAVORITE));
            watch->Notify(MediaFileUtils::Encode(notifyUri), NotifyType::NOTIFY_ADD);
        }
    }
    return changedRows;
}

static int32_t GetPortraitAlbumIds(const string &albumId, vector<string> &portraitAlbumIds)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
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
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    if (values.empty()) {
        return 0;
    }
    std::shared_ptr<TransactionOperations> trans = make_shared<TransactionOperations>(__func__);
    int32_t changedRows = 0;
    int32_t err = NativeRdb::E_OK;
    std::function<int(void)> func = [&]()->int {
        for (const auto &value : values) {
            err =  InsertAnalysisAsset(value, trans);
            if (err == E_HAS_DB_ERROR) {
                MEDIA_WARN_LOG("InsertAnalysisAsset for db error, changedRows now: %{public}d", changedRows);
                return err;
            }
            if (err > 0) {
                changedRows++;
            }
        }
        return err;
    };
    err = trans->RetryTrans(func);
    if (err != E_OK) {
        MEDIA_ERR_LOG("AddAnaLysisPhotoAssets: trans retry fail!, ret:%{public}d", err);
        return err;
    }
    bool isValid = false;
    std::vector<string> albumIdList;
    for (const auto &value : values) {
        int32_t albumId = value.Get(PhotoMap::ALBUM_ID, isValid);
        if (!isValid || albumId <= 0) {
            MEDIA_WARN_LOG("Ignore failure on get album id when add assets. isValid: %{public}d, albumId: %{public}d",
                isValid, albumId);
            continue;
        }
        albumIdList.push_back(to_string(albumId));
    }
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore, albumIdList);
    return changedRows;
}

static void GetDismissAssetsPredicates(NativeRdb::RdbPredicates &rdbPredicate, vector<string> &updateAlbumIds,
    PhotoAlbumSubType subtype, const string &albumId, const vector<string> &assetsArray)
{
    if (subtype == PhotoAlbumSubType::PORTRAIT) {
        GetPortraitAlbumIds(albumId, updateAlbumIds);
        rdbPredicate.In(MAP_ALBUM, updateAlbumIds);
        rdbPredicate.And()->In(MAP_ASSET, assetsArray);
    } else {
        rdbPredicate.EqualTo(MAP_ALBUM, albumId);
        rdbPredicate.And()->In(MAP_ASSET, assetsArray);
        updateAlbumIds.push_back(albumId);
    }
}

int32_t DoDismissAssets(int32_t subtype, const string &albumId, const vector<string> &assetIds)
{
    int32_t deleteRow = 0;
    if (subtype == PhotoAlbumSubType::GROUP_PHOTO) {
        NativeRdb::RdbPredicates rdbPredicate { VISION_IMAGE_FACE_TABLE };
        rdbPredicate.In(MediaColumn::MEDIA_ID, assetIds);
        deleteRow = MediaLibraryRdbStore::Delete(rdbPredicate);
        if (deleteRow != 0 && MediaLibraryDataManagerUtils::IsNumber(albumId)) {
            MediaLibraryAnalysisAlbumOperations::UpdateGroupPhotoAlbumById(atoi(albumId.c_str()));
        }
        return deleteRow;
    }

    vector<string> updateAlbumIds;
    NativeRdb::RdbPredicates rdbPredicate { ANALYSIS_PHOTO_MAP_TABLE };
    GetDismissAssetsPredicates(rdbPredicate, updateAlbumIds,
        static_cast<PhotoAlbumSubType>(subtype), albumId, assetIds);
    deleteRow = MediaLibraryRdbStore::Delete(rdbPredicate);
    if (deleteRow <= 0) {
        return deleteRow;
    }
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStore(), updateAlbumIds, assetIds);
    return deleteRow;
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
    if (subtype != PhotoAlbumSubType::CLASSIFY && subtype != PhotoAlbumSubType::PORTRAIT &&
        subtype != PhotoAlbumSubType::GROUP_PHOTO) {
        MEDIA_ERR_LOG("Invalid album subtype: %{public}d", subtype);
        return E_INVALID_ARGUMENTS;
    }

    vector<string> assetsArray;
    for (size_t i = 1; i < whereArgsId.size() - 1; i++) {
        assetsArray.push_back(whereArgsId[i]);
    }

    int32_t deleteRow = DoDismissAssets(subtype, strAlbumId, assetsArray);
    if (deleteRow > 0) {
        auto watch = MediaLibraryNotify::GetInstance();
        for (size_t i = 1; i < whereArgsUri.size() - 1; i++) {
            watch->Notify(MediaFileUtils::Encode(whereArgsUri[i]), NotifyType::NOTIFY_ALBUM_DISMISS_ASSET, albumId);
        }
    }
    return deleteRow;
}

int32_t PhotoMapOperations::RemovePhotoAssets(RdbPredicates &predicates)
{
    vector<string> whereArgs = predicates.GetWhereArgs();
    MediaLibraryRdbStore::ReplacePredicatesUriToId(predicates);
    int32_t deleteRow = 0;
    vector<string> whereIdArgs = predicates.GetWhereArgs();
    if (whereIdArgs.empty()) {
        return deleteRow;
    }
    whereIdArgs.erase(whereIdArgs.begin());
    deleteRow = MediaLibraryRdbUtils::UpdateRemoveAsset(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStore(), whereIdArgs);

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
        MediaLibraryUnistoreManager::GetInstance().GetRdbStore(), { strAlbumId });

    auto watch = MediaLibraryNotify::GetInstance();
    for (size_t i = 1; i < whereArgs.size(); i++) {
        watch->Notify(MediaFileUtils::Encode(whereArgs[i]), NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, albumId);
    }
    DfxManager::GetInstance()->HandleDeleteBehavior(DfxType::ALBUM_REMOVE_PHOTOS, deleteRow, whereArgs);
    return deleteRow;
}

bool IsQueryGroupPhotoAlbumAssets(const string &albumId, string &tagId, int32_t &isRemoved)
{
    if (albumId.empty() || !MediaLibraryDataManagerUtils::IsNumber(albumId)) {
        return false;
    }
    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    vector<string> columns = {PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumColumns::ALBUM_SUBTYPE, TAG_ID, IS_REMOVED};
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(predicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        return false;
    }
    int32_t albumType = GetInt32Val(PhotoAlbumColumns::ALBUM_TYPE, resultSet);
    int32_t albumSubtype = GetInt32Val(PhotoAlbumColumns::ALBUM_SUBTYPE, resultSet);
    tagId = GetStringVal(TAG_ID, resultSet);
    isRemoved = GetInt32Val(IS_REMOVED, resultSet);
    return albumType == PhotoAlbumType::SMART && albumSubtype == PhotoAlbumSubType::GROUP_PHOTO;
}

shared_ptr<OHOS::NativeRdb::ResultSet> QueryGroupPhotoAlbumAssets(const string &albumId, const string &tagId,
    const vector<string> &columns)
{
    string strColumns;
    for (size_t i = 0; i < columns.size(); i++) {
        strColumns.append("P." + columns[i]);
        if (i != columns.size() - 1) {
            strColumns.append(", ");
        }
    }
    string strTags = "'";
    int32_t albumTagCount = 1;
    for (char c : tagId) {
        if (c == ',') {
            strTags.append("', '");
            albumTagCount++;
        } else {
            strTags.push_back(c);
        }
    }
    strTags.append("'");
    string sql = "SELECT " + strColumns + " FROM " + VISION_IMAGE_FACE_TABLE + " F INNER JOIN " +
        ANALYSIS_ALBUM_TABLE + " AA ON F." + TAG_ID + " = AA." + TAG_ID + " AND AA." + GROUP_TAG + " IN (" + strTags +
        ") INNER JOIN " + ANALYSIS_PHOTO_MAP_TABLE + " ON " + MAP_ALBUM + " = AA." + PhotoAlbumColumns::ALBUM_ID +
        " AND " + MAP_ASSET + " = F." + MediaColumn::MEDIA_ID + " INNER JOIN " + PhotoColumn::PHOTOS_TABLE +
        " P ON P." + MediaColumn::MEDIA_ID + " = F." + MediaColumn::MEDIA_ID + " AND " +
        MediaColumn::MEDIA_DATE_TRASHED + " = 0 AND " + MediaColumn::MEDIA_HIDDEN + " = 0 AND " +
        MediaColumn::MEDIA_TIME_PENDING + " = 0 GROUP BY P." + MediaColumn::MEDIA_ID +
        " HAVING COUNT(" + GROUP_TAG + ") = " + TOTAL_FACES + " AND " +
        " COUNT(DISTINCT " + GROUP_TAG +") = " + to_string(albumTagCount) + ";";
    return MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->QuerySql(sql);
}
shared_ptr<OHOS::NativeRdb::ResultSet> PhotoMapOperations::QueryPhotoAssets(const RdbPredicates &rdbPredicate,
    const vector<string> &columns)
{
    string albumId = rdbPredicate.GetWhereArgs()[0];
    string tagId;
    int32_t isRemoved;
    if (IsQueryGroupPhotoAlbumAssets(albumId, tagId, isRemoved)) {
        if (isRemoved == ALBUM_IS_REMOVED) {
            return nullptr;
        }
        return QueryGroupPhotoAlbumAssets(albumId, tagId, columns);
    }
    return MediaLibraryRdbStore::QueryWithFilter(rdbPredicate, columns);
}
} // namespace OHOS::Media