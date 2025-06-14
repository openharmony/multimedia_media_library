/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Cloud_Dao"

#include "cloud_media_album_dao.h"

#include <string>
#include <utime.h>
#include <vector>

#include "abs_rdb_predicates.h"
#include "media_column.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "cloud_media_file_utils.h"
#include "cloud_media_sync_utils.h"
#include "cloud_media_operation_code.h"
#include "medialibrary_unistore_manager.h"
#include "moving_photo_file_utils.h"
#include "result_set.h"
#include "result_set_utils.h"
#include "thumbnail_const.h"
#include "userfile_manager_types.h"
#include "result_set_reader.h"
#include "photos_po_writer.h"
#include "photo_album_po_writer.h"
#include "cloud_sync_convert.h"
#include "photo_map_column.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "scanner_utils.h"
#include "media_refresh_album_column.h"
#include "cloud_media_dao_const.h"
#include "media_gallery_sync_notify.h"
#include "accurate_common_data.h"

namespace OHOS::Media::CloudSync {
using ChangeType = AAFwk::ChangeInfo::ChangeType;
int32_t CloudMediaAlbumDao::HandleLPathAndAlbumType(PhotoAlbumDto &record)
{
    MEDIA_INFO_LOG("HandleLPathAndAlbumType enter");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "HandleLPathAndAlbumType Failed to get rdbStore.");
    std::unordered_map<std::string, std::string> localAlbumMap = this->GetLocalAlbumMap();
    std::unordered_map<std::string, MediaAlbumPluginRowData> writeListMap = QueryWhiteList();
    std::string localPath = record.lPath;
    if (localPath.empty()) {
        MEDIA_ERR_LOG("HandleLPathAndAlbumType record have no lpath");
        return E_OK;
    }
    std::transform(localPath.begin(), localPath.end(), localPath.begin(), ::tolower);
    auto localAlbumIt = localAlbumMap.find(localPath);
    if (localAlbumIt != localAlbumMap.end()) {
        record.lPath = localAlbumIt->second;
    }
    auto writeListIt = writeListMap.find(localPath);
    if (writeListIt != writeListMap.end()) {
        record.lPath = writeListIt->second.lpath;
    }
    int32_t albumType = PhotoAlbumType::SOURCE;
    int32_t subType = PhotoAlbumSubType::SOURCE_GENERIC;
    if (CloudMediaSyncUtils::IsUserAlbumPath(localPath)) {
        MEDIA_INFO_LOG("HandleLPathAndAlbumType User Album: %{public}s", record.ToString().c_str());
        albumType = PhotoAlbumType::USER;
        subType = PhotoAlbumSubType::USER_GENERIC;
    }
    if (record.albumType == static_cast<int32_t>(PhotoAlbumType::INVALID)) {
        record.albumDateAdded = record.albumDateCreated;
        record.albumDateModified = 0;
    }
    record.albumType = albumType;
    record.albumSubType = subType;
    MEDIA_INFO_LOG("HandleLPathAndAlbumType Record: %{public}s", record.ToString().c_str());
    return E_OK;
}

int32_t CloudMediaAlbumDao::QuerySameNameAlbum(PhotoAlbumDto &record, int32_t &albumId, std::string &newAlbumName)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Query Same Name Album Failed to get rdbStore.");
    std::string albumName = record.albumName;
    int32_t tryTime = 1;
    auto lpath = record.lPath;
    newAlbumName = albumName;
    while (tryTime <= MAX_TRY_TIMES) {
        std::string querySql = "SELECT " + PhotoAlbumColumns::ALBUM_NAME + ", " + PhotoAlbumColumns::ALBUM_ID +
                               " FROM " + PhotoAlbumColumns::TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_NAME +
                               " = ? AND " + PhotoAlbumColumns::ALBUM_TYPE + " = " +
                               std::to_string(PhotoAlbumType::USER) + " AND (" + PhotoAlbumColumns::ALBUM_CLOUD_ID +
                               " ISNULL OR " + PhotoAlbumColumns::ALBUM_CLOUD_ID + " != ?) AND ( " +
                               PhotoAlbumColumns::ALBUM_LPATH + " IS NOT NULL  AND " + PhotoAlbumColumns::ALBUM_LPATH +
                               " != '' AND LOWER(" + PhotoAlbumColumns::ALBUM_LPATH + ") != LOWER(?))";
        std::vector<NativeRdb::ValueObject> queryVec;
        queryVec.push_back(newAlbumName);
        queryVec.push_back(record.cloudId);
        queryVec.push_back(lpath);
        auto resultSet = rdbStore->QuerySql(querySql, queryVec);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_RESULT_SET_NULL, "resultset is null");
        int rowCount = 0;
        int ret = resultSet->GetRowCount(rowCount);
        if (ret != 0 || rowCount < 0) {
            MEDIA_ERR_LOG("result set get row count err %{public}d, rowCount %{public}d", ret, rowCount);
            return E_RDB;
        }
        if (rowCount == 0) {
            break;
        }
        std::string loaclAlbumName = "";
        resultSet->GoToNextRow();
        albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        loaclAlbumName = GetStringVal(PhotoAlbumColumns::ALBUM_NAME, resultSet);
        newAlbumName = loaclAlbumName + " " + std::to_string(tryTime);
        ++tryTime;
    }
    if (tryTime >= MAX_TRY_TIMES) {
        MEDIA_ERR_LOG("rename too may times");
        return E_DATA;
    }
    return E_OK;
}

int32_t CloudMediaAlbumDao::ConflictWithPhysicalAlbum(PhotoAlbumDto &record,
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    int32_t albumId = -1;
    std::string newAlbumName;
    int ret = QuerySameNameAlbum(record, albumId, newAlbumName);
    if (ret != 0) {
        return ret;
    }
    if (albumId == -1) {
        MEDIA_INFO_LOG("FixData: can not find same name album");
        return E_OK;
    }
    int32_t changedRows;
    NativeRdb::ValuesBucket values;
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, newAlbumName);
    values.PutString(PhotoAlbumColumns::ALBUM_LPATH, "/Pictures/Users/" + newAlbumName);
    ret = albumRefreshHandle->Update(
        changedRows, PhotoAlbumColumns::TABLE, values, PhotoAlbumColumns::ALBUM_ID + " = ?", {std::to_string(albumId)});
    if (ret != AccurateRefresh::ACCURATE_REFRESH_RET_OK) {
        MEDIA_ERR_LOG("FixData: updata local album name fail");
        return E_RDB;
    } else if (changedRows == 0) {
        MEDIA_ERR_LOG("FixData: updata local album name changerow = 0");
    } else {
        MEDIA_INFO_LOG("FixData: update success album id is %{public}d", albumId);
    }
    return ret;
}

int32_t CloudMediaAlbumDao::InsertCloudByLPath(PhotoAlbumDto &record,
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    MEDIA_INFO_LOG("FixData: Insert Cloud By LPath of record %{public}s", record.cloudId.c_str());
    /* handle Physical album conflic, if same album name */
    int32_t ret = ConflictWithPhysicalAlbum(record, albumRefreshHandle);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("rename fail ret is %{public}d", ret);
        return ret;
    }
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_CLOUD_ID, record.cloudId);
    if (record.cloudId == DEFAULT_SCREENSHOT_CLOUDID) {
        if (record.bundleName.empty()) {
            MEDIA_ERR_LOG("no bundle name in default-album-2 record");
            return E_DATA;
        }
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, record.bundleName);
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(
        rdbStore != nullptr, E_RDB_STORE_NULL, "Insert Cloud LPath Album Record Failed to get rdbStore.");
    auto resultSet = rdbStore->Query(predicates, {PhotoAlbumColumns::ALBUM_ID});
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_RESULT_SET_NULL, "resultset is null");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    if (ret != 0 || rowCount < 0) {
        MEDIA_ERR_LOG("result set get row count err %{public}d, rowCount %{public}d", ret, rowCount);
        return E_RDB;
    }
    if (rowCount == 0) {
        return InsertAlbums(record, albumRefreshHandle);
    }
    resultSet->GoToNextRow();
    int albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    if (albumId < 0) {
        return E_RDB;
    }
    return UpdateCloudAlbum(record, PhotoAlbumColumns::ALBUM_ID, std::to_string(albumId), albumRefreshHandle);
}

int32_t CloudMediaAlbumDao::InsertCloudByCloudId(PhotoAlbumDto &record,
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    MEDIA_INFO_LOG("insert of record %{public}s", record.cloudId.c_str());
    if (IsConflict(record)) {
        int32_t ret = MergeAlbumOnConflict(record, albumRefreshHandle);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("merge album err %{public}d", ret);
        }
        return ret;
    }
    int32_t ret = InsertAlbums(record, albumRefreshHandle);
    return ret;
}

std::tuple<std::shared_ptr<NativeRdb::ResultSet>, int> CloudMediaAlbumDao::QueryLocalMatchAlbum(std::string &cloudId)
{
    MEDIA_INFO_LOG("QueryLocalMatchAlbum enter");
    std::tuple<std::shared_ptr<NativeRdb::ResultSet>, int> defaultValue = {nullptr, 0};
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, defaultValue, "QueryLocalMatchAlbum Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_CLOUD_ID, cloudId);
    const std::vector<std::string> columns = {
        Media::PhotoAlbumColumns::ALBUM_ID,
        Media::PhotoAlbumColumns::ALBUM_NAME,
        Media::PhotoAlbumColumns::ALBUM_TYPE,
        Media::PhotoAlbumColumns::ALBUM_DIRTY,
        Media::PhotoAlbumColumns::ALBUM_LPATH,
        Media::PhotoAlbumColumns::ALBUM_CLOUD_ID,
    };
    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(
        resultSet != nullptr, defaultValue, "QueryLocalMatchAlbum Failed to query local match album.");
    int32_t rowCount = 0;
    int32_t ret = resultSet->GetRowCount(rowCount);
    CHECK_AND_RETURN_RET_LOG(
        (ret == 0 && rowCount >= 0), defaultValue, "QueryLocalMatchAlbum Failed to query local match album counts.");
    return {std::move(resultSet), rowCount};
}

int32_t CloudMediaAlbumDao::UpdateCloudAlbumSynced(const std::string &field, const std::string &value,
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    MEDIA_INFO_LOG("UpdateCloudAlbumDirty, field: %{public}s, value: %{public}s", field.c_str(), value.c_str());
    int32_t changedRows = DEFAULT_VALUE;
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
    int32_t ret = albumRefreshHandle->Update(changedRows, PhotoAlbumColumns::TABLE, values, field + " = ?", {value});
    CHECK_AND_RETURN_RET_LOG(ret == AccurateRefresh::ACCURATE_REFRESH_RET_OK, E_RDB,
        "Insert pull record failed, rdb ret = %{public}d", ret);
    CHECK_AND_PRINT_LOG(changedRows > 0, "Check updateRows: %{public}d.", changedRows);
    return ret;
}

int32_t CloudMediaAlbumDao::UpdateCloudAlbumInner(PhotoAlbumDto &record, const std::string &field,
    const std::string &value, std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    int32_t changedRows;
    NativeRdb::ValuesBucket values;
    if (!record.albumName.empty()) {
        values.PutString(PhotoAlbumColumns::ALBUM_NAME, record.albumName);
    }
    if (!record.lPath.empty()) {
        values.PutString(PhotoAlbumColumns::ALBUM_LPATH, record.lPath);
    }
    if (!record.lPath.empty() && record.lPath.substr(0, ALBUM_LOCAL_PATH_PREFIX.size()) != ALBUM_LOCAL_PATH_PREFIX) {
        values.PutString(PhotoAlbumColumns::ALBUM_LPATH, record.lPath);
    }
    int32_t ret = SetSourceValues(record, values);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "UpdateCloudAlbumInner fail, ret: %{public}d", ret);
    if (!record.bundleName.empty()) {
        values.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, record.bundleName);
    }
    values.PutInt(PhotoAlbumColumns::ALBUM_PRIORITY, 1);
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, record.albumType);
    values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, record.albumSubType);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_ADDED, record.albumDateAdded);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, record.albumDateModified);
    values.PutString(PhotoAlbumColumns::ALBUM_LOCAL_LANGUAGE, record.localLanguage);
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
    values.PutString(PhotoAlbumColumns::ALBUM_CLOUD_ID, record.cloudId);
    values.PutInt(PhotoAlbumColumns::COVER_URI_SOURCE, record.coverUriSource);
    ret = albumRefreshHandle->Update(changedRows, PhotoAlbumColumns::TABLE, values, field + " = ?", {value});
    CHECK_AND_RETURN_RET_LOG(ret == AccurateRefresh::ACCURATE_REFRESH_RET_OK, E_RDB,
        "Insert pull record failed, rdb ret = %{public}d", ret);
    return E_OK;
}

int32_t CloudMediaAlbumDao::UpdateCloudAlbum(PhotoAlbumDto &record, const std::string &field, const std::string &value,
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    std::shared_ptr<TransactionOperations> trans = make_shared<TransactionOperations>(__func__);
    std::function<int(void)> func = [&]() -> int {
        int32_t retInner = this->UpdateCloudAlbumInner(record, field, value, albumRefreshHandle);
        CHECK_AND_RETURN_RET(retInner == E_OK, retInner);
        return this->UpdateCloudAlbumSynced(field, value, albumRefreshHandle);
    };
    int32_t ret = trans->RetryTrans(func);
    CHECK_AND_RETURN_RET_LOG(
        ret == E_OK, E_CLOUDSYNC_RDB_UPDATE_FAILED, "Failed to UpdateCloudAlbum, ret: %{public}d", ret);
    return ret;
}

void CloudAlbumDeletedNotify(std::vector<AccurateRefresh::AlbumChangeData> &albumDatas)
{
    MEDIA_INFO_LOG("enter CloudAlbumDeletedNotify");
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> albumRefresh =
        std::make_shared<AccurateRefresh::AlbumAccurateRefresh>();
    CHECK_AND_RETURN_LOG(albumRefresh != nullptr, "Delete Cloud Album Failed to get albumRefresh.");
    CHECK_AND_RETURN_LOG(albumRefresh->Init() == AccurateRefresh::ACCURATE_REFRESH_RET_OK,
        "fail to execute albumRefresh init");
    albumRefresh->Notify(albumDatas);
}

int32_t CloudMediaAlbumDao::OnDeleteAlbums(std::vector<std::string> &failedAlbumIds)
{
    MEDIA_INFO_LOG("enter OnDeleteAlbums");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "OnDeleteAlbums Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(Media::DirtyType::TYPE_SDIRTY));
    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_CLOUD_ID,
        PhotoAlbumColumns::ALBUM_TYPE,
        PhotoAlbumColumns::ALBUM_SUBTYPE
    };

    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_RESULT_SET_NULL, "OnDeleteAlbums Failed to query.");
    int32_t rowCount = 0;
    CHECK_AND_RETURN_RET_LOG(
        resultSet->GetRowCount(rowCount) == NativeRdb::E_OK, E_ERR, "OnDeleteAlbums Failed to get rowCount.");
    MEDIA_INFO_LOG("OnDeleteAlbums GetRowCount: %{public}d", rowCount);
    NativeRdb::AbsRdbPredicates update = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    std::vector<AccurateRefresh::AlbumChangeData> albumDatas;

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::shared_ptr<AccurateRefresh::AlbumChangeData> changeData = make_shared<AccurateRefresh::AlbumChangeData>();
        std::string cloudId = GetStringVal(PhotoAlbumColumns::ALBUM_CLOUD_ID, resultSet);
        int32_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        int32_t albumType = GetInt32Val(PhotoAlbumColumns::ALBUM_TYPE, resultSet);
        int32_t albumSubType = GetInt32Val(PhotoAlbumColumns::ALBUM_SUBTYPE, resultSet);
        if (cloudId.empty()) {
            continue;
        }
        changeData->operation_ = AccurateRefresh::RdbOperation::RDB_OPERATION_REMOVE;
        changeData->infoBeforeChange_.albumId_ = albumId;
        changeData->infoBeforeChange_.albumType_ = albumType;
        changeData->infoBeforeChange_.albumSubType_ = albumSubType;
        changeData->infoAfterChange_.albumId_ = albumId;
        changeData->infoAfterChange_.albumType_ = albumType;
        changeData->infoAfterChange_.albumSubType_ = albumSubType;
        albumDatas.push_back(*changeData);
        MEDIA_DEBUG_LOG("OnDeleteAlbums Notify Delete: %{public}s", cloudId.c_str());
        MediaGallerySyncNotify::GetInstance().AddNotify(
            PhotoAlbumColumns::ALBUM_GALLERY_CLOUD_URI_PREFIX, ChangeType::DELETE, cloudId);
    }
    CloudAlbumDeletedNotify(albumDatas);
    MediaGallerySyncNotify::GetInstance().FinalNotify();
    return E_OK;
}

int32_t CloudMediaAlbumDao::OnCreateRecords(const std::vector<PhotoAlbumDto> &albums, int32_t &failSize)
{
    MEDIA_INFO_LOG("enter OnCreateRecords %{public}zu", albums.size());
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "OnCreateRecords Failed to get rdbStore.");
    for (const auto &album : albums) {
        if (!album.isSuccess) {
            InsertAlbumCreateFailedRecord(album.cloudId);
            failSize++;
            continue;
        }
        NativeRdb::ValuesBucket valuesBucket;
        if (album.cloudId != album.newCloudId) {
            valuesBucket.PutString(PhotoAlbumColumns::ALBUM_CLOUD_ID, album.newCloudId);
        }
        valuesBucket.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(Media::DirtyType::TYPE_SYNCED));
        std::string whereClause = PhotoAlbumColumns::ALBUM_CLOUD_ID + " = ?";
        std::vector<std::string> whereArgs = {album.cloudId};
        int32_t changedRows = -1;
        int32_t ret = rdbStore->Update(changedRows, PhotoAlbumColumns::TABLE, valuesBucket, whereClause, whereArgs);
        MEDIA_DEBUG_LOG("OnCreateRecords changedRows %{public}d", changedRows);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("OnCreateRecords Failed to UpdateAlbumAfterUpload.");
            InsertAlbumCreateFailedRecord(album.cloudId);
            failSize++;
            continue;
        }
    }
    return E_OK;
}

int32_t CloudMediaAlbumDao::IsEmptyAlbum(std::shared_ptr<MediaLibraryRdbStore> rdbStore, const std::string &cloudId)
{
    NativeRdb::RdbPredicates predicates = NativeRdb::RdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.InnerJoin(PhotoAlbumColumns::TABLE)
        ->On({PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " = " + PhotoAlbumColumns::TABLE +
              "." + PhotoAlbumColumns::ALBUM_ID});
    predicates.EqualTo(PhotoAlbumColumns::TABLE + "." + PhotoAlbumColumns::ALBUM_CLOUD_ID, cloudId);
    predicates.EqualTo(PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_HIDDEN, 0);
    predicates.EqualTo(PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_DATE_TRASHED, 0);
    predicates.EqualTo(PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::PHOTO_CLEAN_FLAG, 0);
    auto resultSet = rdbStore->Query(predicates, {});
    int32_t rowCount = -1;
    int32_t ret = resultSet->GetRowCount(rowCount);
    MEDIA_INFO_LOG("IsEmptyAlbum rowCount: %{public}d, cloudId: %{public}s", rowCount, cloudId.c_str());
    resultSet->Close();
    if (ret != NativeRdb::E_OK || rowCount != 0) {
        MEDIA_ERR_LOG("IsEmptyAlbum false");
        return E_ERR;
    }
    MEDIA_INFO_LOG("IsEmptyAlbum true");
    return E_OK;
}

int32_t CloudMediaAlbumDao::GetCopyAlbum(int32_t size, std::vector<PhotoAlbumPo> &cloudRecordPoList)
{
    return E_OK;
}

int32_t CloudMediaAlbumDao::QueryConflict(PhotoAlbumDto &record, std::shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Query Album Conflict Failed to get rdbStore.");
    std::string albumName = record.albumName;

    if (albumName.empty()) {
        MEDIA_ERR_LOG("no album name in record");
        return E_INVAL_ARG;
    }
    /* query local */
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    std::string albumType = std::to_string(record.albumType);
    string bundleName = record.bundleName;
    if (albumType == std::to_string(static_cast<int32_t>(AlbumType::SOURCE))) {
        if (!bundleName.empty()) {
            int rowCount = 0;
            NativeRdb::AbsRdbPredicates sourcePredicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
            sourcePredicates.EqualTo(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, bundleName)
                ->IsNull(PhotoAlbumColumns::ALBUM_CLOUD_ID)
                ->And()
                ->BeginWrap()
                ->IsNull(PhotoAlbumColumns::ALBUM_LPATH)
                ->Or()
                ->EqualTo(PhotoAlbumColumns::ALBUM_LPATH, "")
                ->EndWrap();
            resultSet = rdbStore->Query(sourcePredicates, QUERY_ALBUM_COLUMNS);
            if (resultSet == nullptr || resultSet->GetRowCount(rowCount) != E_OK) {
                MEDIA_ERR_LOG("query fail");
                return E_RDB;
            }
            if (rowCount >= 0) {
                return E_OK;
            }
            MEDIA_INFO_LOG("conflict but no colmns");
        }
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, albumType);
    }
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_NAME, albumName);
    predicates.IsNull(PhotoAlbumColumns::ALBUM_CLOUD_ID);
    predicates.IsNull(PhotoAlbumColumns::ALBUM_LPATH);
    resultSet = rdbStore->Query(predicates, ALBUM_LOCAL_QUERY_COLUMNS);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_RESULT_SET_NULL, "resultset is null");
    return E_OK;
}

bool CloudMediaAlbumDao::IsConflict(PhotoAlbumDto &record)
{
    int32_t rowCount = -1;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    int32_t ret = QueryConflict(record, resultSet);
    if (ret != E_OK || resultSet == nullptr) {
        MEDIA_ERR_LOG("query fail ret is %{public}d", ret);
        return false;
    }
    ret = resultSet->GetRowCount(rowCount);
    if (ret != 0) {
        MEDIA_ERR_LOG("result set get row count err %{public}d", ret);
        return false;
    }
    if (rowCount > 0) {
        ret = resultSet->GoToNextRow();
        if (ret != NativeRdb::E_OK) {
            return false;
        }
        record.albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        if (ret != E_OK) {
            return false;
        }
        MEDIA_INFO_LOG("albumId %{public}d, recordId:%{public}s", record.albumId, record.cloudId.c_str());
        return true;
    }
    return false;
}

int32_t CloudMediaAlbumDao::MergeAlbumOnConflict(PhotoAlbumDto &record,
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
    values.PutString(PhotoAlbumColumns::ALBUM_CLOUD_ID, record.cloudId);

    std::string albumType = std::to_string(record.albumType);
    if (albumType == std::to_string(static_cast<int32_t>(AlbumType::SOURCE))) {
        /* fix history data for album_subtype = 1 */
        values.PutString(PhotoAlbumColumns::ALBUM_SUBTYPE, std::to_string(PhotoAlbumSubType::SOURCE_GENERIC));
    }

    int32_t changedRows;
    int32_t ret = albumRefreshHandle->Update(changedRows,
        PhotoAlbumColumns::TABLE,
        values,
        PhotoAlbumColumns::ALBUM_ID + " = ?",
        {std::to_string(record.albumId)});
    if (ret != AccurateRefresh::ACCURATE_REFRESH_RET_OK) {
        MEDIA_ERR_LOG("rdb update failed, err = %{public}d", ret);
        return E_RDB;
    }
    return E_OK;
}

int32_t CloudMediaAlbumDao::SetSourceValues(PhotoAlbumDto &record, NativeRdb::ValuesBucket &values)
{
    if (record.albumType != AlbumType::SOURCE) {
        MEDIA_INFO_LOG("SetSourceValues not source album skip %{public}s", record.albumName.c_str());
        return E_OK;
    }
    MEDIA_INFO_LOG("SetSourceValues enter");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "SetSourceValues Failed to get rdbStore.");
    std::string lpath = record.lPath;
    std::transform(lpath.begin(), lpath.end(), lpath.begin(), ::tolower);
    std::unordered_map<std::string, MediaAlbumPluginRowData> writeListMap = QueryWhiteList();
    MEDIA_INFO_LOG("SetSourceValues writeListMap size:%{public}zu", writeListMap.size());
    auto it = writeListMap.find(lpath);
    if (it != writeListMap.end()) {
        MEDIA_INFO_LOG("SetSourceValues find lpath: %{public}s, name: %{public}s, bundle: %{public}s",
            lpath.c_str(),
            it->second.albumName.c_str(),
            writeListMap.at(lpath).bundleName.c_str());
        values.Delete(PhotoAlbumColumns::ALBUM_PRIORITY);
        values.Delete(PhotoAlbumColumns::ALBUM_NAME);
        values.PutInt(PhotoAlbumColumns::ALBUM_PRIORITY, it->second.priority);
        values.PutString(PhotoAlbumColumns::ALBUM_NAME, it->second.albumName);
        if (!writeListMap.at(lpath).bundleName.empty()) {
            values.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, it->second.bundleName);
        }
    }
    MEDIA_INFO_LOG("SetSourceValues OK record: %{public}s", record.ToString().c_str());
    return E_OK;
}

int32_t CloudMediaAlbumDao::InsertAlbums(PhotoAlbumDto &record,
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    MEDIA_INFO_LOG("FixData: insert of album record %{public}s", record.cloudId.c_str());
    NativeRdb::ValuesBucket values;
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, record.albumName);
    values.PutString(PhotoAlbumColumns::ALBUM_LPATH, record.lPath);
    if (!record.lPath.empty() && record.lPath.substr(0, ALBUM_LOCAL_PATH_PREFIX.size()) != ALBUM_LOCAL_PATH_PREFIX) {
        values.PutString(PhotoAlbumColumns::ALBUM_LPATH, record.lPath);
    }
    int32_t ret = SetSourceValues(record, values);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "SetSourceValues failed");

    if (!record.bundleName.empty()) {
        values.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, record.bundleName);
    }
    values.PutInt(PhotoAlbumColumns::ALBUM_PRIORITY, 1);
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, record.albumType);
    values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, record.albumSubType);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_ADDED, record.albumDateAdded);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, record.albumDateModified);
    values.PutString(PhotoAlbumColumns::ALBUM_LOCAL_LANGUAGE, record.localLanguage);
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
    values.PutString(PhotoAlbumColumns::ALBUM_CLOUD_ID, record.cloudId);
    values.PutInt(PhotoAlbumColumns::ALBUM_IS_LOCAL, ALBUM_FROM_CLOUD);
    /* update if a album with the same name exists? */
    int64_t rowId;
    ret = albumRefreshHandle->Insert(rowId, PhotoAlbumColumns::TABLE, values);
    CHECK_AND_RETURN_RET_LOG(ret == AccurateRefresh::ACCURATE_REFRESH_RET_OK, E_RDB,
        "Insert pull record failed, rdb ret = %{public}d", ret);
    return E_OK;
}

int32_t CloudMediaAlbumDao::OnDeleteAlbumRecords(const std::string &cloudId)
{
    MEDIA_INFO_LOG("enter CloudMediaRdbOperations::OnDeleteAlbumRecords %{public}s", cloudId.c_str());
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "OnDeleteAlbumRecords Failed to get rdbStore.");

    if (IsEmptyAlbum(rdbStore, cloudId) != E_OK) {
        if (ResetAlbumDirty(rdbStore, cloudId, DirtyType::TYPE_NEW) != E_OK) {
            InsertAlbumModifyFailedRecord(cloudId);
            return E_ERR;
        }
        return E_OK;
    }
    std::string whereClause = PhotoAlbumColumns::ALBUM_CLOUD_ID + " = ? AND " + PhotoAlbumColumns::ALBUM_DIRTY + " = " +
                              to_string(static_cast<int32_t>(Media::DirtyType::TYPE_DELETED));
    std::vector<std::string> whereArgs = {cloudId};
    int32_t deletedRows = -1;
    int32_t ret = rdbStore->Delete(deletedRows, PhotoAlbumColumns::TABLE, whereClause, whereArgs);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("OnDeleteAlbumRecords Failed %{public}d", ret);
        InsertAlbumModifyFailedRecord(cloudId);
        return ret;
    }
    MEDIA_INFO_LOG("OnDeleteAlbumRecords deletedRows %{public}d", deletedRows);
    return E_OK;
}

int32_t CloudMediaAlbumDao::OnMdirtyAlbumRecords(const std::string &cloudId)
{
    MEDIA_INFO_LOG("enter OnMdirtyAlbumRecords %{public}s", cloudId.c_str());
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(
        rdbStore != nullptr, E_RDB_STORE_NULL, "OnMdirtyAlbumRecords update Mdirty album get store failed.");

    int32_t changedRows;
    NativeRdb::ValuesBucket valuesBucket;
    string whereClause = Media::PhotoAlbumColumns::ALBUM_CLOUD_ID + " = ?";
    vector<string> whereArgs = {cloudId};
    valuesBucket.PutInt(Media::PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(Media::DirtyType::TYPE_SYNCED));
    int32_t ret = rdbStore->Update(changedRows, PhotoAlbumColumns::TABLE, valuesBucket, whereClause, whereArgs);
    MEDIA_INFO_LOG("OnMdirtyAlbumRecords changedRows: %{public}d", changedRows);
    if (ret != E_OK) {
        InsertAlbumModifyFailedRecord(cloudId);
        MEDIA_ERR_LOG("OnMdirtyAlbumRecords update local records err %{public}d", ret);
        return ret;
    }
    return E_OK;
}

int32_t CloudMediaAlbumDao::ResetAlbumDirty(
    std::shared_ptr<MediaLibraryRdbStore> rdbStore, const std::string &cloudId, DirtyType dirty)
{
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(dirty));
    int32_t changedRows = -1;
    int32_t ret = rdbStore->Update(
        changedRows, PhotoAlbumColumns::TABLE, values, PhotoAlbumColumns::ALBUM_CLOUD_ID + "=?", {cloudId});
    MEDIA_INFO_LOG("ResetAlbumDirty changedRows: %{public}d, ret: %{public}d", changedRows, ret);
    if (ret != NativeRdb::E_OK || changedRows <= 0) {
        return E_ERR;
    }
    return E_OK;
}

int32_t CloudMediaAlbumDao::QueryDeleteAlbums(int32_t size, std::vector<PhotoAlbumPo> &resultList)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "QueryDeleteAlbums Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_DIRTY, to_string(static_cast<int32_t>(DirtyType::TYPE_DELETED)))
        ->NotEqualTo(PhotoAlbumColumns::ALBUM_CLOUD_ID, "")
        ->IsNotNull(PhotoAlbumColumns::ALBUM_CLOUD_ID)
        ->And()
        /* user and source albums */
        ->BeginWrap()
        ->EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::USER_GENERIC))
        ->Or()
        ->EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::SOURCE_GENERIC))
        ->EndWrap();

    if (!albumModifyFailSet_.empty()) {
        predicates.NotIn(PhotoAlbumColumns::ALBUM_CLOUD_ID, albumModifyFailSet_);
    }
    predicates.Limit(size);
    /* query */
    auto resultSet = rdbStore->Query(predicates, QUERY_ALBUM_COLUMNS);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_RESULT_SET_NULL, "resultset is null");
    resultList = ResultSetReader<PhotoAlbumPoWriter, PhotoAlbumPo>(resultSet).ReadRecords();
    resultSet->Close();
    return E_OK;
}

int32_t CloudMediaAlbumDao::GetDeletedRecordsAlbum(int32_t size, std::vector<PhotoAlbumPo> &cloudRecordPoList)
{
    MEDIA_INFO_LOG("enter GetDeletedRecords %{public}d", size);
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(
        rdbStore != nullptr, E_RDB_STORE_NULL, "get album deleted records Failed to get rdbStore.");
    std::vector<PhotoAlbumPo> tempList;
    int32_t ret = QueryDeleteAlbums(size, tempList);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "get album deleted records get count error.");
    /* results to records */
    cloudRecordPoList.reserve(tempList.size());
    std::unordered_map<std::string, MediaAlbumPluginRowData> writeListMap = QueryWhiteList();
    for (auto &record : tempList) {
        // dirty为delete的相册如果非空，则不删除，设置相册dirty为new
        std::string lpath = record.lpath.value_or("");
        RelateToAlbumPluginInfo(record, writeListMap);
        std::string albumCloudId = record.cloudId.value_or("");
        if (IsEmptyAlbum(rdbStore, albumCloudId) != E_OK) {
            if (ResetAlbumDirty(rdbStore, albumCloudId, DirtyType::TYPE_NEW) != E_OK) {
                InsertAlbumModifyFailedRecord(albumCloudId);
            } else {
                MEDIA_DEBUG_LOG("ResetAlbumDirty ok albumCloudId: %{public}s", albumCloudId.c_str());
            }
            continue;
        }
        cloudRecordPoList.emplace_back(move(record));
    }
    return E_OK;
}

int32_t CloudMediaAlbumDao::GetMetaModifiedAlbum(int32_t size, std::vector<PhotoAlbumPo> &cloudRecordPoList)
{
    MEDIA_INFO_LOG("enter GetMetaModifiedAlbum");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "GetMetaModifiedAlbum Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_DIRTY, to_string(static_cast<int32_t>(DirtyType::TYPE_MDIRTY)))
        ->NotEqualTo(PhotoAlbumColumns::ALBUM_CLOUD_ID, "")
        ->IsNotNull(PhotoAlbumColumns::ALBUM_CLOUD_ID)
        ->
        /* user and source albums */
        BeginWrap()
        ->EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::USER_GENERIC))
        ->Or()
        ->EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::SOURCE_GENERIC))
        ->EndWrap();

    if (!albumModifyFailSet_.empty()) {
        predicates.NotIn(PhotoAlbumColumns::ALBUM_CLOUD_ID, albumModifyFailSet_);
    }
    predicates.Limit(size);
    /* query */
    auto resultSet = rdbStore->Query(predicates, QUERY_ALBUM_COLUMNS);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_RESULT_SET_NULL, "resultset is null");
    /* results to records */
    std::vector<PhotoAlbumPo> tempList = ResultSetReader<PhotoAlbumPoWriter, PhotoAlbumPo>(resultSet).ReadRecords();
    resultSet->Close();
    std::unordered_map<std::string, MediaAlbumPluginRowData> writeListMap = QueryWhiteList();
    for (auto &record : tempList) {
        std::string lpath = record.lpath.value_or("");
        std::transform(lpath.begin(), lpath.end(), lpath.begin(), ::tolower);
        if (!lpath.empty() && writeListMap.find(lpath) != writeListMap.end()) {
            // CloudAlbumDataConvert::HandleRecordId 先cloudId然后return,导致isInWhiteList无效,
            // 系统相册cloudId没有使用正确的WriteListMap中的cloudId
            record.isInWhiteList = true;
            std::string albumPluginCloudId = writeListMap.at(lpath).cloudId;
            if (!albumPluginCloudId.empty()) {
                record.cloudId = albumPluginCloudId;
                record.albumPluginCloudId = albumPluginCloudId;
            }
            record.albumNameEn = writeListMap.at(lpath).albumNameEn;
            record.dualAlbumName = writeListMap.at(lpath).dualAlbumName;
            record.priority = writeListMap.at(lpath).priority;
        }

        cloudRecordPoList.emplace_back(move(record));
    }
    return E_OK;
}

int32_t CloudMediaAlbumDao::QueryCreatedAlbums(int32_t size, std::vector<PhotoAlbumPo> &resultList)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates createPredicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    createPredicates.EqualTo(PhotoAlbumColumns::ALBUM_DIRTY, to_string(static_cast<int32_t>(DirtyType::TYPE_NEW)));
    createPredicates.IsNotNull(PhotoAlbumColumns::ALBUM_LPATH)
        ->BeginWrap()
        ->NotEqualTo(PhotoAlbumColumns::ALBUM_COUNT, "0")
        ->Or()
        ->EqualTo(PhotoAlbumColumns::ALBUM_LPATH, "/Pictures/hiddenAlbum")
        ->EndWrap()
        ->BeginWrap()
        ->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::USER))
        ->Or()
        ->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SOURCE))
        ->EndWrap();
    if (!albumModifyFailSet_.empty()) {
        createPredicates.NotIn(PhotoAlbumColumns::ALBUM_CLOUD_ID, albumModifyFailSet_);
    }
    if (!albumInsertFailSet_.empty()) {
        createPredicates.NotIn(PhotoAlbumColumns::ALBUM_LPATH, albumInsertFailSet_);
    }
    createPredicates.Limit(size);

    auto resultSet = rdbStore->Query(createPredicates, QUERY_ALBUM_COLUMNS);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_RESULT_SET_NULL, "resultset is null");
    resultList = ResultSetReader<PhotoAlbumPoWriter, PhotoAlbumPo>(resultSet).ReadRecords();
    resultSet->Close();
    return E_OK;
}

int32_t CloudMediaAlbumDao::GetCreatedAlbum(int32_t size, std::vector<PhotoAlbumPo> &cloudRecordPoList)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Failed to get rdbStore.");
    MEDIA_INFO_LOG("enter GetCreatedAlbum");
    std::vector<PhotoAlbumPo> tempList;
    int32_t ret = QueryCreatedAlbums(size, tempList);
    /* results to records */
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "GetCreatedAlbum Failed to query.");
    cloudRecordPoList.reserve(tempList.size());
    std::string cloudId;
    int32_t albumId;
    std::unordered_map<std::string, MediaAlbumPluginRowData> writeListMap = QueryWhiteList();
    for (auto &record : tempList) {
        RelateToAlbumPluginInfo(record, writeListMap);
        CloudMediaSyncUtils::GenerateCloudIdWithHash(record);
        cloudId = record.cloudId.value_or("");
        albumId = record.albumId.value_or(-1);
        MEDIA_DEBUG_LOG("GetCreatedAlbum Record: %{public}s", record.ToString().c_str());
        cloudRecordPoList.emplace_back(move(record));
        if (!cloudId.empty() && albumId > 0) {
            NativeRdb::AbsRdbPredicates updatePredicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
            updatePredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
            NativeRdb::ValuesBucket values;
            values.PutString(PhotoAlbumColumns::ALBUM_CLOUD_ID, cloudId);
            int32_t changedRows = -1;
            int32_t errCode = rdbStore->Update(changedRows, values, updatePredicates);
            if (errCode != E_OK) {
                MEDIA_ERR_LOG("GetCreatedAlbum Database update failed, err = %{public}d", errCode);
                return E_HAS_DB_ERROR;
            }
        }
    }
    return E_OK;
}

void CloudMediaAlbumDao::RelateToAlbumPluginInfo(
    PhotoAlbumPo &record, std::unordered_map<std::string, MediaAlbumPluginRowData> &writeListMap)
{
    std::string lpath = record.lpath.value_or("");
    std::transform(lpath.begin(), lpath.end(), lpath.begin(), ::tolower);
    MEDIA_INFO_LOG("GetCreatedAlbum lpath: %{public}s, find: %{public}d",
        lpath.c_str(),
        writeListMap.find(lpath) != writeListMap.end());
    if (!lpath.empty() && writeListMap.find(lpath) != writeListMap.end()) {
        // CloudAlbumDataConvert::HandleRecordId 先cloudId然后return,导致isInWhiteList无效,
        // 系统相册cloudId没有使用正确的WriteListMap中的cloudId
        record.isInWhiteList = true;
        if (!writeListMap.at(lpath).cloudId.empty()) {
            record.cloudId = writeListMap.at(lpath).cloudId;
            record.albumPluginCloudId = writeListMap.at(lpath).cloudId;
        }
        record.albumNameEn = writeListMap.at(lpath).albumNameEn;
        record.dualAlbumName = writeListMap.at(lpath).dualAlbumName;
        record.priority = writeListMap.at(lpath).priority;
    }
}

std::tuple<std::shared_ptr<NativeRdb::ResultSet>, std::map<std::string, int>> CloudMediaAlbumDao::QueryLocalAlbum(
    const std::string &key, const std::vector<std::string> &argrs)
{
    MEDIA_INFO_LOG("QueryLocalAlbum enter");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    auto lpathRowIdMap = std::map<std::string, int>();
    std::tuple<std::shared_ptr<NativeRdb::ResultSet>, std::map<std::string, int>> defaultValue = {
        nullptr, std::move(lpathRowIdMap)};
    CHECK_AND_RETURN_RET_LOG(
        rdbStore != nullptr, defaultValue, "QueryLocalAlbum Query Local Album Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    predicates.In(key, argrs);
    auto resultSet = rdbStore->Query(
        predicates, {PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_LPATH, PhotoAlbumColumns::ALBUM_DIRTY});
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, defaultValue, "resultset is null");
    int rowCount = 0;
    int ret = resultSet->GetRowCount(rowCount);
    if (ret != 0 || rowCount < 0) {
        MEDIA_ERR_LOG("QueryLocalAlbum get row count err %{public}d, rowCount %{public}d", ret, rowCount);
        return defaultValue;
    }
    int columnIndex = 0;
    resultSet->GetColumnIndex(PhotoAlbumColumns::ALBUM_LPATH, columnIndex);
    for (int rowId = 0; rowId < rowCount; ++rowId) {
        resultSet->GoToNextRow();
        std::string lpath = "";
        resultSet->GetString(columnIndex, lpath);
        lpathRowIdMap.insert(make_pair(lpath, rowId));
    }
    return {std::move(resultSet), std::move(lpathRowIdMap)};
}

int32_t CloudMediaAlbumDao::DeleteCloudAlbum(const std::string &field, const std::string &value,
    std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle)
{
    MEDIA_INFO_LOG("DeleteCloudAlbum Field: %{public}s, Value: %{public}s", field.c_str(), value.c_str());
    int ret = E_OK;
    int32_t changedRows;
    NativeRdb::ValuesBucket values;
    if (field == PhotoAlbumColumns::ALBUM_LPATH && (value == "/Pictures/hiddenAlbum" || value == "/Pictures/其它")) {
        values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(Media::DirtyType::TYPE_NEW));
        values.PutNull(PhotoAlbumColumns::ALBUM_CLOUD_ID);
    } else {
        MEDIA_INFO_LOG("FixData: set sdirty");
        values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(Media::DirtyType::TYPE_SDIRTY));
    }
    ret = albumRefreshHandle->Update(changedRows, PhotoAlbumColumns::TABLE, values, field + " = ?", {value});
    CHECK_AND_RETURN_RET_LOG(ret == AccurateRefresh::ACCURATE_REFRESH_RET_OK, E_RDB,
        "delete in rdb failed, ret: %{public}d", ret);
    MEDIA_INFO_LOG(" FixData: update success, changerow is %{public}d", changedRows);
    return E_OK;
}

void CloudMediaAlbumDao::InsertAlbumModifyFailedRecord(const std::string &cloudId)
{
    albumModifyFailSet_.push_back(cloudId);
}

void CloudMediaAlbumDao::InsertAlbumInsertFailedRecord(const std::string &cloudId)
{
    albumInsertFailSet_.push_back(cloudId);
}

void CloudMediaAlbumDao::InsertAlbumCreateFailedRecord(const std::string &cloudId)
{
    albumCreateFailSet_.push_back(cloudId);
}

void CloudMediaAlbumDao::RemoveAlbumModifyFailedRecord(const std::string &cloudId)
{
    std::remove(albumModifyFailSet_.begin(), albumModifyFailSet_.end(), cloudId);
}

void CloudMediaAlbumDao::RemoveAlbumInsertFailedRecord(const std::string &cloudId)
{
    std::remove(albumInsertFailSet_.begin(), albumInsertFailSet_.end(), cloudId);
}

void CloudMediaAlbumDao::RemoveAlbumCreateFailedRecord(const std::string &cloudId)
{
    std::remove(albumCreateFailSet_.begin(), albumCreateFailSet_.end(), cloudId);
}

int32_t CloudMediaAlbumDao::ClearAlbumFailedRecords()
{
    albumModifyFailSet_.clear();
    albumCreateFailSet_.clear();
    albumInsertFailSet_.clear();
    return E_OK;
}

std::unordered_map<std::string, MediaAlbumPluginRowData> CloudMediaAlbumDao::QueryWhiteList()
{
    MEDIA_INFO_LOG("WitreListMap start init");
    std::unordered_map<std::string, MediaAlbumPluginRowData> whiteListMap;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, whiteListMap, "GetLocalAlbumMap Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(WRITE_LIST_TABLE_NAME);
    predicates.Like(PhotoAlbumColumns::ALBUM_LPATH, "%");
    auto resultSet = rdbStore->Query(predicates, ALBUM_PLUGIN_QUERY_COLUMNS);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, whiteListMap, "GetLocalAlbumMap get nullptr created result.");
    int rowCount = 0;
    int ret = resultSet->GetRowCount(rowCount);
    MEDIA_INFO_LOG("WitreListMap init count %{public}d", rowCount);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK && rowCount >= 0,
        whiteListMap,
        "result set get row count err %{public}d, rowCount %{public}d",
        ret,
        rowCount);
    std::string albumName = "";
    std::string albumNameEn = "";
    std::string dualAlbumName = "";
    std::string cloudId = "";
    std::string bundleName = "";
    std::string lpath = "";
    int32_t priority = 1;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        priority = GetInt32Val(MEDIA_ALBUM_PRIORITY, resultSet);
        albumNameEn = GetStringVal(MEDIA_ALBUM_NAME_EN, resultSet);
        dualAlbumName = GetStringVal(MEDIA_DUAL_ALBUM_NAME, resultSet);
        albumName = GetStringVal(PhotoAlbumColumns::ALBUM_NAME, resultSet);
        lpath = GetStringVal(PhotoAlbumColumns::ALBUM_LPATH, resultSet);
        cloudId = GetStringVal(PhotoAlbumColumns::ALBUM_CLOUD_ID, resultSet);
        bundleName = GetStringVal(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, resultSet);
        MediaAlbumPluginRowData data;
        data.lpath = lpath;
        data.albumName = albumName;
        data.albumNameEn = albumNameEn;
        data.dualAlbumName = dualAlbumName;
        data.cloudId = cloudId;
        data.bundleName = bundleName;
        data.priority = priority;
        std::transform(lpath.begin(), lpath.end(), lpath.begin(), ::tolower);
        whiteListMap.insert(std::make_pair(lpath, data));
    }
    return whiteListMap;
}

std::unordered_map<std::string, std::string> CloudMediaAlbumDao::GetLocalAlbumMap()
{
    MEDIA_INFO_LOG("GetLocalAlbumMap start init");
    std::unordered_map<std::string, std::string> localAlbumMap;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, localAlbumMap, "GetLocalAlbumMap Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_DIRTY, to_string(static_cast<int32_t>(Media::DirtyType::TYPE_NEW)));
    auto resultSet = rdbStore->Query(predicates, {PhotoAlbumColumns::ALBUM_LPATH});
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, localAlbumMap, "resultset is null");
    int rowCount = 0;
    int ret = resultSet->GetRowCount(rowCount);
    bool isSuccess = (ret == E_OK && rowCount >= 0);
    CHECK_AND_RETURN_RET_LOG(isSuccess,
        localAlbumMap,
        "GetLocalAlbumMap result set get row count err %{public}d, rowCount %{public}d",
        ret,
        rowCount);
    std::string lpath = "";
    for (int rowId = 0; rowId < rowCount; ++rowId) {
        ret = resultSet->GoToNextRow();
        if (ret != NativeRdb::E_OK) {
            resultSet->Close();
            return localAlbumMap;
        }
        lpath = GetStringVal(PhotoAlbumColumns::ALBUM_LPATH, resultSet);
        std::string lowerLpath = lpath;
        std::transform(lowerLpath.begin(), lowerLpath.end(), lowerLpath.begin(), ::tolower);
        localAlbumMap.insert(std::make_pair(lowerLpath, lpath));
    }
    resultSet->Close();
    return localAlbumMap;
}
}  // namespace OHOS::Media::CloudSync