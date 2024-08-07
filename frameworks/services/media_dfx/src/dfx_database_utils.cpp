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

#include <sys/stat.h>
#include "dfx_database_utils.h"

#include "dfx_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "media_log.h"
#include "media_column.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"
#include "photo_album_column.h"

namespace OHOS {
namespace Media {
const std::string RECORD_COUNT = "recordCount";
const std::string ABNORMAL_VALUE = "-1";

int32_t DfxDatabaseUtils::QueryFromPhotos(int32_t mediaType, bool isLocal)
{
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, mediaType);
    if (isLocal) {
        predicates.IsNull(PhotoColumn::PHOTO_CLOUD_ID);
    } else {
        predicates.IsNotNull(PhotoColumn::PHOTO_CLOUD_ID);
    }
    std::vector<std::string> columns = { "count(1) AS count" };
    std::string queryColumn = "count";
    int32_t count;
    int32_t errCode = QueryInt(predicates, columns, queryColumn, count);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("query local image fail: %{public}d", errCode);
    }
    return count;
}

AlbumInfo DfxDatabaseUtils::QueryAlbumInfoBySubtype(int32_t albumSubtype)
{
    AlbumInfo albumInfo;
    NativeRdb::RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, albumSubtype);
    std::vector<std::string> columns = { PhotoAlbumColumns::ALBUM_COUNT, PhotoAlbumColumns::ALBUM_IMAGE_COUNT,
        PhotoAlbumColumns::ALBUM_VIDEO_COUNT, PhotoAlbumColumns::ALBUM_CLOUD_ID };
    auto resultSet = MediaLibraryRdbStore::Query(predicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("query album fail");
        return albumInfo;
    }
    albumInfo.count = GetInt32Val(PhotoAlbumColumns::ALBUM_COUNT, resultSet);
    albumInfo.imageCount = GetInt32Val(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet);
    albumInfo.videoCount = GetInt32Val(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet);
    albumInfo.isLocal = GetStringVal(PhotoAlbumColumns::ALBUM_CLOUD_ID, resultSet) == "" ? true : false;
    return albumInfo;
}

std::vector<PhotoInfo> DfxDatabaseUtils::QueryDirtyCloudPhoto()
{
    vector<PhotoInfo> photoInfoList;
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.IsNotNull(PhotoColumn::PHOTO_CLOUD_ID);
    predicates.NotEqualTo(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t> (DirtyType::TYPE_SYNCED));
    predicates.Limit(DIRTY_PHOTO_COUNT);
    std::vector<std::string> columns = { MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_DIRTY,
        PhotoColumn::PHOTO_CLOUD_ID };
    auto resultSet = MediaLibraryRdbStore::Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        return photoInfoList;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PhotoInfo photoInfo;
        photoInfo.data = DfxUtils::GetSafePath(GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet));
        photoInfo.dirty = GetInt32Val(PhotoColumn::PHOTO_DIRTY, resultSet);
        photoInfo.cloudVersion = GetInt32Val(PhotoColumn::PHOTO_CLOUD_ID, resultSet);
        photoInfoList.push_back(photoInfo);
    }
    return photoInfoList;
}

static int32_t ParseResultSet(const string &querySql, int32_t mediaTypePara, int32_t &photoInfoCount)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr!");
        return E_FAIL;
    }
    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        return E_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        if (mediaTypePara > 0) {
            int32_t mediaType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
            if (mediaType == mediaTypePara) {
                photoInfoCount = GetInt32Val(RECORD_COUNT, resultSet);
            }
        } else {
            photoInfoCount = GetInt32Val(RECORD_COUNT, resultSet);
        }
    }
    return E_OK;
}

int32_t DfxDatabaseUtils::QueryPhotoRecordInfo(PhotoRecordInfo &photoRecordInfo)
{
    const string filterCondition = MediaColumn::MEDIA_TIME_PENDING + " = 0 AND " +
        PhotoColumn::PHOTO_SYNC_STATUS + " = " +
        to_string(static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE)) + " AND " +
        PhotoColumn::PHOTO_CLEAN_FLAG + " = " +
        to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));

    const string imageAndVideoCountQuerySql = "SELECT " + MediaColumn::MEDIA_TYPE + ", COUNT(*) AS " + RECORD_COUNT +
        " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + filterCondition + " GROUP BY " +
        MediaColumn::MEDIA_TYPE;

    const string abnormalSizeCountQuerySql = "SELECT COUNT(*) AS " + RECORD_COUNT + " FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_SIZE + " = " + ABNORMAL_VALUE +
        " AND " + filterCondition;

    const string abnormalWidthHeightQuerySql = "SELECT COUNT(*) AS " + RECORD_COUNT + " FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE (" + PhotoColumn::PHOTO_WIDTH +
        " = " + ABNORMAL_VALUE + "OR" + PhotoColumn::PHOTO_HEIGHT +
        " = " + ABNORMAL_VALUE + ") AND " + filterCondition;

    const string abnormalVideoDurationQuerySql = "SELECT COUNT(*) AS " + RECORD_COUNT + " FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_DURATION + " = " +
        ABNORMAL_VALUE + " AND " + MediaColumn::MEDIA_TYPE + " = " +
        std::to_string(MEDIA_TYPE_VIDEO) +
        " AND " + filterCondition;

    const string totalAbnormalRecordSql = "SELECT COUNT(*) AS " + RECORD_COUNT + " FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE (" + MediaColumn::MEDIA_SIZE + " = 0 OR " +
        MediaColumn::MEDIA_SIZE + " IS NULL OR " +
        MediaColumn::MEDIA_MIME_TYPE + " IS NULL OR " + MediaColumn::MEDIA_MIME_TYPE + " = '' OR " +
        PhotoColumn::PHOTO_HEIGHT + " = 0 OR " + PhotoColumn::PHOTO_HEIGHT + " IS NULL OR " +
        PhotoColumn::PHOTO_WIDTH + " = 0 OR " + PhotoColumn::PHOTO_WIDTH + " IS NULL OR ((" +
        MediaColumn::MEDIA_DURATION + " IS NULL OR " +
        MediaColumn::MEDIA_DURATION + " = 0 ) AND " +
        MediaColumn::MEDIA_TYPE + " = " + std::to_string(MEDIA_TYPE_VIDEO) + " )) AND " + filterCondition;

    int32_t ret = ParseResultSet(imageAndVideoCountQuerySql, MEDIA_TYPE_VIDEO, photoRecordInfo.videoCount);
    ret = ret | ParseResultSet(imageAndVideoCountQuerySql, MEDIA_TYPE_IMAGE, photoRecordInfo.imageCount);
    ret = ret | ParseResultSet(abnormalSizeCountQuerySql, 0, photoRecordInfo.abnormalSizeCount);
    ret = ret | ParseResultSet(abnormalWidthHeightQuerySql, 0, photoRecordInfo.abnormalWidthOrHeightCount);
    ret = ret | ParseResultSet(abnormalVideoDurationQuerySql, 0, photoRecordInfo.abnormalVideoDurationCount);
    ret = ret | ParseResultSet(totalAbnormalRecordSql, 0, photoRecordInfo.toBeUpdatedRecordCount);

    string databaseDir = MEDIA_DB_DIR + "/rdb";
    if (access(databaseDir.c_str(), E_OK) != 0) {
        MEDIA_WARN_LOG("can not get rdb through sandbox");
        return E_FAIL;
    }
    string dbPath = databaseDir.append("/").append(MEDIA_DATA_ABILITY_DB_NAME);

    struct stat statInfo {};
    if (stat(dbPath.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("stat syscall err");
        return E_FAIL;
    }
    photoRecordInfo.dbFileSize = statInfo.st_size;

    return ret;
}

int32_t DfxDatabaseUtils::QueryAnalysisVersion(const std::string &table, const std::string &column)
{
    NativeRdb::RdbPredicates predicates(table);
    string whereClause = "max(" + column + ") AS version";
    std::vector<std::string> columns = { whereClause };
    string version = "version";
    double count;
    int32_t errCode = QueryDouble(predicates, columns, version, count);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("query analysis version fail: %{public}d", errCode);
    }
    return static_cast<int32_t> (count);
}

int32_t DfxDatabaseUtils::QueryDbVersion()
{
    int64_t dbVersion = 0;
    MediaLibraryRdbStore::QueryPragma("user_version", dbVersion);
    return static_cast<int32_t> (dbVersion);
}

int32_t DfxDatabaseUtils::QueryInt(const NativeRdb::AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns, const std::string &queryColumn, int32_t &value)
{
    auto resultSet = MediaLibraryRdbStore::Query(predicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_DB_FAIL;
    }
    value = GetInt32Val(queryColumn, resultSet);
    return E_OK;
}

int32_t DfxDatabaseUtils::QueryDouble(const NativeRdb::AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns, const std::string &queryColumn, double &value)
{
    auto resultSet = MediaLibraryRdbStore::Query(predicates, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_DB_FAIL;
    }
    value = GetDoubleVal(queryColumn, resultSet);
    return E_OK;
}
} // namespace Media
} // namespace OHOS