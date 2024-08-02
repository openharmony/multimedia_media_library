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

int32_t QueryPhotoRecordInfo(PhotoRecordInfo &photoRecordInfo)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_FAIL;
    }

    const string imageAndVideoCountQuerySql = "select media_type,count(*) recordCount from photos group by media_type";
    auto resultSet = uniStore->QuerySql(imageAndVideoCountQuerySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        return E_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t  mediaType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
        if (mediaType == MEDIA_TYPE_IMAGE) {
            photoRecordInfo.imageCount = GetInt32Val("recordCount", resultSet);
        }else if (mediaType == MEDIA_TYPE_VIDEO) {
            photoRecordInfo.videoCount = GetInt32Val("recordCount", resultSet);
        }
    }

    const string abnormalSizeCountQuerySql = "select count(*) recordCount from photos where size = -1";
    auto resultSet = uniStore->QuerySql(abnormalSizeCountQuerySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        return E_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            photoRecordInfo.abnormalSizeCount = GetInt32Val("recordCount", resultSet);
    }

    const string abnormalWHCountQuerySql = "select count(*) recordCount from photos where width = -1 or height = -1";
    auto resultSet = uniStore->QuerySql(abnormalWHCountQuerySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        return E_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            photoRecordInfo.abnormalWidthOrHeightCount = GetInt32Val("recordCount", resultSet);
    }

    const string abnormalVideoDurationQuerySql = "select count(*) recordCount from photos where duration = -1 and media_type = 2";
    auto resultSet = uniStore->QuerySql(abnormalVideoDurationQuerySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        return E_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            photoRecordInfo.abnormalVideoDurationCount = GetInt32Val("recordCount", resultSet);
    }

    const string totalAbnormalRecordSql = "select count(*) recordCount from photos where size = 0 or size is null or mime_type is null or mime_type = '' or height = 0 or height is null or width = 0 or width is null or (duration = 0 and media_type = 2)";
    auto resultSet = uniStore->QuerySql(totalAbnormalRecordSql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        return E_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            photoRecordInfo.toBeUpdatedRecordCount = GetInt32Val("recordCount", resultSet);
    }

    string name = MEDIA_DATA_ABILITY_DB_NAME;
    string databaseDir = MEDIA_DB_DIR + "/rdb";
    if (access(databaseDir.c_str(), E_OK) != 0) {
        MEDIA_WARN_LOG("can not get rdb through sandbox");
        return E_FAIL;
    }
    string dbPath = databaseDir.append("/").append(name);

    struct stat statInfo {};
    if (stat(dbPath.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("stat syscall err");
        return E_FAIL;
    }
    photoRecordInfo.dbFileSize = statInfo.st_size;

    return E_OK;
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