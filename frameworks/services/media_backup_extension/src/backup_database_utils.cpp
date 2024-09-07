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

#include <nlohmann/json.hpp>

#include "backup_const_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
const int32_t SCALE_FACTOR = 2;
const int32_t SCALE_MIN_SIZE = 1080;
const int32_t SCALE_MAX_SIZE = 2560;
const int32_t UPDATE_COUNT = 200;
const float SCALE_DEFAULT = 0.25;
const size_t MIN_GARBLE_SIZE = 2;
const size_t GARBLE_START = 1;
const size_t XY_DIMENSION = 2;
const size_t BYTE_LEN = 4;
const size_t BYTE_BASE_OFFSET = 8;
const size_t LANDMARKS_SIZE = 5;
const std::string LANDMARK_X = "x";
const std::string LANDMARK_Y = "y";
const std::vector<uint32_t> HEX_MAX = { 0xff, 0xffff, 0xffffff, 0xffffffff };

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

int32_t BackupDatabaseUtils::Delete(NativeRdb::AbsRdbPredicates &predicates, int32_t &changeRows,
    std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdb is nullptr");
        return E_FAIL;
    }
    return rdbStore->Delete(changeRows, predicates);
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

int32_t BackupDatabaseUtils::QueryGalleryFavoriteCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_FAVORITE_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE is_hw_favorite = 1 AND _size > 0 AND local_media_id != -1";
    return QueryInt(galleryRdb, QUERY_GALLERY_FAVORITE_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryImportsCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_IMPORTS_COUNT =
        string("SELECT count(1) AS count FROM gallery_media WHERE ") +
        " _data LIKE '/storage/emulated/0/Pictures/cloud/Imports%' AND _size > 0 AND local_media_id != -1";
    return QueryInt(galleryRdb, QUERY_GALLERY_IMPORTS_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryCloneCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_CLONE_COUNT =
        string("SELECT count(1) AS count FROM gallery_media WHERE local_media_id = -3 AND _size > 0 ") +
        "AND (storage_id IN (0, 65537)) AND relative_bucket_id NOT IN ( " +
        "SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1)";
    return QueryInt(galleryRdb, QUERY_GALLERY_CLONE_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGallerySdCardCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
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

int32_t BackupDatabaseUtils::QueryGalleryBurstCoverCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_BURST_COVER_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE is_hw_burst = 1 AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_BURST_COVER_COUNT, CUSTOM_COUNT);
}

int32_t BackupDatabaseUtils::QueryGalleryBurstTotalCount(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    static string QUERY_GALLERY_BURST_TOTAL_COUNT =
        "SELECT count(1) AS count FROM gallery_media WHERE is_hw_burst IN (1, 2) AND _size > 0";
    return QueryInt(galleryRdb, QUERY_GALLERY_BURST_TOTAL_COUNT, CUSTOM_COUNT);
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
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &querySql,
    const std::vector<std::string> &sqlArgs)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return nullptr;
    }
    return rdbStore->QuerySql(querySql, sqlArgs);
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

int32_t BackupDatabaseUtils::QueryExternalAudioCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb)
{
    static string QUERY_EXTERNAL_AUDIO_COUNT = "SELECT count(1) as count FROM files WHERE media_type = 2 AND _size > 0 \
        AND _data LIKE '/storage/emulated/0/Music%'";
    return QueryInt(externalRdb, QUERY_EXTERNAL_AUDIO_COUNT, CUSTOM_COUNT);
}

void BackupDatabaseUtils::UpdateSelection(std::string &selection, const std::string &selectionToAdd, bool needWrap)
{
    if (selectionToAdd.empty()) {
        return;
    }
    std::string wrappedSelectionToAdd = needWrap ? "'" + selectionToAdd + "'" : selectionToAdd;
    selection += selection.empty() ? wrappedSelectionToAdd : ", " + wrappedSelectionToAdd;
}

void BackupDatabaseUtils::UpdateSdWhereClause(std::string &querySql, bool shouldIncludeSd)
{
    if (shouldIncludeSd) {
        return;
    }
    querySql += " AND " + EXCLUDE_SD;
}

int32_t BackupDatabaseUtils::GetBlob(const std::string &columnName, std::shared_ptr<NativeRdb::ResultSet> resultSet,
    std::vector<uint8_t> &blobVal)
{
    int32_t columnIndex = 0;
    int32_t errCode = resultSet->GetColumnIndex(columnName, columnIndex);
    if (errCode) {
        MEDIA_ERR_LOG("Get column index errCode: %{public}d", errCode);
        return E_FAIL;
    }
    if (resultSet->GetBlob(columnIndex, blobVal) != NativeRdb::E_OK) {
        return E_FAIL;
    }
    return E_OK;
}

std::string BackupDatabaseUtils::GetLandmarksStr(const std::string &columnName,
    std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    std::vector<uint8_t> blobVal;
    if (GetBlob(columnName, resultSet, blobVal) != E_OK) {
        MEDIA_ERR_LOG("Get blob failed");
        return "";
    }
    return GetLandmarksStr(blobVal);
}

std::string BackupDatabaseUtils::GetLandmarksStr(const std::vector<uint8_t> &bytes)
{
    if (bytes.size() != LANDMARKS_SIZE * XY_DIMENSION * BYTE_LEN) {
        MEDIA_ERR_LOG("Get landmarks bytes size: %{public}zu, not %{public}zu", bytes.size(),
            LANDMARKS_SIZE * XY_DIMENSION * BYTE_LEN);
        return "";
    }
    nlohmann::json landmarksJson;
    for (size_t index = 0; index < bytes.size(); index += XY_DIMENSION * BYTE_LEN) {
        nlohmann::json landmarkJson;
        landmarkJson[LANDMARK_X] = GetUint32ValFromBytes(bytes, index);
        landmarkJson[LANDMARK_Y] = GetUint32ValFromBytes(bytes, index + BYTE_LEN);
        landmarksJson.push_back(landmarkJson);
    }
    return landmarksJson.dump();
}

uint32_t BackupDatabaseUtils::GetUint32ValFromBytes(const std::vector<uint8_t> &bytes, size_t start)
{
    uint32_t uint32Val = 0;
    for (size_t index = 0; index < BYTE_LEN; index++) {
        uint32Val |= static_cast<uint32_t>(bytes[start + index]) << (index * BYTE_BASE_OFFSET);
        uint32Val &= HEX_MAX[index];
    }
    return uint32Val;
}

void BackupDatabaseUtils::UpdateAnalysisTotalStatus(std::shared_ptr<NativeRdb::RdbStore> rdbStore)
{
    std::string updateSql = "UPDATE tab_analysis_total SET face = CASE WHEN EXISTS \
        (SELECT 1 FROM tab_analysis_image_face WHERE tab_analysis_image_face.file_id = tab_analysis_total.file_id \
        AND tag_id = '-1') THEN 2 ELSE 3 END WHERE EXISTS (SELECT 1 FROM tab_analysis_image_face WHERE \
        tab_analysis_image_face.file_id = tab_analysis_total.file_id)";
    int32_t errCode = rdbStore->ExecuteSql(updateSql);
    if (errCode < 0) {
        MEDIA_ERR_LOG("execute update analysis total failed, ret=%{public}d", errCode);
    }
}

void BackupDatabaseUtils::UpdateAnalysisFaceTagStatus(std::shared_ptr<NativeRdb::RdbStore> rdbStore)
{
    std::string updateSql = "UPDATE tab_analysis_face_tag SET count = (SELECT count(1) from tab_analysis_image_face \
        WHERE tab_analysis_image_face.tag_id = tab_analysis_face_tag.tag_id)";
    int32_t errCode = rdbStore->ExecuteSql(updateSql);
    if (errCode < 0) {
        MEDIA_ERR_LOG("execute update analysis face tag count failed, ret=%{public}d", errCode);
    }
}

bool BackupDatabaseUtils::SetTagIdNew(PortraitAlbumInfo &portraitAlbumInfo,
    std::unordered_map<std::string, std::string> &tagIdMap)
{
    portraitAlbumInfo.tagIdNew = TAG_ID_PREFIX + std::to_string(MediaFileUtils::UTCTimeNanoSeconds());
    tagIdMap[portraitAlbumInfo.tagIdOld] = portraitAlbumInfo.tagIdNew;
    return true;
}

bool BackupDatabaseUtils::SetLandmarks(FaceInfo &faceInfo, const std::unordered_map<std::string, FileInfo> &fileInfoMap)
{
    if (faceInfo.hash.empty() || fileInfoMap.count(faceInfo.hash) == 0) {
        MEDIA_ERR_LOG("Set landmarks for face %{public}s failed, no such file hash", faceInfo.faceId.c_str());
        return false;
    }
    FileInfo fileInfo = fileInfoMap.at(faceInfo.hash);
    if (fileInfo.width == 0 || fileInfo.height == 0) {
        MEDIA_ERR_LOG("Set landmarks for face %{public}s failed, invalid width %{public}d or height %{public}d",
            faceInfo.faceId.c_str(), fileInfo.width, fileInfo.height);
        return false;
    }
    float scale = GetLandmarksScale(fileInfo.width, fileInfo.height);
    if (scale == 0) {
        MEDIA_ERR_LOG("Set landmarks for face %{public}s failed, scale = 0", faceInfo.faceId.c_str());
        return false;
    }
    nlohmann::json landmarksJson = nlohmann::json::parse(faceInfo.landmarks, nullptr, false);
    if (landmarksJson.is_discarded()) {
        MEDIA_ERR_LOG("Set landmarks for face %{public}s failed, parse landmarks failed", faceInfo.faceId.c_str());
        return false;
    }
    for (auto &landmark : landmarksJson) {
        if (!landmark.contains(LANDMARK_X) || !landmark.contains(LANDMARK_Y)) {
            MEDIA_ERR_LOG("Set landmarks for face %{public}s failed, lack of x or y", faceInfo.faceId.c_str());
            return false;
        }
        landmark[LANDMARK_X] = static_cast<float>(landmark[LANDMARK_X]) / fileInfo.width / scale;
        landmark[LANDMARK_Y] = static_cast<float>(landmark[LANDMARK_Y]) / fileInfo.height / scale;
        if (IsLandmarkValid(faceInfo, landmark[LANDMARK_X], landmark[LANDMARK_Y])) {
            continue;
        }
        MEDIA_WARN_LOG("Given landmark may be invalid, (%{public}f, %{public}f), rect TL: (%{public}f, %{public}f), "
            "rect BR: (%{public}f, %{public}f)", static_cast<float>(landmark[LANDMARK_X]),
            static_cast<float>(landmark[LANDMARK_Y]), faceInfo.scaleX, faceInfo.scaleY,
            faceInfo.scaleX + faceInfo.scaleWidth, faceInfo.scaleY + faceInfo.scaleHeight);
    }
    faceInfo.landmarks = landmarksJson.dump();
    return true;
}

bool BackupDatabaseUtils::SetFileIdNew(FaceInfo &faceInfo, const std::unordered_map<std::string, FileInfo> &fileInfoMap)
{
    if (faceInfo.hash.empty() || fileInfoMap.count(faceInfo.hash) == 0) {
        MEDIA_ERR_LOG("Set new file_id for face %{public}s failed, no such file hash", faceInfo.faceId.c_str());
        return false;
    }
    faceInfo.fileIdNew = fileInfoMap.at(faceInfo.hash).fileIdNew;
    if (faceInfo.fileIdNew <= 0) {
        MEDIA_ERR_LOG("Set new file_id for face %{public}s failed, file_id %{public}d <= 0", faceInfo.faceId.c_str(),
            faceInfo.fileIdNew);
        return false;
    }
    return true;
}

bool BackupDatabaseUtils::SetTagIdNew(FaceInfo &faceInfo, const std::unordered_map<std::string, std::string> &tagIdMap)
{
    if (faceInfo.tagIdOld.empty()) {
        MEDIA_ERR_LOG("Set new tag_id for face %{public}s failed, empty tag_id", faceInfo.faceId.c_str());
        return false;
    }
    if (tagIdMap.count(faceInfo.tagIdOld) == 0) {
        faceInfo.tagIdNew = TAG_ID_UNPROCESSED;
        return true;
    }
    faceInfo.tagIdNew = tagIdMap.at(faceInfo.tagIdOld);
    if (faceInfo.tagIdNew.empty() || !MediaFileUtils::StartsWith(faceInfo.tagIdNew, TAG_ID_PREFIX)) {
        MEDIA_ERR_LOG("Set new tag_id for face %{public}s failed, new tag_id %{public}s empty or invalid",
            faceInfo.tagIdNew.c_str(), faceInfo.faceId.c_str());
        return false;
    }
    return true;
}

bool BackupDatabaseUtils::SetAlbumIdNew(FaceInfo &faceInfo, const std::unordered_map<std::string, int32_t> &albumIdMap)
{
    if (faceInfo.tagIdNew == TAG_ID_UNPROCESSED) {
        return true;
    }
    if (albumIdMap.count(faceInfo.tagIdNew) == 0) {
        MEDIA_ERR_LOG("Set new album_id for face %{public}s failed, no such tag_id", faceInfo.faceId.c_str());
        return false;
    }
    faceInfo.albumIdNew = albumIdMap.at(faceInfo.tagIdNew);
    if (faceInfo.albumIdNew <= 0) {
        MEDIA_ERR_LOG("Set new album_id for face %{public}s failed, album_id %{public}d <= 0", faceInfo.faceId.c_str(),
            faceInfo.albumIdNew);
        return false;
    }
    return true;
}

void BackupDatabaseUtils::PrintErrorLog(const std::string &errorLog, int64_t start)
{
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("%{public}s, cost %{public}ld", errorLog.c_str(), (long)(end - start));
}

float BackupDatabaseUtils::GetLandmarksScale(int32_t width, int32_t height)
{
    float scale = 1;
    int32_t minWidthHeight = width <= height ? width : height;
    if (minWidthHeight >= SCALE_MIN_SIZE * SCALE_FACTOR) {
        minWidthHeight = static_cast<int32_t>(minWidthHeight * SCALE_DEFAULT);
        scale = SCALE_DEFAULT;
        if (minWidthHeight < SCALE_MIN_SIZE) {
            minWidthHeight *= SCALE_FACTOR;
            scale *= SCALE_FACTOR;
        }
        if (minWidthHeight < SCALE_MIN_SIZE) {
            scale = 1;
        }
    }
    width = static_cast<int32_t>(width * scale);
    height = static_cast<int32_t>(height * scale);
    int32_t maxWidthHeight = width >= height ? width : height;
    scale *= maxWidthHeight >= SCALE_MAX_SIZE ? static_cast<float>(SCALE_MAX_SIZE) / maxWidthHeight : 1;
    return scale;
}

bool BackupDatabaseUtils::IsLandmarkValid(const FaceInfo &faceInfo, float landmarkX, float landmarkY)
{
    return IsValInBound(landmarkX, faceInfo.scaleX, faceInfo.scaleX + faceInfo.scaleWidth) &&
        IsValInBound(landmarkY, faceInfo.scaleY, faceInfo.scaleY + faceInfo.scaleHeight);
}

bool BackupDatabaseUtils::IsValInBound(float val, float minVal, float maxVal)
{
    return val >= minVal && val <= maxVal;
}

void BackupDatabaseUtils::UpdateGroupTag(std::shared_ptr<NativeRdb::RdbStore> rdbStore,
    const std::unordered_map<std::string, std::string> &groupTagMap)
{
    static std::string UPDATE_SQL_START = "UPDATE AnalysisAlbum SET group_tag = CASE ";
    static std::string UPDATE_SQL_END = " END ";
    auto it = groupTagMap.begin();
    while (it != groupTagMap.end()) {
        std::string updateCase;
        int32_t offset = 0;
        while (offset < UPDATE_COUNT && it != groupTagMap.end()) {
            updateCase += " WHEN group_tag = '" + it->first + "' THEN '" + it->second + "'";
            offset++;
            it++;
        }
        if (updateCase.empty()) {
            break;
        }
        std::string updateSql = UPDATE_SQL_START + updateCase + UPDATE_SQL_END;
        int32_t errCode = rdbStore->ExecuteSql(updateSql);
        if (errCode < 0) {
            MEDIA_ERR_LOG("execute update group tag failed, ret=%{public}d", errCode);
        }
    }
}
} // namespace Media
} // namespace OHOS