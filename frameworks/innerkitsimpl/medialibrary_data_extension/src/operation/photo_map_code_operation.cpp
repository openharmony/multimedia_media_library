/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "PhotoMapCodeOperation"

#include "photo_map_code_column.h"
#include "photo_map_code_operation.h"
#include "media_log.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_rdbstore.h"
#include "directory_ex.h"
#include "media_log.h"
#include "medialibrary_type_const.h"
#include "abs_rdb_predicates.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
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
#include "cloud_media_dao_const.h"
#include "media_gallery_sync_notify.h"
#include "cloud_media_sync_const.h"
#include "cloud_media_dao_utils.h"
#include "base_column.h"
#include "medialibrary_data_manager_utils.h"

#include "cpu_utils.h"
#include <cerrno>
#include <fstream>
#include <iostream>
#include <bitset>
#include <string>
#include <cmath>

namespace OHOS {
namespace Media {
using namespace std;
const int32_t COUNT_INDEX = 0;
const int32_t MIN_INDEX = 1;
const int32_t MAX_INDEX = 2;
const int32_t POINT_SIZE = 2;
const int FAST_COUNT = 30000;

const int PhotoMapCodeOperation::LEVEL_START = 20;
const int PhotoMapCodeOperation::LEVEL_COUNT = 21;
const int PhotoMapCodeOperation::STEP_COUNT = 10;
const int PhotoMapCodeOperation::STEP_LEVEL = 20;

static constexpr double DOUBLE_EPSILON = 1e-15;
static constexpr double MAX_LATITUDE_EPSILON = 1e-15 + 90.0;
static constexpr double MAX_LONGITUDE_EPSILON = 1e-15 + 180.0;

int32_t PhotoMapCodeOperation::ExecSqlWithRetry(std::function<int32_t()> execSql)
{
    int32_t currentTime{0};
    int32_t err = NativeRdb::E_OK;
    while (currentTime < MAX_TRY_TIMES) {
        err = execSql();
        if (err == NativeRdb::E_OK) {
            break;
        } else if (err == NativeRdb::E_SQLITE_LOCKED || err == NativeRdb::E_DATABASE_BUSY ||
            err == NativeRdb::E_SQLITE_BUSY) {
            std::this_thread::sleep_for(std::chrono::milliseconds(TRANSACTION_WAIT_INTERVAL));
            currentTime++;
            MEDIA_ERR_LOG("PhotoMapCodeOperation::ExecSqlWithRetry execSql busy, err: %{public}d, \
                currentTime: %{public}d", err, currentTime);
        } else {
            MEDIA_ERR_LOG("PhotoMapCodeOperation::ExecSqlWithRetry execSql failed, err: %{public}d, \
                currentTime: %{public}d", err, currentTime);
            break;
        }
    }
    return err;
}

int32_t PhotoMapCodeOperation::InsertPhotosMapCodes(const std::vector<PhotoMapData> &photoMapDatas,
    const std::shared_ptr<NativeRdb::RdbStore> cloneLibraryRdb)
{
    vector<NativeRdb::ValuesBucket> mapValues;
    int64_t rowNum{0};
    for (const auto &photoMapData : photoMapDatas) {
        double longitude = photoMapData.longitude;
        double latitude = photoMapData.latitude;
        int32_t fileId = photoMapData.fileId;
        NativeRdb::ValuesBucket mapValue;
        if (fileId > 0 && fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
            fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
            mapValue.PutInt(PhotoMapCodeColumn::MAPCODE_FILE_ID, fileId);
            PhotoMapCodeOperation::GetPhotoMapCode(mapValue, latitude, longitude);
            mapValues.emplace_back(mapValue);
        }
    }

    // 地图数据入库
    MEDIA_DEBUG_LOG("RestoreMapCodeUtils::InsertPhotosMapCodes mapValues size %{public}zu \
        photoMapDatas size %{public}zu", mapValues.size(), photoMapDatas.size());
    if (mapValues.empty()) {
        MEDIA_INFO_LOG("RestoreMapCodeUtils::InsertPhotosMapCodes mapValues.empty");
        return E_OK;
    }

    int32_t ret = E_RDB;
    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore) {
        ret = ExecSqlWithRetry([&]() {
            return rdbStore->BatchInsert(rowNum, PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE, mapValues);
        });
        MEDIA_INFO_LOG("RestoreMapCodeUtils::InsertPhotosMapCodes BatchInsert rdbStore ret %{public}d", ret);
    } else if (cloneLibraryRdb) {
        ret = ExecSqlWithRetry([&]() {
            return cloneLibraryRdb->BatchInsert(rowNum, PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE, mapValues);
        });
        MEDIA_INFO_LOG("RestoreMapCodeUtils::InsertPhotosMapCodes BatchInsert cloneLibraryRdb ret %{public}d", ret);
    } else {
        MEDIA_ERR_LOG("RestoreMapCodeUtils::InsertPhotosMapCodes BatchInsert rdbStore & cloneLibraryRdb both \
            null ret %{public}d", ret);
    }

    return ret;
}

int32_t PhotoMapCodeOperation::GetPhotosMapCodesMRS(const std::vector<PhotoMapData> &photoMapDatas,
    const std::shared_ptr<MediaLibraryRdbStore> store)
{
    vector<NativeRdb::ValuesBucket> mapValues;
    int64_t rowNum{0};
    for (const auto &photoMapData : photoMapDatas) {
        double longitude = photoMapData.longitude;
        double latitude = photoMapData.latitude;
        int32_t fileId = photoMapData.fileId;
        NativeRdb::ValuesBucket mapValue;
        if (fileId > 0 && fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
            fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
            mapValue.PutInt(PhotoMapCodeColumn::MAPCODE_FILE_ID, fileId);
            PhotoMapCodeOperation::GetPhotoMapCode(mapValue, latitude, longitude);
            mapValues.emplace_back(mapValue);
        }
    }

    // 地图数据入库
    MEDIA_DEBUG_LOG("RestoreMapCodeUtils::GetPhotosMapCodesMRS mapValues size %{public}zu \
        photoMapDatas size %{public}zu", mapValues.size(), photoMapDatas.size());
    if (mapValues.empty()) {
        MEDIA_INFO_LOG("RestoreMapCodeUtils::GetPhotosMapCodesMRS mapValues.empty");
        return E_OK;
    }

    int32_t ret = E_RDB;
    if (store) {
        ret = ExecSqlWithRetry([&]() {
            return store->BatchInsert(rowNum, PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE, mapValues);
        });
        MEDIA_INFO_LOG("RestoreMapCodeUtils::GetPhotosMapCodesMRS BatchInsert rdbStore ret %{public}d", ret);
    } else {
        MEDIA_ERR_LOG("RestoreMapCodeUtils::GetPhotosMapCodesMRS BatchInsert rdbStore both \
            null ret %{public}d", ret);
    }

    return ret;
}

int32_t PhotoMapCodeOperation::GetPhotoMapCode(const PhotoMapData &photoMapData, const PhotoMapType &photoMapType)
{
    if (photoMapData.fileId <= 0) {
        MEDIA_INFO_LOG("PhotoMapCodeOperation::GetPhotoMapCode failed fileId is zero");
        return E_OK;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (!rdbStore) {
        MEDIA_ERR_LOG("PhotoMapCodeOperation::GetPhotoMapCode failed rdbStore is null");
        return E_ERR;
    }

    int32_t fileId = photoMapData.fileId;
    if (photoMapType == PhotoMapType::QUERY_AND_INSERT) {
        const std::string QUERY_MAP_CODE_INFO = "SELECT file_id, cell_20 FROM " +
            PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE +
            " WHERE " + PhotoMapCodeColumn::MAPCODE_FILE_ID + " = " + to_string(fileId);
        shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(QUERY_MAP_CODE_INFO);
        int rowCount{-1};
        if (resultSet && resultSet->GetRowCount(rowCount) == NativeRdb::E_OK && rowCount > 0 &&
            resultSet->GoToFirstRow() == NativeRdb::E_OK) {
            MEDIA_ERR_LOG("GetPhotoMapCode success. Query MapCode info in table");
            resultSet->Close();
            return E_OK;
        }
        if (resultSet) {
            resultSet->Close();
        }
    }
    NativeRdb::ValuesBucket mapValue;
    PhotoMapCodeOperation::GetPhotoMapCode(mapValue, photoMapData.latitude, photoMapData.longitude);
    int32_t updateMapCount{0};
    std::string whereMapClause = PhotoMapCodeColumn::MAPCODE_FILE_ID + " = ?";
    std::vector<std::string> whereMapArgs = { to_string(fileId) };
    std::string mapTableName = PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE;
    int32_t result{-1};
    if (photoMapType == PhotoMapType::UPDATE_AND_INSERT) {
        result = rdbStore->Update(updateMapCount, mapTableName, mapValue, whereMapClause, whereMapArgs);
        MEDIA_INFO_LOG("GetPhotoMapCode Update result %{public}d updateMapCount %{public}d", result, updateMapCount);
    }
    if (result != NativeRdb::E_OK || updateMapCount == 0) {
        int64_t insertMapCount{-1};
        mapValue.PutInt(PhotoMapCodeColumn::MAPCODE_FILE_ID, fileId);
        result = rdbStore->Insert(insertMapCount, mapTableName,  mapValue);
        MEDIA_INFO_LOG("GetPhotoMapCode Insert result %{public}d \
            insertMapCount %{public}" PRId64, result, insertMapCount);
        if (result < 0 || insertMapCount <= 0) {
            MEDIA_ERR_LOG("GetPhotoMapCode Ineset failed");
        }
    }
    return result;
}

void PhotoMapCodeOperation::GetPhotoMapCode(NativeRdb::ValuesBucket &mapValue, double lat, double lon)
{
    std::vector<double> latAndlon = SetPoint(lat, lon);
    for (int level = LEVEL_START; level < LEVEL_COUNT; level++) {
        int64_t mapCode = GetMapCode(latAndlon, level);
        mapValue.PutLong("cell_" + std::to_string(level) + "int", mapCode);
    }
}

int32_t PhotoMapCodeOperation::UpgradePhotoMapCode(const std::shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("PhotoMapCodeOperation::UpgradePhotoMapCode");
    if (!store) {
        MEDIA_ERR_LOG("UpgradePhotoMapCode failed. store is nullptr");
        return E_ERR;
    }

    int32_t startFileId{0};
    int32_t ret{-1};
    // 获取当前数据状态
    const std::string sqlDataCounts = "SELECT COUNT(*) AS count, MIN(file_id) AS min_id, MAX(file_id) AS max_id FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE " + PhotoColumn::MEDIA_ID + " > " + to_string(startFileId) + " AND " +
        PhotoColumn::PHOTO_LATITUDE + " <> 0 AND " + PhotoColumn::PHOTO_LONGITUDE + " <> 0";
    shared_ptr<NativeRdb::ResultSet> resultSet = store->QuerySql(sqlDataCounts);
    int32_t rowCount{0};
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("UpgradePhotoMapCode Failed to query data resultSet nullptr");
        return E_ERR;
    }

    if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK ||
        rowCount == 0 || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("UpgradePhotoMapCode Failed to query data rowCount %{public}d", rowCount);
        resultSet->Close();
        return E_OK;
    }

    int count{-1};
    resultSet->GetInt(COUNT_INDEX, count);
    int minId{-1};
    resultSet->GetInt(MIN_INDEX, minId);
    int maxId{-1};
    resultSet->GetInt(MAX_INDEX, maxId);
    MEDIA_INFO_LOG("PhotoMapCodeOperation::UpgradePhotoMapCode count %{public}d", count);
    resultSet->Close();
    ret = DatasToMapCodes(store, count, minId, maxId);
    return ret;
}


vector<std::string> PhotoMapCodeOperation::FilterFileIds(const vector<std::string> &fileIds)
{
    MEDIA_INFO_LOG("PhotoMapCodeOperation::FilterFileIds fileIds size %{public}zu", fileIds.size());
    // 过滤出所有符合fileId格式的数据
    vector<std::string> filterFiles;
    for (auto it = fileIds.begin(); it != fileIds.end();) {
        std::string fileId = (*it);
        if (MediaLibraryDataManagerUtils::IsNumber(fileId)) {
            filterFiles.push_back(fileId);
        }
        ++it;
    }

    return filterFiles;
}

int32_t PhotoMapCodeOperation::RemovePhotosMapCodes(const std::vector<string> &fileIds)
{
    vector<std::string> filterFiles = FilterFileIds(fileIds);
    if (filterFiles.empty()) {
        MEDIA_ERR_LOG("PhotoMapCodeOperation::RemovePhotosMapCodes filterFiles is empty");
        return E_OK;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (!rdbStore) {
        MEDIA_ERR_LOG("PhotoMapCodeOperation::RemovePhotosMapCodes rdbStore is null");
        return E_ERR;
    }

    std::string mapTableName = PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE;
    NativeRdb::RdbPredicates rdbPredicate(mapTableName);
    rdbPredicate.In(PhotoMapCodeColumn::MAPCODE_FILE_ID, filterFiles);
    int32_t rows = 0;
    int32_t ret = rdbStore->Delete(rows, rdbPredicate);
    return ret >= 0 ? E_OK : E_ERR;
}

int32_t PhotoMapCodeOperation::GetPhotosPoByInputValues(const std::vector<std::string> &inputValues,
    std::vector<Media::ORM::PhotosPo> &photosPos, const std::vector<std::string> &getValues)
{
    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (!rdbStore) {
        MEDIA_ERR_LOG("PhotoMapCodeOperation::GetPhotosPoByInputValues rdbStore is null");
        return E_ERR;
    }
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(PhotoColumn::PHOTO_CLOUD_ID, static_cast<std::vector<std::string>>(inputValues));
    predicates.OrderByDesc(PhotoColumn::PHOTO_CLOUD_ID);
    predicates.Limit(inputValues.size());
    auto resultSet = rdbStore->Query(predicates, getValues);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_RESULT_SET_NULL, "DeleteMapCodesByPullDatas Failed to query.");

    int32_t ret = Media::ORM::ResultSetReader<Media::ORM::PhotosPoWriter,
        Media::ORM::PhotosPo>(resultSet).ReadRecords(photosPos);
    MEDIA_DEBUG_LOG("GetPhotosPoByInputValues photosPos size %{public}zu", photosPos.size());
    return ret;
}

int32_t PhotoMapCodeOperation::DatasToMapCodesBySetpLevel(const std::shared_ptr<MediaLibraryRdbStore> store,
    int32_t &i, int32_t endIndex, int32_t &deailCount, int stepLevel)
{
    while (i <= endIndex) {
        std::vector<PhotoMapData> photoMapDatas;
        const std::string sqlUpgradeData = "SELECT file_id, latitude, longitude FROM " +
            PhotoColumn::PHOTOS_TABLE + " WHERE " + PhotoColumn::MEDIA_ID + " > " + to_string(i) + " AND " +
            PhotoColumn::PHOTO_LATITUDE + " <> 0 AND " + PhotoColumn::PHOTO_LONGITUDE + " <> 0 " +
                " ORDER BY " + PhotoColumn::MEDIA_ID + " ASC " + " LIMIT " + to_string(STEP_COUNT * stepLevel);

        shared_ptr<NativeRdb::ResultSet> resultSet = store->QuerySql(sqlUpgradeData);
        int rowCount{-1};
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("PhotoMapCodeOperation::DatasToMapCodesBySetpLevel resultSet nullptr");
            return E_ERR;
        }
        if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK || rowCount == 0 ||
            resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("PhotoMapCodeOperation::DatasToMapCodesBySetpLevel Data Empty rowCount %{public}d",
                rowCount);
            resultSet->Close();
            return E_ERR;
        }
        std::vector<Media::ORM::PhotosPo> photosPos;
        Media::ORM::ResultSetReader<Media::ORM::PhotosPoWriter, Media::ORM::PhotosPo>(resultSet).ReadRecords(photosPos);
        resultSet->Close();
        if (photosPos.empty()) {
            i++;
            continue;
        }
        for (const auto &photoPo : photosPos) {
            if (!(photoPo.longitude.has_value() && photoPo.latitude.has_value() && photoPo.fileId.has_value())) {
                i++;
                continue;
            }
            double longitude = photoPo.longitude.value();
            double latitude = photoPo.latitude.value();
            int32_t fileId = photoPo.fileId.value();
            if (fileId > i) {
                i = fileId;
                deailCount++;
            }
            if (fileId > 0 && fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
                fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
                PhotoMapData photoMapData(fileId, latitude, longitude);
                photoMapDatas.emplace_back(photoMapData);
            }
        }
        MEDIA_DEBUG_LOG("UpgradePhotoMapCode photoMapDatas size %{public}zu", photoMapDatas.size());
        GetPhotosMapCodesMRS(photoMapDatas, store);
    }
    return E_OK;
}

int32_t PhotoMapCodeOperation::DatasToMapCodes(const std::shared_ptr<MediaLibraryRdbStore> store,
    const int count, const int32_t minId, const int32_t maxId)
{
    MEDIA_INFO_LOG("PhotoMapCodeOperation::DatasToMapCodes start");
    int32_t ret{-1};
    int32_t deailCount{0};
    for (int32_t i = minId - 1; i <= maxId;) {
        if (deailCount <= std::min(FAST_COUNT, count)) {
            int32_t endIndex = i;
            ret = DatasToMapCodesBySetpLevel(store, i, endIndex, deailCount, STEP_LEVEL);
            if (ret != E_OK) {
                MEDIA_INFO_LOG("DatasToMapCodes less than FAST_COUNT count: %{public}d", count);
                return ret;
            }
        } else {
            CpuAffinityType cpuAffinityType = CpuAffinityType::CPU_IDX_3;
            Media::CpuUtils::SetSelfThreadAffinity(cpuAffinityType);
            ret = DatasToMapCodesBySetpLevel(store, i, maxId, deailCount, 1);
            Media::CpuUtils::ResetSelfThreadAffinity();
            MEDIA_INFO_LOG("DatasToMapCodes more than FAST_COUNT count: %{public}d", count);
            return ret;
        }
    }
    MEDIA_INFO_LOG("PhotoMapCodeOperation::DatasToMapCodes End");
    return ret;
}

std::vector<double> PhotoMapCodeOperation::SetPoint(double lat, double lon)
{
    std::vector<double> latAndlon;
    latAndlon.push_back(lat);
    latAndlon.push_back(lon);
    return latAndlon;
}

int64_t PhotoMapCodeOperation::GetMapCode(std::vector<double> &latAndLon, int level)
{
    if (latAndLon.size() < POINT_SIZE) {
        return 0;
    }
    double lat = latAndLon[0];
    double lon = latAndLon[1];
    MEDIA_DEBUG_LOG("PhotoMapCodeOperation::GetMapCode level %{public}d", level);
    return PhotoMapCodeOperation::GetMapHilbertCode(lat, lon, level);
}

int64_t PhotoMapCodeOperation::GetMapHilbertCode(double lat, double lon, int level)
{
    double latPercent = (lat + 90) / 180.0;
    double lonPercent = (lon + 180) / 360.0;
    int64_t maxCoord = std::pow(2, std::floor(level));
    MEDIA_DEBUG_LOG("PhotoMapCodeOperation::GetMapHilbertCode latPercent %{public}f, \
        lonPercent %{public}f maxCoord %{public}" PRId64, latPercent, lonPercent, maxCoord);

    int64_t latPosition  = std::floor(latPercent * maxCoord) == maxCoord ?
        std::floor(latPercent * maxCoord) - 1 : std::floor(latPercent * maxCoord);
    int64_t lonPosition = std::floor(lonPercent * maxCoord) == maxCoord ?
        std::floor(lonPercent * maxCoord) - 1 : std::floor(lonPercent * maxCoord);
    MEDIA_DEBUG_LOG("QXY PhotoMapCodeOperation::GetMapHilbertCode latPosition %{public}" PRId64
        ", lonPosition %{public}" PRId64, latPosition, lonPosition);

    return PhotoMapCodeOperation::DistanceFromPoint(latPosition, lonPosition, std::floor(level));
}

std::string PhotoMapCodeOperation::Int64ToBinaryWithPadding(int64_t num, int width)
{
    MEDIA_DEBUG_LOG("PhotoMapCodeOperation::Int64ToBinaryWithPadding num %{public}" PRId64
        ", width %{public}d", num, width);
    std::string binary = std::bitset<64>(num).to_string();
    MEDIA_DEBUG_LOG("PhotoMapCodeOperation::Int64ToBinaryWithPadding binary %{public}s", binary.c_str());

    binary.erase(0, binary.find_first_not_of('0'));
    if (binary.empty()) {
        binary = "0";
    }

    if (binary.length() < width) {
        binary = std::string(width - static_cast<int>(binary.length()), '0') + binary;
    }
    MEDIA_DEBUG_LOG("PhotoMapCodeOperation::Int64ToBinaryWithPadding binary %{public}s", binary.c_str());
    return binary;
}

void PhotoMapCodeOperation::UpdateZoomLevelStep(int64_t zoomLevel, std::vector<int64_t> &point)
{
    int64_t zoomLevelStep = zoomLevel;
    while (zoomLevelStep > 1) {
        int64_t zoomLevelCurrentValue = zoomLevelStep - 1;
        for (size_t i = 0; i < point.size(); i++) {
            if (point[i] & zoomLevelStep) {
                point[0] ^= zoomLevelCurrentValue;
            } else {
                int64_t flagValue = (point[0] ^ point[i]) & zoomLevelCurrentValue;
                point[0] ^= flagValue;
                point[i] ^= flagValue;
            }
        }
        zoomLevelStep >>= 1;
    }
    for (size_t i = 1; i < point.size(); i++) {
        point[i] ^= point[i - 1];
    }

    int64_t valueStep = 0;
    zoomLevelStep = zoomLevel;
    while (zoomLevelStep > 1) {
        if (point[point.size() - 1] & zoomLevelStep) {
            valueStep ^= zoomLevelStep - 1;
        }
        zoomLevelStep >>= 1;
    }

    for (size_t i = 0; i < point.size(); i++) {
        point[i] ^= valueStep;
    }
}

int64_t PhotoMapCodeOperation::DistanceFromPoint(int64_t latPosition, int64_t lonPosition, int level)
{
    MEDIA_DEBUG_LOG("PhotoMapCodeOperation::DistanceFromPoint latPosition %{public}" PRId64
        ", lonPosition %{public}" PRId64 " level %{public}d", latPosition, lonPosition, level);
    int64_t zoomLevel = 1 << (level - 1);
    std::vector<int64_t> point = {latPosition, lonPosition};

    UpdateZoomLevelStep(zoomLevel, point);

    std::vector<std::string> xBitStr;
    for (size_t i = 0; i < point.size(); i++) {
        int64_t value = point[i];
        std::string binaryStr = Int64ToBinaryWithPadding(value, level);
        xBitStr.push_back(binaryStr);
    }
    std::string codeStrCode = "";
    for (int i = 0; i < level; i++) {
        for (size_t y = 0; y < xBitStr.size(); y++) {
            codeStrCode += xBitStr[y][i];
        }
    }
    MEDIA_DEBUG_LOG("PhotoMapCodeOperation::DistanceFromPoint codeStrCode is %{public}s", codeStrCode.c_str());

    int64_t hilbertCode = std::bitset<64>(codeStrCode).to_ullong();
    MEDIA_DEBUG_LOG("PhotoMapCodeOperation::DistanceFromPoint hilbertCode is %{public}" PRId64, hilbertCode);

    return hilbertCode;
}
} // namespace Media
} // namespace OHOS
