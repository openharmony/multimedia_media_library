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
#define CLOUD_MAP_LOG_TAG "CloudMapCode"

#include "cloud_map_code_dao.h"

namespace OHOS {
namespace Media {
using namespace std;
static constexpr double DOUBLE_EPSILON = 1e-15;
static constexpr double MAX_LATITUDE_EPSILON = 1e-15 + 90.0;
static constexpr double MAX_LONGITUDE_EPSILON = 1e-15 + 180.0;

int32_t CloudMapCodeDao::InsertDatasToMapCode(std::vector<CloudSync::CloudMediaPullDataDto> &pullDatas)
{
    MEDIA_INFO_LOG("CloudMapCodeDao::InsertDatasToMapCode");
    if (pullDatas.empty()) {
        return 0;
    }

    const std::vector<std::string> COLUMNS_QUERY = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::PHOTO_LATITUDE,
        PhotoColumn::PHOTO_LONGITUDE,
    };
    std::vector<Media::ORM::PhotosPo> photosPos;

    CloudMapCodeDao::GetPhotosPoByPullDatas(pullDatas, photosPos, COLUMNS_QUERY);

    vector<PhotoMapData> photoMapDatas;
    for (const auto &photoPo : photosPos) {
        if (!(photoPo.longitude.has_value() && photoPo.latitude.has_value() && photoPo.fileId.has_value())) {
            MEDIA_DEBUG_LOG("CloudMapCodeDao::InsertDatasToMapCode photosPos is null");
            continue;
        }

        double longitude = photoPo.longitude.value();
        double latitude = photoPo.latitude.value();
        int32_t fileId = photoPo.fileId.value();
        if (fileId > 0 && fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
            fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
            PhotoMapData photoMapData(fileId, latitude, longitude);
            photoMapDatas.emplace_back(photoMapData);
        }
    }

    return PhotoMapCodeOperation::InsertPhotosMapCodes(photoMapDatas, nullptr);
}

int32_t CloudMapCodeDao::UpdateDataToMapCode(const CloudSync::CloudMediaPullDataDto &pullData)
{
    MEDIA_INFO_LOG("CloudMapCodeDao::UpdateDataToMapCode");
    const std::vector<std::string> COLUMNS_QUERY = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::PHOTO_LATITUDE,
        PhotoColumn::PHOTO_LONGITUDE,
    };
    std::vector<Media::ORM::PhotosPo> photosPos;

    CloudMapCodeDao::GetPhotosPoByPullData(pullData, photosPos, COLUMNS_QUERY);
    if (photosPos.empty()) {
        MEDIA_INFO_LOG("UpdateDataToMapCode photoPo is empty");
        return E_OK;
    }
    Media::ORM::PhotosPo photoPo = photosPos[0];
    if (!(photoPo.longitude.has_value() && photoPo.latitude.has_value() && photoPo.fileId.has_value())) {
        MEDIA_ERR_LOG("UpdateDataToMapCode photoPo is null");
        return E_OK;
    }
    double longitude = photoPo.longitude.value();
    double latitude = photoPo.latitude.value();
    int32_t fileId = photoPo.fileId.value();
    MEDIA_DEBUG_LOG("CloudMapCodeDao::UpdateDataToMapCode photosPos fileId longitude latitude");
    NativeRdb::ValuesBucket mapValue;
    if (fileId > 0 && fabs(longitude) > DOUBLE_EPSILON && fabs(latitude) > DOUBLE_EPSILON &&
        fabs(longitude) < MAX_LONGITUDE_EPSILON && fabs(latitude) < MAX_LATITUDE_EPSILON) {
        PhotoMapData photoMapData(fileId, latitude, longitude);
        return PhotoMapCodeOperation::GetPhotoMapCode(photoMapData, PhotoMapType::UPDATE_AND_INSERT);
    }
    MEDIA_INFO_LOG("CloudMapCodeDao::UpdateDataToMapCode end");
    return NativeRdb::E_OK;
}

int32_t CloudMapCodeDao::DeleteMapCodesByPullDatas(std::vector<CloudSync::CloudMediaPullDataDto> &pullDatas)
{
    MEDIA_INFO_LOG("CloudMapCodeDao::DeleteMapCodesByPullDatas");
    if (pullDatas.empty()) {
        return E_OK;
    }
    std::vector<Media::ORM::PhotosPo> photosPos;
    const std::vector<std::string> COLUMNS_QUERY = {
        PhotoColumn::MEDIA_ID,
    };

    CloudMapCodeDao::GetPhotosPoByPullDatas(pullDatas, photosPos, COLUMNS_QUERY);

    if (photosPos.empty()) {
        MEDIA_INFO_LOG("DeleteMapCodesByPullDatas photosPos size equals to 0");
        return E_OK;
    }

    vector<string> fileIds;
    for (const auto &photoPo : photosPos) {
        if (!(photoPo.fileId)) {
            MEDIA_DEBUG_LOG("DeleteMapCodesByPullDatas photosPos is null");
            continue;
        }

        int32_t fileId = photoPo.fileId.value();
        MEDIA_DEBUG_LOG("DeleteMapCodesByPullDatas photosPos fileId %{private}d", fileId);
        fileIds.push_back(std::to_string(fileId));
    }

    int32_t ret = PhotoMapCodeOperation::RemovePhotosMapCodes(fileIds);
    MEDIA_INFO_LOG("DeleteMapCodesByPullDatas ret is %{public}d", ret);
    return ret;
}

int32_t CloudMapCodeDao::DeleteMapCodesByPullData(const CloudSync::CloudMediaPullDataDto &pullData)
{
    MEDIA_INFO_LOG("CloudMapCodeDao::DeleteMapCodesByPullData");

    std::vector<Media::ORM::PhotosPo> photosPos;
    const std::vector<std::string> COLUMNS_QUERY = {
        PhotoColumn::MEDIA_ID,
    };

    CloudMapCodeDao::GetPhotosPoByPullData(pullData, photosPos, COLUMNS_QUERY);

    if (photosPos.empty()) {
        MEDIA_ERR_LOG("DeleteMapCodesByPullData to-deleted idList size equals to 0");
        return E_OK;
    }

    vector<string> fileIds;
    for (const auto &photoPo : photosPos) {
        if (!(photoPo.fileId)) {
            MEDIA_DEBUG_LOG("DeleteMapCodesByPullData photosPos is null");
            continue;
        }

        int32_t fileId = photoPo.fileId.value();
        MEDIA_DEBUG_LOG("DeleteMapCodesByPullData photosPos fileId %{private}d", fileId);
        fileIds.push_back(std::to_string(fileId));
    }

    int32_t ret = PhotoMapCodeOperation::RemovePhotosMapCodes(fileIds);
    MEDIA_INFO_LOG("DeleteMapCodesByPullData ret is %{public}d", ret);
    return ret;
}

int32_t CloudMapCodeDao::GetPhotosPoByPullDatas(std::vector<CloudSync::CloudMediaPullDataDto> &pullDatas,
    std::vector<Media::ORM::PhotosPo> &photosPos, const std::vector<std::string> &getValues)
{
    std::vector<string> cloudIds;
    for (auto mergeData = pullDatas.begin(); mergeData != pullDatas.end();) {
        std::string cloudId = mergeData->cloudId;
        cloudIds.push_back(cloudId);
        mergeData++;
    }

    int32_t ret = PhotoMapCodeOperation::GetPhotosPoByInputValues(cloudIds, photosPos, getValues);
    return ret;
}

int32_t CloudMapCodeDao::GetPhotosPoByPullData(const CloudSync::CloudMediaPullDataDto &pullData,
    std::vector<Media::ORM::PhotosPo> &photosPos, const std::vector<std::string> &getValues)
{
    std::vector<string> cloudIds;
    cloudIds.push_back(pullData.cloudId);

    int32_t ret = PhotoMapCodeOperation::GetPhotosPoByInputValues(cloudIds, photosPos, getValues);
    return ret;
}
} // namespace Media
} // namespace OHOS