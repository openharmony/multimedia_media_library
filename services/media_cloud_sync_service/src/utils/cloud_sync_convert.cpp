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

#define MLOG_TAG "Media_Cloud_Utils"

#include "cloud_sync_convert.h"

#include <string>
#include <vector>
#include <regex>
#include <unistd.h>
#include <sys/stat.h>
#include <charconv>

#include "cloud_media_photos_service.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS::Media::CloudSync {
const int32_t FIRST_MATCH_PARAM = 1;
const int32_t SECOND_MATCH_PARAM = 2;

constexpr size_t DEFAULT_TIME_SIZE = 32;
static bool convertToLong(const std::string &str, int64_t &value)
{
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    return ec == std::errc{} && ptr == str.data() + str.size();
}

int32_t CloudSyncConvert::CompensateAttTitle(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string title = data.attributesTitle;
    CHECK_AND_RETURN_RET_WARN_LOG(!title.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::title.");
    values.PutString(PhotoColumn::MEDIA_TITLE, title);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttMediaType(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t mediaType = data.attributesMediaType;
    if (mediaType == -1) {
        mediaType = data.basicFileType == FILE_TYPE_VIDEO ? static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)
                                                          : static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    }
    CHECK_AND_RETURN_RET_WARN_LOG(mediaType != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::mediaType.");
    values.PutInt(PhotoColumn::MEDIA_TYPE, mediaType);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateDuration(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t duration = data.duration;
    CHECK_AND_RETURN_RET_WARN_LOG(duration != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::duration.");
    values.PutInt(PhotoColumn::MEDIA_DURATION, duration);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttHidden(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t hidden = data.attributesHidden;
    CHECK_AND_RETURN_RET_WARN_LOG(hidden != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::hidden.");
    values.PutInt(PhotoColumn::MEDIA_HIDDEN, hidden);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttHiddenTime(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t hiddenTime = data.attributesHiddenTime;
    CHECK_AND_RETURN_RET_WARN_LOG(hiddenTime != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::hiddenTime.");
    values.PutLong(PhotoColumn::PHOTO_HIDDEN_TIME, hiddenTime);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttRelativePath(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string relativePath = data.attributesRelativePath;
    CHECK_AND_RETURN_RET_WARN_LOG(
        !relativePath.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::relativePath.");
    values.PutString(PhotoColumn::MEDIA_RELATIVE_PATH, relativePath);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttVirtualPath(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string virtualPath = data.attributesVirtualPath;
    CHECK_AND_RETURN_RET_WARN_LOG(!virtualPath.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::virtualPath.");
    values.PutString(PhotoColumn::MEDIA_VIRTURL_PATH, virtualPath);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttMetaDateModified(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t metaDateModified = data.attributesMetaDateModified;
    CHECK_AND_RETURN_RET_WARN_LOG(
        metaDateModified != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::metaDateModified.");
    values.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, metaDateModified);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttSubtype(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t subtype = data.attributesSubtype;
    CHECK_AND_RETURN_RET_WARN_LOG(subtype != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::subtype.");
    values.PutInt(PhotoColumn::PHOTO_SUBTYPE, subtype);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttBurstCoverLevel(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t burstCoverLevel = data.attributesBurstCoverLevel;
    CHECK_AND_RETURN_RET_WARN_LOG(
        burstCoverLevel != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::burstCoverLevel.");
    int32_t maxLevel = static_cast<int32_t>(BurstCoverLevelType::MEMBER);
    int32_t minLevel = static_cast<int32_t>(BurstCoverLevelType::DEFAULT);
    if (burstCoverLevel > maxLevel || burstCoverLevel < minLevel) {
        burstCoverLevel = minLevel;
    }
    values.PutInt(PhotoColumn::PHOTO_BURST_COVER_LEVEL, burstCoverLevel);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttBurstKey(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string burstKey = data.attributesBurstKey;
    CHECK_AND_RETURN_RET_WARN_LOG(!burstKey.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::burstKey.");
    values.PutString(PhotoColumn::PHOTO_BURST_KEY, burstKey);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttDateYear(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string dateYear = data.attributesDateYear;
    CHECK_AND_RETURN_RET_WARN_LOG(!dateYear.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::dateYear.");
    values.PutString(PhotoColumn::PHOTO_DATE_YEAR, dateYear);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttDateMonth(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string dateMonth = data.attributesDateMonth;
    CHECK_AND_RETURN_RET_WARN_LOG(!dateMonth.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::dateMonth.");
    values.PutString(PhotoColumn::PHOTO_DATE_MONTH, dateMonth);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttDateDay(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string dateDay = data.attributesDateDay;
    CHECK_AND_RETURN_RET_WARN_LOG(!dateDay.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::dateDay.");
    values.PutString(PhotoColumn::PHOTO_DATE_DAY, dateDay);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttShootingMode(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string shootingMode = data.attributesShootingMode;
    CHECK_AND_RETURN_RET_WARN_LOG(
        !shootingMode.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::shootingMode.");
    values.PutString(PhotoColumn::PHOTO_SHOOTING_MODE, shootingMode);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttShootingModeTag(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string shootingModeTag = data.attributesShootingModeTag;
    CHECK_AND_RETURN_RET_WARN_LOG(
        !shootingModeTag.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::shootingModeTag.");
    values.PutString(PhotoColumn::PHOTO_SHOOTING_MODE_TAG, shootingModeTag);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttDynamicRangeType(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t dynamicRangeType = data.attributesDynamicRangeType;
    CHECK_AND_RETURN_RET_WARN_LOG(
        dynamicRangeType != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::dynamicRangeType.");
    values.PutInt(PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, dynamicRangeType);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttFrontCamera(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string frontCamera = data.attributesFrontCamera;
    CHECK_AND_RETURN_RET_WARN_LOG(!frontCamera.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::frontCamera.");
    values.PutString(PhotoColumn::PHOTO_FRONT_CAMERA, frontCamera);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttEditTime(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t editTime = data.attributesEditTime;
    CHECK_AND_RETURN_RET_WARN_LOG(editTime != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::editTime.");
    values.PutLong(PhotoColumn::PHOTO_EDIT_TIME, editTime);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttOriginalSubtype(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t originalSubtype = data.attributesOriginalSubtype;
    CHECK_AND_RETURN_RET_WARN_LOG(
        originalSubtype != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::originalSubtype.");
    values.PutInt(PhotoColumn::PHOTO_ORIGINAL_SUBTYPE, originalSubtype);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttCoverPosition(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t coverPosition = data.attributesCoverPosition;
    CHECK_AND_RETURN_RET_WARN_LOG(coverPosition != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::coverPosition.");
    values.PutLong(PhotoColumn::PHOTO_COVER_POSITION, coverPosition);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttMovingPhotoEffectMode(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t movingPhotoEffectMode = data.attributesMovingPhotoEffectMode;
    CHECK_AND_RETURN_RET_WARN_LOG(
        movingPhotoEffectMode != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::movingPhotoEffectMode.");
    values.PutInt(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, movingPhotoEffectMode);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttSupportedWatermarkType(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t watermarkType = data.attributesSupportedWatermarkType;
    CHECK_AND_RETURN_RET_WARN_LOG(watermarkType != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::watermarkType.");
    values.PutInt(PhotoColumn::SUPPORTED_WATERMARK_TYPE, watermarkType);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateAttStrongAssociation(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t strongAssociation = data.attributesStrongAssociation;
    CHECK_AND_RETURN_RET_WARN_LOG(
        strongAssociation != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::strongAssociation.");
    values.PutInt(PhotoColumn::PHOTO_STRONG_ASSOCIATION, strongAssociation);
    return E_OK;
}

int32_t CloudSyncConvert::CompensatePropTitle(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string title = data.propertiesSourceFileName;
    CHECK_AND_RETURN_RET_WARN_LOG(!title.empty(), E_OK, "Cannot find properties::sourceFileName.");

    size_t pos = title.find_last_of(".");
    if (pos != std::string::npos) {
        title = title.substr(0, pos);
    }
    if (values.HasColumn(PhotoColumn::MEDIA_TITLE)) {
        values.Delete(PhotoColumn::MEDIA_TITLE);
    }
    values.PutString(PhotoColumn::MEDIA_TITLE, title);
    return E_OK;
}

int32_t CloudSyncConvert::CompensatePropOrientation(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t exifRotateValue = data.propertiesRotate;
    CHECK_AND_RETURN_RET_WARN_LOG(
        exifRotateValue != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find attributes::exifRotateValue.");
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, exifRotateValue);
    return E_OK;
}

int32_t CloudSyncConvert::CompensatePropPosition(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string position = data.propertiesPosition;
    CHECK_AND_RETURN_RET_WARN_LOG(!position.empty(), E_OK, "Cannot find properties::position.");
    std::string latitude;
    std::string longitude;
    std::regex positionPattern("(-?\\d+\\.?\\d+|0).*?(-?\\d+\\.?\\d+|0)");
    std::smatch match;
    if (std::regex_search(position, match, positionPattern)) {
        latitude = match[FIRST_MATCH_PARAM];
        longitude = match[SECOND_MATCH_PARAM];
        MEDIA_ERR_LOG("position latitude: %{public}s, longitude: %{public}s", latitude.c_str(), longitude.c_str());
    } else {
        MEDIA_ERR_LOG("position %{public}s extract latitude or longitude error", position.c_str());
        return E_CLOUDSYNC_INVAL_ARG;
    }
    std::stringstream latitudestream(latitude);
    std::stringstream longitudestream(longitude);
    latitudestream.precision(15);   // 15:precision
    longitudestream.precision(15);  // 15:precision
    double latitudeValue;
    double longitudeValue;
    latitudestream >> latitudeValue;
    longitudestream >> longitudeValue;

    values.PutDouble(PhotoColumn::PHOTO_LATITUDE, latitudeValue);
    values.PutDouble(PhotoColumn::PHOTO_LONGITUDE, longitudeValue);
    return E_OK;
}

int32_t CloudSyncConvert::CompensatePropHeight(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t height = data.propertiesHeight;
    CHECK_AND_RETURN_RET_WARN_LOG(height != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find properties::height.");
    values.PutInt(PhotoColumn::PHOTO_HEIGHT, height);
    return E_OK;
}

int32_t CloudSyncConvert::CompensatePropWidth(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t width = data.propertiesWidth;
    CHECK_AND_RETURN_RET_WARN_LOG(width != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find properties::width.");
    values.PutInt(PhotoColumn::PHOTO_WIDTH, width);
    return E_OK;
}

std::string CloudSyncConvert::StrCreateTime(const std::string &format, int64_t time)
{
    char strTime[DEFAULT_TIME_SIZE] = "";
    auto tm = localtime(&time);
    (void)strftime(strTime, sizeof(strTime), format.c_str(), tm);
    return strTime;
}

int32_t CloudSyncConvert::CompensateFormattedDate(uint64_t dateAdded, NativeRdb::ValuesBucket &values)
{
    std::string year = StrCreateTime(PhotoColumn::PHOTO_DATE_YEAR_FORMAT, dateAdded);
    std::string month = StrCreateTime(PhotoColumn::PHOTO_DATE_MONTH_FORMAT, dateAdded);
    std::string day = StrCreateTime(PhotoColumn::PHOTO_DATE_DAY_FORMAT, dateAdded);
    values.PutString(PhotoColumn::PHOTO_DATE_YEAR, year);
    values.PutString(PhotoColumn::PHOTO_DATE_MONTH, month);
    values.PutString(PhotoColumn::PHOTO_DATE_DAY, day);
    return E_OK;
}

int32_t CloudSyncConvert::CompensatePropDataAdded(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t dataAdded = 0;
    std::string tmpStr = data.propertiesFirstUpdateTime;

    if (tmpStr.empty()) {
        dataAdded = data.basicCreatedTime;
    } else {
        if (!convertToLong(tmpStr, dataAdded)) {
            MEDIA_ERR_LOG("extract dataAdded error");
            return E_CLOUDSYNC_INVAL_ARG;
        }
    }
    if (dataAdded == 0) {
        MEDIA_ERR_LOG("The dataAdded createTime of record is incorrect");
    }
    values.PutLong(PhotoColumn::MEDIA_DATE_ADDED, dataAdded);
    CompensateFormattedDate(dataAdded / MILLISECOND_TO_SECOND, values);
    return E_OK;
}

int32_t CloudSyncConvert::CompensatePropDetailTime(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string detailTime = data.propertiesDetailTime;
    CHECK_AND_RETURN_RET_WARN_LOG(!detailTime.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find properties::detailTime.");
    values.PutString(PhotoColumn::PHOTO_DETAIL_TIME, detailTime);
    return E_OK;
}

int32_t CloudSyncConvert::CompensatePropSourcePath(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string sourcePath = data.propertiesSourcePath;
    CHECK_AND_RETURN_RET_WARN_LOG(!sourcePath.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find properties::sourcePath.");
    size_t pos = sourcePath.find(SCREENSHOT_ALBUM_PATH);
    if (pos != std::string::npos) {
        int32_t fileType = data.basicFileType;
        if (fileType == -1) {
            MEDIA_ERR_LOG("Cannot find basic::fileType.");
        }
        std::string displayName = data.basicFileName;
        CHECK_AND_RETURN_RET_WARN_LOG(!displayName.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::displayName.");
        if (fileType == FILE_TYPE_VIDEO) {
            sourcePath = SCREENRECORD_ALBUM_PATH + displayName;
        }
    }
    values.PutString(PhotoColumn::PHOTO_SOURCE_PATH, sourcePath);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicSize(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t size = data.basicSize;
    CHECK_AND_RETURN_RET_WARN_LOG(size != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::size.");
    values.PutLong(MediaColumn::MEDIA_SIZE, size);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicDisplayName(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string displayName = data.basicDisplayName;
    CHECK_AND_RETURN_RET_WARN_LOG(!displayName.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::displayName.");
    values.PutString(MediaColumn::MEDIA_NAME, displayName);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicMimeType(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string mimeType = data.basicMimeType;
    CHECK_AND_RETURN_RET_WARN_LOG(!mimeType.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::mimeType.");
    values.PutString(MediaColumn::MEDIA_MIME_TYPE, mimeType);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicDeviceName(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string deviceName = data.basicDeviceName;
    CHECK_AND_RETURN_RET_WARN_LOG(!deviceName.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::deviceName.");
    values.PutString(PhotoColumn::MEDIA_DEVICE_NAME, deviceName);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicDateModified(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t dateModified = data.attributesEditedTimeMs;
    if (dateModified != -1) {
        values.PutLong(PhotoColumn::MEDIA_DATE_MODIFIED, dateModified);
        return E_OK;
    }
    dateModified = data.basicEditedTime;
    CHECK_AND_RETURN_RET_WARN_LOG(dateModified != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::dateModified.");
    values.PutLong(PhotoColumn::MEDIA_DATE_MODIFIED, dateModified);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicDateTaken(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t createTime = data.basicCreatedTime;
    CHECK_AND_RETURN_RET_WARN_LOG(createTime != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::createTime.");
    values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, createTime);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicFavorite(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t isFavorite = data.basicIsFavorite;
    CHECK_AND_RETURN_RET_WARN_LOG(isFavorite != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::isFavorite.");
    values.PutInt(PhotoColumn::MEDIA_IS_FAV, isFavorite);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicDateTrashed(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t isRecycle = data.basicIsRecycle;
    CHECK_AND_RETURN_RET_WARN_LOG(isRecycle != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::isRecycle.");
    if (isRecycle) {
        int64_t dataTrashed = data.basicRecycledTime;
        CHECK_AND_RETURN_RET_WARN_LOG(dataTrashed != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::dataTrashed.");
        values.PutLong(PhotoColumn::MEDIA_DATE_TRASHED, dataTrashed);
    } else {
        values.PutLong(PhotoColumn::MEDIA_DATE_TRASHED, 0);
    }
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicCloudId(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string cloudId = data.cloudId;
    CHECK_AND_RETURN_RET_WARN_LOG(!cloudId.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::cloudId.");
    values.PutString(PhotoColumn::PHOTO_CLOUD_ID, cloudId);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicDescription(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string description = data.basicDescription;
    CHECK_AND_RETURN_RET_WARN_LOG(!description.empty(), E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::description.");
    values.PutString(PhotoColumn::PHOTO_USER_COMMENT, description);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicFixLivePhoto(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t fileType = data.basicFileType;
    CHECK_AND_RETURN_RET_WARN_LOG(fileType != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::fileType.");
    if (fileType == FILE_TYPE_LIVEPHOTO) {
        values.Delete(PhotoColumn::PHOTO_SUBTYPE);
        values.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    }
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicMediaType(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t fileType = data.basicFileType;
    CHECK_AND_RETURN_RET_LOG(fileType != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::fileType.");
    int32_t mediaType = fileType == FILE_TYPE_VIDEO ? static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)
                                                    : static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    values.PutInt(PhotoColumn::MEDIA_TYPE, mediaType);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicMetaDateModified(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int64_t metaDataModified = data.basicEditedTime;
    CHECK_AND_RETURN_RET_LOG(metaDataModified != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::metaDataModified.");

    // imputed value, may not be accurate
    values.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, metaDataModified);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicSubtype(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    int32_t fileType = data.basicFileType;
    CHECK_AND_RETURN_RET_LOG(fileType != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::fileType.");
    if (fileType == FILE_TYPE_LIVEPHOTO) {
        MEDIA_INFO_LOG("current file is live photo");
        values.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
        return E_OK;
    }

    CHECK_AND_RETURN_RET_WARN_LOG(data.hasProperties, E_OK, "Data cannot find properties");
    std::string sourcePath = data.propertiesSourcePath;
    if (sourcePath.empty()) {
        values.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::DEFAULT));
        return E_OK;
    }

    int32_t subType = static_cast<int32_t>(PhotoSubType::DEFAULT);
    if (sourcePath.find("DCIM") != std::string::npos && sourcePath.find("Camera") != std::string::npos) {
        subType = static_cast<int32_t>(PhotoSubType::CAMERA);
    } else if (sourcePath.find("Screenshots") != std::string::npos) {
        subType = static_cast<int32_t>(PhotoSubType::SCREENSHOT);
    } else {
        subType = static_cast<int32_t>(PhotoSubType::DEFAULT);
    }
    values.PutInt(PhotoColumn::PHOTO_SUBTYPE, subType);
    return E_OK;
}

int32_t CloudSyncConvert::CompensateBasicBurstCoverLevel(
    const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    values.PutInt(PhotoColumn::PHOTO_BURST_COVER_LEVEL, static_cast<int32_t>(BurstCoverLevelType::DEFAULT));
    return E_OK;
}

int32_t CloudSyncConvert::TryCompensateValue(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    CHECK_AND_RETURN_RET_WARN_LOG(data.hasProperties, E_OK, "Data cannot find properties");
    CHECK_AND_RETURN_RET_LOG(CompensatePropTitle(data, values) == E_OK, E_ERR, "CompensateTitle Error");
    CHECK_AND_RETURN_RET_LOG(CompensateBasicMediaType(data, values) == E_OK, E_ERR, "CompensateMediaType Error");
    CHECK_AND_RETURN_RET_LOG(CompensateBasicMetaDateModified(data, values) == E_OK, E_ERR, "MetaModified Error");
    CHECK_AND_RETURN_RET_LOG(CompensateBasicSubtype(data, values) == E_OK, E_ERR, "CompensateSubtype Error");

    // Prevent device-cloud inconsistency caused by the value of the PHOTO_BURST_COVER_LEVEL field out of range.
    CHECK_AND_RETURN_RET(CompensateBasicBurstCoverLevel(data, values) == E_OK, E_ERR);
    return E_OK;
}

int32_t CloudSyncConvert::ExtractAttributeValue(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    CHECK_AND_RETURN_RET_WARN_LOG(data.hasAttributes, E_OK, "Data cannot find hasAttributes");
    CompensateAttTitle(data, values);
    CompensateAttMediaType(data, values);
    CompensateAttHidden(data, values);
    CompensateAttHiddenTime(data, values);
    CompensateAttRelativePath(data, values);
    CompensateAttVirtualPath(data, values);
    CompensateAttMetaDateModified(data, values);
    CompensateAttSubtype(data, values);
    CompensateAttBurstCoverLevel(data, values);
    CompensateAttBurstKey(data, values);
    CompensateAttDateYear(data, values);
    CompensateAttDateMonth(data, values);
    CompensateAttDateDay(data, values);
    CompensateAttShootingMode(data, values);
    CompensateAttShootingModeTag(data, values);
    CompensateAttDynamicRangeType(data, values);
    CompensateAttFrontCamera(data, values);
    CompensateAttEditTime(data, values);
    CompensateAttOriginalSubtype(data, values);
    CompensateAttCoverPosition(data, values);
    CompensateAttMovingPhotoEffectMode(data, values);
    CompensateAttSupportedWatermarkType(data, values);
    CompensateAttStrongAssociation(data, values);
    return E_OK;
}

int32_t CloudSyncConvert::ExtractCompatibleValue(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    /* extract value in first level*/
    CompensateBasicSize(data, values);
    CompensateBasicDisplayName(data, values);
    CompensateBasicMimeType(data, values);
    CompensateBasicDeviceName(data, values);
    CompensateBasicDateModified(data, values);
    CompensateBasicDateTaken(data, values);
    CompensateBasicFavorite(data, values);
    CompensateBasicDateTrashed(data, values);
    CompensateBasicCloudId(data, values);
    CompensateBasicDescription(data, values);
    CompensateBasicFixLivePhoto(data, values);
    CompensateDuration(data, values);

    /* extract value in properties*/
    CompensatePropOrientation(data, values);
    CompensatePropPosition(data, values);
    CompensatePropHeight(data, values);
    CompensatePropWidth(data, values);
    CompensatePropDataAdded(data, values);
    CompensatePropDetailTime(data, values);
    CompensatePropSourcePath(data, values);
    return E_OK;
}

bool CloudSyncConvert::RecordToValueBucket(const CloudMediaPullDataDto &data, NativeRdb::ValuesBucket &values)
{
    std::string title = data.attributesTitle;
    if (!data.hasAttributes) {
        int32_t ret = TryCompensateValue(data, values);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "PullData lose key value, ret: %{public}d.", ret);
    } else {
        int32_t ret = ExtractAttributeValue(data, values);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "PullData do not have attributes set, need, ret: %{public}d.", ret);
        CHECK_AND_RETURN_RET_LOG(CompensatePropTitle(data, values) == E_OK, E_ERR, "CompensatePropTitle Error");
    }
    CHECK_AND_RETURN_RET_LOG(ExtractCompatibleValue(data, values) == E_OK, E_ERR, "ExtractCompatibleValue Error");
    return E_OK;
}
}  // namespace OHOS::Media::CloudSync