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
#define MLOG_TAG "Media_Client"

#include "cloud_file_data_convert.h"

#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "directory_ex.h"
#include "file_ex.h"
#include "media_log.h"
#include "cloud_media_sync_const.h"
#include "mdk_record_photos_data.h"
#include "media_file_utils.h"
#include "moving_photo_file_utils.h"
#include "photo_file_utils.h"

namespace OHOS::Media::CloudSync {

/* path */
std::string CloudFileDataConvert::prefixLCD_ = "/mnt/hmdfs/";
std::string CloudFileDataConvert::sandboxPrefix_ = "/storage/cloud/files";
std::string CloudFileDataConvert::prefix_ = "/data/service/el2/";
std::string CloudFileDataConvert::suffixLCD_ = "/account/device_view/local/files";
std::string CloudFileDataConvert::suffix_ = "/hmdfs/account/files";
const std::string CloudFileDataConvert::recordType_ = "media";

CloudFileDataConvert::CloudFileDataConvert(CloudOperationType type, int32_t userId) : userId_(userId), type_(type) {}

static inline std::string GetThumbnailPath(const std::string &path, const std::string &key)
{
    if (path.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    std::string suffix = (key == "THM_ASTC") ? ".astc" : ".jpg";
    return ROOT_MEDIA_DIR + ".thumbs/" + path.substr(ROOT_MEDIA_DIR.length()) + "/" + key + suffix;
}

std::string CloudFileDataConvert::GetThumbPath(const std::string &path, const std::string &key)
{
    if (path.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    /* transform sandbox path */
    return prefixLCD_ + std::to_string(userId_) + suffixLCD_ + "/" +
           GetThumbnailPath(path, key).substr(ROOT_MEDIA_DIR.length());
}

int32_t CloudFileDataConvert::GetFileSize(const std::string &path, const std::string &thumbSuffix, int64_t &fileSize)
{
    std::string thumbExSuffix = (thumbSuffix == THUMB_SUFFIX) ? THUMB_EX_SUFFIX : LCD_EX_SUFFIX;
    /* try get file size on xxxjpg/THM_EX/THM.jpg */
    std::string thumbnailPath = GetThumbPath(path, thumbExSuffix);
    struct stat fileStat;
    MEDIA_INFO_LOG("GetFileSize stat %{public}s", thumbnailPath.c_str());
    int32_t err = stat(thumbnailPath.c_str(), &fileStat);
    if (err < 0) {
        MEDIA_ERR_LOG("get thumb size failed errno :%{public}d, %{public}s", errno, thumbnailPath.c_str());
    } else {
        fileSize = fileStat.st_size;
        return E_OK;
    }
    /* try get file size on xxxjpg/THM.jpg */
    thumbnailPath = GetThumbPath(path, thumbSuffix);
    err = stat(thumbnailPath.c_str(), &fileStat);
    MEDIA_INFO_LOG("GetFileSize stat end %{public}s", thumbnailPath.c_str());
    if (err < 0) {
        MEDIA_ERR_LOG("get thumb size failed errno :%{public}d, %{public}s", errno, thumbnailPath.c_str());
        return E_PATH_QUERY_FILED;
    }
    fileSize = fileStat.st_size;
    return E_OK;
}

int32_t CloudFileDataConvert::HandleThumbSize(
    std::map<std::string, MDKRecordField> &map, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleThumbSize");
    std::string path = upLoadRecord.data;
    if (path.empty()) {
        MEDIA_ERR_LOG("HandleThumbSize failed to get filepath");
        return E_QUERY_CONTENT_IS_EMPTY;
    }
    int64_t fileSize;
    int32_t ret = GetFileSize(path, THUMB_SUFFIX, fileSize);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("HandleThumbSize failed to get file size");
        return ret;
    }
    map["thumb_size"] = MDKRecordField(fileSize);
    return E_OK;
}

int32_t CloudFileDataConvert::HandleLcdSize(
    std::map<std::string, MDKRecordField> &map, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    if (type_ != FILE_CREATE && type_ != FILE_DATA_MODIFY) {
        return E_OK;
    }

    std::string path = upLoadRecord.data;

    int64_t fileSize;
    int32_t ret = GetFileSize(path, LCD_SUFFIX, fileSize);
    if (ret != E_OK) {
        return ret;
    }

    map["lcd_size"] = MDKRecordField(fileSize);
    return E_OK;
}

int32_t CloudFileDataConvert::HandleFormattedDate(
    std::map<std::string, MDKRecordField> &map, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleFormattedDate");
    std::string year = upLoadRecord.dateYear;
    std::string month = upLoadRecord.dateMonth;
    std::string day = upLoadRecord.dateDay;
    if (year.empty() || month.empty() || day.empty()) {
        MEDIA_INFO_LOG("HandleFormattedDate year month day is empty");
        int64_t createTime = upLoadRecord.dateAdded;
        createTime = createTime / MILLISECOND_TO_SECOND;
        year = MediaFileUtils::StrCreateTime(PhotoColumn::PHOTO_DATE_YEAR_FORMAT, createTime);
        month = MediaFileUtils::StrCreateTime(PhotoColumn::PHOTO_DATE_MONTH_FORMAT, createTime);
        day = MediaFileUtils::StrCreateTime(PhotoColumn::PHOTO_DATE_DAY_FORMAT, createTime);
    }
    map[PhotoColumn::PHOTO_DATE_YEAR] = MDKRecordField(year);
    map[PhotoColumn::PHOTO_DATE_MONTH] = MDKRecordField(month);
    map[PhotoColumn::PHOTO_DATE_DAY] = MDKRecordField(day);
    return E_OK;
}

int32_t CloudFileDataConvert::HandleUniqueFileds(
    std::map<std::string, MDKRecordField> &data, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleUniqueFileds");
    std::map<std::string, MDKRecordField> map;
    /* store media unique fileds in attributes */
    map[PhotoColumn::MEDIA_TITLE] = MDKRecordField(upLoadRecord.title);
    map[PhotoColumn::MEDIA_TYPE] = MDKRecordField(upLoadRecord.mediaType);
    map[PhotoColumn::MEDIA_DURATION] = MDKRecordField(upLoadRecord.duration);
    map[PhotoColumn::MEDIA_HIDDEN] = MDKRecordField(upLoadRecord.hidden);
    map[PhotoColumn::PHOTO_HIDDEN_TIME] = MDKRecordField(upLoadRecord.hiddenTime);
    map[PhotoColumn::MEDIA_RELATIVE_PATH] = MDKRecordField(upLoadRecord.relativePath);
    map[PhotoColumn::MEDIA_VIRTURL_PATH] = MDKRecordField(upLoadRecord.virtualPath);
    map[PhotoColumn::PHOTO_META_DATE_MODIFIED] = MDKRecordField(upLoadRecord.metaDateModified);
    map[PhotoColumn::PHOTO_SUBTYPE] = MDKRecordField(upLoadRecord.subtype);
    map[PhotoColumn::PHOTO_BURST_COVER_LEVEL] = MDKRecordField(upLoadRecord.burstCoverLevel);
    map[PhotoColumn::PHOTO_BURST_KEY] = MDKRecordField(upLoadRecord.burstKey);
    map[PhotoColumn::PHOTO_DATE_YEAR] = MDKRecordField(upLoadRecord.dateYear);
    map[PhotoColumn::PHOTO_DATE_MONTH] = MDKRecordField(upLoadRecord.dateMonth);
    map[PhotoColumn::PHOTO_DATE_DAY] = MDKRecordField(upLoadRecord.dateDay);
    map[PhotoColumn::PHOTO_SHOOTING_MODE] = MDKRecordField(upLoadRecord.shootingMode);
    map[PhotoColumn::PHOTO_SHOOTING_MODE_TAG] = MDKRecordField(upLoadRecord.shootingModeTag);
    map[PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE] = MDKRecordField(upLoadRecord.dynamicRangeType);
    map[PhotoColumn::PHOTO_FRONT_CAMERA] = MDKRecordField(upLoadRecord.frontCamera);
    map[PhotoColumn::PHOTO_EDIT_TIME] = MDKRecordField(upLoadRecord.editTime);
    map[PhotoColumn::PHOTO_ORIGINAL_SUBTYPE] = MDKRecordField(upLoadRecord.originalSubtype);
    map[PhotoColumn::PHOTO_COVER_POSITION] = MDKRecordField(upLoadRecord.originalSubtype);
    map[PhotoColumn::MOVING_PHOTO_EFFECT_MODE] = MDKRecordField(upLoadRecord.movingPhotoEffectMode);
    map[PhotoColumn::SUPPORTED_WATERMARK_TYPE] = MDKRecordField(upLoadRecord.supportedWatermarkType);
    map[PhotoColumn::PHOTO_STRONG_ASSOCIATION] = MDKRecordField(upLoadRecord.strongAssociation);
    map[MediaColumn::MEDIA_ID] = MDKRecordField(upLoadRecord.fileId);
    map[PhotoColumn::MEDIA_FILE_PATH] = MDKRecordField(upLoadRecord.data);
    map[PhotoColumn::MEDIA_DATE_ADDED] = MDKRecordField((upLoadRecord.dateAdded) / MILLISECOND_TO_SECOND);
    map[PhotoColumn::MEDIA_DATE_MODIFIED] = MDKRecordField((upLoadRecord.dateModified) / MILLISECOND_TO_SECOND);
    map[PhotoColumn::PHOTO_SUBTYPE] = MDKRecordField(upLoadRecord.subtype);
    map[PhotoColumn::PHOTO_BURST_COVER_LEVEL] = MDKRecordField(upLoadRecord.burstCoverLevel);
    map[PhotoColumn::PHOTO_BURST_KEY] = MDKRecordField(upLoadRecord.burstKey);
    map[PhotoColumn::PHOTO_OWNER_ALBUM_ID] = MDKRecordField(upLoadRecord.ownerAlbumId);
    map[FILE_FIX_VERSION] = MDKRecordField(0);
    map["editedTime_ms"] = MDKRecordField(upLoadRecord.dateModified);
    int32_t ret = HandleThumbSize(map, upLoadRecord);
    ret = HandleLcdSize(map, upLoadRecord);
    ret = HandleFormattedDate(map, upLoadRecord);
    data[FILE_ATTRIBUTES] = MDKRecordField(map);
    data[FILE_LOCAL_ID] = MDKRecordField(upLoadRecord.fileId);
    return E_OK;
}

int32_t CloudFileDataConvert::HandleFileType(
    std::map<std::string, MDKRecordField> &data, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleFileType %{public}d, %{public}d", upLoadRecord.subtype, upLoadRecord.dirty);
    if (upLoadRecord.subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        data["fileType"] = MDKRecordField(FILE_TYPE_LIVEPHOTO);
        return E_OK;
    }
    // 2. fill fileType with Image/Video when create file
    if (upLoadRecord.dirty == static_cast<int32_t>(DirtyType::TYPE_NEW)) {
        data["fileType"] =
            MDKRecordField(upLoadRecord.mediaType == Media::MEDIA_TYPE_VIDEO ? FILE_TYPE_VIDEO : FILE_TYPE_IMAGE);
        return E_OK;
    }
    // 3. fill fileType with Image when it's a Graffiti
    if (upLoadRecord.subtype == static_cast<int32_t>(PhotoSubType::DEFAULT) &&
        upLoadRecord.originalSubtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        data["fileType"] = MDKRecordField(FILE_TYPE_IMAGE);
    }
    return E_OK;
}

int32_t CloudFileDataConvert::HandlePosition(
    std::map<std::string, MDKRecordField> &map, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandlePosition");
    std::stringstream latitudestream;
    std::stringstream longitudestream;
    latitudestream.precision(15);   // 15:precision
    longitudestream.precision(15);  // 15:precision
    latitudestream << upLoadRecord.latitude;
    longitudestream << upLoadRecord.longitude;
    std::string position = "{\"x\":\"" + latitudestream.str() + "\",\"y\":\"" + longitudestream.str() + "\"}";
    map["position"] = MDKRecordField(position);
    return E_OK;
}

int32_t CloudFileDataConvert::HandleRotate(
    std::map<std::string, MDKRecordField> &map, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleRotate orientation: %{public}d", upLoadRecord.orientation);
    int32_t val;
    switch (upLoadRecord.orientation) {
        case ROTATE_ANGLE_0:
            val = ORIENTATION_NORMAL;
            break;
        case ROTATE_ANGLE_90:
            val = ORIENTATION_ROTATE_90;
            break;
        case ROTATE_ANGLE_180:
            val = ORIENTATION_ROTATE_180;
            break;
        case ROTATE_ANGLE_270:
            val = ORIENTATION_ROTATE_270;
            break;
        default:
            val = ORIENTATION_NORMAL;
            break;
    }
    map["rotate"] = MDKRecordField(val);
    return E_OK;
}

int32_t CloudFileDataConvert::HandleProperties(
    std::map<std::string, MDKRecordField> &data, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleProperties source path:%{public}s", upLoadRecord.sourcePath.c_str());
    std::map<std::string, MDKRecordField> map;
    // 可以封装一个值为0或者为空的异常述职处理函数
    if (upLoadRecord.sourcePath.empty()) {
        MEDIA_ERR_LOG("Get local sourcePath is empty");
    } else {
        map["sourcePath"] = MDKRecordField(upLoadRecord.sourcePath);
    }
    map["sourceFileName"] = MDKRecordField(upLoadRecord.displayName);
    map["first_update_time"] = MDKRecordField(std::to_string(upLoadRecord.dateAdded));
    map["fileCreateTime"] = MDKRecordField(std::to_string(upLoadRecord.dateTaken));
    map["detail_time"] = MDKRecordField(upLoadRecord.detailTime);
    map["duration"] = MDKRecordField(upLoadRecord.duration);
    /* Resolution is combined by cloud sdk, just upload height and width */
    if (upLoadRecord.height == 0 || upLoadRecord.width == 0) {
        MEDIA_ERR_LOG("Get local height or width is 0 ");
        return E_QUERY_CONTENT_IS_EMPTY;
    } else {
        map["height"] = MDKRecordField(upLoadRecord.height);
        map["width"] = MDKRecordField(upLoadRecord.width);
    }
    HandlePosition(map, upLoadRecord);
    HandleRotate(map, upLoadRecord);
    data[FILE_PROPERTIES] = MDKRecordField(map);
    return E_OK;
}

std::string CloudFileDataConvert::GetLowerPath(const std::string &path)
{
    size_t pos = path.find(sandboxPrefix_);
    if (pos == std::string::npos) {
        MEDIA_ERR_LOG("invalid path");
        return "";
    }
    return prefix_ + std::to_string(userId_) + suffix_ + path.substr(pos + sandboxPrefix_.size());
}

static void DeleteTmpFile(bool needDelete, const std::string &path)
{
    if (!needDelete) {
        return;
    }
    if (unlink(path.c_str()) < 0) {
        MEDIA_ERR_LOG("unlink temp file fail, err: %{public}d", errno);
    }
}

int32_t CloudFileDataConvert::HandleEditData(
    std::map<std::string, MDKRecordField> &data, std::string &path, bool isMovingPhoto)
{
    MEDIA_INFO_LOG("enter HandleEditData editDataPath %{public}s, %{public}d", path.c_str(), isMovingPhoto);
    std::string rawFilePath;
    std::string editDataPath;
    std::string editDataCameraPath;

    rawFilePath = PhotoFileUtils::GetEditDataSourcePath(path, userId_);
    editDataPath = PhotoFileUtils::GetEditDataPath(path, userId_);
    editDataCameraPath = PhotoFileUtils::GetEditDataCameraPath(path, userId_);

    MEDIA_INFO_LOG("HandleEditData rawFilePath %{public}s", rawFilePath.c_str());
    if (!rawFilePath.empty() && access(rawFilePath.c_str(), F_OK) == 0) {
        MEDIA_INFO_LOG("HandleEditData rawFilePath is not empty and access success");
        if (isMovingPhoto) {
            if (MovingPhotoFileUtils::ConvertToSourceLivePhoto(path, rawFilePath, userId_) != E_OK) {
                MEDIA_ERR_LOG("HandleEditData ConvertToSourceLivePhoto failed %{public}s", path.c_str());
                return E_PATH_QUERY_FILED;
            }
        }
        MDKAsset content;
        content.uri = move(rawFilePath);
        content.assetName = FILE_RAW;
        content.operationType = MDKAssetOperType::DK_ASSET_ADD;
        data[FILE_RAW] = MDKRecordField(content);
    }
    MEDIA_INFO_LOG("HandleEditData editDataPath %{public}s", editDataPath.c_str());
    if (!editDataPath.empty()) {
        MDKAsset content;
        struct stat fileStat;
        if (stat(editDataPath.c_str(), &fileStat) == 0 && fileStat.st_size > 0) {
            MEDIA_INFO_LOG("HandleEditData editDataPath is not empty and stat success");
            content.uri = move(editDataPath);
            content.assetName = FILE_EDIT_DATA;
            content.operationType = MDKAssetOperType::DK_ASSET_ADD;
            data[FILE_EDIT_DATA] = MDKRecordField(content);
        }
    }
    // -- editDataCamera as properties, append to FILE_ATTRIBUTES --
    MEDIA_INFO_LOG("HandleEditData editDataCameraPath %{public}s", editDataCameraPath.c_str());
    if (!editDataCameraPath.empty() && access(editDataCameraPath.c_str(), F_OK) == 0) {
        MEDIA_INFO_LOG("HandleEditData editDataCameraPath is not empty and access success");
        if (data.find(FILE_ATTRIBUTES) == data.end()) {
            MEDIA_ERR_LOG("Cannot add edit_data_camera to properties.");
            return E_INVALID_ARGUMENTS;
        }
        std::string buf;
        if (!LoadStringFromFile(editDataCameraPath, buf)) {
            MEDIA_ERR_LOG("editDataCameraPath read from file failed.");
            return E_INVALID_ARGUMENTS;
        }
        std::map<std::string, MDKRecordField> map;
        data[FILE_ATTRIBUTES].GetRecordMap(map);
        map[FILE_EDIT_DATA_CAMERA] = MDKRecordField(buf);
        data[FILE_ATTRIBUTES] = MDKRecordField(map);
    }

    return E_OK;
}

int32_t CloudFileDataConvert::HandleContent(
    std::map<std::string, MDKRecordField> &data, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleContent");
    std::string path = upLoadRecord.data;
    int64_t coverPosition = upLoadRecord.coverPosition;
    std::string lowerPath = "";
    bool isMovingPhoto = MovingPhotoFileUtils::IsMovingPhoto(
        upLoadRecord.subtype, upLoadRecord.movingPhotoEffectMode, upLoadRecord.originalSubtype);
    bool isGraffiti = MovingPhotoFileUtils::IsGraffiti(upLoadRecord.subtype, upLoadRecord.originalSubtype);
    MEDIA_INFO_LOG("HandleContent isMovingPhoto: %{public}d, isGraffiti: %{public}d", isMovingPhoto, isGraffiti);
    if (isMovingPhoto && !isGraffiti) {
        if (MovingPhotoFileUtils::ConvertToLivePhoto(path, coverPosition, lowerPath, userId_) != E_OK) {
            MEDIA_ERR_LOG("covert to live photo fail");
            return E_PATH_QUERY_FILED;
        }
    } else {
        lowerPath = GetLowerPath(path);
    }
    struct stat fileStat;
    int err = stat(lowerPath.c_str(), &fileStat);
    if (err < 0) {
        MEDIA_ERR_LOG("HandleContent errno : %{public}d, path : %{public}s, %{public}d, %{public}d",
            errno, lowerPath.c_str(), isMovingPhoto, isGraffiti);
        DeleteTmpFile(isMovingPhoto && !isGraffiti, lowerPath);
        return E_PATH_QUERY_FILED;
    }
    if (fileStat.st_size <= 0) {
        MEDIA_ERR_LOG("HandleContent content size err");
        DeleteTmpFile(isMovingPhoto && !isGraffiti, lowerPath);
        return E_INVALID_ARGUMENTS;
    }
    /* asset */
    MDKAsset content;
    content.uri = move(lowerPath);
    content.assetName = FILE_CONTENT;
    content.operationType = MDKAssetOperType::DK_ASSET_ADD;
    data[FILE_CONTENT] = MDKRecordField(content);
    int32_t ret = HandleEditData(data, path, isMovingPhoto);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("HandleContent handle EditData err %{public}d", ret);
        DeleteTmpFile(isMovingPhoto && !isGraffiti, lowerPath);
        return ret;
    }
    return E_OK;
}

int32_t CloudFileDataConvert::HandleThumbnail(
    std::map<std::string, MDKRecordField> &recordData, std::string &path, int32_t orientation)
{
    MEDIA_INFO_LOG("enter HandleThumbnail");
    std::string thumbnailUploadPath;
    std::string thumbnailExPath = GetThumbPath(path, THUMB_EX_SUFFIX);
    if (orientation == NO_ORIENTATION) {
        std::string thumbnailPath = GetThumbPath(path, THUMB_SUFFIX);
        if (access(thumbnailPath.c_str(), F_OK)) {
            MEDIA_ERR_LOG("thumnail doesn't exist %{public}s", thumbnailPath.c_str());
            return E_PATH_QUERY_FILED;
        }
        thumbnailUploadPath = thumbnailPath;
    } else {
        if (access(thumbnailExPath.c_str(), F_OK)) {
            MEDIA_ERR_LOG("thumbnailEx doesn't exist %{public}s", thumbnailExPath.c_str());
            return E_PATH_QUERY_FILED;
        }
        thumbnailUploadPath = thumbnailExPath;
    }
    /* asset */
    MDKAsset content;
    content.uri = move(thumbnailUploadPath);
    content.assetName = FILE_THUMBNAIL;
    content.operationType = MDKAssetOperType::DK_ASSET_ADD;
    recordData["thumbnail"] = MDKRecordField(content);
    return E_OK;
}

std::string CloudFileDataConvert::GetParentPath(const std::string &path)
{
    std::string name;
    size_t slashIndex = path.rfind("/");
    if (slashIndex != std::string::npos) {
        name = path.substr(0, slashIndex);
    }
    return name;
}

int32_t CloudFileDataConvert::HandleLcd(
    std::map<std::string, MDKRecordField> &recordData, std::string &path, int32_t orientation)
{
    MEDIA_INFO_LOG("enter HandleLcd");
    std::string lcdUploadPath;
    std::string lcdExPath = GetThumbPath(path, LCD_EX_SUFFIX);
    std::string lcdExDir = GetParentPath(lcdExPath);
    if (orientation == NO_ORIENTATION) {
        std::string lcdPath = GetThumbPath(path, LCD_SUFFIX);
        if (access(lcdPath.c_str(), F_OK)) {
            MEDIA_ERR_LOG("HandleLcd lcd path doesn't exist %{public}s", lcdPath.c_str());
            return E_PATH_QUERY_FILED;
        }
        lcdUploadPath = lcdPath;
    } else {
        if (access(lcdExPath.c_str(), F_OK)) {
            MEDIA_ERR_LOG("HandleLcd lcdEx path doesn't exist %{public}s", lcdExPath.c_str());
            return E_PATH_QUERY_FILED;
        }
        lcdUploadPath = lcdExPath;
    }
    /* asset */
    MDKAsset content;
    content.uri = move(lcdUploadPath);
    content.assetName = FILE_LCD;
    content.operationType = MDKAssetOperType::DK_ASSET_ADD;
    recordData[FILE_LCD] = MDKRecordField(content);
    return E_OK;
}

int32_t CloudFileDataConvert::HandleAttachments(
    std::map<std::string, MDKRecordField> &recordData, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleAttachments");
    int32_t orientation = (upLoadRecord.mediaType == MEDIA_TYPE_IMAGE) ? upLoadRecord.orientation : NO_ORIENTATION;
    /* content */
    int32_t ret = HandleContent(recordData, upLoadRecord);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("failed to handle content");
    }

    /* thumb */
    std::string path = upLoadRecord.data;
    ret = HandleThumbnail(recordData, path, orientation);

    /* lcd */
    ret = HandleLcd(recordData, path, orientation);
    return ret;
}

int32_t CloudFileDataConvert::HandleCompatibleFileds(
    std::map<std::string, MDKRecordField> &data, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MEDIA_INFO_LOG("enter HandleCompatibleFileds");
    /* gallery-specific or shared fileds */
    data["fileName"] = MDKRecordField(upLoadRecord.displayName);
    data["createdTime"] = MDKRecordField(upLoadRecord.dateTaken);
    data["hashId"] = MDKRecordField("Md5_default_hash");
    data["size"] = MDKRecordField(upLoadRecord.size);
    data["source"] = MDKRecordField(upLoadRecord.deviceName);
    data["recycled"] = MDKRecordField(!!(upLoadRecord.dateTrashed));
    data["recycledTime"] = MDKRecordField(std::to_string(upLoadRecord.dateTrashed));
    data["favorite"] = MDKRecordField(!!(upLoadRecord.isFavorite));
    data["description"] = MDKRecordField(upLoadRecord.userComment);
    HandleFileType(data, upLoadRecord);

    /* gallery expand fields */
    HandleProperties(data, upLoadRecord);

    /* cloud sdk extra feature */
    HandleAttachments(data, upLoadRecord);

    /* cloudsync-specific fields */
    data["mimeType"] = MDKRecordField(upLoadRecord.mimeType);
    data["editedTime"] = MDKRecordField(std::to_string(upLoadRecord.dateModified));
    return E_OK;
}

int32_t CloudFileDataConvert::SetUpdateSourceAlbum(MDKRecord &record, const CloudMdkRecordPhotosVo &upLoadRecord)
{
    std::map<std::string, MDKRecordField> data;
    record.GetRecordData(data);
    std::string displayName = upLoadRecord.displayName;
    int32_t hidden = upLoadRecord.hidden;
    // int32_t albumId = upLoadRecord.ownerAlbumId;
    std::string albumCloudId = upLoadRecord.albumCloudId;
    std::string albumLPath = upLoadRecord.albumLPath;
    if (hidden == 1) {
        data["albumId"] = MDKRecordField("default-album-4");
    } else if (!albumCloudId.empty()) {
        data["albumId"] = MDKRecordField(albumCloudId);
    }
    MEDIA_INFO_LOG("SetUpdateSourceAlbum Hidden:%{public}d, albumCloudId:%{public}s, albumLPath::%{public}s",
        hidden,
        albumCloudId.c_str(),
        albumLPath.c_str());
    data["isLogic"] = MDKRecordField(false);
    if (!hidden && albumCloudId.empty()) {
        record.SetRecordData(data);
        MEDIA_ERR_LOG("visible media, but albumid is empty");
        return E_CLOUD_SYNC_DATA;
    }
    if (!albumLPath.empty()) {
        if (data.find(FILE_PROPERTIES) == data.end()) {
            MEDIA_ERR_LOG("record data donnot have properties set");
            record.SetRecordData(data);
            return E_CLOUD_SYNC_DATA;
        }
        std::map<std::string, MDKRecordField> properties = data[FILE_PROPERTIES];
        std::string sourcePath;
        if (albumCloudId == "default-album-2") {
            sourcePath = SCREENSHOT_ALBUM_PATH + displayName;
        } else {
            sourcePath = "/storage/emulated/0" + albumLPath + "/" + displayName;
        }
        properties.erase("sourcePath");
        properties["sourcePath"] = MDKRecordField(sourcePath);
        data[FILE_PROPERTIES] = MDKRecordField(properties);
    }
    record.SetRecordData(data);
    return E_OK;
}

int32_t CloudFileDataConvert::InsertAlbumIdChanges(MDKRecord &record, std::vector<MDKRecord> &records,
    const CloudMdkRecordPhotosVo &upLoadRecord)
{
    MDKRecord tmp = record;
    std::map<std::string, MDKRecordField> data;
    tmp.GetRecordData(data);
    std::string albumCloudId;
    if (data.find("albumId") == data.end() ||
        data["albumId"].GetString(albumCloudId) != MDKLocalErrorCode::NO_ERROR) {
        MEDIA_ERR_LOG("get albumId failed");
    }
    std::vector<MDKRecordField> rmList;
    /* remove */
    std::vector<std::string> removeId = upLoadRecord.removeAlbumCloudId;
    for (auto &id : removeId) {
            rmList.push_back(MDKRecordField(MDKReference{ id, "album" }));
    }
    if (!rmList.empty()) {
        data.erase("albumId");
        data["isLogic"] = MDKRecordField(true);
        data["FILE_RM_LOGIC_ALBUM_IDS"] = MDKRecordField(rmList);
        tmp.SetRecordData(data);
        records.push_back(tmp);
    }
    return E_OK;
}

int32_t CloudFileDataConvert::ConvertToMdkRecord(const CloudMdkRecordPhotosVo &upLoadRecord, MDKRecord &record)
{
    MEDIA_INFO_LOG("CloudFileDataConvert::ConvertToMdkRecord type:%{public}d, cloudId: %{public}s",
        static_cast<int32_t>(type_), upLoadRecord.cloudId.c_str());
    record.SetRecordType(recordType_);
    if (type_ == CloudOperationType::FILE_CREATE) {
        record.SetNewCreate(true);
    }
    record.SetRecordId(upLoadRecord.cloudId);
    if (type_ == CloudOperationType::FILE_DELETE) {
        return E_OK;
    }
    std::map<std::string, MDKRecordField> data;
    int32_t ret = HandleUniqueFileds(data, upLoadRecord);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CloudFileDataConvert::ConvertToMdkRecord failed to handle HandleUniqueFileds");
        return ret;
    }
    ret = HandleCompatibleFileds(data, upLoadRecord);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CloudFileDataConvert::ConvertToMdkRecord failed to handle CompatibleFileds");
        return ret;
    }
    record.SetRecordData(data);
    ret = SetUpdateSourceAlbum(record, upLoadRecord);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CloudFileDataConvert::ConvertToMdkRecord failed to SetUpdateSourceAlbum");
        return ret;
    }
    return E_OK;
}

int32_t CloudFileDataConvert::BuildCopyRecord(const std::string &cloudId, const MDKRecordOperResult &result,
    OnCopyRecord &record)
{
    MDKRecordPhotosData photosData = MDKRecordPhotosData(result.GetDKRecord());
    std::optional<std::string> optionalCloudId = photosData.GetCloudId();
    record.cloudId = cloudId;
    std::optional<std::string> optPath = photosData.GetFilePath();
    record.path = optPath.value_or("");
    std::optional<int32_t> optFileId = photosData.GetFileId();
    record.fileId = optFileId.value_or(-1);
    std::optional<std::string> optFileName = photosData.GetFileName();
    record.fileName = optFileName.value_or("");
    std::optional<int64_t> optSize = photosData.GetSize();
    record.size = optSize.value_or(-1);
    std::optional<int64_t> optSingleEditTime = photosData.GetDateModified().value_or(0);
    int64_t singleEditTime = optSingleEditTime.value();
    int64_t dualEditTime = static_cast<int64_t>(result.GetDKRecord().GetEditedTime());
    record.modifyTime = dualEditTime > singleEditTime ? dualEditTime : singleEditTime;
    record.createTime = static_cast<int64_t>(result.GetDKRecord().GetCreateTime());
    int32_t rotate = photosData.GetRotate().value_or(ORIENTATION_NORMAL);
    if (FILE_ROTATIONS.find(rotate) != FILE_ROTATIONS.end()) {
        record.rotation = FILE_ROTATIONS.find(rotate)->second;
    }
    std::optional<int32_t> optFileType = photosData.GetFileType();
    record.fileType = optFileType.value_or(-1);
    std::optional<std::string> optSourcePath = photosData.GetSourcePath();
    record.sourcePath = optSourcePath.value_or("");
    record.version = result.GetDKRecord().GetVersion();
    record.serverErrorCode = result.GetDKError().serverErrorCode;
    record.errorType = static_cast<ErrorType>(static_cast<int32_t>(result.GetDKError().errorType));
    record.isSuccess = result.IsSuccess();
    ConvertErrorTypeDetails(result, record.errorDetails);
    return E_OK;
}

void CloudFileDataConvert::ConvertErrorTypeDetails(
    const MDKRecordOperResult &result, std::vector<CloudErrorDetail> &errorDetails)
{
    auto errorType = result.GetDKError();
    if (errorType.errorDetails.empty()) {
        return;
    }
    for (const auto &element : errorType.errorDetails) {
        CloudErrorDetail detail;
        detail.domain = element.domain;
        detail.reason = element.reason;
        detail.errorCode = element.errorCode;
        detail.description = element.description;
        detail.errorPos = element.errorPos;
        detail.errorParam = element.errorParam;
        detail.detailCode = element.detailCode;
        errorDetails.push_back(detail);
    }
}

int32_t CloudFileDataConvert::BuildModifyRecord(const std::string &cloudId, const MDKRecordOperResult &result,
    OnModifyRecord &record)
{
    MDKRecordPhotosData photosData = MDKRecordPhotosData(result.GetDKRecord());
    std::optional<std::string> optionalCloudId = photosData.GetCloudId();
    record.cloudId = cloudId;
    std::optional<std::string> optPath = photosData.GetFilePath();
    record.path = optPath.value_or("");
    std::optional<int32_t> optFileId = photosData.GetFileId();
    record.fileId = optFileId.value_or(-1);
    std::optional<int64_t> optSingleEditTime = photosData.GetDateModified().value_or(0);
    int64_t singleEditTime = optSingleEditTime.value();
    int64_t dualEditTime = static_cast<int64_t>(result.GetDKRecord().GetEditedTime());
    record.modifyTime = dualEditTime > singleEditTime ? dualEditTime : singleEditTime;
    record.metaDateModified = photosData.GetPhotoMetaDateModified().value_or(-1);
    record.version = result.GetDKRecord().GetVersion();
    record.isSuccess = result.IsSuccess();
    record.serverErrorCode = result.GetDKError().serverErrorCode;
    ConvertErrorTypeDetails(result, record.errorDetails);
    return E_OK;
}

int32_t CloudFileDataConvert::ConvertFdirtyRecord(const std::string &cloudId, const MDKRecordOperResult &result,
    OnFileDirtyRecord &record)
{
    MDKRecordPhotosData photosData = MDKRecordPhotosData(result.GetDKRecord());
    record.cloudId = cloudId;
    auto metaDateModifiedOpt = photosData.GetPhotoMetaDateModified();
    if (metaDateModifiedOpt.has_value()) {
        record.metaDateModified = metaDateModifiedOpt.value();
    } else {
        record.metaDateModified = -1;
    }
    record.isSuccess = result.IsSuccess();
    record.version = result.GetDKRecord().GetVersion();
    record.serverErrorCode = result.GetDKError().serverErrorCode;
    ConvertErrorTypeDetails(result, record.errorDetails);
    return E_OK;
}

int32_t CloudFileDataConvert::ConvertToOnCreateRecord(const std::string &cloudId, const MDKRecordOperResult &result,
    OnCreateRecord &record)
{
    MDKRecordPhotosData photosData = MDKRecordPhotosData(result.GetDKRecord());
    record.cloudId = cloudId;
    record.fileId = photosData.GetFileId().value_or(-1);
    record.path = photosData.GetFilePath().value_or("");
    record.fileName = photosData.GetFileName().value_or("");
    record.localId = photosData.GetLocalId().value_or(-1);
    record.fileType = photosData.GetFileType().value_or(-1);
    record.size = photosData.GetSize().value_or(-1);
    record.createTime = photosData.GetCreatedTime().value_or(-1);
    record.editedTimeMs = photosData.GetEditTimeMs().value_or(-1);
    record.metaDateModified = photosData.GetPhotoMetaDateModified().value_or(-1);
    record.version = result.GetDKRecord().GetVersion();
    record.isSuccess = result.IsSuccess();
    record.livePhotoCachePath = MovingPhotoFileUtils::GetLivePhotoCachePath(record.path, userId_);
    record.serverErrorCode = result.GetDKError().serverErrorCode;
    ConvertErrorTypeDetails(result, record.errorDetails);
    return E_OK;
}

int32_t CloudFileDataConvert::ConverMDKRecordToOnFetchPhotosVo(const MDKRecord &mdkRecord,
    OnFetchPhotosVo &onFetchPhotoVo)
{
    MDKRecordPhotosData photosData = MDKRecordPhotosData(mdkRecord);
    onFetchPhotoVo.cloudId = mdkRecord.GetRecordId();
    onFetchPhotoVo.fileId = photosData.GetCloudFileId().value_or(0L);
    onFetchPhotoVo.fileName = photosData.GetFileName().value_or("");
    onFetchPhotoVo.localPath = photosData.GetFilePath().value_or("");
    onFetchPhotoVo.size = photosData.GetSize().value_or(0L);
    onFetchPhotoVo.lcdSize = photosData.GetLcdSize().value_or(0L);
    onFetchPhotoVo.thmSize = photosData.GetThmSize().value_or(0L);
    onFetchPhotoVo.metaDateModified = photosData.GetPhotoMetaDateModified().value_or(0L);
    onFetchPhotoVo.editedTimeMs = photosData.GetEditTimeMs().value_or(0L);
    onFetchPhotoVo.dualEditTime = static_cast<int64_t>(mdkRecord.GetEditedTime());
    onFetchPhotoVo.createTime = static_cast<int64_t>(mdkRecord.GetCreateTime());
    int32_t rotate = photosData.GetRotate().value_or(ORIENTATION_NORMAL);
    CHECK_AND_RETURN_RET_WARN_LOG(!(FILE_ROTATIONS.find(rotate) == FILE_ROTATIONS.end()), 9, "not find mdkRecord Rotate");
    onFetchPhotoVo.rotation = FILE_ROTATIONS.find(rotate)->second;
    onFetchPhotoVo.fileType = photosData.GetFileType().value_or(0L);
    onFetchPhotoVo.fileSourcePath = photosData.GetSourcePath().value_or("");
    onFetchPhotoVo.fixVersion = photosData.GetFixVersion().value_or(0);
    onFetchPhotoVo.version = mdkRecord.GetVersion();
    onFetchPhotoVo.isDelete = mdkRecord.GetIsDelete();
    onFetchPhotoVo.hasAttributes = true;
    onFetchPhotoVo.hasproperties = true;
    onFetchPhotoVo.firstVisitTime = photosData.GetFirstUpdateTime().value_or("");
    onFetchPhotoVo.mimeType = photosData.GetMimeType().value_or("");
    onFetchPhotoVo.isFavorite = photosData.GetFavorite().value_or(false);
    onFetchPhotoVo.isRecycle = photosData.GetRecycled().value_or(false);
    if (onFetchPhotoVo.isRecycle) {
        onFetchPhotoVo.recycledTime = photosData.GetRecycledTime().value_or(0L);
    }
    onFetchPhotoVo.photoHeight = photosData.GetHeight().value_or(0);
    onFetchPhotoVo.photoWidth = photosData.GetWidth().value_or(0);
    onFetchPhotoVo.detailTime = photosData.GetDetailTime().value_or("");
    onFetchPhotoVo.frontCamera = photosData.GetFrontCamera().value_or("");
    onFetchPhotoVo.editDataCamera = photosData.GetEditDataCamera().value_or("");
    onFetchPhotoVo.title = photosData.GetTitle().value_or("");
    onFetchPhotoVo.mediaType = photosData.GetMediaType().value_or(0);
    onFetchPhotoVo.duration = photosData.GetDuration().value_or(0);
    onFetchPhotoVo.hidden = photosData.GetHidden().value_or(0);
    onFetchPhotoVo.hiddenTime = photosData.GetHiddenTime().value_or(0L);
    onFetchPhotoVo.relativePath = photosData.GetRelativePath().value_or("");
    onFetchPhotoVo.virtualPath = photosData.GetVirtualPath().value_or("");
    onFetchPhotoVo.dateYear = photosData.GetDateYear().value_or("");
    onFetchPhotoVo.dateMonth = photosData.GetDateMonth().value_or("");
    onFetchPhotoVo.dateDay = photosData.GetDateDay().value_or("");
    onFetchPhotoVo.shootingMode = photosData.GetShootingMode().value_or("");
    onFetchPhotoVo.shootingModeTag = photosData.GetShootingModeTag().value_or("");
    onFetchPhotoVo.burstKey = photosData.GetBurstKey().value_or("");
    onFetchPhotoVo.burstCoverLevel = photosData.GetBurstCoverLevel().value_or(0L);
    onFetchPhotoVo.subtype = photosData.GetSubType().value_or(0);
    onFetchPhotoVo.originalSubtype = photosData.GetOriginalSubType().value_or(0);
    onFetchPhotoVo.dynamicRangeType = photosData.GetDynamicRangeType().value_or(0);
    onFetchPhotoVo.movingPhotoEffectMode = photosData.GetMovingPhotoEffectMode().value_or(0);
    onFetchPhotoVo.editTime = photosData.GetEditTime().value_or(0);
    onFetchPhotoVo.coverPosition = photosData.GetCoverPosition().value_or(0);
    onFetchPhotoVo.position = photosData.GetPosition().value_or("");
    onFetchPhotoVo.description = photosData.GetDescription().value_or("");
    onFetchPhotoVo.source = photosData.GetSource().value_or("");
    onFetchPhotoVo.supportedWatermarkType = photosData.GetSupportedWatermarkType().value_or(0);
    onFetchPhotoVo.strongAssociation = photosData.GetStrongAssociation().value_or(0);
    std::map<std::string, MDKRecordField> data;
    std::vector<MDKRecordField> list;
    mdkRecord.GetRecordData(data);
    if (data.find("albumIds") != data.end()) {
        if (data["albumIds"].GetRecordList(list) != MDKLocalErrorCode::NO_ERROR) {
            MEDIA_WARN_LOG("cannot get album ids from record");
        }
    } else {
        MEDIA_WARN_LOG("not find albumIds from record");
    }
    if (list.size() > 0) {
        for (const auto &it : list) {
            MDKReference ref;
            if (it.GetReference(ref) != MDKLocalErrorCode::NO_ERROR) {
                continue;
            }
            onFetchPhotoVo.sourceAlbumIds.emplace_back(ref.recordId);
        }
    } else {
        MEDIA_WARN_LOG("albumIds list size is 0");
    }
    return E_OK;
}
}  // namespace OHOS::Media::CloudSync