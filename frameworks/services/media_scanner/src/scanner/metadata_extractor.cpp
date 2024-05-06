/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Scanner"

#include "metadata_extractor.h"

#include <fcntl.h>
#include "hitrace_meter.h"
#include "media_exif.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "nlohmann/json.hpp"
#include "sandbox_helper.h"

namespace OHOS {
namespace Media {
using namespace std;

const double DEGREES2MINUTES = 60.0;
const double DEGREES2SECONDS = 3600.0;
constexpr int32_t OFFSET_NUM = 2;

template <class Type>
static Type stringToNum(const string &str)
{
    std::istringstream iss(str);
    Type num;
    iss >> num;
    return num;
}

double GetLongitudeLatitude(string inputStr, const string& ref = "")
{
    auto pos = inputStr.find(',');
    if (pos == string::npos) {
        return 0;
    }
    double ret = stringToNum<double>(inputStr.substr(0, pos));

    inputStr = inputStr.substr(pos + OFFSET_NUM);
    pos = inputStr.find(',');
    if (pos == string::npos) {
        return 0;
    }
    ret += stringToNum<double>(inputStr.substr(0, pos)) / DEGREES2MINUTES;

    inputStr = inputStr.substr(pos + OFFSET_NUM);
    ret += stringToNum<double>(inputStr) / DEGREES2SECONDS;
    return (ref.compare("W") == 0 || ref.compare("S") == 0) ? -ret : ret;
}

static time_t convertTimeStr2TimeStamp(string &timeStr)
{
    struct tm timeinfo;
    strptime(timeStr.c_str(), "%Y-%m-%d %H:%M:%S",  &timeinfo);
    time_t timeStamp = mktime(&timeinfo);
    return timeStamp;
}

static string GetCastShootingMode(string &shootingModeTag)
{
    auto it = SHOOTING_MODE_CAST_MAP.find(shootingModeTag);
    if (it != SHOOTING_MODE_CAST_MAP.end()) {
        return it->second;
    }
    return "";
}

static string GetCompatibleUserComment(const string& userComment)
{
    const string startFlag = "<mgzn-content>";
    const string endFlag = "<mgzn-worksdes>";
    size_t posStart = userComment.find(startFlag);
    size_t posEnd = userComment.find(endFlag);
    if (posStart == string::npos || posEnd == string::npos || posStart >= posEnd) {
        return userComment;
    }

    posStart += startFlag.length();
    return userComment.substr(posStart, posEnd - posStart);
}

int32_t MetadataExtractor::ExtractImageExif(std::unique_ptr<ImageSource> &imageSource, std::unique_ptr<Metadata> &data)
{
    if (imageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain image source");
        return E_OK;
    }

    int32_t intTempMeta = 0;
    string propertyStr;
    uint32_t err;
    try {
        nlohmann::json exifJson;
        err = imageSource->GetImagePropertyInt(0, PHOTO_DATA_IMAGE_ORIENTATION, intTempMeta);
        exifJson[PHOTO_DATA_IMAGE_ORIENTATION] = (err == 0) ? intTempMeta: 0;

        err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_LONGITUDE, propertyStr);
        exifJson[PHOTO_DATA_IMAGE_GPS_LONGITUDE] = (err == 0) ? GetLongitudeLatitude(propertyStr): 0;

        err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_LATITUDE, propertyStr);
        exifJson[PHOTO_DATA_IMAGE_GPS_LATITUDE] = (err == 0) ? GetLongitudeLatitude(propertyStr): 0;

        for (auto &exifKey : exifInfoKeys) {
            err = imageSource->GetImagePropertyString(0, exifKey, propertyStr);
            exifJson[exifKey] = (err == 0) ? propertyStr: "";
        }
        exifJson[PHOTO_DATA_IMAGE_IMAGE_DESCRIPTION] =
            AppFileService::SandboxHelper::Encode(exifJson[PHOTO_DATA_IMAGE_IMAGE_DESCRIPTION]);
        data->SetAllExif(exifJson.dump());
    } catch (std::system_error &e) {
        MEDIA_ERR_LOG("exception, err: %{public}s", e.what());
    }

    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_USER_COMMENT, propertyStr);
    if (err == 0) {
        data->SetUserComment(GetCompatibleUserComment(propertyStr));
    }
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_PHOTO_MODE, propertyStr);
    if (err == 0 && !propertyStr.empty()) {
        data->SetShootingModeTag(propertyStr);
        data->SetShootingMode(GetCastShootingMode(propertyStr));
    }

    int64_t timeNow = MediaFileUtils::UTCTimeMilliSeconds();
    data->SetLastVisitTime(timeNow);

    return E_OK;
}

static void ExtractLocationMetadata(unique_ptr<ImageSource>& imageSource, unique_ptr<Metadata>& data)
{
    string propertyStr;
    string refStr;
    double tempLocation = -1;
    uint32_t err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_LONGITUDE, propertyStr);
    uint32_t refErr = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_LONGITUDE_REF, refStr);
    if (err == 0 && refErr == 0) {
        tempLocation = GetLongitudeLatitude(propertyStr, refStr);
        data->SetLongitude(tempLocation);
    }

    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_LATITUDE, propertyStr);
    refErr = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_LATITUDE_REF, refStr);
    if (err == 0 && refErr == 0) {
        tempLocation = GetLongitudeLatitude(propertyStr, refStr);
        data->SetLatitude(tempLocation);
    }
}

int32_t MetadataExtractor::ExtractImageMetadata(std::unique_ptr<Metadata> &data)
{
    uint32_t err = 0;

    SourceOptions opts;
    opts.formatHint = "image/" + data->GetFileExtension();
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data->GetFilePath(), opts, err);
    if (err != 0 || imageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain image source, err = %{public}d", err);
        return E_OK;
    }

    ImageInfo imageInfo;
    err = imageSource->GetImageInfo(0, imageInfo);
    if (err == 0) {
        data->SetFileWidth(imageInfo.size.width);
        data->SetFileHeight(imageInfo.size.height);
    } else {
        MEDIA_ERR_LOG("Failed to get image info, err = %{public}d", err);
    }

    string propertyStr;
    int64_t int64TempMeta = 0;
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_DATE_TIME_ORIGINAL_FOR_MEDIA, propertyStr);
    if (err == 0) {
        int64TempMeta = convertTimeStr2TimeStamp(propertyStr);
        if (int64TempMeta < 0) {
            data->SetDateTaken(data->GetFileDateModified() / MSEC_TO_SEC);
        } else {
            data->SetDateTaken(int64TempMeta);
        }
    } else {
        // use modified time as date taken time when date taken not set
        data->SetDateTaken(data->GetFileDateModified() / MSEC_TO_SEC);
    }

    int32_t intTempMeta = 0;
    err = imageSource->GetImagePropertyInt(0, PHOTO_DATA_IMAGE_ORIENTATION, intTempMeta);
    if (err == 0) {
        data->SetOrientation(intTempMeta);
    }

    ExtractLocationMetadata(imageSource, data);
    ExtractImageExif(imageSource, data);
    return E_OK;
}

static std::string ExtractVideoShootingMode(const std::string &genreJson)
{
    if (genreJson.empty()) {
        return "";
    }
    size_t pos = genreJson.find("param-use-tag");
    if (pos != std::string::npos) {
        size_t start = genreJson.find(":", pos);
        size_t end = genreJson.find(",", pos);
        if (end == std::string::npos) {
            end = genreJson.find("}", pos);
        }
        return genreJson.substr(start + 1, end - start - 1); // 1: length offset
    }
    return "";
}

void PopulateExtractedAVMetadataOne(const std::unordered_map<int32_t, std::string> &resultMap,
    std::unique_ptr<Metadata> &data)
{
    int32_t intTempMeta;

    string strTemp = resultMap.at(AV_KEY_ALBUM);
    if (strTemp != "") {
        data->SetAlbum(strTemp);
    }

    strTemp = resultMap.at(AV_KEY_ARTIST);
    if (strTemp != "") {
        data->SetFileArtist(strTemp);
    }

    strTemp = resultMap.at(AV_KEY_DURATION);
    if (strTemp != "") {
        intTempMeta = stringToNum<int32_t>(strTemp);
        data->SetFileDuration(intTempMeta);
    }

    strTemp = resultMap.at(AV_KEY_VIDEO_HEIGHT);
    if (strTemp != "") {
        intTempMeta = stringToNum<int32_t>(strTemp);
        data->SetFileHeight(intTempMeta);
    }

    strTemp = resultMap.at(AV_KEY_VIDEO_WIDTH);
    if (strTemp != "") {
        intTempMeta = stringToNum<int32_t>(strTemp);
        data->SetFileWidth(intTempMeta);
    }

    strTemp = resultMap.at(AV_KEY_MIME_TYPE);
    if (strTemp != "") {
        data->SetFileMimeType(strTemp);
    }
}

void PopulateExtractedAVMetadataTwo(const std::unordered_map<int32_t, std::string> &resultMap,
    std::unique_ptr<Metadata> &data)
{
    int32_t intTempMeta;

    string strTemp = resultMap.at(AV_KEY_DATE_TIME_FORMAT);
    if (strTemp != "") {
        int64_t int64TempMeta = convertTimeStr2TimeStamp(strTemp);
        if (int64TempMeta < 0) {
            data->SetDateTaken(data->GetFileDateModified() / MSEC_TO_SEC);
        } else {
            data->SetDateTaken(int64TempMeta);
        }
    } else {
        // use modified time as date taken time when date taken not set
        data->SetDateTaken(data->GetFileDateModified() / MSEC_TO_SEC);
    }

    strTemp = resultMap.at(AV_KEY_VIDEO_ORIENTATION);
    if (strTemp == "") {
        intTempMeta = 0;
    } else {
        intTempMeta = stringToNum<int32_t>(strTemp);
    }
    data->SetOrientation(intTempMeta);

    strTemp = resultMap.at(AV_KEY_TITLE);
    if (!strTemp.empty()) {
        data->SetFileTitle(strTemp);
    }
    strTemp = resultMap.at(AV_KEY_GENRE);
    if (!strTemp.empty()) {
        std::string videoShootingMode = ExtractVideoShootingMode(strTemp);
        data->SetShootingMode(videoShootingMode);
    }
}

void MetadataExtractor::FillExtractedMetadata(const std::unordered_map<int32_t, std::string> &resultMap,
    std::unique_ptr<Metadata> &data)
{
    PopulateExtractedAVMetadataOne(resultMap, data);
    PopulateExtractedAVMetadataTwo(resultMap, data);
    
    int64_t timeNow = MediaFileUtils::UTCTimeMilliSeconds();
    data->SetLastVisitTime(timeNow);
}

int32_t MetadataExtractor::ExtractAVMetadata(std::unique_ptr<Metadata> &data)
{
    MediaLibraryTracer tracer;
    tracer.Start("ExtractAVMetadata");

    tracer.Start("CreateAVMetadataHelper");
    std::shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    tracer.Finish();
    if (avMetadataHelper == nullptr) {
        MEDIA_ERR_LOG("AV metadata helper is null");
        return E_AVMETADATA;
    }

    string filePath = data->GetFilePath();
    if (filePath.empty()) {
        MEDIA_ERR_LOG("AV metadata file path is empty");
        return E_AVMETADATA;
    }

    int32_t fd = open(filePath.c_str(), O_RDONLY);
    if (fd <= 0) {
        MEDIA_ERR_LOG("Open file descriptor failed, errno = %{public}d", errno);
        return E_SYSCALL;
    }
    struct stat64 st;
    if (fstat64(fd, &st) != 0) {
        MEDIA_ERR_LOG("Get file state failed for the given fd");
        (void)close(fd);
        return E_SYSCALL;
    }
    data->SetFileSize(st.st_size);

    tracer.Start("avMetadataHelper->SetSource");
    int32_t err = avMetadataHelper->SetSource(fd, 0, static_cast<int64_t>(st.st_size), AV_META_USAGE_META_ONLY);
    tracer.Finish();
    if (err != 0) {
        MEDIA_ERR_LOG("SetSource failed for the given file descriptor, err = %{public}d", err);
        (void)close(fd);
        return E_AVMETADATA;
    } else {
        tracer.Start("avMetadataHelper->ResolveMetadata");
        std::unordered_map<int32_t, std::string> resultMap = avMetadataHelper->ResolveMetadata();
        tracer.Finish();
        if (!resultMap.empty()) {
            FillExtractedMetadata(resultMap, data);
        }
    }

    (void)close(fd);

    return E_OK;
}

int32_t MetadataExtractor::CombineMovingPhotoMetadata(std::unique_ptr<Metadata> &data)
{
    // if video of moving photo does not exist, just return
    string videoPath = MediaFileUtils::GetMovingPhotoVideoPath(data->GetFilePath());
    if (!MediaFileUtils::IsFileExists(videoPath)) {
        MEDIA_INFO_LOG("Video of moving photo does not exist, path: %{private}s", videoPath.c_str());
        return E_OK;
    }

    unique_ptr<Metadata> videoData = make_unique<Metadata>();
    videoData->SetFilePath(videoPath);
    int32_t err = ExtractAVMetadata(videoData);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to extract video metadata for moving photo: %{private}s", videoPath.c_str());
        return err;
    }

    data->SetFileSize(data->GetFileSize() + videoData->GetFileSize());
    int64_t videoDateModified = videoData->GetFileDateModified();
    if (videoDateModified > data->GetFileDateModified()) {
        data->SetFileDateModified(videoDateModified);
    }

    int32_t duration = videoData->GetFileDuration();
    if (!MediaFileUtils::CheckMovingPhotoVideoDuration(duration)) {
        MEDIA_ERR_LOG("Failed to check video duration (%{public}d ms) of moving photo", duration);
        return E_MOVING_PHOTO;
    }
    return E_OK;
}

int32_t MetadataExtractor::Extract(std::unique_ptr<Metadata> &data)
{
    if (data->GetFileMediaType() == MEDIA_TYPE_IMAGE) {
        int32_t ret = ExtractImageMetadata(data);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Failed to extract image metadata");
        if (data->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            return CombineMovingPhotoMetadata(data);
        }
        return ret;
    } else {
        return ExtractAVMetadata(data);
    }
}
} // namespace Media
} // namespace OHOS
