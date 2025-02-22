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
#include "directory_ex.h"
#include "hitrace_meter.h"
#include "media_exif.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "meta.h"
#include "meta_key.h"
#include "nlohmann/json.hpp"
#include "sandbox_helper.h"
#include "shooting_mode_column.h"
#include "moving_photo_file_utils.h"
#include "directory_ex.h"

namespace OHOS {
namespace Media {
using namespace std;

const double DEGREES2MINUTES = 60.0;
const double DEGREES2SECONDS = 3600.0;
constexpr int32_t OFFSET_NUM = 2;
constexpr int32_t HOURSTOSECOND = 60 * 60;
constexpr int32_t MINUTESTOSECOND = 60;
const string ZEROTIMESTRING = "0000:00:00 00:00:00";

static const std::unordered_map<std::string, std::string> SHOOTING_MODE_CAST_MAP = {
    {PORTRAIT_ALBUM_TAG, PORTRAIT_ALBUM},
    {WIDE_APERTURE_ALBUM_TAG, WIDE_APERTURE_ALBUM},
    {NIGHT_SHOT_ALBUM_TAG, NIGHT_SHOT_ALBUM},
    {REAR_CAMERA_NIGHT_SHOT_TAG, NIGHT_SHOT_ALBUM},
    {MOVING_PICTURE_ALBUM_TAG, MOVING_PICTURE_ALBUM},
    {PRO_PHOTO_ALBUM_TAG, PRO_PHOTO_ALBUM},
    {TAIL_LIGHT_ALBUM_TAG, LIGHT_PAINTING_ALBUM},
    {LIGHT_GRAFFITI_TAG, LIGHT_PAINTING_ALBUM},
    {SILKY_WATER_TAG, LIGHT_PAINTING_ALBUM},
    {STAR_TRACK_TAG, LIGHT_PAINTING_ALBUM},
    {HIGH_PIXEL_ALBUM_TAG, HIGH_PIXEL_ALBUM},
    {SUPER_MACRO_ALBUM_TAG, SUPER_MACRO_ALBUM},
    {SLOW_MOTION_ALBUM_TAG, SLOW_MOTION_ALBUM},
    {SUPER_SLOW_MOTION_ALBUM_TAG, SLOW_MOTION_ALBUM},
};

template <class Type>
static Type stringToNum(const string &str)
{
    std::istringstream iss(str);
    Type num;
    iss >> num;
    return num;
}

static bool IsMovingPhoto(unique_ptr<Metadata> &data)
{
    return data->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO) ||
        data->GetMovingPhotoEffectMode() == static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY);
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

/* used for video */
static time_t convertTimeStr2TimeStamp(string &timeStr)
{
    struct tm timeinfo;
    strptime(timeStr.c_str(), "%Y-%m-%d %H:%M:%S",  &timeinfo);
    time_t timeStamp = mktime(&timeinfo);
    return timeStamp;
}

/* used for Image */
static time_t convertTimeStrToTimeStamp(string &timeStr)
{
    struct tm timeinfo;
    strptime(timeStr.c_str(), "%Y:%m:%d %H:%M:%S",  &timeinfo);
    time_t timeStamp = mktime(&timeinfo);
    return timeStamp;
}

static time_t convertUTCTimeStrToTimeStamp(string &timeStr)
{
    struct tm timeinfo;
    strptime(timeStr.c_str(), "%Y:%m:%d %H:%M:%S", &timeinfo);
    time_t convertOnceTime = mktime(&timeinfo);
    time_t convertTwiceTime = mktime(gmtime(&convertOnceTime));
    if (convertOnceTime == -1 || convertTwiceTime == -1) {
        return 0;
    }
    time_t offset = convertOnceTime - convertTwiceTime;
    time_t utcTimeStamp = convertOnceTime + offset;
    return utcTimeStamp;
}

static int32_t offsetTimeToSeconds(const string& offsetStr, int32_t& offsetTime)
{
    char sign = offsetStr[0];
    const int32_t offsetTimeSize = 6;
    if (offsetStr.size() != offsetTimeSize || (sign != '+' && sign != '-')) {
        MEDIA_WARN_LOG("Invalid offset format, Offset string must be in format +HH:MM or -HH:MM");
        return E_ERR;
    }

    const int32_t colonPosition = 3;
    for (size_t i = 1; i < offsetStr.size(); i++) {
        if (i == colonPosition) {
            continue;
        }
        if (!isdigit(offsetStr[i])) {
            MEDIA_WARN_LOG("Invalid hour or minute format");
            return E_ERR;
        }
    }
    int32_t hours = stoi(offsetStr.substr(1, 2));
    int32_t minutes = stoi(offsetStr.substr(colonPosition + 1, 2));

    int totalSeconds = hours * HOURSTOSECOND + minutes * MINUTESTOSECOND;
    offsetTime = (sign == '-') ? totalSeconds : -totalSeconds;
    MEDIA_DEBUG_LOG("get offset success offsetTime=%{public}d", offsetTime);
    return E_OK;
}

static void setSubSecondTime(unique_ptr<ImageSource>& imageSource, int64_t& timeStamp)
{
    uint32_t err = E_ERR;
    string subTimeString;
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_SUBSEC_TIME_ORIGINAL, subTimeString);
    if (err == E_OK && !subTimeString.empty()) {
        for (size_t i = 0; i < subTimeString.size(); i++) {
            if (!isdigit(subTimeString[i])) {
                MEDIA_WARN_LOG("Invalid subTime format");
                return;
            }
        }
        int32_t subTime = 0;
        const int32_t subTimeSize = 3;
        if (subTimeString.size() > subTimeSize) {
            subTime = stoi(subTimeString.substr(0, subTimeSize));
        } else {
            subTime = stoi(subTimeString);
        }
        timeStamp = timeStamp + subTime;
        MEDIA_DEBUG_LOG("Set subTime from SubsecTimeOriginal in exif");
    } else {
        MEDIA_DEBUG_LOG("get SubsecTimeOriginalNot fail ,Not Set subTime");
    }
}

static void ExtractDetailTimeMetadata(unique_ptr<ImageSource>& imageSource, unique_ptr<Metadata>& data)
{
    uint32_t err = E_ERR;
    string timeString;
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_DATE_TIME_ORIGINAL, timeString);
    if (err == E_OK && !timeString.empty() && timeString.compare(ZEROTIMESTRING) != 0) {
        data->SetDetailTime(timeString);
        MEDIA_DEBUG_LOG("Set detail_time from DateTimeOriginal in exif");
        return;
    }
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_DATE_TIME, timeString);
    if (err == E_OK && !timeString.empty() && timeString.compare(ZEROTIMESTRING) != 0) {
        data->SetDetailTime(timeString);
        MEDIA_DEBUG_LOG("Set detail_time from DateTime in exif");
        return;
    }
    int64_t dateTaken = data->GetDateTaken() / MSEC_TO_SEC;
    data->SetDetailTime(MediaFileUtils::StrCreateTime(PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken));
}

static void GetDateTakenByExif(unique_ptr<ImageSource>& imageSource, int64_t& timeStamp)
{
    string dateString;
    string timeString;
    int32_t offsetTime = 0;
    string offsetString;
    uint32_t err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_DATE_TIME_ORIGINAL, timeString);
    if (err == E_OK && !timeString.empty() && timeString.compare(ZEROTIMESTRING) != 0) {
        err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_OFFSET_TIME_ORIGINAL, offsetString);
        if (err == E_OK && offsetTimeToSeconds(offsetString, offsetTime) == E_OK) {
            timeStamp = (convertUTCTimeStrToTimeStamp(timeString) + offsetTime) * MSEC_TO_SEC;
            MEDIA_DEBUG_LOG("Set date_taken from DateTimeOriginal and OffsetTimeOriginal in exif");
        } else {
            timeStamp = (convertTimeStrToTimeStamp(timeString)) * MSEC_TO_SEC;
            MEDIA_DEBUG_LOG("Set date_taken from DateTimeOriginal in exif");
        }
        if (timeStamp > 0) {
            return;
        }
    }
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_DATE_TIME, timeString);
    if (err == E_OK && !timeString.empty() && timeString.compare(ZEROTIMESTRING) != 0) {
        err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_OFFSET_TIME_ORIGINAL, offsetString);
        if (err == E_OK && offsetTimeToSeconds(offsetString, offsetTime) == E_OK) {
            timeStamp = (convertUTCTimeStrToTimeStamp(timeString) + offsetTime) * MSEC_TO_SEC;
            MEDIA_DEBUG_LOG("Set date_taken from DateTime and OffsetTimeOriginal in exif");
        } else {
            timeStamp = (convertTimeStrToTimeStamp(timeString)) * MSEC_TO_SEC;
            MEDIA_DEBUG_LOG("Set date_taken from DateTime in exif");
        }
        if (timeStamp > 0) {
            return;
        }
    }
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_DATE_STAMP, dateString);
    if (err == E_OK && !dateString.empty()) {
        err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_TIME_STAMP, timeString);
        string fullTimeString = dateString + " " + timeString;
        if (err == E_OK && !timeString.empty() && fullTimeString.compare(ZEROTIMESTRING) != 0) {
            timeStamp = convertUTCTimeStrToTimeStamp(fullTimeString) * MSEC_TO_SEC;
            MEDIA_DEBUG_LOG("Set date_taken from GPSTimeStamp in exif");
            return;
        }
    }
}

static void ExtractDateTakenMetadata(unique_ptr<ImageSource>& imageSource, unique_ptr<Metadata>& data)
{
    int64_t timeStamp = 0;
    GetDateTakenByExif(imageSource, timeStamp);
    if (timeStamp > 0) {
        setSubSecondTime(imageSource, timeStamp);
        data->SetDateTaken(timeStamp);
        return;
    }
    // use modified time as date taken time when date taken not set
    data->SetDateTaken((data->GetDateTaken() == 0 || data->GetForAdd()) ?
        data->GetFileDateModified() : data->GetDateTaken());
    MEDIA_DEBUG_LOG("Set date_taken use modified time");
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

    nlohmann::json exifJson;
    err = imageSource->GetImagePropertyInt(0, PHOTO_DATA_IMAGE_ORIENTATION, intTempMeta);
    exifJson[PHOTO_DATA_IMAGE_ORIENTATION] = (err == 0) ? intTempMeta: 0;

    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_LONGITUDE, propertyStr);
    exifJson[PHOTO_DATA_IMAGE_GPS_LONGITUDE] = (err == 0) ? GetLongitudeLatitude(propertyStr): 0;

    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_GPS_LATITUDE, propertyStr);
    exifJson[PHOTO_DATA_IMAGE_GPS_LATITUDE] = (err == 0) ? GetLongitudeLatitude(propertyStr): 0;

    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_FRONT_CAMERA, propertyStr);
    data->SetFrontCamera(err == 0 ? propertyStr : "0");

    for (auto &exifKey : exifInfoKeys) {
        err = imageSource->GetImagePropertyString(0, exifKey, propertyStr);
        exifJson[exifKey] = (err == 0) ? propertyStr: "";
    }
    exifJson[PHOTO_DATA_IMAGE_IMAGE_DESCRIPTION] =
        AppFileService::SandboxHelper::Encode(exifJson[PHOTO_DATA_IMAGE_IMAGE_DESCRIPTION]);
    data->SetAllExif(exifJson.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));

    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_USER_COMMENT, propertyStr);
    if (err == 0 && !propertyStr.empty()) {
        data->SetUserComment(GetCompatibleUserComment(propertyStr));
    }
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_PHOTO_MODE, propertyStr);
    if (err != 0 || propertyStr == "default_exif_value") {
        err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_ISO_SPEED_LATITUDE_ZZZ, propertyStr);
    }
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
        return E_IMAGE;
    }

    ImageInfo imageInfo;
    err = imageSource->GetImageInfoFromExif(0, imageInfo);
    if (err == 0) {
        data->SetFileWidth(imageInfo.size.width);
        data->SetFileHeight(imageInfo.size.height);
    } else {
        MEDIA_ERR_LOG("Failed to get image info, err = %{public}d", err);
    }

    ExtractDateTakenMetadata(imageSource, data);
    ExtractDetailTimeMetadata(imageSource, data);

    int32_t intTempMeta = 0;
    err = imageSource->GetImagePropertyInt(0, PHOTO_DATA_IMAGE_ORIENTATION, intTempMeta);
    if (err == 0) {
        data->SetOrientation(intTempMeta);
    }

    if (imageSource->IsHdrImage()) {
        data->SetDynamicRangeType(static_cast<int32_t>(DynamicRangeType::HDR));
    } else {
        data->SetDynamicRangeType(static_cast<int32_t>(DynamicRangeType::SDR));
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
            data->SetDateTaken(data->GetFileDateModified());
        } else {
            data->SetDateTaken(int64TempMeta * MSEC_TO_SEC);
        }
    } else {
        // use modified time as date taken time when date taken not set
        data->SetDateTaken(data->GetFileDateModified());
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
        data->SetShootingModeTag(videoShootingMode);
        data->SetShootingMode(GetCastShootingMode(videoShootingMode));
    }
    strTemp = resultMap.at(AV_KEY_VIDEO_IS_HDR_VIVID);
    const string isHdr = "yes";
    if (strcmp(strTemp.c_str(), isHdr.c_str()) == 0) {
        data->SetDynamicRangeType(static_cast<int32_t>(DynamicRangeType::HDR));
    } else {
        data->SetDynamicRangeType(static_cast<int32_t>(DynamicRangeType::SDR));
    }
    int64_t dateTaken = data->GetDateTaken() / MSEC_TO_SEC;
    data->SetDetailTime(MediaFileUtils::StrCreateTime(PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken));
}

void PopulateExtractedAVLocationMeta(std::shared_ptr<Meta> &meta, std::unique_ptr<Metadata> &data)
{
    float floatTempMeta;

    if (meta->GetData(Tag::MEDIA_LATITUDE, floatTempMeta)) {
        data->SetLatitude((double)floatTempMeta);
    }
    if (meta->GetData(Tag::MEDIA_LONGITUDE, floatTempMeta)) {
        data->SetLongitude((double)floatTempMeta);
    }
}

static void ParseLivePhotoCoverPosition(std::unique_ptr<Metadata> &data)
{
    string extraPath = MovingPhotoFileUtils::GetMovingPhotoExtraDataPath(data->GetMovingPhotoImagePath());
    string absExtraPath;
    if (!PathToRealPath(extraPath, absExtraPath)) {
        MEDIA_ERR_LOG("file is not real path: %{private}s, errno: %{public}d", extraPath.c_str(), errno);
        return;
    }
    UniqueFd fd(open(absExtraPath.c_str(), O_RDONLY));
    uint32_t version{0};
    uint32_t frameIndex{0};
    bool hasCinemagraphInfo{false};
    if (MovingPhotoFileUtils::GetVersionAndFrameNum(fd, version, frameIndex, hasCinemagraphInfo) != E_OK) {
        return;
    }
    uint64_t coverPosition;
    if (MovingPhotoFileUtils::GetCoverPosition(data->GetFilePath(), frameIndex, coverPosition) != E_OK) {
        return;
    }
    data->SetCoverPosition(static_cast<int64_t>(coverPosition));
}

static void ParseMovingPhotoCoverPosition(std::shared_ptr<Meta> &meta, std::unique_ptr<Metadata> &data)
{
    shared_ptr<Meta> customMeta = make_shared<Meta>();
    bool isValid = meta->GetData(PHOTO_DATA_VIDEO_CUSTOM_INFO, customMeta);
    if (!isValid) {
        MEDIA_INFO_LOG("Video of moving photo does not contain customInfo");
        return ParseLivePhotoCoverPosition(data);
    }

    float coverPosition = 0.0f;
    isValid = customMeta->GetData(PHOTO_DATA_VIDEO_COVER_TIME, coverPosition);
    if (!isValid) {
        MEDIA_INFO_LOG("Video of moving photo does not contain cover position");
        return ParseLivePhotoCoverPosition(data);
    }
    // convert cover position from ms(float) to us(int64_t)
    constexpr int32_t MS_TO_US = 1000;
    data->SetCoverPosition(static_cast<int64_t>(coverPosition * MS_TO_US));
}

void MetadataExtractor::FillExtractedMetadata(const std::unordered_map<int32_t, std::string> &resultMap,
    std::shared_ptr<Meta> &meta, std::unique_ptr<Metadata> &data)
{
    PopulateExtractedAVMetadataOne(resultMap, data);
    PopulateExtractedAVMetadataTwo(resultMap, data);
    PopulateExtractedAVLocationMeta(meta, data);

    int64_t timeNow = MediaFileUtils::UTCTimeMilliSeconds();
    data->SetLastVisitTime(timeNow);

    if (IsMovingPhoto(data)) {
        ParseMovingPhotoCoverPosition(meta, data);
    }
}

static void FillFrameIndex(std::shared_ptr<AVMetadataHelper> &avMetadataHelper,
    std::unique_ptr<Metadata> &data)
{
    if (!IsMovingPhoto(data)) {
        MEDIA_WARN_LOG("data is not moving photo");
        return;
    }

    uint64_t coverPosition = static_cast<uint64_t>(data->GetCoverPosition());
    uint32_t frameIndex = 0;
    int32_t err = avMetadataHelper->GetFrameIndexByTime(coverPosition, frameIndex);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get frame index, err: %{public}d", err);
        return;
    }
    data->SetFrameIndex(static_cast<int32_t>(frameIndex));
}

int32_t MetadataExtractor::ExtractAVMetadata(std::unique_ptr<Metadata> &data, int32_t scene)
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

    // notify media_service clone event.
    if (scene == Scene::AV_META_SCENE_CLONE) {
        avMetadataHelper->SetScene(static_cast<Scene>(scene));
    }

    string filePath = data->GetFilePath();
    CHECK_AND_RETURN_RET_LOG(!filePath.empty(), E_AVMETADATA, "AV metadata file path is empty");
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
    }
    tracer.Start("avMetadataHelper->ResolveMetadata");
    std::shared_ptr<Meta> meta = avMetadataHelper->GetAVMetadata();
    std::unordered_map<int32_t, std::string> resultMap = avMetadataHelper->ResolveMetadata();
    tracer.Finish();
    if (!resultMap.empty()) {
        FillExtractedMetadata(resultMap, meta, data);
        if (IsMovingPhoto(data)) {
            FillFrameIndex(avMetadataHelper, data);
        }
    }

    (void)close(fd);

    return E_OK;
}

int32_t MetadataExtractor::CombineMovingPhotoMetadata(std::unique_ptr<Metadata> &data,
    bool isCameraShotMovingPhoto)
{
    // if video of moving photo does not exist, just return
    string videoPath = MediaFileUtils::GetMovingPhotoVideoPath(data->GetFilePath());
    if (!MediaFileUtils::IsFileExists(videoPath)) {
        MEDIA_INFO_LOG("Video of moving photo does not exist, path: %{private}s", videoPath.c_str());
        return E_OK;
    }

    unique_ptr<Metadata> videoData = make_unique<Metadata>();
    videoData->SetMovingPhotoImagePath(data->GetFilePath());
    videoData->SetFilePath(videoPath);
    videoData->SetPhotoSubType(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    int32_t err = ExtractAVMetadata(videoData);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to extract video metadata for moving photo: %{private}s", videoPath.c_str());
        return err;
    }

    data->SetCoverPosition(videoData->GetCoverPosition());

    uint32_t frameIndex = MovingPhotoFileUtils::GetFrameIndex(videoData->GetCoverPosition(),
        UniqueFd(open(videoPath.c_str(), O_RDONLY)));
    off_t extraDataSize{0};
    if (MovingPhotoFileUtils::GetExtraDataLen(data->GetFilePath(), videoPath,
        frameIndex, videoData->GetCoverPosition(), extraDataSize, isCameraShotMovingPhoto) != E_OK) {
        MEDIA_WARN_LOG("Failed to get extra data file size");
    }
    data->SetFileSize(data->GetFileSize() + videoData->GetFileSize() + extraDataSize);
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

int32_t MetadataExtractor::Extract(std::unique_ptr<Metadata> &data, bool isCameraShotMovingPhoto)
{
    if (data->GetFileMediaType() == MEDIA_TYPE_IMAGE) {
        int32_t ret = ExtractImageMetadata(data);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Failed to extract image metadata");
        if (IsMovingPhoto(data)) {
            return CombineMovingPhotoMetadata(data, isCameraShotMovingPhoto);
        }
        return ret;
    } else {
        return ExtractAVMetadata(data);
    }
}
} // namespace Media
} // namespace OHOS
