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

#include "hitrace_meter.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"

namespace OHOS {
namespace Media {
using namespace std;

template <class Type>
static Type stringToNum(const string &str)
{
    std::istringstream iss(str);
    Type num;
    iss >> num;
    return num;
}

static time_t convertTimeStr2TimeStamp(string &timeStr)
{
    struct tm timeinfo;
    strptime(timeStr.c_str(), "%Y-%m-%d %H:%M:%S",  &timeinfo);
    time_t timeStamp = mktime(&timeinfo);
    return timeStamp;
}

int32_t MetadataExtractor::ExtractImageMetadata(Metadata &fileMetadata)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/" + fileMetadata.GetFileExtension();
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(fileMetadata.GetFilePath(), opts, errorCode);
    if (errorCode != ERR_SUCCESS || imageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain image source");
        return ERR_SUCCESS;
    }

    ImageInfo imageInfo;
    uint32_t ret = imageSource->GetImageInfo(0, imageInfo);
    if (ret == ERR_SUCCESS) {
        fileMetadata.SetFileWidth(imageInfo.size.width);
        fileMetadata.SetFileHeight(imageInfo.size.height);
    }

    string propertyStr;
    int64_t int64TempMeta = 0;
    ret = imageSource->GetImagePropertyString(0, MEDIA_DATA_IMAGE_DATE_TIME_ORIGINAL, propertyStr);
    if (ret == ERR_SUCCESS) {
        int64TempMeta = convertTimeStr2TimeStamp(propertyStr);
        if (int64TempMeta < 0) {
            fileMetadata.SetDateTaken(fileMetadata.GetFileDateModified());
        } else {
            fileMetadata.SetDateTaken(int64TempMeta);
        }
    } else {
        // use modified time as date taken time when date taken not set
        fileMetadata.SetDateTaken(fileMetadata.GetFileDateModified());
    }

    int32_t intTempMeta = 0;
    ret = imageSource->GetImagePropertyInt(0, MEDIA_DATA_IMAGE_ORIENTATION, intTempMeta);
    if (ret == ERR_SUCCESS) {
        fileMetadata.SetOrientation(intTempMeta);
    }

    double dbleTempMeta = -1;
    ret = imageSource->GetImagePropertyString(0, MEDIA_DATA_IMAGE_GPS_LONGITUDE, propertyStr);
    if (ret == ERR_SUCCESS) {
        dbleTempMeta = stringToNum<double>(propertyStr);
        fileMetadata.SetLongitude(dbleTempMeta);
    }

    ret = imageSource->GetImagePropertyString(0, MEDIA_DATA_IMAGE_GPS_LATITUDE, propertyStr);
    if (ret == ERR_SUCCESS) {
        dbleTempMeta = stringToNum<double>(propertyStr);
        fileMetadata.SetLatitude(dbleTempMeta);
    }

    return ERR_SUCCESS;
}

void MetadataExtractor::FillExtractedMetadata(const std::unordered_map<int32_t, std::string> &metadataMap,
                                              Metadata &fileMetadata)
{
    string strTemp;
    int32_t intTempMeta;
    int64_t int64TempMeta;

    strTemp = metadataMap.at(AV_KEY_ALBUM);
    if (strTemp != "") {
        fileMetadata.SetAlbum(strTemp);
    }

    strTemp = metadataMap.at(AV_KEY_ARTIST);
    if (strTemp != "") {
        fileMetadata.SetFileArtist(strTemp);
    }

    strTemp = metadataMap.at(AV_KEY_DURATION);
    if (strTemp != "") {
        intTempMeta = stringToNum<int32_t>(strTemp);
        fileMetadata.SetFileDuration(intTempMeta);
    }

    strTemp = metadataMap.at(AV_KEY_VIDEO_HEIGHT);
    if (strTemp != "") {
        intTempMeta = stringToNum<int32_t>(strTemp);
        fileMetadata.SetFileHeight(intTempMeta);
    }

    strTemp = metadataMap.at(AV_KEY_VIDEO_WIDTH);
    if (strTemp != "") {
        intTempMeta = stringToNum<int32_t>(strTemp);
        fileMetadata.SetFileWidth(intTempMeta);
    }

    strTemp = metadataMap.at(AV_KEY_MIME_TYPE);
    if (strTemp != "") {
        fileMetadata.SetFileMimeType(strTemp);
    }

    strTemp = metadataMap.at(AV_KEY_DATE_TIME_FORMAT);
    if (strTemp != "") {
        int64TempMeta = convertTimeStr2TimeStamp(strTemp);
        if (int64TempMeta < 0) {
            fileMetadata.SetDateTaken(fileMetadata.GetFileDateModified());
        } else {
            fileMetadata.SetDateTaken(int64TempMeta);
        }
    } else {
        // use modified time as date taken time when date taken not set
        fileMetadata.SetDateTaken(fileMetadata.GetFileDateModified());
    }

    strTemp = metadataMap.at(AV_KEY_VIDEO_ORIENTATION);
    if (strTemp == "") {
        intTempMeta = 0;
    } else {
        intTempMeta = stringToNum<int32_t>(strTemp);
    }
    fileMetadata.SetOrientation(intTempMeta);
}

int32_t MetadataExtractor::ExtractMetadata(Metadata &fileMetadata, const string &uri)
{
    int32_t errCode = ERR_FAIL;

    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "CreateAVMetadataHelper");
    std::shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    if (avMetadataHelper == nullptr) {
        MEDIA_ERR_LOG("AV metadata helper is null");
        return errCode;
    }

    int32_t fd = open(uri.c_str(), O_RDONLY);
    if (fd <= 0) {
        MEDIA_ERR_LOG("Open file descriptor failed, errno = %{public}d", errno);
        return errCode;
    }

    struct stat64 st;
    if (fstat64(fd, &st) != 0) {
        MEDIA_ERR_LOG("Get file state failed for the given fd");
        (void)close(fd);
        return errCode;
    }

    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "avMetadataHelper->SetSource");
    errCode = avMetadataHelper->SetSource(fd, 0, static_cast<int64_t>(st.st_size), AV_META_USAGE_META_ONLY);
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    if (errCode != ERR_SUCCESS) {
        MEDIA_ERR_LOG("SetSource failed for the given file descriptor");
        (void)close(fd);
        return errCode;
    } else {
        StartTrace(HITRACE_TAG_FILEMANAGEMENT, "avMetadataHelper->ResolveMetadata");
        std::unordered_map<int32_t, std::string> metadataMap = avMetadataHelper->ResolveMetadata();
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        if (!metadataMap.empty()) {
            FillExtractedMetadata(metadataMap, fileMetadata);
        }
    }

    (void)close(fd);

    return errCode;
}

int32_t MetadataExtractor::Extract(Metadata &fileMetadata, const string &uri)
{
    int32_t errCode = ERR_SUCCESS;

    auto mimeType = ScannerUtils::GetMimeTypeFromExtension(fileMetadata.GetFileExtension());
    fileMetadata.SetFileMimeType(mimeType);

    // If the file type is not audio/video/image
    if (std::find(EXTRACTOR_SUPPORTED_MIME.begin(), EXTRACTOR_SUPPORTED_MIME.end(), mimeType) ==
        EXTRACTOR_SUPPORTED_MIME.end()) {
        return errCode;
    }

    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "ExtractMetadata");
    if (fileMetadata.GetFileMediaType() == MEDIA_TYPE_IMAGE) {
        errCode = ExtractImageMetadata(fileMetadata);
    } else {
        errCode = ExtractMetadata(fileMetadata, uri);
    }
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);

    return errCode;
}
} // namespace Media
} // namespace OHOS
