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

#include "thumbnail_source_loading.h"

#include <fcntl.h>

#include "dfx_manager.h"
#include "image_source.h"
#include "media_exif.h"
#include "media_file_utils.h"
#include "medialibrary_tracer.h"
#include "post_proc.h"
#include "thumbnail_utils.h"

using namespace std;

namespace OHOS {
namespace Media {

const std::string LOCAL_MEDIA_PATH = "/storage/media/local/files/";

std::string GetLocalThumbnailPath(const std::string &path, const std::string &key)
{
    if (path.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    std::string suffix = (key == "") ? "" : "/" + key + ".jpg";
    return LOCAL_MEDIA_PATH + ((key == "") ? "" : ".thumbs/") + path.substr(ROOT_MEDIA_DIR.length()) + suffix;
}
    
bool IsLocalSourceAvailable(const std::string& path)
{
    char tmpPath[PATH_MAX] = { 0 };
    if (realpath(path.c_str(), tmpPath) == nullptr) {
        // it's alright if source loading fails here, just move on to next source
        MEDIA_ERR_LOG("SourceLoader path to realPath is nullptr: %{public}s", path.c_str());
        return false;
    }

    FILE* filePtr = fopen(tmpPath, "rb");
    if (filePtr == nullptr) {
        MEDIA_ERR_LOG("SourceLoader open local file fail: %{public}s", path.c_str());
        return false;
    }
    if (fclose(filePtr) != E_OK) {
        MEDIA_ERR_LOG("SourceLoader close filePtr fail: %{public}s", path.c_str());
        return false;
    }
    return true;
}

bool IsCloudSourceAvailable(const std::string& path)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("SourceLoader open cloud file fail: %{public}s", path.c_str());
        return false;
    }
    close(fd);
    return true;
}

bool NeedAutoResize(const Size &size)
{
    // Only small thumbnails need to be scaled after decoding, others should resized while decoding.
    return size.width > SHORT_SIDE_THRESHOLD && size.height > SHORT_SIDE_THRESHOLD;
}

bool GenDecodeOpts(const Size &sourceSize, const Size &targetSize, DecodeOptions &decodeOpts)
{
    if (targetSize.width == 0) {
        MEDIA_ERR_LOG("Failed to generate decodeOpts, scale size contains zero");
        return false;
    }
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    if (NeedAutoResize(targetSize)) {
        decodeOpts.desiredSize = targetSize;
        return true;
    }

    int32_t decodeScale = 1;
    int32_t scaleFactor = sourceSize.width / targetSize.width;
    while (scaleFactor /= DECODE_SCALE_BASE) {
        decodeScale *= DECODE_SCALE_BASE;
    }
    decodeOpts.desiredSize = {
        std::ceil(sourceSize.width / decodeScale),
        std::ceil(sourceSize.height / decodeScale),
    };
    return true;
}

Size ConvertDecodeSize(ThumbnailData& data, const Size& sourceSize, Size& desiredSize)
{
    int width = sourceSize.width;
    int height = sourceSize.height;
    if (!ThumbnailUtils::ResizeThumb(width, height)) {
        MEDIA_ERR_LOG("ResizeThumb failed");
        return {0, 0};
    }
    Size thumbDesiredSize = {width, height};
    data.thumbDesiredSize = thumbDesiredSize;
    float desiredScale = static_cast<float>(thumbDesiredSize.height) / static_cast<float>(thumbDesiredSize.width);
    float sourceScale = static_cast<float>(sourceSize.height) / static_cast<float>(sourceSize.width);
    float scale = 1.0f;
    if (sourceScale - desiredScale <= EPSILON) {
        scale = (float)thumbDesiredSize.height / sourceSize.height;
    } else {
        scale = (float)thumbDesiredSize.width / sourceSize.width;
    }
    scale = scale < 1.0f ? scale : 1.0f;
    Size thumbDecodeSize = {
        static_cast<int32_t> (scale * sourceSize.width),
        static_cast<int32_t> (scale * sourceSize.height),
    };

    width = sourceSize.width;
    height = sourceSize.height;
    if (!ThumbnailUtils::ResizeLcd(width, height)) {
        MEDIA_ERR_LOG("ResizeLcd failed");
        return {0, 0};
    }
    Size lcdDesiredSize = {width, height};
    data.lcdDesiredSize = lcdDesiredSize;

    int lcdMinSide = std::min(lcdDesiredSize.width, lcdDesiredSize.height);
    int thumbMinSide = std::min(thumbDesiredSize.width, thumbDesiredSize.height);
    Size lcdDecodeSize = lcdMinSide < thumbMinSide ? thumbDecodeSize : lcdDesiredSize;
    
    if (data.useThumbAsSource) {
        desiredSize = thumbDesiredSize;
        return thumbDecodeSize;
    } else if (data.needResizeLcd) {
        desiredSize = lcdDesiredSize;
        return lcdDecodeSize;
    } else {
        desiredSize = lcdDesiredSize;
        return lcdDesiredSize;
    }
}

unique_ptr<ImageSource> LoadImageSource(const std::string &path, uint32_t &err)
{
    MediaLibraryTracer tracer;
    tracer.Start("ImageSource::CreateImageSource");

    SourceOptions opts;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, err);
    if (err != E_OK || !imageSource) {
        MEDIA_ERR_LOG("Failed to LoadImageSource, pixelmap path: %{public}s exists: %{public}d",
            path.c_str(), MediaFileUtils::IsFileExists(path));
        DfxManager::GetInstance()->HandleThumbnailError(path, DfxType::IMAGE_SOURCE_CREATE, err);
        return imageSource;
    }
    return imageSource;
}

void SourceLoader::SetCurrentStateFunction()
{
    StateFunc stateFunc = STATE_FUNC_MAP.at(state_);
    IsSourceAvailable = stateFunc.IsSourceAvailable;
    SwitchToNextState = stateFunc.SwitchToNextState;
    IsSizeLargeEnough = stateFunc.IsSizeLargeEnough;
}

bool SourceLoader::CreateImage(std::unique_ptr<ImageSource>& imageSource, ImageInfo& imageInfo)
{
    MediaLibraryTracer tracer;
    tracer.Start("imageSource->CreateImage");
    DecodeOptions decodeOpts;
    Size targetSize = ConvertDecodeSize(data_, imageInfo.size, desiredSize_);
    if (!GenDecodeOpts(imageInfo.size, targetSize, decodeOpts)) {
        MEDIA_DEBUG_LOG("SourceLoader Failed to generate decodeOpts, pixelmap path %{private}s",
            data_.path.c_str());
        error_ = E_ERR;
        return false;
    }
    uint32_t err = 0;
    data_.source = imageSource->CreatePixelMap(decodeOpts, err);
    if ((err != E_OK) || (data_.source == nullptr)) {
        DfxManager::GetInstance()->HandleThumbnailError(data_.path, DfxType::IMAGE_SOURCE_CREATE_PIXELMAP, err);
        error_ = E_ERR;
        return false;
    }
    if (!NeedAutoResize(targetSize) && !ThumbnailUtils::ScaleTargetPixelMap(data_, targetSize)) {
        MEDIA_ERR_LOG("SourceLoader Failed to scale target, pixelmap path %{private}s", data_.path.c_str());
        error_ = E_ERR;
        return false;
    }
    tracer.Finish();

    int intTempMeta = 0;
    err = imageSource->GetImagePropertyInt(0, PHOTO_DATA_IMAGE_ORIENTATION, intTempMeta);
    if (err != E_OK) {
        MEDIA_DEBUG_LOG("SourceLoader Failed to get ImageProperty, path: %{private}s", data_.path.c_str());
    }
    data_.degrees = static_cast<float>(intTempMeta);
    MEDIA_DEBUG_LOG("SourceLoader status:%{public}s, width:%{public}d, height:%{public}d",
        STATE_NAME_MAP.at(state_).c_str(), imageInfo.size.width, imageInfo.size.height);
    return true;
}

bool SourceLoader::RunLoading()
{
    state_ = SourceState::BEGIN;
    data_.source = nullptr;
    SetCurrentStateFunction();

    // always check state not final after every state switch
    while (!IsFinal()) {
        SwitchToNextState(data_, state_);
        MEDIA_INFO_LOG("SourceLoader new cycle status:%{public}s", STATE_NAME_MAP.at(state_).c_str());
        if (IsFinal()) {
            break;
        }
        SetCurrentStateFunction();
        do {
            if (state_ < SourceState::CLOUD_THUMB) {
                data_.stats.sourceType = LoadSourceType::LOCAL_PHOTO;
            } else if (state_ >= SourceState::CLOUD_THUMB && state_ <= SourceState::CLOUD_ORIGIN) {
                data_.stats.sourceType = static_cast<LoadSourceType>(state_);
            }
            std::unique_ptr<ImageSource> imageSource = IsSourceAvailable(data_, error_);
            if (imageSource == nullptr) {
                MEDIA_DEBUG_LOG("SourceLoader source unavailable, "
                    "status:%{public}s, path:%{private}s", STATE_NAME_MAP.at(state_).c_str(), data_.path.c_str());
                break;
            }
            ImageInfo imageInfo;
            if (!IsSizeAcceptable(imageSource, imageInfo)) {
                MEDIA_ERR_LOG("SourceLoader source unacceptable, "
                    "status:%{public}s, path:%{private}s", STATE_NAME_MAP.at(state_).c_str(), data_.path.c_str());
                break;
            }
            if (!CreateImage(imageSource, imageInfo)) {
                MEDIA_ERR_LOG("SourceLoader  fail to create image, "
                    "status:%{public}s, path:%{private}s", STATE_NAME_MAP.at(state_).c_str(), data_.path.c_str());
                break;
            }
            state_ = SourceState::FINISH;
            DfxManager::GetInstance()->HandleThumbnailGeneration(data_.stats);
        } while (0);
    };
    if (state_ == SourceState::ERROR) {
        data_.source = nullptr;
    }
    if (data_.source == nullptr) {
        MEDIA_ERR_LOG("SourceLoader source is nullptr, "
            "status:%{public}s, path:%{private}s", STATE_NAME_MAP.at(state_).c_str(), data_.path.c_str());
        return false;
    }
    return true;
}

bool SourceLoader::IsSizeAcceptable(std::unique_ptr<ImageSource>& imageSource, ImageInfo& imageInfo)
{
    error_ = imageSource->GetImageInfo(0, imageInfo);
    if (error_ != E_OK) {
        DfxManager::GetInstance()->HandleThumbnailError(data_.path, DfxType::IMAGE_SOURCE_GET_INFO, error_);
        return false;
    }

    int32_t minSize = imageInfo.size.width < imageInfo.size.height ? imageInfo.size.width : imageInfo.size.height;
    if (!IsSizeLargeEnough(data_, minSize)) {
        MEDIA_DEBUG_LOG("SourceLoader size not acceptable, width:%{public}d, height:%{public}d", imageInfo.size.width,
            imageInfo.size.height);
        return false;
    }

    // upload if minSize is larger than SHORT_SIDE_THRESHOLD and source is not from thumb
    data_.needUpload = minSize >= SHORT_SIDE_THRESHOLD && state_ != SourceState::LOCAL_THUMB
        && state_ != SourceState::CLOUD_THUMB;
    data_.stats.sourceWidth = imageInfo.size.width;
    data_.stats.sourceHeight = imageInfo.size.height;
    return true;
}

bool SourceLoader::IsFinal()
{
    if (error_ != E_OK) {
        state_ = SourceState::ERROR;
        return true;
    }
    if (state_ == SourceState::FINISH) {
        return true;
    }
    return false;
}

void BeginSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        state = SourceState::LOCAL_THUMB;
    } else {
        state = SourceState::LOCAL_ORIGIN;
    }
}

std::unique_ptr<ImageSource> LocalThumbSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    std::string tmpPath = GetLocalThumbnailPath(data.path, THUMBNAIL_THUMB_SUFFIX);
    if (!IsLocalSourceAvailable(tmpPath)) {
        return nullptr;
    }
    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource == nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader LocalThumbSource LoadSource error:%{public}d", err);
        return nullptr;
    }
    return imageSource;
}

void LocalThumbSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        state = SourceState::LOCAL_LCD;
    } else {
        state = SourceState::FINISH;
    }
}

bool LocalThumbSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD && data.isLoadingFromThumbToLcd) {
        return false;
    }
    return true;
}

std::unique_ptr<ImageSource> LocalLcdSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    std::string tmpPath = GetLocalThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX);
    if (!IsLocalSourceAvailable(tmpPath)) {
        return nullptr;
    }
    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource == nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader LocalLcdSource LoadSource error:%{public}d", err);
        return nullptr;
    }
    return imageSource;
}

void LocalLcdSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        state = SourceState::LOCAL_ORIGIN;
    } else {
        state = SourceState::FINISH;
    }
};

bool LocalLcdSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD) {
        return false;
    }
    return true;
}

std::unique_ptr<ImageSource> LocalOriginSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    std::string tmpPath = GetLocalThumbnailPath(data.path, "");
    if (!IsLocalSourceAvailable(tmpPath)) {
        return nullptr;
    }
    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource == nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader LocalOriginSource LoadSource error:%{public}d", err);
        return nullptr;
    }
    return imageSource;
}

void LocalOriginSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        if (data.isForeGroundLoading) {
            state = SourceState::CLOUD_THUMB;
        } else if (data.isCloudLoading) {
            state = SourceState::CLOUD_LCD;
        } else {
            state = SourceState::CLOUD_THUMB;
        }
    } else {
        state = SourceState::FINISH;
    }
}

bool LocalOriginSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD) {
        if (!data.isLoadingFromThumbToLcd) {
            return true;
        }
        if (!data.isCloudLoading && !data.isForeGroundLoading) {
            return true;
        }
        return false;
    }
    return true;
}

std::unique_ptr<ImageSource> CloudThumbSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    std::string tmpPath = GetThumbnailPath(data.path, THUMBNAIL_THUMB_SUFFIX);
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    if (!IsCloudSourceAvailable(tmpPath)) {
        return nullptr;
    }
    int32_t totalCost = static_cast<int32_t>(MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    data.stats.openThumbCost = totalCost;

    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource == nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader CloudThumbSource LoadSource error:%{public}d", err);
        return nullptr;
    }
    return imageSource;
}

void CloudThumbSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    state = SourceState::CLOUD_LCD;
};

bool CloudThumbSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD) {
        return false;
    }
    return true;
}

std::unique_ptr<ImageSource> CloudLcdSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    std::string tmpPath = GetThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX);
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    if (!IsCloudSourceAvailable(tmpPath)) {
        return nullptr;
    }
    int32_t totalCost = static_cast<int32_t>(MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    data.stats.openLcdCost = totalCost;

    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource == nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader CloudLcdSource LoadSource error:%{public}d", err);
        return nullptr;
    }
    return imageSource;
}

void CloudLcdSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    state = SourceState::CLOUD_ORIGIN;
};

bool CloudLcdSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD) {
        return false;
    }
    return true;
}

std::unique_ptr<ImageSource> CloudOriginSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    if (!IsCloudSourceAvailable(data.path)) {
        return nullptr;
    }
    int32_t totalCost = static_cast<int32_t>(MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    data.stats.openOriginCost = totalCost;

    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(data.path, err);
    if (err != E_OK || imageSource == nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader CloudOriginSource LoadSource error:%{public}d", err);
        return nullptr;
    }
    return imageSource;
}

void CloudOriginSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    state = SourceState::FINISH;
}

bool CloudOriginSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    return true;
}

} // namespace Media
} // namespace OHOS