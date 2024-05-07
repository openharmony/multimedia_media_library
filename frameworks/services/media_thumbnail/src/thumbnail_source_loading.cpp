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
#include ""

using namespace std;

namespace OHOS {
namespace Media {
    
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
    fclose(filePtr);
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
    state_ = SourceState::Begin;
    data_.source = nullptr;
    SetCurrentStateFunction();

    // always check state not final after every state switch
    while (!IsFinal()) {
        SwitchToNextState(data_, state_);
        MEDIA_DEBUG_LOG("SourceLoader new cycle status:%{public}s", STATE_NAME_MAP.at(state_).c_str());
        if (IsFinal()) {
            break;
        }
        SetCurrentStateFunction();
        do {
            if (state_ < SourceState::CloudThumb) {
                data_.stats.sourceType = LoadSourceType::LOCAL_PHOTO;
            } else if (state_ >= SourceState::CloudThumb && state_ <= SourceState::CloudOrigin) {
                data_.stats.sourceType = LoadSourceType::CLOUD_PHOTO;
            } else {
                data_.stats.sourceType = LoadSourceType::UNKNOWN;
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
            state_ = SourceState::Finish;
            DfxManager::GetInstance()->HandleThumbnailGeneration(data.stats);
        } while (0);
    };
    if (state_ == SourceState::Error) {
        data_.source = nullptr;
        return false;
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
        MEDIA_ERR_LOG("SourceLoader size not acceptable, width:%{public}d, height:%{public}d", imageInfo.size.width,
            imageInfo.size.height);
        return false;
    }

    // upload if minSize is larger than SHORT_SIDE_THRESHOLD and source is not from thumb
    data_.needUpload = minSize >= SHORT_SIDE_THRESHOLD && state_ != SourceState::LocalThumb && state_ != SourceState::CloudThumb;
    data_.stats.sourceWidth = imageInfo.size.width;
    data_.stats.sourceHeight = imageInfo.size.height;
    return true;
}

bool SourceLoader::IsFinal()
{
    if (error_ != E_OK) {
        state_ = SourceState::Error;
        return true;
    }
    if (state_ == SourceState::Finish) {
        return true;
    }
    return false;
}

void BeginSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        state = SourceState::LocalThumb;
    } else {
        state = SourceState::LocalOrigin;
    }
}

std::unique_ptr<ImageSource> LocalThumbSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    std::string tmpPath = GetThumbnailPath(data.path, THUMBNAIL_THUMB_SUFFIX);
    if (!IsLocalSourceAvailable(tmpPath)) {
        return nullptr;
    }
    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = ThumbnailUtils::LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource != nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader LocalThumbSource LoadSource error");
        return nullptr;
    }
    return imageSource;
}

void LocalThumbSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        state = SourceState::LocalLcd;
    } else {
        state = SourceState::Finish;
    }
};

bool LocalThumbSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD && data.isLoadingFromThumbToLcd) {
        return false;
    }
    return true;
};

std::unique_ptr<ImageSource> LocalLcdSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    std::string tmpPath = GetThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX);
    if (!IsLocalSourceAvailable(tmpPath)) {
        return nullptr;
    }
    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = ThumbnailUtils::LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource != nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader LocalLcdSource LoadSource error");
        return nullptr;
    }
    return imageSource;
}

void LocalLcdSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        state = SourceState::LocalOrigin;
    } else {
        state = SourceState::Finish;
    }
};

bool LocalLcdSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD) {
        return false;
    }
    return true;
};

std::unique_ptr<ImageSource> LocalOriginSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    if (!IsLocalSourceAvailable(data.path)) {
        return nullptr;
    }
    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = ThumbnailUtils::LoadImageSource(data.path, err);
    if (err != E_OK || imageSource != nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader LocalOriginSource LoadSource error");
        return nullptr;
    }
    return imageSource;
}

void LocalOriginSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        if (data.isForeGroundLoading ) {
            state = SourceState::CloudThumb;
        } else if (data.isCloudLoading) {
            state = SourceState::CloudLcd;
        } else {
            state = SourceState::CloudThumb;
        }
    } else {
        state = SourceState::Finish;
    }
};

bool LocalOriginSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD) {
        if (!data.isLoadingFromThumbToLcd) {
            return true;
        }
        if (!data.isCloudLoading && !data.isFrontLoading) {
            return true;
        }
        return false;
    }
    return true;
};

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
    std::unique_ptr<ImageSource> imageSource = ThumbnailUtils::LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource != nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader CloudThumbSource LoadSource error");
        return nullptr;
    }
    return imageSource;
}

void CloudThumbSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    state = SourceState::CloudLcd;
};

bool CloudThumbSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD) {
        return false;
    }
    return true;
};

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
    std::unique_ptr<ImageSource> imageSource = ThumbnailUtils::LoadImageSource(tmpPath, err);
    if (err != E_OK || imageSource != nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader CloudLcdSource LoadSource error");
        return nullptr;
    }
    return imageSource;
}

void CloudLcdSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    state = SourceState::CloudOrigin;
};

bool CloudLcdSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    if (minSize < SHORT_SIDE_THRESHOLD) {
        return false;
    }
    return true;
};

std::unique_ptr<ImageSource> CloudOriginSource::IsSourceAvailable(ThumbnailData& data, int32_t& error)
{
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    if (!IsCloudSourceAvailable(data.path)) {
        return nullptr;
    }
    int32_t totalCost = static_cast<int32_t>(MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    data.stats.openOriginCost = totalCost;

    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = ThumbnailUtils::LoadImageSource(data.path, err);
    if (err != E_OK || imageSource != nullptr) {
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoader CloudOriginSource LoadSource error");
        return nullptr;
    }
    return imageSource;
}

void CloudOriginSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    state = SourceState::Finish;
};

bool CloudOriginSource::IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize)
{
    return true;
};

} // namespace Media
} // namespace OHOS