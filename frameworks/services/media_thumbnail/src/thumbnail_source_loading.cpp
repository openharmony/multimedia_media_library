/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

using namespace std;

namespace OHOS {
namespace Media {
    
bool IsLocalSourceAvailable(const std::string& path)
{
    char tmpPath[PATH_MAX] = { 0 };
    if (realpath(path.c_str(), tmpPath) == nullptr) {

        // it's alright if source loading fails here, just move on to next source
        MEDIA_ERR_LOG("SourceLoading path to realPath is nullptr: %{public}s", path.c_str());
        return false;
    }

    FILE* filePtr = fopen(tmpPath, "rb");
    if (filePtr == nullptr) {
        MEDIA_ERR_LOG("SourceLoading open local file fail: %{public}s", path.c_str());
        return false;
    }
    return true;
}

bool IsCloudSourceAvailable(const std::string& path)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("SourceLoading open cloud file fail: %{public}s", path.c_str());
        return false;
    }
    return true;
}

bool ScaleTargetPixelMap(ThumbnailData &data, const Size &targetSize)
{
    MediaLibraryTracer tracer;
    tracer.Start("ImageSource::ScaleTargetPixelMap");

    PostProc postProc;
    if (!postProc.ScalePixelMapEx(targetSize, *data.source, Media::AntiAliasingOption::HIGH)) {
        MEDIA_ERR_LOG("thumbnail scale failed [%{private}s]", data.id.c_str());
        return false;
    }
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

bool ResizeThumb(int &width, int &height)
{
    int maxLen = max(width, height);
    int minLen = min(width, height);
    if (minLen == 0) {
        MEDIA_ERR_LOG("Divisor minLen is 0");
        return false;
    }
    double ratio = (double)maxLen / minLen;
    if (minLen > SHORT_SIDE_THRESHOLD) {
        minLen = SHORT_SIDE_THRESHOLD;
        maxLen = static_cast<int>(SHORT_SIDE_THRESHOLD * ratio);
        if (maxLen > MAXIMUM_SHORT_SIDE_THRESHOLD) {
            maxLen = MAXIMUM_SHORT_SIDE_THRESHOLD;
        }
        if (height > width) {
            width = minLen;
            height = maxLen;
        } else {
            width = maxLen;
            height = minLen;
        }
    } else if (minLen <= SHORT_SIDE_THRESHOLD && maxLen > SHORT_SIDE_THRESHOLD) {
        if (ratio > ASPECT_RATIO_THRESHOLD) {
            int newMaxLen = static_cast<int>(minLen * ASPECT_RATIO_THRESHOLD);
            if (height > width) {
                width = minLen;
                height = newMaxLen;
            } else {
                width = newMaxLen;
                height = minLen;
            }
        }
    }
    return true;
}

bool ResizeLcd(int &width, int &height)
{
    int maxLen = max(width, height);
    int minLen = min(width, height);
    if (minLen == 0) {
        MEDIA_ERR_LOG("Divisor minLen is 0");
        return false;
    }
    double ratio = (double)maxLen / minLen;
    if (std::abs(ratio) < EPSILON) {
        MEDIA_ERR_LOG("ratio is 0");
        return false;
    }
    int newMaxLen = maxLen;
    int newMinLen = minLen;
    if (maxLen > LCD_LONG_SIDE_THRESHOLD) {
        newMaxLen = LCD_LONG_SIDE_THRESHOLD;
        newMinLen = static_cast<int>(newMaxLen / ratio);
    }
    int lastMinLen = newMinLen;
    int lastMaxLen = newMaxLen;
    if (newMinLen < LCD_SHORT_SIDE_THRESHOLD && minLen >= LCD_SHORT_SIDE_THRESHOLD) {
        lastMinLen = LCD_SHORT_SIDE_THRESHOLD;
        lastMaxLen = static_cast<int>(lastMinLen * ratio);
        if (lastMaxLen > MAXIMUM_LCD_LONG_SIDE) {
            lastMaxLen = MAXIMUM_LCD_LONG_SIDE;
            lastMinLen = static_cast<int>(lastMaxLen / ratio);
        }
    }
    if (height > width) {
        width = lastMinLen;
        height = lastMaxLen;
    } else {
        width = lastMaxLen;
        height = lastMinLen;
    }
    return true;
}

Size ConvertDecodeSize(ThumbnailData& data, const Size& sourceSize, Size& desiredSize)
{
    int width = sourceSize.width;
    int height = sourceSize.height;
    if (!ResizeThumb(width, height)) {
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
    if (!ResizeLcd(width, height)) {
        MEDIA_ERR_LOG("ResizeLcd failed");
        return {0, 0};
    }
    Size lcdDesiredSize = {width, height};
    data.lcdDesiredSize = lcdDesiredSize;

    int lcdMinSide = std::min(lcdDesiredSize.width, lcdDesiredSize.height);
    int thumbMinSide = std::min(thumbDesiredSize.width, thumbDesiredSize.height);
    Size lcdDecodeSize = lcdMinSide < thumbMinSide ? thumbDecodeSize : lcdDesiredSize;
    
    if (data.isCreatingThumbSource) {
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

bool SourceLoading::RunLoading()
{
    state_ = SourceState::Begin;
    data_.source = nullptr;
    SET_CURRENT_STATE_FUNCTION(state_);

    // always check status not final after every state switch
    while(!IsFinal()) {
        SwitchToNextState(data_, state_);
        MEDIA_DEBUG_LOG("SourceLoading new cycle status:%{public}s", STATE_NAME_MAP.at(state_).c_str());
        if (IsFinal()) {
            break;
        }
        SET_CURRENT_STATE_FUNCTION(state_);
        do {
            if (state_ < SourceState::CloudThumb) {
                data_.stats.sourceType = LoadSourceType::LOCAL_PHOTO;
            } else if (state_ >= SourceState::CloudThumb && state_ <= SourceState::CloudOrigin) {
                data_.stats.sourceType = static_cast<LoadSourceType>(state_);
            } else {
                data_.stats.sourceType = LoadSourceType::UNKNOWN;
            }
            std::unique_ptr<ImageSource> imageSource = IsSourceAvailable(data_, error_);
            if (imageSource == nullptr) {
                MEDIA_DEBUG_LOG("SourceLoading source unavailable, 
                    status:%{public}s, path:%{private}s", STATE_NAME_MAP.at(state_).c_str(), data_.path.c_str());
                break;
            }

            ImageInfo imageInfo;
            if (!IsSizeAcceptable(imageSource, imageInfo)) {
                break;
            }

            MediaLibraryTracer tracer;
            tracer.Start("imageSource->CreatePixelMap");
            DecodeOptions decodeOpts;
            Size targetSize = ConvertDecodeSize(data_, imageInfo.size, desiredSize_);
            if (!GenDecodeOpts(imageInfo.size, targetSize, decodeOpts)) {
                MEDIA_ERR_LOG("SourceLoading Failed to generate decodeOpts, pixelmap path %{private}s", 
                    data_.path.c_str());
                return false;
            }
            uint32_t err = 0;
            data_.source = imageSource->CreatePixelMap(decodeOpts, err);
            if ((err != E_OK) || (data_.source == nullptr)) {
                DfxManager::GetInstance()->HandleThumbnailError(data_.path, DfxType::IMAGE_SOURCE_CREATE_PIXELMAP, err);
                error_ = E_ERR;
                break;
            }
            if (!NeedAutoResize(targetSize) && !ScaleTargetPixelMap(data_, targetSize)) {
                MEDIA_ERR_LOG("SourceLoading Failed to scale target, pixelmap path %{private}s", data_.path.c_str());
                error_ = E_ERR;
                break;
            }
            tracer.Finish();

            int intTempMeta = 0;
            err = imageSource->GetImagePropertyInt(0, PHOTO_DATA_IMAGE_ORIENTATION, intTempMeta);
            if (err != E_OK) {
                MEDIA_DEBUG_LOG("SourceLoading Failed to get ImageProperty, path: %{private}s", data_.path.c_str());
            }
            data_.degrees = static_cast<float>(intTempMeta);
            DfxManager::GetInstance()->HandleHighMemoryThumbnail(data_.path, MEDIA_TYPE_IMAGE, imageInfo.size.width,
                imageInfo.size.height);
            MEDIA_DEBUG_LOG("SourceLoading status:%{public}s, width:%{public}d, height:%{public}d", 
                STATE_NAME_MAP.at(state_).c_str(), imageInfo.size.width, imageInfo.size.height);
            state_ = SourceState::Finish;
        } while(0);
    };
    if (state_ == SourceState::Error) {
        data_.source = nullptr;
        return false;
    }
    if (data_.source == nullptr) {
        return false;
    }
    return true;
}

bool SourceLoading::IsSizeAcceptable(std::unique_ptr<ImageSource>& imageSource, ImageInfo& imageInfo)
{
    error_ = imageSource->GetImageInfo(0, imageInfo);
    if (error_ != E_OK) {
        DfxManager::GetInstance()->HandleThumbnailError(data_.path, DfxType::IMAGE_SOURCE_GET_INFO, error_);
        return false;
    }

    int32_t minSize = imageInfo.size.width < imageInfo.size.height ? imageInfo.size.width : imageInfo.size.height;
    if (!IsSizeLargeEnough(data_, minSize)) {
        MEDIA_ERR_LOG("SourceLoading size not acceptable, width:%{public}d, height:%{public}d", imageInfo.size.width,
            imageInfo.size.height);
        return false;
    }

    // upload if minSize is larger than SHORT_SIDE_THRESHOLD and source is not from thumb
    data_.needUpload = data_.isCloudLoading && minSize >= SHORT_SIDE_THRESHOLD && state_ != SourceState::LocalThumb;
    data_.stats.sourceWidth = imageInfo.size.width;
    data_.stats.sourceHeight = imageInfo.size.height;
    DfxManager::GetInstance()->HandleThumbnailGeneration(data_.stats);
    return true;
}

bool SourceLoading::IsFinal()
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
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(tmpPath, err);
    if (err != E_OK || !imageSource) {     
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoading LoadSource error");
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
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(tmpPath, err);
    if (err != E_OK || !imageSource) {     
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoading LoadSource error");
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
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(data.path, err);
    if (err != E_OK || !imageSource) {     
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoading LoadSource error");
        return nullptr;
    }
    return imageSource;
}

void LocalOriginSource::SwitchToNextState(ThumbnailData& data, SourceState& state)
{
    if (data.isLoadingFromThumbToLcd) {
        if (data.isFrontLoading) {
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
    DfxManager::GetInstance()->HandleThumbnailGeneration(data.stats);

    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(tmpPath, err);
    if (err != E_OK || !imageSource) {     
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoading LoadSource error");
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
    std::string localPath = GetThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX);
    std::string suffixStr = data.path.substr(ROOT_MEDIA_DIR.length()) + "/" + "LCD.jpg";
    std::string tmpPath = ROOT_SANDBOX_DIR + ".thumbs/" + suffixStr; 
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    if (!IsCloudSourceAvailable(tmpPath)) {
        return nullptr;
    }
    int32_t totalCost = static_cast<int32_t>(MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    data.stats.openThumbCost = totalCost;
    DfxManager::GetInstance()->HandleThumbnailGeneration(data.stats);

    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(localPath, err);
    if (err != E_OK || !imageSource) {     
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoading LoadSource error");
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
    data.stats.openThumbCost = totalCost;
    DfxManager::GetInstance()->HandleThumbnailGeneration(data.stats);

    uint32_t err = E_OK;
    std::unique_ptr<ImageSource> imageSource = LoadImageSource(data.path, err);
    if (err != E_OK || !imageSource) {     
        error = E_ERR;
        MEDIA_ERR_LOG("SourceLoading LoadSource error");
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


