/*
 * Copyright (C) 2024    Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SOURCE_LOADING_H
#define FRAMEWORKS_SERVICES_THUMBNAIL_SOURCE_LOADING_H

#include <unordered_map>

#include "image_packer.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "thumbnail_const.h"
#include "thumbnail_data.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

EXPORT Size ConvertDecodeSize(ThumbnailData& data, const Size& sourceSize, Size& desiredSize);
EXPORT std::unique_ptr<ImageSource> LoadImageSource(const std::string& path, uint32_t& err);
EXPORT bool GenDecodeOpts(const Size& sourceSize, const Size& targetSize, DecodeOptions& decodeOpts);
EXPORT bool NeedAutoResize(const Size& size);
EXPORT bool ResizeThumb(int& width, int& height);
EXPORT bool ResizeLcd(int& width, int& height);
EXPORT bool ScaleTargetPixelMap(ThumbnailData& data, const Size& targetSize);

enum class SourceState : int32_t {
    Begin = -3,
    LocalThumb,
    LocalLcd,
    LocalOrigin,
    CloudThumb,
    CloudLcd,
    CloudOrigin,
    Error,
    Finish,
};

const std::unordered_map<SourceState, std::string> STATE_NAME_MAP = {
    { SourceState::Begin, "Begin" },
    { SourceState::LocalThumb, "LocalThumb" },
    { SourceState::LocalLcd, "LocalLcd" },
    { SourceState::LocalOrigin, "LocalOrigin" },
    { SourceState::CloudThumb, "CloudThumb" },
    { SourceState::CloudLcd, "CloudLcd" },
    { SourceState::CloudOrigin, "CloudOrigin" },
    { SourceState::Error, "Error" },
    { SourceState::Finish, "Finish" },
};

class BeginSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error) 
        { return nullptr; }
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize) { return false; }
};

class LocalThumbSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class LocalLcdSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class LocalOriginSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class CloudThumbSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class CloudLcdSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class CloudOriginSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class ErrorSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error) 
        { return nullptr; }
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state) { return; }
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize) { return false; }
};

class FinishSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& error) 
        { return nullptr; }
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state) { return; }
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize) { return false; }
};

struct StateFunc {
    std::unique_ptr<ImageSource> (*IsSourceAvailable)(ThumbnailData& data, int32_t& error);
    void (*SwitchToNextState)(ThumbnailData& data, SourceState& state);
    bool (*IsSizeLargeEnough)(ThumbnailData& data, int32_t& minSize);
};

const std::unordered_map<SourceState, StateFunc> STATE_FUNC_MAP = {
    { SourceState::Begin, { BeginSource::IsSourceAvailable, BeginSource::SwitchToNextState,
        BeginSource::IsSizeLargeEnough } },
    { SourceState::LocalThumb, { LocalThumbSource::IsSourceAvailable, LocalThumbSource::SwitchToNextState,                      
        LocalThumbSource::IsSizeLargeEnough } },
    { SourceState::LocalLcd, { LocalLcdSource::IsSourceAvailable, LocalLcdSource::SwitchToNextState,
        LocalLcdSource::IsSizeLargeEnough } },
    { SourceState::LocalOrigin, { LocalOriginSource::IsSourceAvailable, LocalOriginSource::SwitchToNextState,
        LocalOriginSource::IsSizeLargeEnough } },
    { SourceState::CloudThumb, { CloudThumbSource::IsSourceAvailable, CloudThumbSource::SwitchToNextState,
        CloudThumbSource::IsSizeLargeEnough } },
    { SourceState::CloudLcd, { CloudLcdSource::IsSourceAvailable, CloudLcdSource::SwitchToNextState,
        CloudLcdSource::IsSizeLargeEnough } },
    { SourceState::CloudOrigin, { CloudOriginSource::IsSourceAvailable, CloudOriginSource::SwitchToNextState,
        CloudOriginSource::IsSizeLargeEnough } },
    { SourceState::Error, { ErrorSource::IsSourceAvailable, ErrorSource::SwitchToNextState,
        ErrorSource::IsSizeLargeEnough } },
    { SourceState::Finish, { FinishSource::IsSourceAvailable, FinishSource::SwitchToNextState,
        FinishSource::IsSizeLargeEnough } },
};

#define SET_CURRENT_STATE_FUNCTION(state)                                                                              \
    do {                                                                                                               \
        StateFunc stateFunc = STATE_FUNC_MAP.at(state);                                                                \
        IsSourceAvailable = stateFunc.IsSourceAvailable;                                                               \
        SwitchToNextState = stateFunc.SwitchToNextState;                                                               \
        IsSizeLargeEnough = stateFunc.IsSizeLargeEnough;                                                               \
    } while(0);


class SourceLoading {
public:
    SourceLoading(Size& desiredSize, ThumbnailData& data) : data_(data), desiredSize_(desiredSize) {};
    ~SourceLoading() = default;
    bool RunLoading();
private:
    bool IsSizeAcceptable(std::unique_ptr<ImageSource>& imageSource, ImageInfo& imageInfo);
    bool IsFinal();

    int32_t error_ { E_OK };
    std::unique_ptr<ImageSource> (*IsSourceAvailable)(ThumbnailData& data, int32_t& error);
    void (*SwitchToNextState)(ThumbnailData& data, SourceState& state);
    bool (*IsSizeLargeEnough)(ThumbnailData& data, int32_t& minSize);

    ThumbnailData& data_;
    Size& desiredSize_;
    SourceState state_ { SourceState::Begin };
};

} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_SERVICES_THUMBNAIL_SOURCE_LOADING_H