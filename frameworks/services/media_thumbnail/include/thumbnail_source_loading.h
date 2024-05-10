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
EXPORT bool GenDecodeOpts(const Size& sourceSize, const Size& targetSize, DecodeOptions& decodeOpts);
EXPORT std::unique_ptr<ImageSource> LoadImageSource(const std::string &path, uint32_t &err);
EXPORT bool NeedAutoResize(const Size& size);

enum class SourceState : int32_t {
    BEGIN = -3,
    LOCAL_THUMB,
    LOCAL_LCD,
    LOCAL_ORIGIN,
    CLOUD_THUMB,
    CLOUD_LCD,
    CLOUD_ORIGIN,
    ERROR,
    FINISH,
};

const std::unordered_map<SourceState, std::string> STATE_NAME_MAP = {
    { SourceState::BEGIN, "BEGIN" },
    { SourceState::LOCAL_THUMB, "LOCAL_THUMB" },
    { SourceState::LOCAL_LCD, "LOCAL_LCD" },
    { SourceState::LOCAL_ORIGIN, "LOCAL_ORIGIN" },
    { SourceState::CLOUD_THUMB, "CLOUD_THUMB" },
    { SourceState::CLOUD_LCD, "CLOUD_LCD" },
    { SourceState::CLOUD_ORIGIN, "CLOUD_ORIGIN" },
    { SourceState::ERROR, "ERROR" },
    { SourceState::FINISH, "FINISH" },
};

class BeginSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR)
        { return nullptr; }
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize) { return false; }
};

class LocalThumbSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class LocalLcdSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class LocalOriginSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class CloudThumbSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class CloudLcdSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class CloudOriginSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR);
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state);
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize);
};

class ErrorSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR)
        { return nullptr; }
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state) { return; }
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize) { return false; }
};

class FinishSource {
public:
    EXPORT static std::unique_ptr<ImageSource> IsSourceAvailable(ThumbnailData& data, int32_t& ERROR)
        { return nullptr; }
    EXPORT static void SwitchToNextState(ThumbnailData& data, SourceState& state) { return; }
    EXPORT static bool IsSizeLargeEnough(ThumbnailData& data, int32_t& minSize) { return false; }
};

struct StateFunc {
    std::unique_ptr<ImageSource> (*IsSourceAvailable)(ThumbnailData& data, int32_t& ERROR);
    void (*SwitchToNextState)(ThumbnailData& data, SourceState& state);
    bool (*IsSizeLargeEnough)(ThumbnailData& data, int32_t& minSize);
};

const std::unordered_map<SourceState, StateFunc> STATE_FUNC_MAP = {
    { SourceState::BEGIN, { BeginSource::IsSourceAvailable,
        BeginSource::SwitchToNextState, BeginSource::IsSizeLargeEnough } },
    { SourceState::LOCAL_THUMB, { LocalThumbSource::IsSourceAvailable,
        LocalThumbSource::SwitchToNextState, LocalThumbSource::IsSizeLargeEnough } },
    { SourceState::LOCAL_LCD, { LocalLcdSource::IsSourceAvailable,
        LocalLcdSource::SwitchToNextState, LocalLcdSource::IsSizeLargeEnough } },
    { SourceState::LOCAL_ORIGIN, { LocalOriginSource::IsSourceAvailable,
        LocalOriginSource::SwitchToNextState, LocalOriginSource::IsSizeLargeEnough } },
    { SourceState::CLOUD_THUMB, { CloudThumbSource::IsSourceAvailable,
        CloudThumbSource::SwitchToNextState, CloudThumbSource::IsSizeLargeEnough } },
    { SourceState::CLOUD_LCD, { CloudLcdSource::IsSourceAvailable,
        CloudLcdSource::SwitchToNextState, CloudLcdSource::IsSizeLargeEnough } },
    { SourceState::CLOUD_ORIGIN, { CloudOriginSource::IsSourceAvailable,
        CloudOriginSource::SwitchToNextState, CloudOriginSource::IsSizeLargeEnough } },
    { SourceState::ERROR, { ErrorSource::IsSourceAvailable,
        ErrorSource::SwitchToNextState, ErrorSource::IsSizeLargeEnough } },
    { SourceState::FINISH, { FinishSource::IsSourceAvailable,
        FinishSource::SwitchToNextState, FinishSource::IsSizeLargeEnough } },
};

class SourceLoader {
public:
    SourceLoader(Size& desiredSize, ThumbnailData& data) : data_(data), desiredSize_(desiredSize) {};
    ~SourceLoader() = default;
    bool RunLoading();
private:
    void SetCurrentStateFunction();
    bool IsSizeAcceptable(std::unique_ptr<ImageSource>& imageSource, ImageInfo& imageInfo);
    bool CreateImage(std::unique_ptr<ImageSource>& imageSource, ImageInfo& imageInfo);
    bool IsFinal();

    int32_t error_ { E_OK };
    std::unique_ptr<ImageSource> (*IsSourceAvailable)(ThumbnailData& data, int32_t& ERROR);
    void (*SwitchToNextState)(ThumbnailData& data, SourceState& state);
    bool (*IsSizeLargeEnough)(ThumbnailData& data, int32_t& minSize);

    ThumbnailData& data_;
    Size& desiredSize_;
    SourceState state_ { SourceState::BEGIN };
};

} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_SERVICES_THUMBNAIL_SOURCE_LOADING_H