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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_DATA_H
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_DATA_H

#include <pixel_map.h>

#include "thumbnail_const.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
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

class ThumbnailData {
public:
    struct GenerateStats {
        std::string uri;
        GenerateScene scene {GenerateScene::LOCAL};
        int32_t openThumbCost {0};
        int32_t openLcdCost {0};
        int32_t openOriginCost {0};
        LoadSourceType sourceType {LoadSourceType::LOCAL_PHOTO};
        int32_t sourceWidth {0};
        int32_t sourceHeight {0};
        int32_t totalCost {0};
        int32_t errorCode {0};
        int64_t startTime {0};
        int64_t finishTime {0};
    };

    struct SourceLoaderOptions {
        // if false, target decode size is LCD size
        bool decodeInThumbSize {false};
        bool needUpload {false};

        // if true, create HDR pixelmap
        EXPORT bool isHdr {false};
        std::unordered_map<SourceState, SourceState> loadingStates;
    };

    EXPORT ThumbnailData() = default;

    EXPORT virtual ~ThumbnailData()
    {
        source = nullptr;
        thumbnail.clear();
        lcd.clear();
        monthAstc.clear();
        yearAstc.clear();
    }

    EXPORT int32_t mediaType {-1};
    EXPORT int64_t dateModified {0};
    EXPORT int32_t orientation {0};
    EXPORT int32_t photoHeight {0};
    EXPORT int32_t photoWidth {0};

    // Loaded lcd source can be resized to generate thumbnail in order
    EXPORT bool needResizeLcd {false};
    EXPORT bool isLocalFile {true};
    EXPORT bool isOpeningCloudFile {false};
    EXPORT bool isNeedStoreSize {true};
    EXPORT std::shared_ptr<PixelMap> source;
    EXPORT std::shared_ptr<PixelMap> sourceEx;
    EXPORT std::vector<uint8_t> thumbnail;
    EXPORT std::vector<uint8_t> thumbAstc;
    EXPORT std::vector<uint8_t> monthAstc;
    EXPORT std::vector<uint8_t> yearAstc;
    EXPORT std::vector<uint8_t> lcd;
    EXPORT std::string dateAdded;
    EXPORT std::string dateTaken;
    EXPORT std::string displayName;
    EXPORT std::string fileUri;
    EXPORT std::string id;
    EXPORT std::string cloudId;
    EXPORT std::string udid;
    EXPORT std::string path;
    EXPORT std::string thumbnailKey;
    EXPORT std::string lcdKey;
    EXPORT std::string tracks;
    EXPORT std::string trigger;
    EXPORT std::string frame;
    EXPORT std::string timeStamp;
    EXPORT Size lcdDesiredSize;
    EXPORT Size thumbDesiredSize;
    EXPORT GenerateStats stats;
    EXPORT SourceLoaderOptions loaderOpts;
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_DATA_H
