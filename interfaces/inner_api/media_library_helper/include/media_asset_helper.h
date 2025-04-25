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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_HELPER_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_HELPER_H

#include "media_asset_base_capi.h"

namespace OHOS {
namespace Media {

class MediaAssetHelper {
public:
    virtual ~MediaAssetHelper() = default;

    virtual OH_MediaAsset* GetMediaAsset(std::string uri, int32_t cameraShotType, std::string burstKey) = 0;

    virtual OH_MediaAsset *GetOhMediaAsset(const std::string &uri) = 0;
};

class __attribute__((visibility("default"))) MediaAssetHelperFactory {
public:
    static std::shared_ptr<MediaAssetHelper> CreateMediaAssetHelper();
private:
    MediaAssetHelperFactory() = default;
    ~MediaAssetHelperFactory() = default;
};

} // Media
} // OHOS
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_HELPER_H