/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_HIDDEN_ASSET_HELPER_H
#define OHOS_MEDIALIBRARY_HIDDEN_ASSET_HELPER_H

#include "album_asset_helper.h"

namespace OHOS {
namespace Media::AccurateRefresh {
class HiddenAssetHelper {
public:
    // 系统资产
    static bool IsAsset(const PhotoAssetChangeInfo &assetInfo);

    // 视频资产
    static bool IsVideoAsset(const PhotoAssetChangeInfo &assetInfo);
    static bool IsHiddenAsset(const PhotoAssetChangeInfo &assetInfo);
    static bool IsNewerAsset(const PhotoAssetChangeInfo &compareAssetInfo,
        const PhotoAssetChangeInfo &currentAssetInfo);
    static bool IsNewerHiddenAsset(const PhotoAssetChangeInfo &compareAssetInfo,
        const PhotoAssetChangeInfo &currentAssetInfo);
};

} // namespace Media
} // namespace OHOS

#endif