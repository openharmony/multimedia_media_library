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

#define MLOG_TAG "AccurateRefresh::SystemAlbumInfoCalculation"

#include "system_album_info_calculation.h"
#include "album_asset_helper.h"

#include "accurate_debug_log.h"

using namespace std;

namespace OHOS {
namespace Media::AccurateRefresh {

bool SystemAlbumInfoCalculation::CalAlbumRefreshInfo(const PhotoAssetChangeData &assetChangeData,
    AlbumRefreshInfo &refreshInfo)
{
    bool ret = false;
    // count/hidden count/video count数量更新
    AlbumRefreshInfo beforeRefreshInfo = refreshInfo;
    if (UpdateCount(assetChangeData, isSystemAsset_, refreshInfo.deltaCount_)) {
        ret = true;
    }
    
    if (UpdateCount(assetChangeData, isHiddenSystemAsset_, refreshInfo.deltaHiddenCount_)) {
        ret = true;
    }
    
    if (UpdateCount(assetChangeData, isVideoAsset_, refreshInfo.deltaVideoCount_)) {
        ret = true;
    }

    // cover/hidden cover更新
    if (UpdateCover(assetChangeData, isSystemAsset_, isNewerAsset_, refreshInfo.deltaAddCover_,
        refreshInfo.deltaRemoveCover_)) {
        ret = true;
    }
    
    if (UpdateCover(assetChangeData, isHiddenSystemAsset_, isNewerHiddenAsset_, refreshInfo.deltaAddHiddenCover_,
        refreshInfo.deltaRemoveHiddenCover_)) {
        ret = true;
    }

    if (ret) {
        ACCURATE_INFO("system album refreshInfo[%{public}d] before: %{public}s", subType_,
            beforeRefreshInfo.ToString().c_str());
        ACCURATE_INFO("system album refreshInfo[%{public}d] after: %{public}s", subType_,
            refreshInfo.ToString().c_str());
    }
    
    return ret;
}

bool SystemAlbumInfoCalculation::UpdateCover(const PhotoAssetChangeData &assetChangeData,
    std::function<bool(const PhotoAssetChangeInfo&)> isSystemAsset,
    std::function<bool(const PhotoAssetChangeInfo&, const PhotoAssetChangeInfo&)> isNewerAsset,
    PhotoAssetChangeInfo &addCover, PhotoAssetChangeInfo &removeCover)
{
    return AlbumAssetHelper::UpdateCover(assetChangeData, isSystemAsset, isNewerAsset, addCover, removeCover);
}

bool SystemAlbumInfoCalculation::UpdateCount(const PhotoAssetChangeData &assetChangeData,
    std::function<bool(PhotoAssetChangeInfo)> isSystemAsset, int32_t &count)
{
    return AlbumAssetHelper::UpdateCount(assetChangeData, isSystemAsset, count);
}

} // namespace Media
} // namespace OHOS