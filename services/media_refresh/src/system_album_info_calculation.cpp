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
        refreshInfo.assetModifiedCnt_++;
        ret = true;
    }
    
    if (UpdateCount(assetChangeData, isHiddenSystemAsset_, refreshInfo.deltaHiddenCount_)) {
        refreshInfo.hiddenAssetModifiedCnt_++;
        ret = true;
    }
    
    if (UpdateCount(assetChangeData, isVideoAsset_, refreshInfo.deltaVideoCount_)) {
        ret = true;
    }

    // cover/hidden cover更新
    if (UpdateCover(assetChangeData, isSystemAsset_, isNewerAsset_, refreshInfo.deltaAddCover_,
        refreshInfo.removeFileIds)) {
        ret = true;
    }
    
    if (UpdateCover(assetChangeData, isHiddenSystemAsset_, isNewerHiddenAsset_, refreshInfo.deltaAddHiddenCover_,
        refreshInfo.removeHiddenFileIds)) {
        ret = true;
    }
    return ret;
}

bool SystemAlbumInfoCalculation::UpdateCover(const PhotoAssetChangeData &assetChangeData,
    std::function<bool(const PhotoAssetChangeInfo&)> isSystemAsset,
    std::function<bool(const PhotoAssetChangeInfo&, const PhotoAssetChangeInfo&)> isNewerAsset,
    PhotoAssetChangeInfo &addCover, unordered_set<int32_t> &removeFileIds)
{
    return AlbumAssetHelper::UpdateCover(assetChangeData, isSystemAsset, isNewerAsset, addCover, removeFileIds);
}

bool SystemAlbumInfoCalculation::UpdateCount(const PhotoAssetChangeData &assetChangeData,
    std::function<bool(PhotoAssetChangeInfo)> isSystemAsset, int32_t &count)
{
    return AlbumAssetHelper::UpdateCount(assetChangeData, isSystemAsset, count);
}

} // namespace Media
} // namespace OHOS