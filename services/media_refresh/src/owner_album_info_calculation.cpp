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

#define MLOG_TAG "AccurateRefresh::OwnerAlbumInfoCalculation"

#include "owner_album_info_calculation.h"
#include "album_asset_helper.h"
#include "accurate_debug_log.h"

using namespace std;

namespace OHOS {
namespace Media::AccurateRefresh {

map<int32_t, AlbumRefreshInfo> OwnerAlbumInfoCalculation::CalOwnerAlbumInfo(
    const std::vector<PhotoAssetChangeData> &assetChangeDatas)
{
    map<int32_t, AlbumRefreshInfo> ownerAlbumInfos;
    for (auto &assetChangeData : assetChangeDatas) {
        auto initAlbumId = assetChangeData.infoBeforeChange_.ownerAlbumId_;
        auto modifiedAlbumId = assetChangeData.infoAfterChange_.ownerAlbumId_;

        // 无效数据
        if (initAlbumId == INVALID_INT32_VALUE && modifiedAlbumId == INVALID_INT32_VALUE) {
            MEDIA_WARN_LOG("assset change data invalid albumId.");
            continue;
        }

        // 更新initAlbumId
        if (initAlbumId != INVALID_INT32_VALUE) {
            auto iterInitAlbumInfo = ownerAlbumInfos.find(initAlbumId);
            if (iterInitAlbumInfo != ownerAlbumInfos.end()) {
                CalOwnerAlbumInfo(assetChangeData, initAlbumId, iterInitAlbumInfo->second);
            } else {
                AlbumRefreshInfo initRefreshInfo;
                CalOwnerAlbumInfo(assetChangeData, initAlbumId, initRefreshInfo);
                ownerAlbumInfos.emplace(initAlbumId, initRefreshInfo);
            }
        }

        // 更新modifiedAlbumId; 如果和initAlbumId相同，则不需要再次处理
        if (modifiedAlbumId != INVALID_INT32_VALUE && initAlbumId != modifiedAlbumId) {
            auto iterModifiedAlbumInfo = ownerAlbumInfos.find(modifiedAlbumId);
            if (iterModifiedAlbumInfo != ownerAlbumInfos.end()) {
                CalOwnerAlbumInfo(assetChangeData, modifiedAlbumId, iterModifiedAlbumInfo->second);
            } else {
                AlbumRefreshInfo modifedRefreshInfo;
                CalOwnerAlbumInfo(assetChangeData, modifiedAlbumId, modifedRefreshInfo);
                ownerAlbumInfos.emplace(modifiedAlbumId, modifedRefreshInfo);
            }
        }
    }
    return ownerAlbumInfos;
}

bool OwnerAlbumInfoCalculation::IsOwnerAlbumAsset(const PhotoAssetChangeInfo &assetInfo, int32_t albumId)
{
    return assetInfo.ownerAlbumId_ == albumId && AlbumAssetHelper::IsCommonSystemAsset(assetInfo, false);
}

bool OwnerAlbumInfoCalculation::IsOwnerAlbumHiddenAsset(const PhotoAssetChangeInfo &assetInfo, int32_t albumId)
{
    return assetInfo.ownerAlbumId_ == albumId && AlbumAssetHelper::IsCommonSystemAsset(assetInfo, true);
}

bool OwnerAlbumInfoCalculation::IsOwnerAlbumVideoAsset(const PhotoAssetChangeInfo &assetInfo, int32_t albumId)
{
    return IsOwnerAlbumAsset(assetInfo, albumId) && AlbumAssetHelper::IsVideoAsset(assetInfo);
}

bool OwnerAlbumInfoCalculation::IsNewerAsset(const PhotoAssetChangeInfo &compareAssetInfo,
    const PhotoAssetChangeInfo &currentAssetInfo, int32_t albumId)
{
    return IsOwnerAlbumAsset(compareAssetInfo, albumId) && IsOwnerAlbumAsset(currentAssetInfo, albumId)
        && AlbumAssetHelper::IsNewerByDateTaken(compareAssetInfo, currentAssetInfo, false);
}

bool OwnerAlbumInfoCalculation::IsNewerHiddenAsset(const PhotoAssetChangeInfo &compareAssetInfo,
    const PhotoAssetChangeInfo &currentAssetInfo, int32_t albumId)
{
    return IsOwnerAlbumAsset(compareAssetInfo, albumId) && IsOwnerAlbumAsset(currentAssetInfo, albumId)
        && AlbumAssetHelper::IsNewerByHiddenTime(compareAssetInfo, currentAssetInfo);
}

bool OwnerAlbumInfoCalculation::UpdateCover(const PhotoAssetChangeData &assetChangeData,
    function<bool(const PhotoAssetChangeInfo&, int32_t)> isAsset, int32_t albumId,
    function<bool(const PhotoAssetChangeInfo&, const PhotoAssetChangeInfo&, int32_t)> isNewerAsset,
    PhotoAssetChangeInfo &addCover, PhotoAssetChangeInfo &removeCover)
{
    function<bool(const PhotoAssetChangeInfo&)> isAlbumAsset =
        [&] (const PhotoAssetChangeInfo& assetChangeData) -> bool {
            return isAsset(assetChangeData, albumId);
    };
    function<bool(const PhotoAssetChangeInfo&, const PhotoAssetChangeInfo&)> isAlbumNewerAsset =
        [&] (const PhotoAssetChangeInfo &compare, const PhotoAssetChangeInfo &current) -> bool {
            return isNewerAsset(compare, current, albumId);
    };
    return AlbumAssetHelper::UpdateCover(assetChangeData, isAlbumAsset, isAlbumNewerAsset, addCover, removeCover);
}

bool OwnerAlbumInfoCalculation::UpdateCount(const PhotoAssetChangeData &assetChangeData,
    std::function<bool(const PhotoAssetChangeInfo&, int32_t)> isAsset, int32_t albumId, int32_t &count)
{
    function<bool(const PhotoAssetChangeInfo&)> isAlbumAsset =
        [&] (const PhotoAssetChangeInfo& assetChangeData) -> bool {
            return isAsset(assetChangeData, albumId);
    };
    return AlbumAssetHelper::UpdateCount(assetChangeData, isAlbumAsset, count);
}

bool OwnerAlbumInfoCalculation::CalOwnerAlbumInfo(const PhotoAssetChangeData &assetChangeData, int32_t albumId,
    AlbumRefreshInfo &refreshInfo)
{
    bool ret = false;
    AlbumRefreshInfo beforeRefreshInfo = refreshInfo;
    // count/hidden count/video count数量更新
    if (UpdateCount(assetChangeData, IsOwnerAlbumAsset, albumId, refreshInfo.deltaCount_)) {
        ret = true;
    }
    
    if (UpdateCount(assetChangeData, IsOwnerAlbumHiddenAsset, albumId, refreshInfo.deltaHiddenCount_)) {
        ret = true;
    }
    
    if (UpdateCount(assetChangeData, IsOwnerAlbumVideoAsset, albumId, refreshInfo.deltaVideoCount_)) {
        ret = true;
    }

    // cover/hidden cover更新
    if (UpdateCover(assetChangeData, IsOwnerAlbumAsset, albumId, IsNewerAsset, refreshInfo.deltaAddCover_,
        refreshInfo.deltaRemoveCover_)) {
        ret = true;
    }
    
    if (UpdateCover(assetChangeData, IsOwnerAlbumHiddenAsset, albumId, IsNewerHiddenAsset,
        refreshInfo.deltaAddHiddenCover_, refreshInfo.deltaRemoveHiddenCover_)) {
        ret = true;
    }
    return ret;
}

} // namespace Media
} // namespace OHOS