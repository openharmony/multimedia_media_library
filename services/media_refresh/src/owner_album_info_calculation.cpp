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

unordered_map<int32_t, AlbumRefreshInfo> OwnerAlbumInfoCalculation::CalOwnerAlbumInfo(
    const std::vector<PhotoAssetChangeData> &assetChangeDatas)
{
    unordered_map<int32_t, AlbumRefreshInfo> ownerAlbumInfos;
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
                if (CalOwnerAlbumInfo(assetChangeData, initAlbumId, initRefreshInfo)) {
                    ownerAlbumInfos.emplace(initAlbumId, initRefreshInfo);
                }
            }
        }

        // 更新modifiedAlbumId; 如果和initAlbumId相同，则不需要再次处理
        if (modifiedAlbumId != INVALID_INT32_VALUE && initAlbumId != modifiedAlbumId) {
            auto iterModifiedAlbumInfo = ownerAlbumInfos.find(modifiedAlbumId);
            if (iterModifiedAlbumInfo != ownerAlbumInfos.end()) {
                CalOwnerAlbumInfo(assetChangeData, modifiedAlbumId, iterModifiedAlbumInfo->second);
            } else {
                AlbumRefreshInfo modifedRefreshInfo;
                if (CalOwnerAlbumInfo(assetChangeData, modifiedAlbumId, modifedRefreshInfo)) {
                    ownerAlbumInfos.emplace(modifiedAlbumId, modifedRefreshInfo);
                }
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
    PhotoAssetChangeInfo &addCover, unordered_set<int32_t> &removeFileIds)
{
    function<bool(const PhotoAssetChangeInfo&)> isAlbumAsset =
        [&] (const PhotoAssetChangeInfo& assetChangeData) -> bool {
            return isAsset(assetChangeData, albumId);
    };
    function<bool(const PhotoAssetChangeInfo&, const PhotoAssetChangeInfo&)> isAlbumNewerAsset =
        [&] (const PhotoAssetChangeInfo &compare, const PhotoAssetChangeInfo &current) -> bool {
            return isNewerAsset(compare, current, albumId);
    };
    return AlbumAssetHelper::UpdateCover(assetChangeData, isAlbumAsset, isAlbumNewerAsset, addCover, removeFileIds);
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
    AlbumRefreshTimestamp assetTimestamp(assetChangeData.infoBeforeChange_.timestamp_,
        assetChangeData.infoAfterChange_.timestamp_);
    // 用户相册信息变化
    if (IsOwnerAlbumInfoChange(assetChangeData, IsOwnerAlbumAsset, albumId)) {
        function<bool(AlbumRefreshInfo&)> calRefreshInfoFunc = [&assetChangeData, albumId]
            (AlbumRefreshInfo &refreshInfo) -> bool {
                return OwnerAlbumInfoCalculation::UpdateRefreshNormalInfo(assetChangeData, albumId, refreshInfo);
        };
        ret = AlbumAssetHelper::CalAlbumRefreshInfo(calRefreshInfoFunc, refreshInfo, albumId, false, assetTimestamp);
    }
    // 用户相册隐藏信息变化
    if (IsOwnerAlbumInfoChange(assetChangeData, IsOwnerAlbumHiddenAsset, albumId)) {
        function<bool(AlbumRefreshInfo&)> calHiddenRefreshInfoFunc = [&assetChangeData, albumId]
            (AlbumRefreshInfo &refreshInfo) -> bool {
                return OwnerAlbumInfoCalculation::UpdateRefreshHiddenInfo(assetChangeData, albumId, refreshInfo);
        };
        ret = AlbumAssetHelper::CalAlbumRefreshInfo(calHiddenRefreshInfoFunc, refreshInfo, albumId, true,
            assetTimestamp) || ret;
    }
    return ret;
}

bool OwnerAlbumInfoCalculation::UpdateRefreshNormalInfo(const PhotoAssetChangeData &assetChangeData, int32_t albumId,
    AlbumRefreshInfo& refreshInfo)
{
    bool ret = false;
    if (UpdateCount(assetChangeData, IsOwnerAlbumAsset, albumId, refreshInfo.deltaCount_)) {
        refreshInfo.assetModifiedCnt_++;
        ret = true;
    }
    if (UpdateCount(assetChangeData, IsOwnerAlbumVideoAsset, albumId,
        refreshInfo.deltaVideoCount_)) {
        ret = true;
    }
    if (UpdateCover(assetChangeData, IsOwnerAlbumAsset, albumId, IsNewerAsset,
        refreshInfo.deltaAddCover_, refreshInfo.removeFileIds)) {
        ret = true;
    }
    return ret;
}

bool OwnerAlbumInfoCalculation::UpdateRefreshHiddenInfo(const PhotoAssetChangeData &assetChangeData, int32_t albumId,
AlbumRefreshInfo& refreshInfo)
{
    bool ret = false;
    if (UpdateCount(assetChangeData, IsOwnerAlbumHiddenAsset, albumId,
        refreshInfo.deltaHiddenCount_)) {
        refreshInfo.hiddenAssetModifiedCnt_++;
        ret = true;
    }
    if (UpdateCover(assetChangeData, IsOwnerAlbumHiddenAsset, albumId, IsNewerHiddenAsset,
        refreshInfo.deltaAddHiddenCover_, refreshInfo.removeHiddenFileIds)) {
        ret = true;
    }
    return ret;
}

bool OwnerAlbumInfoCalculation::IsOwnerAlbumInfoChange(const PhotoAssetChangeData &assetChangeData,
        std::function<bool(PhotoAssetChangeInfo, int32_t)> isAlbumAsset, int32_t albumId)
{
    return isAlbumAsset(assetChangeData.infoBeforeChange_, albumId) !=
        isAlbumAsset(assetChangeData.infoAfterChange_, albumId);
}

} // namespace Media
} // namespace OHOS