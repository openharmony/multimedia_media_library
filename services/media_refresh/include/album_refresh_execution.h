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

#ifndef OHOS_MEDIALIBRARY_ALBUM_REFRESH_EXECUTION_H
#define OHOS_MEDIALIBRARY_ALBUM_REFRESH_EXECUTION_H

#include <functional>
#include <map>
#include <vector>
#include <set>

#include "photo_asset_change_info.h"
#include "album_change_info.h"
#include "userfile_manager_types.h"
#include "album_accurate_refresh.h"
#include "system_album_info_calculation.h"

namespace OHOS {
namespace Media::AccurateRefresh {

class AlbumRefreshExecution {
public:
    int32_t RefreshAlbum(const std::vector<PhotoAssetChangeData> &assetChangeDatas);
    int32_t Notify();

private:
    std::vector<PhotoAlbumSubType> GetAlbumSubTypes();
    std::vector<int32_t> GetOwnerAlbumIds();
    int32_t CalAlbumsRefreshInfo(const std::vector<PhotoAssetChangeData> &assetChangeDatas);
    int32_t CalRefreshAlbumInfos();
    int32_t RefreshAlbumInfos();
    int32_t ForceRefreshAlbumInfo(int32_t albumId, bool isHidden);
    int32_t RefreshAlbumInfo();
    void UpdateAlbumCount(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo);
    bool IsValidCover(const PhotoAssetChangeInfo &assetInfo);

    int32_t UpdateRefreshAlbumInfo(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo, int32_t subType);
    bool UpdateAlbumCover(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo, int32_t subType);
    bool UpdateAlbumHiddenCover(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo);
    void ClearAlbumInfo(AlbumChangeInfo &albumInfo);
    void ClearHiddenAlbumInfo(AlbumChangeInfo &albumInfo);
    int32_t GetUpdateValues(NativeRdb::ValuesBucket &values, const AlbumChangeInfo &albumInfo, bool isHidden);

    void CheckUpdateAlbumInfo(const AlbumChangeInfo &albumInfo, bool isHidden);

private:
    // 系统相册
    static std::map<PhotoAlbumSubType, SystemAlbumInfoCalculation> systemAlbumCalculations_;
    std::map<PhotoAlbumSubType, AlbumRefreshInfo> systemAlbumInfos_;
    
    // 用户相册和来源相册
    std::map<int32_t, AlbumRefreshInfo> ownerAlbumInfos_;
    // 修改前相册信息
    std::map<int32_t, AlbumChangeInfo> initAlbumInfos_;

    std::shared_ptr<AlbumAccurateRefresh> albumRefresh_;

    // 需要刷新的相册信息
    std::map<int32_t, AlbumChangeInfo> refreshAlbums_;

    // 需要强制刷新的相册信息
    std::set<int32_t> forceRefreshAlbums_;
    std::set<int32_t> forceRefreshHiddenAlbums_;

    std::mutex albumRefreshMtx_;
};

} // namespace Media
} // namespace OHOS

#endif