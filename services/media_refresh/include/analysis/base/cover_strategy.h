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
#ifndef OHOS_MEDIALIBRARY_COVER_STRATEGY_REGISTER_H
#define OHOS_MEDIALIBRARY_COVER_STRATEGY_REGISTER_H

#include "album_change_info.h"
#include "medialibrary_rdb_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "photo_asset_change_info.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

// 接口：封面策略
class ICoverStrategy {
public:
    virtual ~ICoverStrategy() = default;

    virtual void RecordPotentialCoverChange(const PhotoAssetChangeData &data,
        AnalysisAlbumRefreshInfo &info, int32_t assetDelta) = 0;

    virtual bool NeedCoverRefresh(const UpdateAlbumData &baseInfo, AnalysisAlbumRefreshInfo &info) = 0;
};

// 抽象基类：提供通用封面变更检测
class CoverStrategyBase : public ICoverStrategy {
public:
    // 需要通过data记录受影响封面范围
    void RecordPotentialCoverChange(const PhotoAssetChangeData &data, AnalysisAlbumRefreshInfo &info,
        int32_t assetDelta) override;

    // 无需data，解析记录的数据，计算封面是否需要刷新
    bool NeedCoverRefresh(const UpdateAlbumData &baseInfo, AnalysisAlbumRefreshInfo &info) override;

protected:
    virtual bool NeedUpdateAddCover(const PhotoAssetChangeData &data, AnalysisAlbumRefreshInfo &info);
    virtual void UpdateAddCover(const PhotoAssetChangeData &data, AnalysisAlbumRefreshInfo &info);
    virtual void UpdateDeleteFileId(const PhotoAssetChangeData &data, AnalysisAlbumRefreshInfo &info);
    virtual bool ShouldRefreshCover(const UpdateAlbumData &oldAlbum, const AnalysisAlbumRefreshInfo &info);

    static std::string GetPhotoId(const std::string &uri);
    bool isCurrentCoverDeleted(const UpdateAlbumData &oldAlbum, const AnalysisAlbumRefreshInfo &info);
};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_COVER_STRATEGY_REGISTER_H
