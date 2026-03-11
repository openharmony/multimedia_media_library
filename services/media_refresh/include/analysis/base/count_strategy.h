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
#ifndef OHOS_MEDIALIBRARY_COUNT_STRATEGY_REGISTER_H
#define OHOS_MEDIALIBRARY_COUNT_STRATEGY_REGISTER_H

#include "album_change_info.h"
#include "medialibrary_rdb_utils.h"
#include "media_log.h"
#include "photo_asset_change_info.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

// 接口：计数策略
class ICountStrategy {
public:
    virtual ~ICountStrategy() = default;
    virtual int32_t CalcCountDelta(const PhotoAssetChangeData &data,
        const UpdateAlbumData &baseInfo, AnalysisAlbumRefreshInfo &info) = 0;
};

// 抽象基类：提供通用 count 计算逻辑
class CountStrategyBase : public ICountStrategy {
public:
    virtual int32_t CalcCountDelta(const PhotoAssetChangeData &data,
        const UpdateAlbumData &baseInfo, AnalysisAlbumRefreshInfo &info) override;

protected:
    static constexpr int32_t DELTA_ADD = 1;
    static constexpr int32_t DELTA_REMOVE = -1;
    static constexpr int32_t DELTA_NO_CHANGE = 0;

    virtual int ComputeDelta(const PhotoAssetChangeData &data, const UpdateAlbumData &baseInfo) const;

    virtual bool IsVisibleSystemAsset(const PhotoAssetChangeInfo &assetInfo) const;

    virtual int HandleAddOperation(const PhotoAssetChangeData &data, const UpdateAlbumData &baseInfo) const;
    virtual int HandleRemoveOperation(const PhotoAssetChangeData &data, const UpdateAlbumData &baseInfo) const;

    // 默认实现：和新增/删除一致，子类可覆盖
    virtual int HandleUpdateOperation(const PhotoAssetChangeData &data, const UpdateAlbumData &baseInfo) const;
};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_COUNT_STRATEGY_REGISTER_H
