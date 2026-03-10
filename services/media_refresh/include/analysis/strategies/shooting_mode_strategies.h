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
#ifndef OHOS_MEDIALIBRARY_SHOOTING_MODE_STRATEGIES_H
#define OHOS_MEDIALIBRARY_SHOOTING_MODE_STRATEGIES_H

#include <memory>
#include <string>

#include "analysis_album_impact_analyzer.h"
#include "analysis_strategy_registry.h"
#include "count_strategy.h"
#include "cover_strategy.h"
#include "cover_picker_strategy.h"
#include "effective_strategy.h"
#include "media_log.h"
#include "photo_asset_change_info.h"
#include "shooting_mode_column.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

// 拍摄模式相册默认有效策略
using ShootingModeAlbumEffectiveStrategy = AlbumEffectiveStrategyBase;

// 拍摄模式相册自定义计数策略
class ShootingModeCountStrategy : public CountStrategyBase {
private:
    int HandleUpdateOperation(const PhotoAssetChangeData &data, const UpdateAlbumData &baseInfo) const override;

    bool IsTypeExist(const PhotoAssetChangeInfo &info, ShootingModeAlbumType currentType) const;
    int HandleDeltaCountResult(int delta, bool isTypeContainBefore, bool isTypeContainAfter,
        const UpdateAlbumData &baseInfo) const;
};

// 拍摄模式相册封面默认变更策略
using ShootingModeCoverStrategy = CoverStrategyBase;

// 拍摄模式相册默认封面挑选器
using ShootingModeCoverPickerStrategy = CoverPickerStrategyBase;

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_SHOOTING_MODE_STRATEGIES_H
