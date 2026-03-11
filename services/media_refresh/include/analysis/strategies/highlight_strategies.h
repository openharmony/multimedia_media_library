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
#ifndef OHOS_MEDIALIBRARY_HIGHLIGHT_STRATEGIES_H
#define OHOS_MEDIALIBRARY_HIGHLIGHT_STRATEGIES_H

#include <memory>
#include <string>

#include "analysis_album_impact_analyzer.h"
#include "analysis_strategy_registry.h"
#include "count_strategy.h"
#include "cover_strategy.h"
#include "cover_picker_strategy.h"
#include "effective_strategy.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

// 高光时刻相册（4104、4105）默认有效策略
using HighlightAlbumEffectiveStrategy = AlbumEffectiveStrategyBase;

// 人像计数策略（默认）
using HighlightCountStrategy = CountStrategyBase;

// 人像封面策略
class HighlightCoverStrategy : public CoverStrategyBase {
private:
    bool ShouldRefreshCover(const UpdateAlbumData &oldAlbum, const AnalysisAlbumRefreshInfo &info) override;
};

// 专用封面挑选器
using HighlightCoverPickerStrategy = CoverPickerStrategyBase;

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_HIGHLIGHT_STRATEGIES_H
