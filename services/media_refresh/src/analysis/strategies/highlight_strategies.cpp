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

#include "highlight_strategies.h"

#include "analysis_strategy_registry.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

bool HighlightCoverStrategy::ShouldRefreshCover(const UpdateAlbumData &oldAlbum,
    const AnalysisAlbumRefreshInfo &info)
{
    // 目前时刻相册媒体库无需刷新封面
    return false;
}

static auto RegisterHighlightStrategy(PhotoAlbumSubType subtype)
{
    return AnalysisStrategyRegistry::Register(subtype)
        .Effective<HighlightAlbumEffectiveStrategy>()
        .Count<HighlightCountStrategy>()
        .Cover<HighlightCoverStrategy>()
        .Picker<HighlightCoverPickerStrategy>()
        .UseDefaultPipeline()
        .Build();
}

static const auto HighlightStrategyReg = RegisterHighlightStrategy(PhotoAlbumSubType::HIGHLIGHT);
static const auto HighlightSuggestionStrategyReg = RegisterHighlightStrategy(PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS);

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
