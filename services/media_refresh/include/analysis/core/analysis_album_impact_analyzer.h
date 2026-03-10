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
#ifndef OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_IMPACT_ANALYZER_H
#define OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_IMPACT_ANALYZER_H

#include "analysis_album_pipeline.h"
#include "analysis_analyzer_context.h"
#include "effective_strategy.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

struct AnalysisStrategyPolicy {
    std::shared_ptr<IAlbumEffectiveStrategy> effective;
    std::shared_ptr<ICountStrategy> count;
    std::shared_ptr<ICoverStrategy> cover;
    std::shared_ptr<ICoverPickerStrategy> picker;

    bool isValidPolicy() const
    {
        return effective != nullptr && count != nullptr && cover != nullptr && picker != nullptr;
    }
};

class AnalysisAlbumImpactAnalyzer final {
public:
    AnalysisAlbumImpactAnalyzer(AnalysisStrategyPolicy policy, AnalysisAlbumPipelineEngine pipeline);

    void Analyze(AnalysisAnalyzerContext &ctx, PipelineFlow flow = PipelineFlow::All());
    int32_t CalcDataChange(const PhotoAssetChangeData &data,
        const UpdateAlbumData &base, AnalysisAlbumRefreshInfo &info);
    bool ApplyCoverChange(const UpdateAlbumData &base, AnalysisAlbumRefreshInfo &info);

private:
    AnalysisStrategyPolicy policy_;
    AnalysisAlbumPipelineEngine pipeline_;
};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_IMPACT_ANALYZER_H
