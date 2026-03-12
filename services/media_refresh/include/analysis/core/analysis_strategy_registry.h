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
#ifndef OHOS_MEDIALIBRARY_ANALYSIS_STRATEGY_REGISTRY_H
#define OHOS_MEDIALIBRARY_ANALYSIS_STRATEGY_REGISTRY_H

#include <unordered_map>

#include "analysis_album_impact_analyzer.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

class AnalysisStrategyRegistry {
public:
    class AnalyzerBuilder {
    public:
        explicit AnalyzerBuilder(int32_t subtype);

        template<class T>
        AnalyzerBuilder& Effective()
        {
            policy_.effective = std::make_shared<T>();
            return *this;
        }

        template<class T>
        AnalyzerBuilder& Count()
        {
            policy_.count = std::make_shared<T>();
            return *this;
        }

        template<class T>
        AnalyzerBuilder& Cover()
        {
            policy_.cover = std::make_shared<T>();
            return *this;
        }

        template<class T>
        AnalyzerBuilder& Picker()
        {
            policy_.picker = std::make_shared<T>();
            return *this;
        }

        AnalyzerBuilder& UseDefaultPipeline();
        bool Build();

    private:
        int32_t subtype_;
        AnalysisStrategyPolicy policy_;
        AnalysisAlbumPipelineEngine pipeline_;
    };

    static AnalysisAlbumImpactAnalyzer* GetAnalyzer(int32_t subtype);

    static AnalyzerBuilder Register(int32_t subtype);
    static AnalyzerBuilder RegisterDefault();

private:
    static constexpr int32_t DEFAULT_SUBTYPE = PhotoAlbumSubType::ANY;
    static std::unordered_map<int32_t, std::unique_ptr<AnalysisAlbumImpactAnalyzer>>& Impl();
    static std::unique_ptr<AnalysisAlbumImpactAnalyzer> CreateDefaultAnalyzer();
};

} // AccurateRefresh
} // Media
} // OHOS
#endif // OHOS_MEDIALIBRARY_ANALYSIS_STRATEGY_REGISTRY_H
