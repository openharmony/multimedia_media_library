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

#ifndef OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_PIPELINE_H
#define OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_PIPELINE_H

#include <memory>
#include <vector>

#include "analysis_analyzer_context.h"
#include "count_strategy.h"
#include "cover_strategy.h"
#include "cover_picker_strategy.h"
#include "photo_asset_change_info.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

enum Step : uint16_t {
    STEP_NONE     = 0x0000,
    STEP_COUNT    = 0x0001,
    STEP_RECORD   = 0x0002,
    STEP_DECISION = 0x0004,
    STEP_PICKER   = 0x0008,
    STEP_ALL      = 0x0001 | 0x0002 | 0x0004 | 0x0008
};

constexpr Step Combine(Step formerStep, Step laterStep)
{
    return static_cast<Step>(static_cast<uint16_t>(formerStep) | static_cast<uint16_t>(laterStep));
}

class PipelineFlow {
public:
    explicit constexpr PipelineFlow(Step mask = STEP_ALL) : mask_(mask) {}

    constexpr bool Allow(Step step) const
    {
        return (mask_ & step) != 0;
    }
    
    constexpr PipelineFlow operator+(Step step) const
    {
        return PipelineFlow(Combine(mask_, step));
    }

    constexpr PipelineFlow operator+(const PipelineFlow &o) const
    {
        return PipelineFlow(Combine(mask_, o.mask_));
    }

    constexpr PipelineFlow Only(Step step) const
    {
        return PipelineFlow(step);
    }

    // 预设流
    static constexpr PipelineFlow All()
    {
        return PipelineFlow(STEP_ALL);
    }

    static constexpr PipelineFlow CalculateDataChangePhase()
    {
        return PipelineFlow(Combine(STEP_COUNT, STEP_RECORD));
    }

    static constexpr PipelineFlow ApplyCoverChangePhase()
    {
        return PipelineFlow(Combine(STEP_DECISION, STEP_PICKER));
    }

private:
    Step mask_ { STEP_ALL };
};

class IPipelineStep {
public:
    explicit IPipelineStep(Step step) : step_(step) {}
    virtual ~IPipelineStep() = default;
    Step GetStep() const { return step_; }
    virtual bool Execute(AnalysisAnalyzerContext &ctx) = 0;

private:
    Step step_;
};

class AnalysisAlbumPipelineEngine {
public:
    void AddStep(std::unique_ptr<IPipelineStep> step);
    void Run(AnalysisAnalyzerContext &ctx) const;
    void Run(AnalysisAnalyzerContext &ctx, const PipelineFlow &flow) const;

private:
    std::vector<std::unique_ptr<IPipelineStep>> steps_;
};

// Step 声明
class CountStep : public IPipelineStep {
public:
    explicit CountStep(std::shared_ptr<ICountStrategy> strategy);
    bool Execute(AnalysisAnalyzerContext &ctx) override;
private:
    std::shared_ptr<ICountStrategy> strategy_;
};

// 记录潜在封面变更
class CoverRecordStep : public IPipelineStep {
public:
    explicit CoverRecordStep(std::shared_ptr<ICoverStrategy> strategy);
    bool Execute(AnalysisAnalyzerContext &ctx) override;
private:
    std::shared_ptr<ICoverStrategy> strategy_;
};

// 决策是否需要刷新封面
class CoverDecisionStep : public IPipelineStep {
public:
    explicit CoverDecisionStep(std::shared_ptr<ICoverStrategy> strategy);
    bool Execute(AnalysisAnalyzerContext &ctx) override;
private:
    std::shared_ptr<ICoverStrategy> strategy_;
};

// 真正 Pick 封面
class PickerStep : public IPipelineStep {
public:
    explicit PickerStep(std::shared_ptr<ICoverPickerStrategy> strategy);
    bool Execute(AnalysisAnalyzerContext &ctx) override;
private:
    std::shared_ptr<ICoverPickerStrategy> strategy_;
};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_PIPELINE_H
