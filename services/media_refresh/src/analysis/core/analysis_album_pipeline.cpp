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

#include "analysis_album_pipeline.h"

#include "media_log.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

void AnalysisAlbumPipelineEngine::AddStep(std::unique_ptr<IPipelineStep> step)
{
    CHECK_AND_RETURN_LOG(step != nullptr, "Add step fail, invalid step");
    steps_.push_back(std::move(step));
}

void AnalysisAlbumPipelineEngine::Run(AnalysisAnalyzerContext &ctx) const
{
    Run(ctx, PipelineFlow::All());
}


void AnalysisAlbumPipelineEngine::Run(AnalysisAnalyzerContext &ctx, const PipelineFlow &flow) const
{
    for (const auto &step : steps_) {
        CHECK_AND_CONTINUE(step != nullptr);
        CHECK_AND_CONTINUE_DEBUG_LOG(flow.Allow(step->GetStep()), "Skip step: 0x%{public}ux", step->GetStep());
        CHECK_AND_RETURN_LOG(step->Execute(ctx), "Execute step failed");
    }
}

// CountStep:计算资产变化对相册内资产数量影响
CountStep::CountStep(std::shared_ptr<ICountStrategy> strategy) : IPipelineStep(STEP_COUNT), strategy_(strategy) {}

bool CountStep::Execute(AnalysisAnalyzerContext &ctx)
{
    CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, false, "Invalid input, execute count step failed");
    PhotoAssetChangeData changeData;
    CHECK_AND_RETURN_RET_INFO_LOG(ctx.GetAssetChangeData(changeData), true, "Skip CountStep");

    int32_t delta = strategy_->CalcCountDelta(changeData, ctx.GetBaseInfo(), ctx.GetRefreshInfo());
    ctx.SetLastDelta(delta);
    return true;
}

// CoverRecordStep:记录资产变化对相册封面的影响，仅记录不操作封面
CoverRecordStep::CoverRecordStep(std::shared_ptr<ICoverStrategy> strategy) : IPipelineStep(STEP_RECORD),
    strategy_(strategy) {}

bool CoverRecordStep::Execute(AnalysisAnalyzerContext &ctx)
{
    CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, false, "Invalid input, execute cover record step failed");
    PhotoAssetChangeData changeData;
    CHECK_AND_RETURN_RET_INFO_LOG(ctx.GetAssetChangeData(changeData), true, "Skip cover record step");
    strategy_->RecordPotentialCoverChange(changeData, ctx.GetRefreshInfo(), ctx.GetLastDelta());
    return true;
}

// CoverDecisionStep: 遍历完成后，根据记录的结果判断是否需要刷新封面
CoverDecisionStep::CoverDecisionStep(std::shared_ptr<ICoverStrategy> strategy) : IPipelineStep(STEP_DECISION),
    strategy_(strategy) {}

bool CoverDecisionStep::Execute(AnalysisAnalyzerContext &ctx)
{
    CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, false, "Invalid input, execute cover decision step failed");
    const auto &base = ctx.GetBaseInfo();
    auto &info = ctx.GetRefreshInfo();
    bool needCoverRefresh = strategy_->NeedCoverRefresh(base, info);
    ctx.SetNeedCoverRefresh(needCoverRefresh);

    // 无需刷新场景，直接将刷新信息中的封面标记为原封面
    if (!needCoverRefresh) {
        info.refreshCover_ = base.albumCoverUri;
    }
    return true;
}

// PickerStep: 对于需要刷新封面的相册，查询替换的相册封面
PickerStep::PickerStep(std::shared_ptr<ICoverPickerStrategy> strategy) : IPipelineStep(STEP_PICKER),
    strategy_(strategy) {}

bool PickerStep::Execute(AnalysisAnalyzerContext &ctx)
{
    CHECK_AND_RETURN_RET_LOG(strategy_ != nullptr, false, "Invalid input, execute cover picker step failed");
    CHECK_AND_RETURN_RET_INFO_LOG(ctx.NeedCoverRefresh(), true,
        "No need to refresh cover, album id: %{public}d", ctx.GetBaseInfo().albumId);

    if (!strategy_->PickCover(ctx.GetBaseInfo(), ctx.GetRefreshInfo())) {
        ctx.GetRefreshInfo().refreshCover_ = ctx.GetBaseInfo().albumCoverUri;
    }
    return true;
}

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
