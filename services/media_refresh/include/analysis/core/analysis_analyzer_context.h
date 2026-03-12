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

#ifndef OHOS_MEDIALIBRARY_ANALYSIS_ANALYZER_CONTEXT_H
#define OHOS_MEDIALIBRARY_ANALYSIS_ANALYZER_CONTEXT_H

#include <cstdint>
#include <optional>

#include "album_change_info.h"
#include "photo_asset_change_info.h"
#include "medialibrary_rdb_utils.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

// Usage contract:
// - Context must be fully built before pipeline execution.
// - Optional inputs must be accessed via safe query APIs.
// - Phase results are only valid after corresponding pipeline flows.
// - Direct field access is forbidden.
// - Context represents one pipeline execution lifecycle.
class AnalysisAnalyzerContext {
public:
    AnalysisAnalyzerContext() = delete;

    AnalysisAnalyzerContext(UpdateAlbumData base, AnalysisAlbumRefreshInfo &info) : baseInfo_(std::move(base)),
        refreshInfo_(&info) {}

    const UpdateAlbumData& GetBaseInfo() const
    {
        return baseInfo_;
    }

    AnalysisAlbumRefreshInfo& GetRefreshInfo()
    {
        return *refreshInfo_;
    }

    void SetAssetChangeData(const PhotoAssetChangeData &data)
    {
        changeData_ = data;
    }

    bool HasAssetChangeData() const
    {
        return changeData_.has_value();
    }

    bool GetAssetChangeData(PhotoAssetChangeData &data) const
    {
        CHECK_AND_RETURN_RET_LOG(changeData_.has_value(), false, "AssetChangeData not set");
        data = *changeData_;
        return true;
    }

    void SetLastDelta(int32_t delta)
    {
        lastDelta_ = delta;
        deltaReady_ = true;
    }

    int32_t GetLastDelta() const
    {
        CHECK_AND_RETURN_RET_LOG(deltaReady_, 0, "lastDelta not set");
        return lastDelta_;
    }

    bool HasDelta() const
    {
        return deltaReady_;
    }

    void SetNeedCoverRefresh(bool need)
    {
        needCoverRefresh_ = need;
        coverDecisionReady_ = true;
    }

    bool NeedCoverRefresh() const
    {
        CHECK_AND_RETURN_RET_LOG(coverDecisionReady_, false, "cover decision not set");
        return needCoverRefresh_;
    }

private:
    UpdateAlbumData baseInfo_;
    AnalysisAlbumRefreshInfo *refreshInfo_ {nullptr};
    std::optional<PhotoAssetChangeData> changeData_;

    int32_t lastDelta_ {0};
    bool deltaReady_ {false};

    bool needCoverRefresh_ {false};
    bool coverDecisionReady_ {false};
};

class AnalysisAnalyzerContextBuilder {
public:
    AnalysisAnalyzerContextBuilder& SetBaseInfo(const UpdateAlbumData &base)
    {
        base_ = base;
        return *this;
    }

    AnalysisAnalyzerContextBuilder& SetAssetChangeData(const PhotoAssetChangeData &data)
    {
        change_ = data;
        return *this;
    }

    AnalysisAnalyzerContextBuilder& SetRefreshInfo(AnalysisAlbumRefreshInfo &info)
    {
        info_ = &info;
        return *this;
    }

    [[nodiscard]]
    std::optional<AnalysisAnalyzerContext> Build() const
    {
        CHECK_AND_RETURN_RET_LOG(base_.has_value() && info_ != nullptr,
            std::nullopt, "Build context failed: base or info null");

        AnalysisAnalyzerContext ctx(*base_, *info_);
        if (change_.has_value()) {
            ctx.SetAssetChangeData(*change_);
        }
        return ctx;
    }

private:
    std::optional<UpdateAlbumData> base_;
    std::optional<PhotoAssetChangeData> change_;
    AnalysisAlbumRefreshInfo *info_ {nullptr};
};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_ANALYSIS_ANALYZER_CONTEXT_H
