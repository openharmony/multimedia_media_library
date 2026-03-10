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

#ifndef OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_REFRESH_EXECUTION_H
#define OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_REFRESH_EXECUTION_H

#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "album_change_info.h"
#include "analysis_album_impact_analyzer.h"
#include "analysis_album_accurate_refresh.h"
#include "analysis_strategy_registry.h"
#include "medialibrary_rdb_utils.h"
#include "shooting_mode_column.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

using AlbumIdSet = std::unordered_set<int32_t>;

class AnalysisAlbumRefreshExecution {
public:
    int32_t RefreshAlbum(const std::vector<PhotoAssetChangeData> &assetChangeDatas,
        NotifyAlbumType notifyAlbumType, bool isRefreshWithDateModified);

    void RefreshAllAlbum(const std::vector<std::string> &albumIdList);

    void Notify(std::vector<PhotoAssetChangeData> &assetChangeDatas);

    void NotifyAssetForReCheck();
private:
    struct AlbumContext {
        UpdateAlbumData baseInfo;
        AnalysisAlbumRefreshInfo refreshInfo;
        AnalysisAlbumImpactAnalyzer *analyzer {nullptr};
    };

    struct GroupContext {
        std::vector<int32_t> albumIds;
        std::string groupTag;
        UpdateAlbumData baseInfo;
        AnalysisAlbumRefreshInfo refreshInfo;
        AnalysisAlbumImpactAnalyzer *analyzer {nullptr};
    };

    struct NotifyContext {
        bool hasNotified {false};
        bool needNotify {false};
    };

    // 主计算流程
    int32_t CalAnalysisRefreshInfos(const std::vector<PhotoAssetChangeData> &assetChangeDatas);
    void HandleInfoRelatedShootingModeTypes(const PhotoAssetChangeInfo &info, AlbumIdSet &outAlbumIds);
    void PrepareAffectedAssets(const std::vector<PhotoAssetChangeData> &assetChangeDatas,
        AlbumIdSet &affectedAlbumIds);
    void BuildContexts(const AlbumIdSet &affectedAlbumIds);
    void CalculateAlbumChanges(const std::vector<PhotoAssetChangeData> &assetChangeDatas);
    void ProcessCoverChanges();

    // 刷新数据库 + 通知收集
    int32_t CommitAnalysisAlbumRefreshResults(NotifyAlbumType notifyAlbumType);
    void ResetExecutionStatus();

    // Album/Asset 刷新差异记录
    void InsertRefreshMapByDelta(int32_t fileId, const std::vector<int32_t> &albumIds, int32_t delta);

    // Photo -> 通知结构准备
    void PreparePhotoChangeForNotify(std::vector<PhotoAssetChangeData> &assetChangeDatas,
        std::vector<PhotoAssetChangeData> &preparedAssetChangeDatas);

    // Album -> 通知结构准备
    void PrepareAlbumChangeForNotify(std::vector<AlbumChangeData> &albumChangeDatas,
        const std::vector<int32_t> &albumIds = {});

    void ProcessAlbumForNotify(int32_t albumId, std::vector<AlbumChangeData> &albumChangeDatas);

    AlbumChangeInfo GenerateAlbumChangeInfoBase(int32_t albumId, const UpdateAlbumData &baseInfo);
    AlbumChangeInfo GenerateAlbumChangeInfoBeforeChange(int32_t albumId);
    AlbumChangeInfo GenerateAlbumChangeInfoAfterChange(int32_t albumId);
    bool CheckAlbumNotifyStatus(int32_t albumId);

    void PrepareAlbumChangeInfos(const AlbumIdSet &albumIds, bool isAfterChange,
        std::vector<std::shared_ptr<AlbumChangeInfo>> &albumChangeInfos);

    void CheckBatchCountForUpdateAndNotify(std::vector<BatchUpdateItem> &batchItems);

    void ConcludeAlbumRefreshValues(const UpdateAlbumData &base,
        const AnalysisAlbumRefreshInfo &info, std::string &newCover, int32_t &newCount);

    void UpdateNotifyContext(int32_t albumId, bool needNotify);

private:
    static std::mutex albumRefreshMtx_;
    bool isRefreshWithDateModified_ {false};
    AnalysisAlbumAccurateRefresh albumRefresh_;

    // Cache [fileId] -> [Related analysisAlbums] relationship for query
    unordered_map<int32_t, AlbumIdSet> assetAlbumMap_;

    // Cache [fileId] -> Related analysisAlbums [before update, after update] for notify
    unordered_map<int32_t, pair<AlbumIdSet, AlbumIdSet>> assetAlbumRefreshMap_;

    // Final refresh results stored here
    std::unordered_map<int32_t, AlbumContext> albumCtxMap_;
    std::unordered_map<std::string, GroupContext> groupCtxMap_;
    std::unordered_map<int32_t, NotifyContext> albumNotifyCtxMap_;

    // record shootingModeAlbumId, avoid unnecessary query
    std::unordered_map<ShootingModeAlbumType, int32_t> shootingModeAlbumIdMap_;
};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_REFRESH_EXECUTION_H
