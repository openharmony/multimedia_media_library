/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef CLONE_RESTORE_CV_ANALYSIS_H
#define CLONE_RESTORE_CV_ANALYSIS_H

#include <sstream>
#include <string>

#include "backup_const.h"
#include "clone_restore_highlight.h"
#include "media_log.h"
#include "nlohmann/json.hpp"
#include "rdb_store.h"
#include "safe_map.h"

namespace OHOS::Media {
class CloneRestoreCVAnalysis {
public:
    void Init(int32_t sceneCode, const std::string &taskId, std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb,
        std::shared_ptr<NativeRdb::RdbStore> mediaRdb, const std::string &backupRestoreDir);
    void RestoreAlbums(CloneRestoreHighlight &cloneHighlight);

private:
    struct AnalysisLabelInfo {
        std::optional<int32_t> id;
        std::optional<int32_t> fileId;
        std::optional<int32_t> fileIdNew;
        std::optional<int32_t> categoryId;
        std::optional<std::string> subLabel;
        std::optional<double> prob;
        std::optional<std::string> feature;
        std::optional<std::string> simResult;
        std::optional<std::string> labelVersion;
        std::optional<std::string> saliencySubprob;
        std::optional<std::string> analysisVersion;
        std::optional<int32_t> duplicateChecking;

        std::string ToString() const
        {
            std::stringstream outputStr;
            outputStr << "AnalysisLabelInfo[" << "id: ";
            if (id.has_value()) { outputStr << id.value(); }
            outputStr << ", fileId: ";
            if (fileId.has_value()) { outputStr << fileId.value(); }
            outputStr << "]";
            return outputStr.str();
        }
    };

    struct AnalysisSaliencyInfo {
        std::optional<int32_t> id;
        std::optional<int32_t> fileId;
        std::optional<int32_t> fileIdNew;
        std::optional<double> saliencyX;
        std::optional<double> saliencyY;
        std::optional<std::string> saliencyVersion;
        std::optional<std::string> analysisVersion;

        std::string ToString() const
        {
            std::stringstream outputStr;
            outputStr << "AnalysisSaliencyInfo[" << "id: ";
            if (id.has_value()) { outputStr << id.value(); }
            outputStr << ", fileId: ";
            if (fileId.has_value()) { outputStr << fileId.value(); }
            outputStr << "]";
            return outputStr.str();
        }
    };

    struct AnalysisRecommendationInfo {
        std::optional<int32_t> id;
        std::optional<int32_t> fileId;
        std::optional<int32_t> fileIdNew;
        std::optional<int32_t> rcmdId;
        std::optional<std::string> rcmdResolution;
        std::optional<int32_t> rcmdScaleX;
        std::optional<int32_t> rcmdScaleY;
        std::optional<int32_t> rcmdScaleWidth;
        std::optional<int32_t> rcmdScaleHeight;
        std::optional<std::string> rcmdVersion;
        std::optional<double> scaleX;
        std::optional<double> scaleY;
        std::optional<double> scaleWidth;
        std::optional<double> scaleHeight;
        std::optional<std::string> analysisVersion;
        std::optional<std::string> movementCrop;
        std::optional<std::string> movementVersion;

        std::string ToString() const
        {
            std::stringstream outputStr;
            outputStr << "AnalysisRecommendationInfo[" << "id: ";
            if (id.has_value()) { outputStr << id.value(); }
            outputStr << ", fileId: ";
            if (fileId.has_value()) { outputStr << fileId.value(); }
            outputStr << "]";
            return outputStr.str();
        }
    };

    void GetAssetMapInfos(CloneRestoreHighlight &cloneHighlight);
    void GetAssetAlbumInfos(CloneRestoreHighlight &cloneHighlight);
    void MoveAnalysisAssets(const std::string &srcPath, const std::string &dstPath);
    void InsertIntoAssetMap();
    void InsertIntoSdMap();
    int32_t BatchInsertWithRetry(const std::string &tableName,
        const std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum);
    void GetAnalysisLabelInfos(CloneRestoreHighlight &cloneHighlight);
    void GetLabelRowInfo(AnalysisLabelInfo &info, std::shared_ptr<NativeRdb::ResultSet> resultSet);
    void InsertIntoAnalysisLabel();
    void GetLabelInsertValue(NativeRdb::ValuesBucket &value, const AnalysisLabelInfo &info);
    std::unordered_set<std::string> GetCommonColumns(const std::string &tableName);
    void GetAnalysisSaliencyInfos(CloneRestoreHighlight &cloneHighlight);
    void GetSaliencyRowInfo(AnalysisSaliencyInfo &info, std::shared_ptr<NativeRdb::ResultSet> resultSet);
    void InsertIntoAnalysisSaliency();
    void GetSaliencyInsertValue(NativeRdb::ValuesBucket &value, const AnalysisSaliencyInfo &info);
    void GetAnalysisRecommendationInfos(CloneRestoreHighlight &cloneHighlight);
    void GetRecommendationRowInfo(AnalysisRecommendationInfo &info, std::shared_ptr<NativeRdb::ResultSet> resultSet);
    void InsertIntoAnalysisRecommendation();
    void GetRecommendationInsertValue(NativeRdb::ValuesBucket &value, const AnalysisRecommendationInfo &info);
    std::string ParsePlayInfo(const std::string &oldPlayInfo, CloneRestoreHighlight &cloneHighlight);
    void ParseEffectline(nlohmann::json &newPlayInfo, size_t effectlineIndex, CloneRestoreHighlight &cloneHighlight);
    void ParseTimeline(nlohmann::json &newPlayInfo, size_t TimelineIndex, CloneRestoreHighlight &cloneHighlight);
    void UpdateHighlightPlayInfos(CloneRestoreHighlight &cloneHighlight, std::vector<int32_t> &updateHighlightIds);
    void ReportCloneRestoreCVAnalysisTask();
    int32_t GetNewAssetId(int32_t assetId);
    std::string GetNewEffectVideoUri(const std::string &oldVideoUri);
    std::string GetNewTransitionVideoUri(const std::string &oldVideoUri, CloneRestoreHighlight &cloneHighlight);
    std::string GetNewPhotoUriByUri(const std::string &oldUri, CloneRestoreHighlight &cloneHighlight);

    int32_t sceneCode_{-1};
    std::string taskId_;
    // old media_liabrary.db
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb_;
    // new media_liabrary.db
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::string assetPath_;
    std::string garblePath_;
    std::vector<std::pair<int32_t, int32_t>> assetMapDatas_;
    std::vector<std::pair<int32_t, int32_t>> sdMapDatas_;
    std::unordered_map<int32_t, int32_t> fileIdMap_;
    std::unordered_map<int32_t, int32_t> albumIdMap_;
    std::unordered_map<int32_t, int32_t> assetIdMap_;
    std::unordered_map<std::string, std::string> assetUriMap_;
    std::unordered_map<std::string, std::unordered_set<std::string>> intersectionMap_;
    std::vector<AnalysisLabelInfo> labelInfos_;
    std::vector<AnalysisSaliencyInfo> saliencyInfos_;
    std::vector<AnalysisRecommendationInfo> recommendInfos_;
    int64_t failCnt_{0};
};
} // namespace OHOS::Media
#endif // CLONE_RESTORE_CV_ANALYSIS_H