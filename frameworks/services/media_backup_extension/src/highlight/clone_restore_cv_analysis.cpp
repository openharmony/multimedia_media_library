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

#define MLOG_TAG "MediaLibraryCloneRestoreCVAnalysis"

#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "clone_restore_cv_analysis.h"
#include "medialibrary_data_manager_utils.h"
#include "media_file_utils.h"
#include "upgrade_restore_task_report.h"

namespace OHOS::Media {
const int32_t PAGE_SIZE = 200;
const std::vector<std::string> EFFECTLINE_ID = { "fileId", "prefileId" };
const std::vector<std::string> EFFECTLINE_URI = { "fileUri", "prefileUri" };
const std::string EFFECTLINE_TYPE_HITCHCOCK = "TYPE_HITCHCOCK";
const std::string EFFECTLINE_TYPE_UAV = "TYPE_UAV";
const std::string EFFECTLINE_TYPE_HILIGHT_SLOW = "TYPE_HILIGHT_SLOW";
const std::string EFFECTLINE_TYPE_HILIGHT_CLIP = "TYPE_HILIGHT_CLIP";
const std::string EFFECTLINE_TYPE_MASK1 = "TYPE_MASK1";
const std::string EFFECTLINE_TYPE_MASK2 = "TYPE_MASK2";
const std::string HIGHLIGHT_ASSET_URI_PREFIX = "file://media/highlight/video/";
const std::string HIGHLIGHT_ASSET_URI_SUFFIX = "?oper=highlight";
const std::string PHOTO_URI_PREFIX = "file://media/Photo/";
const std::string GARBLE_DST_PATH = "/storage/media/local/files";

const std::unordered_map<std::string, std::unordered_set<std::string>> ALBUM_COLUMNS_MAP = {
    { "tab_analysis_label",
        {
            "id",
            "file_id",
            "category_id",
            "sub_label",
            "prob",
            "feature",
            "sim_result",
            "label_version",
            "saliency_sub_prob",
            "analysis_version",
            "duplicate_checking"
        }
    },
    { "tab_analysis_saliency_detect",
        {
            "id",
            "file_id",
            "saliency_x",
            "saliency_y",
            "saliency_version",
            "analysis_version"
        }
    },
    { "tab_analysis_recommendation",
        {
            "id",
            "file_id",
            "recommendation_id",
            "recommendation_resolution",
            "recommendation_scale_x",
            "recommendation_scale_y",
            "recommendation_scale_width",
            "recommendation_scale_height",
            "recommendation_version",
            "scale_x",
            "scale_y",
            "scale_width",
            "scale_height",
            "analysis_version",
            "movement_crop",
            "movement_version"
        }
    }
};

template<typename Key, typename Value>
Value GetValueFromMap(const std::unordered_map<Key, Value> &map, const Key &key, const Value &defaultValue = Value())
{
    auto it = map.find(key);
    CHECK_AND_RETURN_RET(it != map.end(), defaultValue);
    return it->second;
}

void CloneRestoreCVAnalysis::Init(int32_t sceneCode, const std::string &taskId,
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb,
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb, const std::string &backupRestoreDir)
{
    sceneCode_ = sceneCode;
    taskId_ = taskId;
    mediaLibraryRdb_ = mediaLibraryRdb;
    mediaRdb_ = mediaRdb;
    assetPath_ = backupRestoreDir + "/storage/media/local/files/highlight/video/";
    MEDIA_INFO_LOG("/highlight/video/ source dir %{public}s.",
        MediaFileUtils::IsDirectory(assetPath_) ? "exist" : "don't exist");
    garblePath_ = backupRestoreDir + GARBLE_DST_PATH;
    failCnt_ = 0;
}

void CloneRestoreCVAnalysis::RestoreAlbums(CloneRestoreHighlight &cloneHighlight)
{
    CHECK_AND_RETURN_LOG(mediaRdb_ != nullptr && mediaLibraryRdb_ != nullptr, "rdbStore is nullptr.");
    CHECK_AND_RETURN_LOG(cloneHighlight.IsCloneHighlight(), "clone highlight flag is false.");

    MEDIA_INFO_LOG("restore highlight cv analysis album start.");
    int64_t startRestoreMapTime = MediaFileUtils::UTCTimeMilliSeconds();
    RestoreAssetSdMap(cloneHighlight);
    RestoreAlbumAssetMap(cloneHighlight);
    int64_t startUpdatePlayInfoTime = MediaFileUtils::UTCTimeMilliSeconds();
    std::vector<int32_t> updateHighlightIds;
    UpdateHighlightPlayInfos(cloneHighlight, updateHighlightIds);
    cloneHighlight.UpdateHighlightStatus(updateHighlightIds);
    int64_t startRestoreLabelTime = MediaFileUtils::UTCTimeMilliSeconds();
    GetAnalysisLabelInfos(cloneHighlight);
    InsertIntoAnalysisLabel();
    int64_t startRestoreSaliencyTime = MediaFileUtils::UTCTimeMilliSeconds();
    GetAnalysisSaliencyInfos(cloneHighlight);
    InsertIntoAnalysisSaliency();
    int64_t startRestoreRcmdTime = MediaFileUtils::UTCTimeMilliSeconds();
    GetAnalysisRecommendationInfos(cloneHighlight);
    InsertIntoAnalysisRecommendation();
    int64_t endTime = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("RestoreAllCVAlbums cost %{public}" PRId64 ", RestoreAssetMaps cost %{public}" PRId64
        ", UpdateHighlightPlayInfos cost %{public}" PRId64 ", RestoreLabel cost %{public}" PRId64
        ", RestoreSaliency cost %{public}" PRId64 ", RestoreRecommendation cost %{public}" PRId64,
        endTime - startRestoreMapTime, startUpdatePlayInfoTime - startRestoreMapTime,
        startRestoreLabelTime - startUpdatePlayInfoTime, startRestoreSaliencyTime - startRestoreLabelTime,
        startRestoreRcmdTime - startRestoreSaliencyTime, endTime - startRestoreRcmdTime);
    ReportCloneRestoreCVAnalysisTask();
}

void CloneRestoreCVAnalysis::RestoreAssetSdMap(CloneRestoreHighlight &cloneHighlight)
{
    const std::string QUERY_SQL = "SELECT * FROM tab_analysis_asset_sd_map LIMIT ?, ?";
    std::vector<NativeRdb::ValuesBucket> values;
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        std::vector<NativeRdb::ValueObject> params = {offset, PAGE_SIZE};
        auto resultSet = BackupDatabaseUtils::QuerySql(mediaRdb_, QUERY_SQL, params);
        CHECK_AND_BREAK_ERR_LOG(resultSet != nullptr, "resultSet is nullptr");

        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t oldFileId = GetInt32Val("map_asset_source", resultSet);
            int32_t oldAssetId = GetInt32Val("map_asset_destination", resultSet);
            NativeRdb::ValuesBucket value;
            value.PutInt("map_asset_source", cloneHighlight.GetNewHighlightPhotoId(oldFileId));
            value.PutInt("map_asset_destination", cloneHighlight.GetNewHighlightPhotoId(oldAssetId));
            values.emplace_back(value);
        }
        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount == PAGE_SIZE);
    InsertIntoAssetSdMap(values);
}

void CloneRestoreCVAnalysis::RestoreAlbumAssetMap(CloneRestoreHighlight &cloneHighlight)
{
    const std::string QUERY_SQL = "SELECT tab_analysis_album_asset_map.* FROM tab_analysis_album_asset_map "
        " INNER JOIN tab_highlight_album AS h ON tab_analysis_album_asset_map.map_album = h.id "
        " WHERE h.highlight_status > 0 LIMIT ?, ?";
    std::vector<NativeRdb::ValuesBucket> values;
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        std::vector<NativeRdb::ValueObject> params = {offset, PAGE_SIZE};
        auto resultSet = BackupDatabaseUtils::QuerySql(mediaRdb_, QUERY_SQL, params);
        CHECK_AND_BREAK_ERR_LOG(resultSet != nullptr, "resultSet is nullptr");

        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t oldAlbumId = GetInt32Val("map_album", resultSet);
            int32_t oldAssetId = GetInt32Val("map_asset", resultSet);
            NativeRdb::ValuesBucket value;
            value.PutInt("map_album", cloneHighlight.GetNewHighlightAlbumId(oldAlbumId));
            value.PutInt("map_asset", cloneHighlight.GetNewHighlightPhotoId(oldAssetId));
            values.emplace_back(value);
        }
        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount == PAGE_SIZE);
    InsertIntoAlbumAssetMap(values);
}

void CloneRestoreCVAnalysis::InsertIntoAssetSdMap(std::vector<NativeRdb::ValuesBucket> &values)
{
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry("tab_analysis_asset_sd_map", values, rowNum);
    CHECK_AND_RETURN(errCode != E_OK || rowNum != static_cast<int64_t>(values.size()));
    int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
    MEDIA_ERR_LOG("insert into sdMap failed, num:%{public}" PRId64, failNums);
    ErrorInfo errorInfo(RestoreError::INSERT_FAILED, 0, std::to_string(errCode),
        "insert into sdMap fail. num:" + std::to_string(failNums));
    failCnt_ += failNums;
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_).ReportError(errorInfo);
}

void CloneRestoreCVAnalysis::InsertIntoAlbumAssetMap(std::vector<NativeRdb::ValuesBucket> &values)
{
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry("tab_analysis_album_asset_map", values, rowNum);
    CHECK_AND_RETURN(errCode != E_OK || rowNum != static_cast<int64_t>(values.size()));
    int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
    MEDIA_ERR_LOG("insert into assetMap failed, num:%{public}" PRId64, failNums);
    ErrorInfo errorInfo(RestoreError::INSERT_FAILED, 0, std::to_string(errCode),
        "insert into AssetMap fail. num:" + std::to_string(failNums));
    failCnt_ += failNums;
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_).ReportError(errorInfo);
}

int32_t CloneRestoreCVAnalysis::BatchInsertWithRetry(const std::string &tableName,
    const std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum)
{
    CHECK_AND_RETURN_RET(!values.empty(), 0);
    int32_t errCode = E_ERR;
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(mediaLibraryRdb_);
    std::function<int(void)> func = [&]()->int {
        errCode = trans.BatchInsert(rowNum, tableName, values);
        CHECK_AND_PRINT_LOG(errCode == E_OK,
            "InsertSql failed, errCode: %{public}d, rowNum: %{public}" PRId64, errCode, rowNum);
        return errCode;
    };
    errCode = trans.RetryTrans(func, true);
    CHECK_AND_PRINT_LOG(errCode == E_OK, "BatchInsertWithRetry: tans finish fail!, ret:%{public}d", errCode);
    return errCode;
}

void CloneRestoreCVAnalysis::GetAnalysisLabelInfos(CloneRestoreHighlight &cloneHighlight)
{
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        const std::string QUERY_SQL = "SELECT * FROM tab_analysis_label LIMIT " + std::to_string(offset) + ", " +
            std::to_string(PAGE_SIZE);
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, QUERY_SQL);
        CHECK_AND_BREAK_ERR_LOG(resultSet != nullptr, "query resultSql is null.");

        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            AnalysisLabelInfo info;
            GetLabelRowInfo(info, resultSet);
            CHECK_AND_EXECUTE(!info.fileId.has_value(),
                info.fileIdNew = cloneHighlight.GetNewHighlightPhotoId(info.fileId.value()));
            labelInfos_.emplace_back(info);
        }
        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount == PAGE_SIZE);
    MEDIA_INFO_LOG("query tab_analysis_label nums: %{public}zu", labelInfos_.size());
}

void CloneRestoreCVAnalysis::GetLabelRowInfo(AnalysisLabelInfo &info, std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    if (intersectionMap_.find("tab_analysis_label") == intersectionMap_.end()) {
        intersectionMap_.insert(std::make_pair("tab_analysis_label", GetCommonColumns("tab_analysis_label")));
    }
    std::unordered_set<std::string>& intersection = intersectionMap_["tab_analysis_label"];
    CloneRestoreHighlight::GetIfInIntersection("id", info.id, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("file_id", info.fileId, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("category_id", info.categoryId, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("sub_label", info.subLabel, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("prob", info.prob, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("feature", info.feature, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("sim_result", info.simResult, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("label_version", info.labelVersion, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("saliency_sub_prob", info.saliencySubprob, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("analysis_version", info.analysisVersion, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("duplicate_checking", info.duplicateChecking, intersection, resultSet);
}

void CloneRestoreCVAnalysis::InsertIntoAnalysisLabel()
{
    size_t offset = 0;
    do {
        std::vector<NativeRdb::ValuesBucket> values;
        for (size_t index = 0; index < PAGE_SIZE && index + offset < labelInfos_.size(); index++) {
            NativeRdb::ValuesBucket value;
            GetLabelInsertValue(value, labelInfos_[index + offset]);
            values.emplace_back(value);
        }
        int64_t rowNum = 0;
        int32_t errCode = BatchInsertWithRetry("tab_analysis_label", values, rowNum);
        if (errCode != E_OK || rowNum != static_cast<int64_t>(values.size())) {
            int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
            MEDIA_ERR_LOG("insert into tab_analysis_label fail, num: %{public}" PRId64, failNums);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, 0, std::to_string(errCode),
                "insert into tab_analysis_label fail, num:" + std::to_string(failNums));
            failCnt_ += failNums;
            UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_).ReportError(errorInfo);
        }
        offset += PAGE_SIZE;
    } while (offset < labelInfos_.size());
}

void CloneRestoreCVAnalysis::GetLabelInsertValue(NativeRdb::ValuesBucket &value, const AnalysisLabelInfo &info)
{
    std::unordered_set<std::string>& intersection = intersectionMap_["tab_analysis_label"];
    CloneRestoreHighlight::PutIfInIntersection(value, "file_id", info.fileIdNew, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "category_id", info.categoryId, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "sub_label", info.subLabel, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "prob", info.prob, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "feature", info.feature, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "sim_result", info.simResult, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "label_version", info.labelVersion, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "saliency_sub_prob", info.saliencySubprob, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "analysis_version", info.analysisVersion, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "duplicate_checking", info.duplicateChecking, intersection);
}

std::unordered_set<std::string> CloneRestoreCVAnalysis::GetCommonColumns(const std::string &tableName)
{
    std::unordered_map<std::string, std::string> srcColumnInfoMap =
        BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_, tableName);
    std::unordered_map<std::string, std::string> dstColumnInfoMap =
        BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_, tableName);
    std::unordered_set<std::string> result;
    auto comparedColumns = GetValueFromMap(ALBUM_COLUMNS_MAP, tableName);
    for (auto it = dstColumnInfoMap.begin(); it != dstColumnInfoMap.end(); ++it) {
        bool cond = (srcColumnInfoMap.find(it->first) != srcColumnInfoMap.end() &&
            comparedColumns.count(it->first) > 0);
        CHECK_AND_EXECUTE(!cond, result.insert(it->first));
    }
    return result;
}

void CloneRestoreCVAnalysis::GetAnalysisSaliencyInfos(CloneRestoreHighlight &cloneHighlight)
{
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        const std::string QUERY_SQL = "SELECT * FROM tab_analysis_saliency_detect LIMIT " + std::to_string(offset) +
            ", " + std::to_string(PAGE_SIZE);
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, QUERY_SQL);
        CHECK_AND_BREAK_INFO_LOG(resultSet != nullptr, "query resultSql is null.");

        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            AnalysisSaliencyInfo info;
            GetSaliencyRowInfo(info, resultSet);
            CHECK_AND_EXECUTE(!info.fileId.has_value(),
                info.fileIdNew = cloneHighlight.GetNewHighlightPhotoId(info.fileId.value()));
            saliencyInfos_.emplace_back(info);
        }
        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount == PAGE_SIZE);
    MEDIA_INFO_LOG("query tab_analysis_saliency_detect nums: %{public}zu", saliencyInfos_.size());
}

void CloneRestoreCVAnalysis::GetSaliencyRowInfo(AnalysisSaliencyInfo &info,
    std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    if (intersectionMap_.find("tab_analysis_saliency_detect") == intersectionMap_.end()) {
        intersectionMap_.insert(
            std::make_pair("tab_analysis_saliency_detect", GetCommonColumns("tab_analysis_saliency_detect")));
    }
    std::unordered_set<std::string>& intersection = intersectionMap_["tab_analysis_saliency_detect"];
    CloneRestoreHighlight::GetIfInIntersection("id", info.id, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("file_id", info.fileId, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("saliency_x", info.saliencyX, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("saliency_y", info.saliencyY, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("saliency_version", info.saliencyVersion, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("analysis_version", info.analysisVersion, intersection, resultSet);
}

void CloneRestoreCVAnalysis::InsertIntoAnalysisSaliency()
{
    size_t offset = 0;
    do {
        std::vector<NativeRdb::ValuesBucket> values;
        for (size_t index = 0; index < PAGE_SIZE && index + offset < saliencyInfos_.size(); index++) {
            NativeRdb::ValuesBucket value;
            GetSaliencyInsertValue(value, saliencyInfos_[index + offset]);
            values.emplace_back(value);
        }
        int64_t rowNum = 0;
        int32_t errCode = BatchInsertWithRetry("tab_analysis_saliency_detect", values, rowNum);
        if (errCode != E_OK || rowNum != static_cast<int64_t>(values.size())) {
            int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
            MEDIA_ERR_LOG("insert into tab_analysis_saliency_detect fail, num: %{public}" PRId64, failNums);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, 0, std::to_string(errCode),
                "insert into tab_analysis_saliency_detect fail, num:" + std::to_string(failNums));
            failCnt_ += failNums;
            UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_).ReportError(errorInfo);
        }
        offset += PAGE_SIZE;
    } while (offset < saliencyInfos_.size());
}

void CloneRestoreCVAnalysis::GetSaliencyInsertValue(NativeRdb::ValuesBucket &value, const AnalysisSaliencyInfo &info)
{
    std::unordered_set<std::string>& intersection = intersectionMap_["tab_analysis_saliency_detect"];
    CloneRestoreHighlight::PutIfInIntersection(value, "file_id", info.fileIdNew, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "saliency_x", info.saliencyX, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "saliency_y", info.saliencyY, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "saliency_version", info.saliencyVersion, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "analysis_version", info.analysisVersion, intersection);
}

void CloneRestoreCVAnalysis::GetAnalysisRecommendationInfos(CloneRestoreHighlight &cloneHighlight)
{
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        const std::string QUERY_SQL = "SELECT * FROM tab_analysis_recommendation LIMIT " + std::to_string(offset) +
            ", " + std::to_string(PAGE_SIZE);
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, QUERY_SQL);
        CHECK_AND_BREAK_INFO_LOG(resultSet != nullptr, "query resultSql is null.");
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            AnalysisRecommendationInfo info;
            GetRecommendationRowInfo(info, resultSet);
            CHECK_AND_EXECUTE(!info.fileId.has_value(),
                info.fileIdNew = cloneHighlight.GetNewHighlightPhotoId(info.fileId.value()));
            recommendInfos_.emplace_back(info);
        }
        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount == PAGE_SIZE);
    MEDIA_INFO_LOG("query tab_analysis_recommendation nums: %{public}zu", recommendInfos_.size());
}

void CloneRestoreCVAnalysis::GetRecommendationRowInfo(AnalysisRecommendationInfo &info,
    std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    if (intersectionMap_.find("tab_analysis_recommendation") == intersectionMap_.end()) {
        intersectionMap_.insert(
            std::make_pair("tab_analysis_recommendation", GetCommonColumns("tab_analysis_recommendation")));
    }
    std::unordered_set<std::string>& intersection = intersectionMap_["tab_analysis_recommendation"];
    CloneRestoreHighlight::GetIfInIntersection("id", info.id, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("file_id", info.fileId, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("recommendation_id", info.rcmdId, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("recommendation_resolution", info.rcmdResolution, intersection,
        resultSet);
    CloneRestoreHighlight::GetIfInIntersection("recommendation_scale_x", info.rcmdScaleX, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("recommendation_scale_y", info.rcmdScaleY, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("recommendation_scale_width", info.rcmdScaleWidth, intersection,
        resultSet);
    CloneRestoreHighlight::GetIfInIntersection("recommendation_scale_height", info.rcmdScaleHeight, intersection,
        resultSet);
    CloneRestoreHighlight::GetIfInIntersection("recommendation_version", info.rcmdVersion, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("scale_x", info.scaleX, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("scale_y", info.scaleY, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("scale_width", info.scaleWidth, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("scale_height", info.scaleHeight, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("analysis_version", info.analysisVersion, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("movement_crop", info.movementCrop, intersection, resultSet);
    CloneRestoreHighlight::GetIfInIntersection("movement_version", info.movementVersion, intersection, resultSet);
}

void CloneRestoreCVAnalysis::InsertIntoAnalysisRecommendation()
{
    size_t offset = 0;
    do {
        std::vector<NativeRdb::ValuesBucket> values;
        for (size_t index = 0; index < PAGE_SIZE && index + offset < recommendInfos_.size(); index++) {
            NativeRdb::ValuesBucket value;
            GetRecommendationInsertValue(value, recommendInfos_[index + offset]);
            values.emplace_back(value);
        }
        int64_t rowNum = 0;
        int32_t errCode = BatchInsertWithRetry("tab_analysis_recommendation", values, rowNum);
        if (errCode != E_OK || rowNum != static_cast<int64_t>(values.size())) {
            int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
            MEDIA_ERR_LOG("insert into tab_analysis_recommendation fail, num: %{public}" PRId64, failNums);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, 0, std::to_string(errCode),
                "insert into tab_analysis_recommendation fail, num:" + std::to_string(failNums));
            failCnt_ += failNums;
            UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_).ReportError(errorInfo);
        }
        offset += PAGE_SIZE;
    } while (offset < recommendInfos_.size());
}

void CloneRestoreCVAnalysis::GetRecommendationInsertValue(NativeRdb::ValuesBucket &value,
    const AnalysisRecommendationInfo &info)
{
    std::unordered_set<std::string>& intersection = intersectionMap_["tab_analysis_recommendation"];
    CloneRestoreHighlight::PutIfInIntersection(value, "file_id", info.fileIdNew, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "recommendation_id", info.rcmdId, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "recommendation_resolution", info.rcmdResolution, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "recommendation_scale_x", info.rcmdScaleX, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "recommendation_scale_y", info.rcmdScaleY, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "recommendation_scale_width", info.rcmdScaleWidth, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "recommendation_scale_height", info.rcmdScaleHeight,
        intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "recommendation_version", info.rcmdVersion, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "scale_x", info.scaleX, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "scale_y", info.scaleY, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "scale_width", info.scaleWidth, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "scale_height", info.scaleHeight, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "analysis_version", info.analysisVersion, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "movement_crop", info.movementCrop, intersection);
    CloneRestoreHighlight::PutIfInIntersection(value, "movement_version", info.movementVersion, intersection);
}

std::string CloneRestoreCVAnalysis::ParsePlayInfo(const std::string &oldPlayInfo, CloneRestoreHighlight &cloneHighlight)
{
    nlohmann::json newPlayInfo = nlohmann::json::parse(oldPlayInfo, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!newPlayInfo.is_discarded(), cloneHighlight.GetDefaultPlayInfo(),
        "parse json string failed.");
    if (newPlayInfo["effectline"].contains("effectline")) {
        for (size_t effectlineIndex = 0; effectlineIndex < newPlayInfo["effectline"]["effectline"].size();
            effectlineIndex++) {
            ParseEffectline(newPlayInfo, effectlineIndex, cloneHighlight);
        }
    }
    if (newPlayInfo.contains("timeline")) {
        for (size_t timelineIndex = 0; timelineIndex < newPlayInfo["timeline"].size(); timelineIndex++) {
            ParseTimeline(newPlayInfo, timelineIndex, cloneHighlight);
        }
    }
    return newPlayInfo.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

void CloneRestoreCVAnalysis::ParseEffectline(nlohmann::json &newPlayInfo, size_t effectlineIndex,
    CloneRestoreHighlight &cloneHighlight)
{
    if (newPlayInfo["effectline"]["effectline"][effectlineIndex].contains("effectVideoUri")) {
        std::string oldEffectVideoUri = newPlayInfo["effectline"]["effectline"][effectlineIndex]["effectVideoUri"];
        if (MediaFileUtils::StartsWith(oldEffectVideoUri, PHOTO_URI_PREFIX)) {
            newPlayInfo["effectline"]["effectline"][effectlineIndex]["effectVideoUri"] =
                GetNewPhotoUriByUri(oldEffectVideoUri, cloneHighlight);
        } else if (MediaFileUtils::StartsWith(oldEffectVideoUri, HIGHLIGHT_ASSET_URI_PREFIX)) {
            newPlayInfo["effectline"]["effectline"][effectlineIndex]["effectVideoUri"] =
                GetNewEffectVideoUri(oldEffectVideoUri, cloneHighlight);
        }
    }

    bool cond = newPlayInfo["effectline"]["effectline"][effectlineIndex].contains("effect") &&
        newPlayInfo["effectline"]["effectline"][effectlineIndex]["effect"] == EFFECTLINE_TYPE_MASK2 &&
        newPlayInfo["effectline"]["effectline"][effectlineIndex].contains("transitionVideoUri");
    if (cond) {
        std::string transVideoUri = GetNewTransitionVideoUri(
            newPlayInfo["effectline"]["effectline"][effectlineIndex]["transitionVideoUri"], cloneHighlight);
        newPlayInfo["effectline"]["effectline"][effectlineIndex]["transitionVideoUri"] = transVideoUri;

        cond = (effectlineIndex > 0 &&
            newPlayInfo["effectline"]["effectline"][effectlineIndex - 1].contains("effect") &&
            newPlayInfo["effectline"]["effectline"][effectlineIndex - 1]["effect"] == EFFECTLINE_TYPE_MASK1 &&
            newPlayInfo["effectline"]["effectline"][effectlineIndex - 1].contains("transitionVideoUri"));
        CHECK_AND_EXECUTE(!cond,
            newPlayInfo["effectline"]["effectline"][effectlineIndex - 1]["transitionVideoUri"] = transVideoUri);
    }

    ParseEffectlineFileData(newPlayInfo, effectlineIndex, cloneHighlight);
}

void CloneRestoreCVAnalysis::ParseEffectlineFileData(nlohmann::json &newPlayInfo, size_t effectlineIndex,
    CloneRestoreHighlight &cloneHighlight)
{
    for (size_t infoIndex = 0; infoIndex < EFFECTLINE_ID.size(); infoIndex++) {
        if (newPlayInfo["effectline"]["effectline"][effectlineIndex].contains(EFFECTLINE_ID[infoIndex])) {
            for (size_t idIndex = 0;
                idIndex < newPlayInfo["effectline"]["effectline"][effectlineIndex][EFFECTLINE_ID[infoIndex]].size();
                idIndex++) {
                int32_t oldFileId =
                    newPlayInfo["effectline"]["effectline"][effectlineIndex][EFFECTLINE_ID[infoIndex]][idIndex];
                newPlayInfo["effectline"]["effectline"][effectlineIndex][EFFECTLINE_ID[infoIndex]][idIndex] =
                    cloneHighlight.GetNewHighlightPhotoId(oldFileId);
            }
        }

        if (newPlayInfo["effectline"]["effectline"][effectlineIndex].contains(EFFECTLINE_URI[infoIndex])) {
            for (size_t uriIndex = 0;
                uriIndex < newPlayInfo["effectline"]["effectline"][effectlineIndex][EFFECTLINE_URI[infoIndex]].size();
                uriIndex++) {
                std::string oldFileUri =
                    newPlayInfo["effectline"]["effectline"][effectlineIndex][EFFECTLINE_URI[infoIndex]][uriIndex];
                newPlayInfo["effectline"]["effectline"][effectlineIndex][EFFECTLINE_URI[infoIndex]][uriIndex] =
                    GetNewPhotoUriByUri(oldFileUri, cloneHighlight);
            }
        }
    }
}

void CloneRestoreCVAnalysis::ParseTimeline(nlohmann::json &newPlayInfo, size_t timelineIndex,
    CloneRestoreHighlight &cloneHighlight)
{
    if (newPlayInfo["timeline"][timelineIndex].contains("effectVideoUri")) {
        std::string oldEffectVideoUri = newPlayInfo["timeline"][timelineIndex]["effectVideoUri"];
        newPlayInfo["timeline"][timelineIndex]["effectVideoUri"] = GetValueFromMap(assetUriMap_, oldEffectVideoUri);
    }

    if (newPlayInfo["timeline"][timelineIndex].contains("transitionVideoUri")) {
        std::string oldTransVideoUri = newPlayInfo["timeline"][timelineIndex]["transitionVideoUri"];
        newPlayInfo["timeline"][timelineIndex]["transitionVideoUri"] = GetValueFromMap(assetUriMap_, oldTransVideoUri);
    }

    if (newPlayInfo["timeline"][timelineIndex].contains("fileId")) {
        for (size_t idIndex = 0; idIndex < newPlayInfo["timeline"][timelineIndex]["fileId"].size(); idIndex++) {
            int32_t oldFileId = newPlayInfo["timeline"][timelineIndex]["fileId"][idIndex];
            newPlayInfo["timeline"][timelineIndex]["fileId"][idIndex] =
                cloneHighlight.GetNewHighlightPhotoId(oldFileId);
        }
    }

    if (newPlayInfo["timeline"][timelineIndex].contains("fileUri")) {
        for (size_t uriIndex = 0; uriIndex < newPlayInfo["timeline"][timelineIndex]["fileUri"].size(); uriIndex++) {
            std::string oldFileUri = newPlayInfo["timeline"][timelineIndex]["fileUri"][uriIndex];
            newPlayInfo["timeline"][timelineIndex]["fileUri"][uriIndex] =
                GetNewPhotoUriByUri(oldFileUri, cloneHighlight);
        }
    }
}

std::string CloneRestoreCVAnalysis::GetNewEffectVideoUri(const std::string &oldVideoUri,
    CloneRestoreHighlight &cloneHighlight)
{
    CHECK_AND_RETURN_RET(assetUriMap_.find(oldVideoUri) == assetUriMap_.end(), assetUriMap_.at(oldVideoUri));
    CHECK_AND_RETURN_RET(oldVideoUri != "", "");
    size_t rightIndex = oldVideoUri.rfind("/");
    CHECK_AND_RETURN_RET(rightIndex != std::string::npos && rightIndex > 0, "");
    size_t leftIndex = oldVideoUri.rfind("/", rightIndex - 1);
    CHECK_AND_RETURN_RET(leftIndex != std::string::npos && rightIndex > leftIndex + 1, "");
    int32_t oldAssetId = std::atoi((oldVideoUri.substr(leftIndex + 1, rightIndex - leftIndex - 1)).c_str());
    int32_t newAssetId = cloneHighlight.GetNewHighlightPhotoId(oldAssetId);

    size_t suffixLeftIndex = oldVideoUri.find("_", rightIndex);
    CHECK_AND_RETURN_RET(suffixLeftIndex != std::string::npos, "");
    size_t suffixRightIndex = oldVideoUri.find("?", suffixLeftIndex);
    CHECK_AND_RETURN_RET(suffixRightIndex != std::string::npos && suffixRightIndex > suffixLeftIndex, "");
    std::string suffix = oldVideoUri.substr(suffixLeftIndex, suffixRightIndex - suffixLeftIndex);
    std::string newVideoUri = HIGHLIGHT_ASSET_URI_PREFIX + std::to_string(newAssetId)
        + "/" + std::to_string(newAssetId) + suffix + HIGHLIGHT_ASSET_URI_SUFFIX;

    assetUriMap_.insert(std::make_pair(oldVideoUri, newVideoUri));
    std::string dstPath = "/storage/media/local/files/highlight/video/" + std::to_string(newAssetId) + "/" +
        std::to_string(newAssetId) + suffix;
    std::string srcPath = assetPath_ + std::to_string(oldAssetId) + "/" + std::to_string(oldAssetId) + suffix;
    MoveAnalysisAssets(srcPath, dstPath);
    return newVideoUri;
}

std::string CloneRestoreCVAnalysis::GetNewTransitionVideoUri(const std::string &oldVideoUri,
    CloneRestoreHighlight &cloneHighlight)
{
    CHECK_AND_RETURN_RET(assetUriMap_.find(oldVideoUri) == assetUriMap_.end(), assetUriMap_.at(oldVideoUri));
    CHECK_AND_RETURN_RET(oldVideoUri != "", "");
    size_t rightIndex = oldVideoUri.rfind("/");
    CHECK_AND_RETURN_RET(rightIndex != std::string::npos && rightIndex > 0, "");
    size_t leftIndex = oldVideoUri.rfind("/", rightIndex - 1);
    CHECK_AND_RETURN_RET(leftIndex != std::string::npos && rightIndex > leftIndex + 1, "");
    int32_t oldAssetId = std::atoi((oldVideoUri.substr(leftIndex + 1, rightIndex - leftIndex - 1)).c_str());
    int32_t newAssetId = cloneHighlight.GetNewHighlightPhotoId(oldAssetId);

    size_t secondLeftIndex = oldVideoUri.find("_", rightIndex);
    CHECK_AND_RETURN_RET(secondLeftIndex != std::string::npos, "");
    size_t secondRightIndex = oldVideoUri.find("_", secondLeftIndex + 1);
    CHECK_AND_RETURN_RET(secondRightIndex != std::string::npos && secondRightIndex > secondLeftIndex + 1, "");
    int32_t oldNextAssetId = std::atoi((oldVideoUri.substr(secondLeftIndex + 1,
        secondRightIndex - secondLeftIndex - 1)).c_str());
    int32_t newNextPhotoId = cloneHighlight.GetNewHighlightPhotoId(oldNextAssetId);

    size_t suffixRightIndex = oldVideoUri.find("?", secondRightIndex);
    CHECK_AND_RETURN_RET(suffixRightIndex != std::string::npos && suffixRightIndex > secondRightIndex, "");
    std::string suffix = oldVideoUri.substr(secondRightIndex, suffixRightIndex - secondRightIndex);

    std::string newVideoUri = HIGHLIGHT_ASSET_URI_PREFIX + std::to_string(newAssetId) + "/" +
        std::to_string(newAssetId) + "_" + std::to_string(newNextPhotoId) + suffix + HIGHLIGHT_ASSET_URI_SUFFIX;
    assetUriMap_.insert(std::make_pair(oldVideoUri, newVideoUri));

    std::string dstPath = "/storage/media/local/files/highlight/video/" + std::to_string(newAssetId) + "/" +
        std::to_string(newAssetId) + "_" + std::to_string(newNextPhotoId) + suffix;
    std::string srcPath = assetPath_ + std::to_string(oldAssetId) + "/" +
        std::to_string(oldAssetId) + "_" + std::to_string(oldNextAssetId) + suffix;
    MoveAnalysisAssets(srcPath, dstPath);
    return newVideoUri;
}

std::string CloneRestoreCVAnalysis::GetNewPhotoUriByUri(const std::string &oldUri,
    CloneRestoreHighlight &cloneHighlight)
{
    CHECK_AND_RETURN_RET(assetUriMap_.find(oldUri) == assetUriMap_.end(), assetUriMap_.at(oldUri));
    CHECK_AND_RETURN_RET(oldUri != "", "");
    size_t rightIndex = oldUri.rfind("/");
    CHECK_AND_RETURN_RET(rightIndex != std::string::npos && rightIndex > 0, "");
    size_t suffixIndex = oldUri.find("?", rightIndex);
    rightIndex = oldUri.rfind("/", rightIndex - 1);
    CHECK_AND_RETURN_RET(rightIndex != std::string::npos && rightIndex > 0, "");
    size_t leftIndex = oldUri.rfind("/", rightIndex - 1);
    CHECK_AND_RETURN_RET(leftIndex != std::string::npos && rightIndex > leftIndex + 1, "");

    int32_t oldPhotoId = std::atoi((oldUri.substr(leftIndex + 1, rightIndex - leftIndex - 1)).c_str());
    int32_t newPhotoId = cloneHighlight.GetNewHighlightPhotoId(oldPhotoId);
    std::string newUri = cloneHighlight.GetNewHighlightPhotoUri(newPhotoId);
    
    CHECK_AND_EXECUTE(suffixIndex == std::string::npos, newUri += oldUri.substr(suffixIndex));
    assetUriMap_.insert(std::make_pair(oldUri, newUri));
    return newUri;
}

void CloneRestoreCVAnalysis::MoveAnalysisAssets(const std::string &srcPath, const std::string &dstPath)
{
    std::string srcGarble = srcPath;
    srcGarble.replace(0, assetPath_.length(), "*/");
    std::string dstGarble = MediaFileUtils::DesensitizePath(dstPath);
    CHECK_AND_RETURN_LOG(MediaFileUtils::IsFileExists(srcPath), "src file doesn't exist, srcPath:%{public}s."
        "dstPath:%{public}s", srcGarble.c_str(), dstGarble.c_str());
    CHECK_AND_RETURN_INFO_LOG(!MediaFileUtils::IsFileExists(dstPath),
        "dst file already exists, srcPath:%{public}s, dstPath:%{public}s.", srcGarble.c_str(), dstGarble.c_str());
    int32_t errCode = BackupFileUtils::PreparePath(dstPath);
    CHECK_AND_RETURN_LOG(errCode == E_OK, "PreparePath failed, can't move file, srcPath:%{public}s, "
        "dstPath:%{public}s, errcode:%{public}d", srcGarble.c_str(), dstGarble.c_str(), errCode);
    errCode = BackupFileUtils::MoveFile(srcPath, dstPath, sceneCode_);
    CHECK_AND_RETURN_LOG(errCode == E_OK, "move file failed, srcPath:%{public}s, dstPath:%{public}s, "
        "errcode:%{public}d", srcGarble.c_str(), dstGarble.c_str(), errCode);
    MEDIA_INFO_LOG("move file successed, srcPath:%{public}s, dstPath:%{public}s", srcGarble.c_str(), dstGarble.c_str());
}

void CloneRestoreCVAnalysis::UpdateHighlightPlayInfos(CloneRestoreHighlight &cloneHighlight,
    std::vector<int32_t> &updateHighlightIds)
{
    int32_t rowCount = 0;
    int32_t offset = 0;
    std::string defaultPlayInfo = cloneHighlight.GetDefaultPlayInfo();
    do {
        const std::string QUERY_SQL = "SELECT p.album_id, p.play_info_id, p.play_info FROM tab_highlight_play_info AS p"
            " INNER JOIN tab_highlight_album AS h ON p.album_id = h.id WHERE h.highlight_status > 0 "
            " LIMIT " + std::to_string(offset) + ", " + std::to_string(PAGE_SIZE);
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, QUERY_SQL);
        CHECK_AND_RETURN_INFO_LOG(resultSet != nullptr, "query resultSql is null.");

        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            std::optional<int32_t> oldAlbumId = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, "p.album_id");
            CHECK_AND_CONTINUE(oldAlbumId.has_value());
            std::optional<int32_t> playId = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, "p.play_info_id");
            std::optional<std::string> oldPlayInfo =
                BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, "p.play_info");
            std::string newPlayInfo = defaultPlayInfo;
            CHECK_AND_EXECUTE(!oldPlayInfo.has_value(),
                newPlayInfo = ParsePlayInfo(oldPlayInfo.value(), cloneHighlight));

            int32_t albumId = cloneHighlight.GetNewHighlightAlbumId(oldAlbumId.value());
            std::string updatePlayInfoSql = "UPDATE tab_highlight_play_info SET play_info = ? WHERE album_id = ? ";
            int32_t ret = E_ERR;
            if (playId.has_value()) {
                std::string playInfoId = std::to_string(playId.value());
                updatePlayInfoSql += "AND play_info_id = ?";
                ret = BackupDatabaseUtils::ExecuteSQL(mediaLibraryRdb_, updatePlayInfoSql,
                    { newPlayInfo, albumId, playInfoId });
            } else {
                updatePlayInfoSql += "AND play_info_id ISNULL";
                ret = BackupDatabaseUtils::ExecuteSQL(mediaLibraryRdb_, updatePlayInfoSql,
                    { newPlayInfo, albumId });
            }
            bool successfulParseCond = (newPlayInfo != defaultPlayInfo && ret == E_OK) ||
                (newPlayInfo == defaultPlayInfo && oldPlayInfo == defaultPlayInfo);
            if (successfulParseCond) {
                updateHighlightIds.emplace_back(albumId);
                continue;
            }
            CHECK_AND_PRINT_LOG(ret == E_OK, "Update play_info Sql err, highlight id: %{public}d, errCode: %{public}d",
                albumId, ret);
            ErrorInfo errorInfo(RestoreError::UPDATE_FAILED, 0, std::to_string(ret),
                "Update play_info failed. highlight id:" + std::to_string(albumId));
            UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_).ReportError(errorInfo);
        }
        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount == PAGE_SIZE);
}

void CloneRestoreCVAnalysis::ReportCloneRestoreCVAnalysisTask()
{
    const int32_t ERR_STATUS = 1;
    MEDIA_INFO_LOG("Highlight restore failCnt_: %{public}" PRId64, failCnt_);
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_)
        .Report("Highlight restore", std::to_string(ERR_STATUS), "failCnt_: " + std::to_string(failCnt_));
}
} // namespace OHOS::Media