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
#include "clone_restore_classify.h"

#include "backup_database_utils.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_unistore_manager.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "upgrade_restore_task_report.h"

namespace OHOS::Media {
const int32_t PAGE_SIZE = 200;

const string ID = "id";
const string FILE_ID = "file_id";
const string CATEGORY_ID = "category_id";
const string SUB_LABEL = "sub_label";
const string PROB = "prob";
const string FEATURE = "feature";
const string SIM_RESULT = "sim_result";
const string LABEL_VERSION = "label_version";
const string SALIENCY_SUB_PROB = "saliency_sub_prob";
const string ANALYSIS_VERSION = "analysis_version";
const string CAPTION_RESULT = "caption_result";
const string CAPTION_VERSION = "caption_version";

const string CONFIDENCE_PROBABILITY = "confidence_probability";
const string SUB_CATEGORY = "sub_category";
const string SUB_CONFIDENCE_PROB = "sub_confidence_prob";
const string SUB_LABEL_PROB = "sub_label_prob";
const string SUB_LABEL_TYPE = "sub_label_type";
const string TRACKS = "tracks";
const string VIDEO_PART_FEATURE = "video_part_feature";
const string FILTER_TAG = "filter_tag";
const string ALGO_VERSION = "algo_version";
const string TRIGGER_GENERATE_THUMBNAIL = "trigger_generate_thumbnail";

const string ANALYSIS_LABEL_TABLE = "tab_analysis_label";
const string ANALYSIS_VIDEO_TABLE = "tab_analysis_video_label";
const string FIELD_TYPE_INT = "INT";
const string FIELD_NAME_DATA = "data";

const int32_t CLASSIFY_STATUS_SUCCESS = 1;
const int32_t CLASSIFY_TYPE = 4097;

const unordered_map<string, unordered_set<string>> COMPARED_COLUMNS_MAP = {
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
            "caption_result",
            "caption_version",
        }
    },
    { "tab_analysis_video_label",
        {
            "id",
            "file_id",
            "category_id",
            "confidence_probability",
            "sub_category",
            "sub_confidence_prob",
            "sub_label",
            "sub_label_prob",
            "sub_label_type",
            "tracks",
            "video_part_feature",
            "filter_tag",
            "algo_version",
            "analysis_version",
            "trigger_generate_thumbnail",
        }
    }
};

template<typename Key, typename Value>
Value GetValueFromMap(const unordered_map<Key, Value> &map, const Key &key, const Value &defaultValue = Value())
{
    auto it = map.find(key);
    CHECK_AND_RETURN_RET(it == map.end(), it->second);
    return defaultValue;
}

void CloneRestoreClassify::Init(int32_t sceneCode, const std::string &taskId,
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, std::shared_ptr<NativeRdb::RdbStore> mediaRdb)
{
    sceneCode_ = sceneCode;
    taskId_ = taskId;
    mediaLibraryRdb_ = mediaLibraryRdb;
    mediaRdb_ = mediaRdb;
    successInsertLabelCnt_ = 0;
    successInsertVideoLabelCnt_ = 0;
    failInsertLabelCnt_ = 0;
    failInsertVideoLabelCnt_ = 0;
}

void CloneRestoreClassify::RestoreMaps()
{
    bool cond = (mediaRdb_ == nullptr || mediaLibraryRdb_ == nullptr);
    CHECK_AND_RETURN_LOG(!cond, "rdbStore is nullptr");

    MEDIA_INFO_LOG("restore classify albums start.");
    for (size_t offset = 0; offset < analysisTotalInfos_.size(); offset += PAGE_SIZE) {
        std::vector<ClassifyCloneInfo> classifyInfos;
        GetClassifyInfos(classifyInfos, offset);
        InsertClassifyAlbums(classifyInfos);
    }
    MEDIA_INFO_LOG("restore classify albums end.");
}

void CloneRestoreClassify::RestoreVideoMaps()
{
    bool cond = (mediaRdb_ == nullptr || mediaLibraryRdb_ == nullptr);
    CHECK_AND_RETURN_LOG(!cond, "rdbStore is nullptr");

    MEDIA_INFO_LOG("restore classify video albums start.");
    for (size_t offset = 0; offset < analysisTotalInfos_.size(); offset += PAGE_SIZE) {
        std::vector<ClassifyVideoCloneInfo> classifyVideoInfos;
        GetClassifyVideoInfos(classifyVideoInfos, offset);
        InsertClassifyVideoAlbums(classifyVideoInfos);
    }
    MEDIA_INFO_LOG("restore classify video albums end.");
}

void CloneRestoreClassify::GetClassifyInfos(std::vector<ClassifyCloneInfo> &classifyInfo, size_t offset)
{
    std::unordered_map<std::string, std::string> columns;
    columns[FILE_ID] = FIELD_TYPE_INT;
    bool hasRequiredColumns = CheckTableColumns(ANALYSIS_LABEL_TABLE, columns);
    if (!hasRequiredColumns) {
        MEDIA_ERR_LOG("The tab_analysis_label does not contain the required columns.");
        ErrorInfo errorInfo(RestoreError::TABLE_LACK_OF_COLUMN, static_cast<int32_t>(columns.size()),
            "", "The tab_analysis_label does not contain id or file_id");
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return;
    }
    int32_t count = 0;
    std::stringstream querySql;
    querySql << "SELECT * FROM " + ANALYSIS_LABEL_TABLE + " WHERE " + FILE_ID + " IN (";
    std::vector<NativeRdb::ValueObject> params;
    for (size_t index = 0; index < PAGE_SIZE && index + offset < analysisTotalInfos_.size(); index++) {
        auto analysisTotalInfo = analysisTotalInfos_[index + offset];
        if (analysisTotalInfo.fileIdOld > 0) {
            querySql << (count++ > 0 ? "," : "");
            querySql << "?";
            params.emplace_back(analysisTotalInfo.fileIdOld);
        }
    }
    querySql << ")";

    auto resultSet = BackupDatabaseUtils::QuerySql(mediaRdb_, querySql.str(), params);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        ClassifyCloneInfo info;
        GetClassifyInfo(info, resultSet);
        classifyInfo.emplace_back(info);
    }
    resultSet->Close();
    MEDIA_INFO_LOG("query tab_analysis_label nums: %{public}zu", classifyInfo.size());
}

void CloneRestoreClassify::GetClassifyVideoInfos(std::vector<ClassifyVideoCloneInfo> &classifyVideoInfo, size_t offset)
{
    std::unordered_map<std::string, std::string> columns;
    columns[FILE_ID] = FIELD_TYPE_INT;
    bool hasRequiredColumns = CheckTableColumns(ANALYSIS_VIDEO_TABLE, columns);
    if (!hasRequiredColumns) {
        MEDIA_ERR_LOG("The tab_analysis_video_label does not contain the required columns.");
        ErrorInfo errorInfo(RestoreError::TABLE_LACK_OF_COLUMN, static_cast<int32_t>(columns.size()),
            "", "The tab_analysis_video_label does not contain file_id");
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return;
    }
    int32_t count = 0;
    std::stringstream querySql;
    querySql << "SELECT * FROM " + ANALYSIS_VIDEO_TABLE + " WHERE " + FILE_ID + " IN (";
    std::vector<NativeRdb::ValueObject> params;
    for (size_t index = 0; index < PAGE_SIZE && index + offset < analysisTotalInfos_.size(); index++) {
        auto analysisTotalInfo = analysisTotalInfos_[index + offset];
        if (analysisTotalInfo.fileIdOld > 0) {
            querySql << (count++ > 0 ? "," : "");
            querySql << "?";
            params.emplace_back(analysisTotalInfo.fileIdOld);
        }
    }
    querySql << ")";

    auto resultSet = BackupDatabaseUtils::QuerySql(mediaRdb_, querySql.str(), params);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        ClassifyVideoCloneInfo info;
        GetClassifyVideoInfo(info, resultSet);
        classifyVideoInfo.emplace_back(info);
    }
    resultSet->Close();
    MEDIA_INFO_LOG("query tab_analysis_video_label nums: %{public}zu", classifyVideoInfo.size());
}

void CloneRestoreClassify::DeduplicateClassifyInfos(std::vector<ClassifyCloneInfo> &classifyInfos)
{
    for (auto &classifyInfo : classifyInfos) {
        auto it = std::find_if(analysisTotalInfos_.begin(), analysisTotalInfos_.end(),
            [classifyInfo](const AnalysisTotalInfo &analysisTotalInfo) {
                return classifyInfo.fileIdOld == analysisTotalInfo.fileIdOld;
            });
        if (it != analysisTotalInfos_.end()) {
            classifyInfo.fileIdNew = it->fileIdNew;
        }
    }
    // TODO CHANGE TO BULK QUERY
    auto itr = classifyInfos.begin();
    while (itr != classifyInfos.end()) {
        if (!itr->fileIdNew.has_value()) {
            ++itr;
            continue;
        }
        std::vector<NativeRdb::ValueObject> params { itr->fileIdNew.value() };
        const std::string querySql = "SELECT 1 FROM " + ANALYSIS_LABEL_TABLE + " WHERE " + FILE_ID + " = ?";
        auto resultSet = BackupDatabaseUtils::QuerySql(mediaLibraryRdb_, querySql, params);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Query resultSql is null.");
            break;
        }
        if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            itr = classifyInfos.erase(itr);
        } else {
            ++itr;
        }
        resultSet->Close();
    }
}

void CloneRestoreClassify::DeduplicateClassifyVideoInfos(std::vector<ClassifyVideoCloneInfo> &classifyVideoInfos)
{
    for (auto &classifyVideoInfo : classifyVideoInfos) {
        auto it = std::find_if(analysisTotalInfos_.begin(), analysisTotalInfos_.end(),
            [classifyVideoInfo](const AnalysisTotalInfo &analysisTotalInfo) {
                return classifyVideoInfo.fileIdOld == analysisTotalInfo.fileIdOld;
            });
        if (it != analysisTotalInfos_.end()) {
            classifyVideoInfo.fileIdNew = it->fileIdNew;
        }
    }
    auto itr = classifyVideoInfos.begin();
    while (itr != classifyVideoInfos.end()) {
        if (!itr->fileIdNew.has_value()) {
            ++itr;
            continue;
        }
        std::vector<NativeRdb::ValueObject> params { itr->fileIdNew.value() };
        const std::string querySql = "SELECT 1 FROM " + ANALYSIS_VIDEO_TABLE + " WHERE " + FILE_ID + " = ?";
        auto resultSet = BackupDatabaseUtils::QuerySql(mediaLibraryRdb_, querySql, params);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Query resultSql is null.");
            break;
        }
        if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            itr = classifyVideoInfos.erase(itr);
        } else {
            ++itr;
        }
        resultSet->Close();
    }
}

void CloneRestoreClassify::InsertClassifyAlbums(std::vector<ClassifyCloneInfo> &classifyInfos)
{
    DeduplicateClassifyInfos(classifyInfos);
    std::unordered_set<std::string> intersection = GetCommonColumns(ANALYSIS_LABEL_TABLE);
    size_t offset = 0;
    do {
        std::vector<NativeRdb::ValuesBucket> values;
        for (size_t index = 0; index < PAGE_SIZE && index + offset < classifyInfos.size(); index++) {
            if (!classifyInfos[index + offset].fileIdNew.has_value()) {
                continue;
            }
            NativeRdb::ValuesBucket value;
            GetMapInsertValue(value, classifyInfos[index + offset], intersection);
            values.emplace_back(value);
        }
        MEDIA_INFO_LOG("Insert classify albums, values size: %{public}zu", values.size());
        int64_t rowNum = 0;
        int32_t errCode = BatchInsertWithRetry(ANALYSIS_LABEL_TABLE, values, rowNum);
        if (errCode != E_OK || rowNum != static_cast<int64_t>(values.size())) {
            int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
            MEDIA_ERR_LOG("Insert classify albums fail, num: %{public}" PRId64, failNums);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, static_cast<int32_t>(values.size()),
                "errCode: " + std::to_string(errCode), "Insert classify albums fail");
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
            failInsertLabelCnt_ += failNums;
        }
        offset += PAGE_SIZE;
        successInsertLabelCnt_ += rowNum;
    } while (offset < classifyInfos.size());
}

void CloneRestoreClassify::InsertClassifyVideoAlbums(std::vector<ClassifyVideoCloneInfo> &classifyVideoInfos)
{
    DeduplicateClassifyVideoInfos(classifyVideoInfos);
    std::unordered_set<std::string> intersection = GetCommonColumns(ANALYSIS_VIDEO_TABLE);
    size_t offset = 0;
    do {
        std::vector<NativeRdb::ValuesBucket> values;
        for (size_t index = 0; index < PAGE_SIZE && index + offset < classifyVideoInfos.size(); index++) {
            if (!classifyVideoInfos[index + offset].fileIdNew.has_value()) {
                continue;
            }
            NativeRdb::ValuesBucket value;
            GetVideoMapInsertValue(value, classifyVideoInfos[index + offset], intersection);
            values.emplace_back(value);
        }
        MEDIA_INFO_LOG("Insert classify video albums, values size: %{public}zu", values.size());
        int64_t rowNum = 0;
        int32_t errCode = BatchInsertWithRetry(ANALYSIS_VIDEO_TABLE, values, rowNum);
        if (errCode != E_OK || rowNum != static_cast<int64_t>(values.size())) {
            int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
            MEDIA_ERR_LOG("Insert classify video albums fail, num: %{public}" PRId64, failNums);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, static_cast<int32_t>(values.size()),
                "errCode: " + std::to_string(errCode), "Insert classify video albums fail");
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
            failInsertVideoLabelCnt_ += failNums;
        }
        offset += PAGE_SIZE;
        successInsertVideoLabelCnt_ += rowNum;
    } while (offset < classifyVideoInfos.size());
}

void CloneRestoreClassify::GetClassifyInfo(ClassifyCloneInfo &info,
    std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    info.id = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, ID);
    info.fileIdOld = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, FILE_ID);
    info.categoryId = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, CATEGORY_ID);
    info.subLabel = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SUB_LABEL);
    info.prob = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, PROB);
    info.feature = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FEATURE);
    info.simResult = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SIM_RESULT);
    info.labelVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, LABEL_VERSION);
    info.saliencySubProb = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SALIENCY_SUB_PROB);
    info.analysisVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_VERSION);
    info.captionResult = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, CAPTION_RESULT);
    info.captionVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, CAPTION_VERSION);
}

void CloneRestoreClassify::GetMapInsertValue(NativeRdb::ValuesBucket &value, ClassifyCloneInfo info,
    const std::unordered_set<std::string> &intersection)
{
    PutIfInIntersection(value, FILE_ID, info.fileIdNew, intersection);
    PutIfInIntersection(value, CATEGORY_ID, info.categoryId, intersection);
    PutIfInIntersection(value, SUB_LABEL, info.subLabel, intersection);
    PutIfInIntersection(value, PROB, info.prob, intersection);
    PutIfInIntersection(value, FEATURE, info.feature, intersection);
    PutIfInIntersection(value, SIM_RESULT, info.simResult, intersection);
    PutIfInIntersection(value, LABEL_VERSION, info.labelVersion, intersection);
    PutIfInIntersection(value, SALIENCY_SUB_PROB, info.saliencySubProb, intersection);
    PutIfInIntersection(value, ANALYSIS_VERSION, info.analysisVersion, intersection);
    PutIfInIntersection(value, CAPTION_RESULT, info.captionResult, intersection);
    PutIfInIntersection(value, CAPTION_VERSION, info.captionVersion, intersection);
}

void CloneRestoreClassify::GetClassifyVideoInfo(ClassifyVideoCloneInfo &info,
    std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    info.id = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, ID);
    info.fileIdOld = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, FILE_ID);
    info.categoryId = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, CATEGORY_ID);
    info.confidenceProbability = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, CONFIDENCE_PROBABILITY);
    info.subCategory = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SUB_CATEGORY);
    info.subConfidenceProb = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, SUB_CONFIDENCE_PROB);
    info.subLabel = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SUB_LABEL);
    info.subLabelProb = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, SUB_LABEL_PROB);
    info.subLabelType = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, SUB_LABEL_TYPE);
    info.tracks = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, TRACKS);
    info.videoPartFeature = BackupDatabaseUtils::GetOptionalValue<std::vector<uint8_t>>(resultSet, VIDEO_PART_FEATURE);
    info.filterTag = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FILTER_TAG);
    info.algoVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ALGO_VERSION);
    info.analysisVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_VERSION);
    info.triggerGenerateThumbnail = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet,
        TRIGGER_GENERATE_THUMBNAIL);
}

void CloneRestoreClassify::GetVideoMapInsertValue(NativeRdb::ValuesBucket &value, ClassifyVideoCloneInfo info,
    const std::unordered_set<std::string> &intersection)
{
    PutIfInIntersection(value, FILE_ID, info.fileIdNew, intersection);
    PutIfInIntersection(value, CATEGORY_ID, info.categoryId, intersection);
    PutIfInIntersection(value, CONFIDENCE_PROBABILITY, info.confidenceProbability, intersection);
    PutIfInIntersection(value, SUB_CATEGORY, info.subCategory, intersection);
    PutIfInIntersection(value, SUB_CONFIDENCE_PROB, info.subConfidenceProb, intersection);
    PutIfInIntersection(value, SUB_LABEL, info.subLabel, intersection);
    PutIfInIntersection(value, SUB_LABEL_PROB, info.subLabelProb, intersection);
    PutIfInIntersection(value, SUB_LABEL_TYPE, info.subLabelType, intersection);
    PutIfInIntersection(value, TRACKS, info.tracks, intersection);
    PutIfInIntersection(value, VIDEO_PART_FEATURE, info.videoPartFeature, intersection);
    PutIfInIntersection(value, FILTER_TAG, info.filterTag, intersection);
    PutIfInIntersection(value, ALGO_VERSION, info.algoVersion, intersection);
    PutIfInIntersection(value, ANALYSIS_VERSION, info.analysisVersion, intersection);
    PutIfInIntersection(value, TRIGGER_GENERATE_THUMBNAIL, info.triggerGenerateThumbnail, intersection);
}

bool CloneRestoreClassify::CheckTableColumns(const std::string& tableName,
    std::unordered_map<std::string, std::string>& columns)
{
    std::unordered_map<std::string, std::string> srcColumnInfoMap =
        BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_, tableName);
    for (auto it = columns.begin(); it != columns.end(); ++it) {
        if (srcColumnInfoMap.find(it->first) != srcColumnInfoMap.end()) {
            continue;
        }
        return false;
    }
    return true;
}

std::unordered_set<std::string> CloneRestoreClassify::GetCommonColumns(const string &tableName)
{
    std::unordered_map<std::string, std::string> srcColumnInfoMap =
        BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_, tableName);
    std::unordered_map<std::string, std::string> dstColumnInfoMap =
        BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_, tableName);
    std::unordered_set<std::string> result;
    auto comparedColumns = GetValueFromMap(COMPARED_COLUMNS_MAP, tableName);
    for (auto it = dstColumnInfoMap.begin(); it != dstColumnInfoMap.end(); ++it) {
        if (srcColumnInfoMap.find(it->first) != srcColumnInfoMap.end() && comparedColumns.count(it->first) > 0) {
            result.insert(it->first);
        }
    }
    return result;
}

int32_t CloneRestoreClassify::BatchInsertWithRetry(const std::string &tableName,
    std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum)
{
    CHECK_AND_RETURN_RET(!values.empty(), E_OK);
    int32_t errCode = E_ERR;
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(mediaLibraryRdb_);
    std::function<int(void)> func = [&]()->int {
        errCode = trans.BatchInsert(rowNum, tableName, values);
        CHECK_AND_PRINT_LOG(errCode == E_OK, "InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.",
            errCode, (long)rowNum);
        return errCode;
    };
    errCode = trans.RetryTrans(func, true);
    CHECK_AND_PRINT_LOG(errCode == E_OK, "BatchInsertWithRetry: tans finish fail!, ret:%{public}d", errCode);
    return errCode;
}

void CloneRestoreClassify::ReportClassifyRestoreTask()
{
    MEDIA_INFO_LOG("Classify label insert successInsertCnt_: %{public}d, failInsertCnt_: %{public}d",
        successInsertLabelCnt_.load(), failInsertLabelCnt_.load());
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_)
        .Report("Classify label restore", std::to_string(CLASSIFY_STATUS_SUCCESS),
        "successInsertCnt_: " + std::to_string(successInsertLabelCnt_) +
        ", failInsertCnt_: " + std::to_string(failInsertLabelCnt_));

    MEDIA_INFO_LOG("Classify video label insert successInsertCnt_: %{public}d, failInsertCnt_: %{public}d",
        successInsertVideoLabelCnt_.load(), failInsertVideoLabelCnt_.load());
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_)
        .Report("Classify video label restore", std::to_string(CLASSIFY_STATUS_SUCCESS),
        "successInsertCnt_: " + std::to_string(successInsertVideoLabelCnt_) +
        ", failInsertCnt_: " + std::to_string(failInsertVideoLabelCnt_));
}

void CloneRestoreClassify::Restore(const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap)
{
    // int32_t totalNumber = QueryTotalNumberOfAnalysisTotal(); // TODO MAKE LESS SENSE?
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    std::vector<int32_t> minIds = GetMinIdsOfAnalysisTotal();
    for (auto minId : minIds) {
        RestoreBatch(photoInfoMap, minId);
    }
    ReportClassifyRestoreTask();
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("@classify, total time cost: %{public}" PRId64, end - start);
    // TODO PRINT COUNT & TIME COST
}

std::vector<int32_t> CloneRestoreClassify::GetMinIdsOfAnalysisTotal()
{
    int64_t startGetCloudPhotoMinIds = MediaFileUtils::UTCTimeMilliSeconds();
    std::vector<int32_t> minIds;
    const std::string QUERY_SQL = "SELECT id FROM ("
        "SELECT id, ROW_NUMBER() OVER (ORDER BY id ASC) AS row_num FROM tab_analysis_total) AS numbered "
        "WHERE (row_num - 1) % 200 = 0 ;";
    std::vector<NativeRdb::ValueObject> params;
    auto resultSet = BackupDatabaseUtils::QuerySql(mediaRdb_, QUERY_SQL, params);
    CHECK_AND_RETURN_RET(resultSet != nullptr, minIds);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        minIds.emplace_back(GetInt32Val("id", resultSet));
    }
    int64_t endGetCloudPhotoMinIds = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("TimeCost: GetMinIdsOfAnalysisTotal cost: %{public}" PRId64,
        endGetCloudPhotoMinIds - startGetCloudPhotoMinIds);
    return minIds;
}

void CloneRestoreClassify::RestoreBatch(const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap, int32_t minId)
{
    int64_t startGet = MediaFileUtils::UTCTimeMilliSeconds();
    GetAnalysisTotalInfos(photoInfoMap, minId);
    int64_t startRestoreMaps = MediaFileUtils::UTCTimeMilliSeconds();
    RestoreMaps();
    int64_t startRestoreVideoMaps = MediaFileUtils::UTCTimeMilliSeconds();
    RestoreVideoMaps();
    int64_t startUpdate = MediaFileUtils::UTCTimeMilliSeconds();
    UpdateAnalysisTotal();
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("TimeCost: GetAnalysisTotalInfos cost: %{public}" PRId64 ", RestoreMaps cost: %{public}" PRId64
        ", RestoreVideoMaps cost: %{public}" PRId64 ", UpdateAnalysisTotal cost: %{public}" PRId64,
        startRestoreMaps - startGet, startRestoreVideoMaps - startRestoreMaps, startUpdate - startRestoreVideoMaps,
        end - startUpdate);
}

void CloneRestoreClassify::GetAnalysisTotalInfos(const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap,
    int32_t minId)
{
    analysisTotalInfos_.clear();
    const std::string QUERY_SQL = "SELECT file_id, label FROM tab_analysis_total WHERE id >= ? LIMIT ?;";
    std::vector<NativeRdb::ValueObject> params = { minId, PAGE_SIZE };
    auto resultSet = BackupDatabaseUtils::QuerySql(mediaRdb_, QUERY_SQL, params);
    CHECK_AND_RETURN(resultSet != nullptr);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileIdOld = GetInt32Val("file_id", resultSet);
        int32_t status = GetInt32Val("label", resultSet);
        if (photoInfoMap.count(fileIdOld) == 0) {
            MEDIA_ERR_LOG("Cannot find %{public}d", fileIdOld);
            continue;
        }
        AnalysisTotalInfo info;
        info.fileIdOld = fileIdOld;
        info.status = status;
        analysisTotalInfos_.emplace_back(info);
    }
}

void CloneRestoreClassify::UpdateAnalysisTotal()
{
    std::unordered_map<int32_t, std::vector<std::string>> statusFileIdsMap =
        GetAnalysisTotalStatusFileIdsMap();
    for (auto iter : statusFileIdsMap) {
        int32_t updatedRows = UpdateAnalysisTotalByStatus(iter.first, iter.second);
        MEDIA_INFO_LOG("status: %{public}d, size: %{public}zu, updatedRows: %{public}d", iter.first,
            iter.second.size(), updatedRows);
    }
}

std::unordered_map<int32_t, std::vector<std::string>> CloneRestoreClassify::GetAnalysisTotalStatusFileIdsMap()
{
    std::unordered_map<int32_t, std::vector<std::string>> statusFileIdsMap;
    for (const auto info : analysisTotalInfos_) {
        if (info.restoreStatus != RestoreStatus::SUCCESS || info.status == AnalysisStatus::UNANALYZED) {
            continue;
        }
        auto &fileIds = statusFileIdsMap[info.status];
        fileIds.emplace_back(std::to_string(info.fileIdNew));
    }
    return statusFileIdsMap;
}

int32_t CloneRestoreClassify::UpdateAnalysisTotalByStatus(int32_t status, const std::vector<std::string> &fileIds)
{
    if (fileIds.empty()) {
        return 0;
    }

    int32_t updatedRows = 0;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt("label", status);
    std::unique_ptr<NativeRdb::AbsRdbPredicates> updatePredicates =
        std::make_unique<NativeRdb::AbsRdbPredicates>("tab_analysis_total");
    updatePredicates->In("file_id", fileIds);
    return BackupDatabaseUtils::Update(mediaLibraryRdb_, updatedRows, valuesBucket, updatePredicates);
}
}