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
    if (it != map.end()) {
        return it->second;
    }
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

void CloneRestoreClassify::RestoreClassifyInfos()
{
    if (mediaRdb_ == nullptr || mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }

    MEDIA_INFO_LOG("RestoreClassifyInfos start");
    GetClassifyInfos(mediaRdb_, classifyInfos_);
    GetClassifyInfos(mediaLibraryRdb_, dstClassifyInfos_);
    GetClassifyVideoInfos(mediaRdb_, classifyVideoInfos_);
    GetClassifyVideoInfos(mediaLibraryRdb_, dstClassifyVideoInfos_);
    MEDIA_INFO_LOG("RestoreClassifyInfos end");
}

void CloneRestoreClassify::RestoreMaps(std::vector<FileInfo> &fileInfos)
{
    MEDIA_INFO_LOG("CloneRestoreClassify RestoreMaps");
    if (mediaRdb_ == nullptr || mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    if (classifyInfos_.empty()) {
        MEDIA_INFO_LOG("classifyInfos_ is empty");
        return;
    }
    size_t offset = 0;
    do {
        std::vector<NativeRdb::ValuesBucket> values;
        for (size_t index = 0; index < PAGE_SIZE && index + offset < fileInfos.size(); index++) {
            UpdateMapInsertValues(values, fileInfos[index + offset]);
        }
        MEDIA_INFO_LOG("RestoreMaps insert values size: %{public}zu", values.size());
        int64_t rowNum = 0;
        int32_t errCode = BatchInsertWithRetry(ANALYSIS_LABEL_TABLE, values, rowNum);
        if (errCode != E_OK || rowNum != static_cast<int64_t>(values.size())) {
            int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
            MEDIA_ERR_LOG("Classify: RestoreMaps insert fail, num: %{public}" PRId64, failNums);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, static_cast<int32_t>(values.size()),
                "errCode: " + std::to_string(errCode), "Classify: RestoreMaps insert fail");
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
            failInsertLabelCnt_ += failNums;
        }
        offset += PAGE_SIZE;
        successInsertLabelCnt_ += rowNum;
    } while (offset < fileInfos.size());
}

void CloneRestoreClassify::RestoreVideoMaps(std::vector<FileInfo> &fileInfos)
{
    MEDIA_INFO_LOG("CloneRestoreClassify RestoreVideoMaps");
    if (mediaRdb_ == nullptr || mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    if (classifyVideoInfos_.empty()) {
        MEDIA_INFO_LOG("classifyVideoInfos_ is empty");
        return;
    }
    size_t offset = 0;
    do {
        std::vector<NativeRdb::ValuesBucket> values;
        for (size_t index = 0; index < PAGE_SIZE && index + offset < fileInfos.size(); index++) {
            UpdateVideoMapInsertValues(values, fileInfos[index + offset]);
        }
        MEDIA_INFO_LOG("RestoreVideoMaps insert values size: %{public}zu", values.size());
        int64_t rowNum = 0;
        int32_t errCodeVideo = BatchInsertWithRetry(ANALYSIS_VIDEO_TABLE, values, rowNum);
        if (errCodeVideo != E_OK || rowNum != static_cast<int64_t>(values.size())) {
            int64_t failNums = static_cast<int64_t>(values.size()) - rowNum;
            MEDIA_ERR_LOG("ClassifyVideo: RestoreVideo insert fail, num: %{public}" PRId64, failNums);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, static_cast<int32_t>(values.size()),
                "errCodeVideo: " + std::to_string(errCodeVideo), "ClassifyVideo: RestoreMaps insert fail");
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
            failInsertVideoLabelCnt_ += failNums;
        }
        offset += PAGE_SIZE;
        successInsertVideoLabelCnt_ += rowNum;
    } while (offset < fileInfos.size());
}

void CloneRestoreClassify::GetClassifyInfos(std::shared_ptr<NativeRdb::RdbStore> rdb,
    std::vector<ClassifyCloneInfo> &classifyInfo)
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
    const std::string querySql = "SELECT * FROM " + ANALYSIS_LABEL_TABLE + " WHERE " + FILE_ID +
        " in (SELECT " + FILE_ID + " FROM Photos) LIMIT ?, ?";
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        std::vector<NativeRdb::ValueObject> params = {offset, PAGE_SIZE};
        auto resultSet = BackupDatabaseUtils::QuerySql(rdb, querySql, params);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Query resultSql is null.");
            break;
        }
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            ClassifyCloneInfo info;
            GetClassifyInfo(info, resultSet);
            classifyInfo.emplace_back(info);
        }
        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount > 0);
    MEDIA_INFO_LOG("query tab_analysis_label nums: %{public}zu", classifyInfo.size());
}

void CloneRestoreClassify::GetClassifyVideoInfos(std::shared_ptr<NativeRdb::RdbStore> rdb,
    std::vector<ClassifyVideoCloneInfo> &classifyVideoInfo)
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
    const std::string querySql = "SELECT * FROM " + ANALYSIS_VIDEO_TABLE + " WHERE " + FILE_ID +
        " in (SELECT " + FILE_ID + " FROM Photos) LIMIT ?, ?";
    int32_t rowCount = 0;
    int32_t offset = 0;
    do {
        std::vector<NativeRdb::ValueObject> params = {offset, PAGE_SIZE};
        auto resultSet = BackupDatabaseUtils::QuerySql(rdb, querySql, params);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Query resultSql is null.");
            break;
        }
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            ClassifyVideoCloneInfo info;
            GetClassifyVideoInfo(info, resultSet);
            classifyVideoInfo.emplace_back(info);
        }
        resultSet->GetRowCount(rowCount);
        offset += PAGE_SIZE;
        resultSet->Close();
    } while (rowCount > 0);
    MEDIA_INFO_LOG("query tab_analysis_video_label nums: %{public}zu", classifyVideoInfo.size());
}

void CloneRestoreClassify::UpdateMapInsertValues(std::vector<NativeRdb::ValuesBucket> &values,
    const FileInfo &fileInfo)
{
    if (fileInfo.fileIdOld <= 0 || fileInfo.fileIdNew <= 0) {
        return;
    }
    auto itrCheck = std::find_if(classifyInfos_.begin(), classifyInfos_.end(),
        [fileInfo](const ClassifyCloneInfo& info) {
            return info.fileId.has_value() && info.subLabel.has_value() && info.fileId == fileInfo.fileIdOld;
        });
    if (itrCheck == classifyInfos_.end()) {
        MEDIA_INFO_LOG("not match fileId: %{public}d", fileInfo.fileIdNew);
        return;
    }

    auto itrDeduplicate = std::find_if(dstClassifyInfos_.begin(), dstClassifyInfos_.end(),
        [fileInfo](const ClassifyCloneInfo& info) {
            return info.fileId.has_value() && info.fileId == fileInfo.fileIdNew;
        });
    if (itrDeduplicate == dstClassifyInfos_.end()) {
        NativeRdb::ValuesBucket value;
        std::unordered_set<std::string> intersection = GetCommonColumns(ANALYSIS_LABEL_TABLE);
        GetMapInsertValue(value, itrCheck, intersection, fileInfo.fileIdNew);
        values.emplace_back(value);
    }
}

void CloneRestoreClassify::UpdateVideoMapInsertValues(std::vector<NativeRdb::ValuesBucket> &values,
    const FileInfo &fileInfo)
{
    if (fileInfo.fileIdOld <= 0 || fileInfo.fileIdNew <= 0) {
        return;
    }
    auto itrCheck = std::find_if(classifyVideoInfos_.begin(), classifyVideoInfos_.end(),
        [fileInfo](const ClassifyVideoCloneInfo& info) {
            return info.fileId.has_value() && info.subLabel.has_value() && info.fileId == fileInfo.fileIdOld;
        });
    if (itrCheck == classifyVideoInfos_.end()) {
        MEDIA_INFO_LOG("not match fileId: %{public}d", fileInfo.fileIdNew);
        return;
    }

    auto itrDeduplicate = std::find_if(dstClassifyVideoInfos_.begin(), dstClassifyVideoInfos_.end(),
        [fileInfo](const ClassifyVideoCloneInfo& info) {
            return info.fileId.has_value() && info.fileId == fileInfo.fileIdNew;
        });
    if (itrDeduplicate == dstClassifyVideoInfos_.end()) {
        std::unordered_set<std::string> intersection = GetCommonColumns(ANALYSIS_VIDEO_TABLE);
        NativeRdb::ValuesBucket value;
        GetVideoMapInsertValue(value, itrCheck, intersection, fileInfo.fileIdNew);
        values.emplace_back(value);
    }
}

void CloneRestoreClassify::GetClassifyInfo(ClassifyCloneInfo &info,
    std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    info.id = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, ID);
    info.fileId = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, FILE_ID);
    info.categoryId = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, CATEGORY_ID);
    info.subLabel = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SUB_LABEL);
    info.prob = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, PROB);
    info.feature = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FEATURE);
    info.simResult = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SIM_RESULT);
    info.labelVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, LABEL_VERSION);
    info.saliencySubProb = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, SALIENCY_SUB_PROB);
    info.analysisVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_VERSION);
}

void CloneRestoreClassify::GetMapInsertValue(NativeRdb::ValuesBucket &value,
    std::vector<ClassifyCloneInfo>::iterator it, const std::unordered_set<std::string> &intersection, int32_t fileId)
{
    value.PutInt(FILE_ID, fileId);
    PutIfInIntersection(value, CATEGORY_ID, it->categoryId, intersection);
    PutIfInIntersection(value, SUB_LABEL, it->subLabel, intersection);
    PutIfInIntersection(value, PROB, it->prob, intersection);
    PutIfInIntersection(value, FEATURE, it->feature, intersection);
    PutIfInIntersection(value, SIM_RESULT, it->simResult, intersection);
    PutIfInIntersection(value, LABEL_VERSION, it->labelVersion, intersection);
    PutIfInIntersection(value, SALIENCY_SUB_PROB, it->saliencySubProb, intersection);
    PutIfInIntersection(value, ANALYSIS_VERSION, it->analysisVersion, intersection);
}

void CloneRestoreClassify::GetClassifyVideoInfo(ClassifyVideoCloneInfo &info,
    std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    info.id = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, ID);
    info.fileId = BackupDatabaseUtils::GetOptionalValue<int64_t>(resultSet, FILE_ID);
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

void CloneRestoreClassify::GetVideoMapInsertValue(NativeRdb::ValuesBucket &value,
    std::vector<ClassifyVideoCloneInfo>::iterator it,
    const std::unordered_set<std::string> &intersection, int32_t fileId)
{
    value.PutInt(FILE_ID, fileId);
    PutIfInIntersection(value, CATEGORY_ID, it->categoryId, intersection);
    PutIfInIntersection(value, CONFIDENCE_PROBABILITY, it->confidenceProbability, intersection);
    PutIfInIntersection(value, SUB_CATEGORY, it->subCategory, intersection);
    PutIfInIntersection(value, SUB_CONFIDENCE_PROB, it->subConfidenceProb, intersection);
    PutIfInIntersection(value, SUB_LABEL, it->subLabel, intersection);
    PutIfInIntersection(value, SUB_LABEL_PROB, it->subLabelProb, intersection);
    PutIfInIntersection(value, SUB_LABEL_TYPE, it->subLabelType, intersection);
    PutIfInIntersection(value, TRACKS, it->tracks, intersection);
    PutIfInIntersection(value, VIDEO_PART_FEATURE, it->videoPartFeature, intersection);
    PutIfInIntersection(value, FILTER_TAG, it->filterTag, intersection);
    PutIfInIntersection(value, ALGO_VERSION, it->algoVersion, intersection);
    PutIfInIntersection(value, ANALYSIS_VERSION, it->analysisVersion, intersection);
    PutIfInIntersection(value, TRIGGER_GENERATE_THUMBNAIL, it->triggerGenerateThumbnail, intersection);
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
    if (values.empty()) {
        return E_OK;
    }
    int32_t errCode = E_ERR;
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(mediaLibraryRdb_);
    std::function<int(void)> func = [&]()->int {
        errCode = trans.BatchInsert(rowNum, tableName, values);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.", errCode, (long)rowNum);
        }
        return errCode;
    };
    errCode = trans.RetryTrans(func, true);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("BatchInsertWithRetry: tans finish fail!, ret:%{public}d", errCode);
    }
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
}