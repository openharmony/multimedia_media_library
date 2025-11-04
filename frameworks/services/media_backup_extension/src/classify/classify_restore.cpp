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

#include "classify_restore.h"

#include "backup_database_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "upgrade_restore_task_report.h"

namespace OHOS::Media {
const int32_t PAGE_SIZE = 200;
const int32_t INVALID_LABEL = -2;
const int32_t CLASSIFY_RESTORE_STATUS_SUCCESS = 1;
const std::string VERSION_PREFIX = "backup";
const std::string ANALYSIS_LABEL_TABLE = "tab_analysis_label";
const std::string ID = "id";

void ClassifyRestore::Init(int32_t sceneCode, const std::string &taskId,
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
{
    sceneCode_ = sceneCode;
    taskId_ = taskId;
    mediaLibraryRdb_ = mediaLibraryRdb;
    galleryRdb_ = galleryRdb;
}

void ClassifyRestore::RestoreClassify(const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap)
{
    MEDIA_INFO_LOG("RestoreClassify start");
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    CHECK_AND_RETURN_LOG(galleryRdb_ != nullptr && mediaLibraryRdb_ != nullptr, "rdbStore is nullptr");
    GetMaxIds();
    RestoreLabel(photoInfoMap);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    restoreTimeCost_ = end - start;
    ReportRestoreTask();
    MEDIA_INFO_LOG("RestoreClassify Time cost: %{public}" PRId64, end - start);
}

void ClassifyRestore::TransferLabelInfo(GalleryLabelInfo &info)
{
    info.version = VERSION_PREFIX + info.version;
    CHECK_AND_EXECUTE(info.categoryId != INVALID_LABEL, info.subLabel = "");
    CHECK_AND_EXECUTE(info.subLabel.empty(), info.subLabel.pop_back()); // remove last ','
    info.subLabel = "[" + info.subLabel + "]";
}

void ClassifyRestore::UpdateLabelInsertValues(std::vector<NativeRdb::ValuesBucket> &values,
    const GalleryLabelInfo &info)
{
    CHECK_AND_RETURN(info.photoInfo.fileIdNew > 0);
    NativeRdb::ValuesBucket value;
    value.PutInt("file_id", info.photoInfo.fileIdNew);
    value.PutInt("category_id", info.categoryId);
    value.PutString("sub_label", info.subLabel);
    value.PutDouble("prob", info.prob);
    value.PutString("label_version", info.version);
    values.push_back(value);
}

void ClassifyRestore::UpdateStatus(std::vector<int32_t> &fileIds)
{
    CHECK_AND_RETURN_WARN_LOG(!fileIds.empty(), "fileIds is empty");
    std::string fileIdClause = "(" + BackupDatabaseUtils::JoinValues<int>(fileIds, ", ") + ");";
    std::string updateSql =
        "UPDATE tab_analysis_total "
        "SET label = 1 "
        "WHERE EXISTS (SELECT 1 FROM tab_analysis_label "
                        "WHERE tab_analysis_label.file_id = tab_analysis_total.file_id) "
        "AND file_id IN " + fileIdClause;
    int32_t ret = BackupDatabaseUtils::ExecuteSQL(mediaLibraryRdb_, updateSql);
    CHECK_AND_RETURN_LOG(ret >= 0, "execute update analysis total failed, ret = %{public}d", ret);
}

void ClassifyRestore::ProcessLabelInfo(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap)
{
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "resultSet is nullptr");
    std::vector<int32_t> labelFileIds;
    std::vector<NativeRdb::ValuesBucket> values;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        GalleryLabelInfo labelInfo;
        labelInfo.fileIdOld = GetInt32Val("_id", resultSet);
        CHECK_AND_CONTINUE(photoInfoMap.find(labelInfo.fileIdOld) != photoInfoMap.end());
        labelInfo.photoInfo = photoInfoMap.at(labelInfo.fileIdOld);
        labelInfo.categoryId = GetInt32Val("category_id", resultSet);
        labelInfo.subLabel = GetStringVal("sub_label", resultSet);
        labelInfo.prob = GetDoubleVal("prob", resultSet);
        labelInfo.version = GetStringVal("version", resultSet);
        labelFileIds.push_back(labelInfo.photoInfo.fileIdNew);
        TransferLabelInfo(labelInfo);
        UpdateLabelInsertValues(values, labelInfo);
    }
    resultSet->Close();
    int64_t updateRows = 0;
    int errCode = BatchInsertWithRetry(ANALYSIS_LABEL_TABLE, values, updateRows);
    if (errCode != E_OK || updateRows != static_cast<int64_t>(values.size())) {
        int64_t failNums = static_cast<int64_t>(values.size()) - updateRows;
        MEDIA_ERR_LOG("RestoreLabelInfos fail, num: %{public}" PRId64, failNums);
        ErrorInfo errorInfo(RestoreError::INSERT_FAILED, static_cast<int32_t>(values.size()),
            "errCode: " + std::to_string(errCode), "RestoreLabelInfos fail.");
        UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_).ReportError(errorInfo);
        failInsertLabelCnt_ += failNums;
    }
    successInsertLabelCnt_ += updateRows;
    UpdateStatus(labelFileIds);
    MEDIA_INFO_LOG("RestoreLabelInfos one batch end, values count: %{public}d, updateRows: %{public}d",
        static_cast<int>(values.size()), static_cast<int>(updateRows));
}

void ClassifyRestore::RestoreLabel(const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap)
{
    MEDIA_INFO_LOG("RestoreLabel start");
    CHECK_AND_RETURN_LOG(galleryRdb_ != nullptr, "rdbStore is nullptr");
    std::vector<int32_t> fileIdOldBatch;
    size_t count = 0;
    for (auto& pair : photoInfoMap) {
        fileIdOldBatch.push_back(pair.first);
        if (fileIdOldBatch.size() == PAGE_SIZE || count == photoInfoMap.size() - 1) {
            std::string querySql = QUERY_LABEL_SQL +
                BackupDatabaseUtils::JoinValues<int>(fileIdOldBatch, ", ") + ");";
            auto resultSet = galleryRdb_->QuerySql(querySql);
            ProcessLabelInfo(resultSet, photoInfoMap);
            fileIdOldBatch.clear();
        }
        ++count;
    }
    MEDIA_INFO_LOG("RestoreLabel end");
}

int32_t ClassifyRestore::BatchInsertWithRetry(const std::string &tableName,
    std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum)
{
    CHECK_AND_RETURN_RET(!values.empty(), E_OK);
    int32_t errCode = E_ERR;
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(mediaLibraryRdb_);
    std::function<int(void)> func = [&]() -> int {
        errCode = trans.BatchInsert(rowNum, tableName, values);
        CHECK_AND_PRINT_LOG(errCode == E_OK,
            "InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.", errCode, (long)rowNum);
        return errCode;
    };
    errCode = trans.RetryTrans(func, true);
    CHECK_AND_PRINT_LOG(errCode == E_OK, "BatchInsertWithRetry: trans finish fail!, ret: %{public}d", errCode);
    return errCode;
}

void ClassifyRestore::GetMaxIds()
{
    maxIdOfLabel_ = BackupDatabaseUtils::QueryMaxId(mediaLibraryRdb_, ANALYSIS_LABEL_TABLE, ID);
}

void ClassifyRestore::ReportRestoreTask()
{
    RestoreTaskInfo info;
    info.type = "CLASSIFY_RESTORE_IMAGE";
    info.errorCode = std::to_string(CLASSIFY_RESTORE_STATUS_SUCCESS);
    info.errorInfo =
        "max_id: " + std::to_string(maxIdOfLabel_) +
        ", timeCost: " + std::to_string(restoreTimeCost_);
    info.successCount = successInsertLabelCnt_;
    info.failedCount = failInsertLabelCnt_;
    info.duplicateCount = duplicateLabelCnt_;
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_).Report(info);
}
} // namespace OHOS::Media