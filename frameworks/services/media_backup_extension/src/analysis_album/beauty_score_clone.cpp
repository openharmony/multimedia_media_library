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

#include "beauty_score_clone.h"

#include "backup_database_utils.h"
#include "backup_const.h"
#include "backup_const_column.h"
#include "backup_dfx_utils.h"
#include "backup_file_utils.h"
#include "backup_log_utils.h"
#include "database_report.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_library_db_upgrade.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "rdb_store.h"
#include "result_set_utils.h"

namespace OHOS::Media {
BeautyScoreClone::BeautyScoreClone(
    const std::shared_ptr<NativeRdb::RdbStore>& sourceRdb,
    const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
    const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap
    )
    : sourceRdb_(sourceRdb),
      destRdb_(destRdb),
      photoInfoMap_(photoInfoMap)
{
}

bool BeautyScoreClone::CloneBeautyScoreInfo()
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    std::vector<int32_t> oldFileIds;
    oldFileIds.reserve(photoInfoMap_.size());
    std::vector<int32_t> newFileIds;
    newFileIds.reserve(photoInfoMap_.size());

    for (const auto& pair : photoInfoMap_) {
        oldFileIds.push_back(pair.first);
        newFileIds.push_back(pair.second.fileIdNew);
    }

    if (oldFileIds.empty()) {
        MEDIA_INFO_LOG("photoInfoMap_ is empty, no aesthetics score entries to clone.");
        migrateScoreTotalTimeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start;
        return true;
    }

    std::string fileIdOldInClause = "(" + BackupDatabaseUtils::JoinValues<int>(oldFileIds, ", ") + ")";
    std::string querySql = QUERY_BEAUTY_SCORE_COUNT;
    querySql += " WHERE " + BEAUTY_SCORE_COL_FILE_ID + " IN " + fileIdOldInClause;
    int32_t totalNumber = BackupDatabaseUtils::QueryInt(sourceRdb_, querySql, CUSTOM_COUNT);
    MEDIA_INFO_LOG("QueryBeautyScoreTotalNumber, totalNumber = %{public}d", totalNumber);
    if (totalNumber <= 0) {
        int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
        migrateScoreTotalTimeCost_ += end - start;
        return true;
    }

    std::vector<std::string> commonColumn = BackupDatabaseUtils::GetCommonColumnInfos(sourceRdb_, destRdb_,
        VISION_AESTHETICS_TABLE);
    std::vector<std::string> commonColumns = BackupDatabaseUtils::filterColumns(commonColumn,
        EXCLUDED_BEAUTY_SCORE_COLUMNS);
    CHECK_AND_RETURN_RET_LOG(!commonColumns.empty(),
        false, "No common columns found for aesthetics score table after exclusion.");

    DeleteExistingBeautyScoreData(newFileIds);

    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        std::vector<BeautyScoreTbl> beautyScoreTbls = QueryBeautyScoreTbl(offset, fileIdOldInClause, commonColumns);
        if (beautyScoreTbls.empty()) {
            MEDIA_WARN_LOG("Query returned empty result for offset %{public}d", offset);
            continue;
        }

        std::vector<BeautyScoreTbl> processBeautyScores = ProcessBeautyScoreTbls(beautyScoreTbls);
        BatchInsertBeautyScores(processBeautyScores);
    }
    UpdateTotalTblBeautyScoreStatus(destRdb_, newFileIds);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    migrateScoreTotalTimeCost_ += end - start;
    MEDIA_INFO_LOG("CloneBeautyScoreInfo completed. Migrated %{public}lld records. "
        "Total time: %{public}lld ms",
        (long long)migrateScoreNum_, (long long)migrateScoreTotalTimeCost_);
    return true;
}

std::vector<BeautyScoreTbl> BeautyScoreClone::QueryBeautyScoreTbl(
    int32_t offset, std::string &fileIdClause, const std::vector<std::string> &commonColumns)
{
    std::vector<BeautyScoreTbl> result;
    result.reserve(QUERY_COUNT);

    std::string inClause = BackupDatabaseUtils::JoinValues<std::string>(commonColumns, ", ");
    std::string querySql =
        "SELECT " + inClause +
        " FROM " + VISION_AESTHETICS_TABLE;
    querySql += " WHERE " + BEAUTY_SCORE_COL_FILE_ID + " IN " + fileIdClause;
    querySql += " LIMIT " + std::to_string(offset) + ", " + std::to_string(QUERY_COUNT);

    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(sourceRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSet is null.");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        BeautyScoreTbl beautyScoreTbl;
        ParseBeautyScoreResultSet(resultSet, beautyScoreTbl);
        result.emplace_back(beautyScoreTbl);
    }

    resultSet->Close();
    return result;
}

void BeautyScoreClone::ParseBeautyScoreResultSet(
    const std::shared_ptr<NativeRdb::ResultSet>& resultSet, BeautyScoreTbl& beautyScoreTbl)
{
    beautyScoreTbl.file_id = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, BEAUTY_SCORE_COL_FILE_ID);
    beautyScoreTbl.aesthetics_score = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        BEAUTY_SCORE_COL_AESTHETICS_SCORE);
    beautyScoreTbl.aesthetics_version = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        BEAUTY_SCORE_COL_AESTHETICS_VERSION);
    beautyScoreTbl.prob = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, BEAUTY_SCORE_COL_PROB);
    beautyScoreTbl.analysis_version = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        BEAUTY_SCORE_COL_ANALYSIS_VERSION);
    beautyScoreTbl.selected_flag = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        BEAUTY_SCORE_COL_SELECTED_FLAG);
    beautyScoreTbl.selected_algo_version = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        BEAUTY_SCORE_COL_SELECTED_ALGO_VERSION);
    beautyScoreTbl.selected_status = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        BEAUTY_SCORE_COL_SELECTED_STATUS);
    beautyScoreTbl.negative_flag = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        BEAUTY_SCORE_COL_NEGATIVE_FLAG);
    beautyScoreTbl.negative_algo_version = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        BEAUTY_SCORE_COL_NEGATIVE_ALGO_VERSION);
}

std::vector<BeautyScoreTbl> BeautyScoreClone::ProcessBeautyScoreTbls(
    const std::vector<BeautyScoreTbl>& beautyScoreTbls)
{
    CHECK_AND_RETURN_RET_LOG(!beautyScoreTbls.empty(), {}, "aesthetics scores tbl empty");

    std::vector<BeautyScoreTbl> beautyScoreNewTbls;
    beautyScoreNewTbls.reserve(beautyScoreTbls.size());

    for (const auto& beautyScoreTbl : beautyScoreTbls) {
        if (beautyScoreTbl.file_id.has_value()) {
            int32_t oldFileId = beautyScoreTbl.file_id.value();
            const auto it = photoInfoMap_.find(oldFileId);
            if (it != photoInfoMap_.end()) {
                BeautyScoreTbl updatedScore = beautyScoreTbl;
                updatedScore.file_id = it->second.fileIdNew;
                beautyScoreNewTbls.push_back(std::move(updatedScore));
            } else {
                MEDIA_WARN_LOG("Original file_id %{public}d not found in photoInfoMap_, skipping.", oldFileId);
            }
        }
    }
    return beautyScoreNewTbls;
}

void BeautyScoreClone::BatchInsertBeautyScores(
    const std::vector<BeautyScoreTbl>& beautyScoreTbls)
{
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    std::unordered_set<int32_t> fileIdSet;
    valuesBuckets.reserve(beautyScoreTbls.size());
    for (const auto& beautyScoreTbl : beautyScoreTbls) {
        valuesBuckets.push_back(CreateValuesBucketFromBeautyScoreTbl(beautyScoreTbl));
    }

    int64_t rowNum = 0;
    int32_t ret = BatchInsertWithRetry(VISION_AESTHETICS_TABLE, valuesBuckets, rowNum);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to batch insert aesthetics scores");

    for (const auto& beautyScoreTbl : beautyScoreTbls) {
        if (beautyScoreTbl.file_id.has_value()) {
            fileIdSet.insert(beautyScoreTbl.file_id.value());
        }
    }

    migrateScoreNum_ += rowNum;
    migrateScoreFileNumber_ += fileIdSet.size();
}

NativeRdb::ValuesBucket BeautyScoreClone::CreateValuesBucketFromBeautyScoreTbl(
    const BeautyScoreTbl& beautyScoreTbl)
{
    NativeRdb::ValuesBucket values;

    PutIfPresent(values, BEAUTY_SCORE_COL_ID, beautyScoreTbl.id);
    PutIfPresent(values, BEAUTY_SCORE_COL_FILE_ID, beautyScoreTbl.file_id);
    PutIfPresent(values, BEAUTY_SCORE_COL_AESTHETICS_SCORE, beautyScoreTbl.aesthetics_score);
    PutIfPresent(values, BEAUTY_SCORE_COL_AESTHETICS_VERSION, beautyScoreTbl.aesthetics_version);
    PutIfPresent(values, BEAUTY_SCORE_COL_PROB, beautyScoreTbl.prob);
    PutIfPresent(values, BEAUTY_SCORE_COL_ANALYSIS_VERSION, beautyScoreTbl.analysis_version);
    PutIfPresent(values, BEAUTY_SCORE_COL_SELECTED_FLAG, beautyScoreTbl.selected_flag);
    PutIfPresent(values, BEAUTY_SCORE_COL_SELECTED_ALGO_VERSION, beautyScoreTbl.selected_algo_version);
    PutIfPresent(values, BEAUTY_SCORE_COL_SELECTED_STATUS, beautyScoreTbl.selected_status);
    PutIfPresent(values, BEAUTY_SCORE_COL_NEGATIVE_FLAG, beautyScoreTbl.negative_flag);
    PutIfPresent(values, BEAUTY_SCORE_COL_NEGATIVE_ALGO_VERSION, beautyScoreTbl.negative_algo_version);

    return values;
}

int32_t BeautyScoreClone::BatchInsertWithRetry(const std::string &tableName,
    std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum)
{
    CHECK_AND_RETURN_RET(!values.empty(), E_OK);
    int32_t errCode = E_ERR;
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(destRdb_);
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

void BeautyScoreClone::DeleteExistingBeautyScoreData(const std::vector<int32_t>& newFileIds)
{
    if (newFileIds.empty()) {
        MEDIA_INFO_LOG("No new file IDs to delete aesthetics score data for.");
        return;
    }

    std::string fileIdNewFilterClause = "(" + BackupDatabaseUtils::JoinValues<int>(newFileIds, ", ") + ")";
    std::string deleteScoreSql = "DELETE FROM " + VISION_AESTHETICS_TABLE +
        " WHERE " + BEAUTY_SCORE_COL_FILE_ID + " IN " + fileIdNewFilterClause;
    BackupDatabaseUtils::ExecuteSQL(destRdb_, deleteScoreSql);
}

void BeautyScoreClone::UpdateTotalTblBeautyScoreStatus(
    std::shared_ptr<NativeRdb::RdbStore> rdbStore, std::vector<int32_t> newFileIds)
{
    std::string fileIdNewFilterClause = "(" + BackupDatabaseUtils::JoinValues<int>(newFileIds, ", ") + ")";


    std::string updateSql = "UPDATE tab_analysis_total "
        "SET aesthetics_score = 1 "
        "WHERE EXISTS (SELECT 1 FROM tab_analysis_aesthetics_score "
        "WHERE tab_analysis_aesthetics_score.file_id = tab_analysis_total.file_id) "
        "AND tab_analysis_total.file_id IN " + fileIdNewFilterClause;

    int32_t errCode = BackupDatabaseUtils::ExecuteSQL(rdbStore, updateSql);
    CHECK_AND_PRINT_LOG(errCode >= 0, "execute update analysis total failed, ret=%{public}d", errCode);
}
} // namespace OHOS::Media