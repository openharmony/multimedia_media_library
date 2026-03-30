/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryCloneRestoreWatermarkTbl"

#include "watermark_clone.h"

#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>
#include <chrono>

#include "backup_database_utils.h"
#include "backup_const_column.h"
#include "backup_dfx_utils.h"
#include "media_file_utils.h"
#include "media_log.h"

namespace OHOS::Media {
// LCOV_EXCL_START
WaterMarkClone::WaterMarkClone(
    const std::shared_ptr<NativeRdb::RdbStore>& sourceRdb,
    const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
    const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap)
    : sourceRdb_(sourceRdb), destRdb_(destRdb), photoInfoMap_(photoInfoMap)
{
}

bool WaterMarkClone::Clone()
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();

    if (photoInfoMap_.empty()) {
        migrateWaterMarkTotalTimeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start;
        MEDIA_INFO_LOG("photoInfoMap_ is empty, no watermark entries to clone Total time:  %{public}lld ms",
            (long long)migrateWaterMarkTotalTimeCost_);
        return true;
    }

    std::vector<int32_t> oldFileIds;
    oldFileIds.reserve(photoInfoMap_.size());

    for (const auto& pair : photoInfoMap_) {
        oldFileIds.push_back(pair.first);
    }

    std::string fileIdOldInClause = "(" + BackupDatabaseUtils::JoinValues<int32_t>(oldFileIds, ", ") + ")";
    CHECK_AND_RETURN_RET_LOG(ShouldClone(fileIdOldInClause, start), true,
        "sourceRdb_ does not need to be cloned, timeCost: %{public}lld ms", (long long)migrateWaterMarkTotalTimeCost_);

    std::vector<std::string> commonColumns = BackupDatabaseUtils::GetCommonColumnInfos(sourceRdb_, destRdb_,
        ANALYSIS_WATERMARK_TABLE);
    migrateWaterMarkTotalTimeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start;
    CHECK_AND_RETURN_RET_LOG(!commonColumns.empty(),
        false, "No common columns found for watermark table, timeCost: %{public}lld ms",
        (long long)migrateWaterMarkTotalTimeCost_);

    for (size_t i = 0; i < oldFileIds.size(); i += QUERY_COUNT) {
        auto batch_begin = oldFileIds.begin() + i;
        auto batch_end = ((i + QUERY_COUNT < oldFileIds.size()) ?
            (oldFileIds.begin() + i + QUERY_COUNT) : oldFileIds.end());
        std::vector<int32_t> batchOldFileIds(batch_begin, batch_end);

        CHECK_AND_CONTINUE(!batchOldFileIds.empty());

        std::string fileIdOldInClause = "(" + BackupDatabaseUtils::JoinValues<int32_t>(batchOldFileIds, ", ") + ")";
        std::vector<AnalysisWaterMarkTbl> analysisWaterMarkTbls = QueryAnalysisWaterMarkTbl(
            fileIdOldInClause, commonColumns);

        CHECK_AND_CONTINUE_ERR_LOG(!analysisWaterMarkTbls.empty(),
            "Query returned empty result for batch starting at index %{public}zu", i);

        ProcessWaterMarkTbls(analysisWaterMarkTbls);
        BatchInsertWaterMark(analysisWaterMarkTbls);
    }

    migrateWaterMarkTotalTimeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start;
    MEDIA_INFO_LOG("WaterMarkClone::Clone completed. Migrated %{public}lld records."
        "Total time: %{public}lld ms", (long long)migrateWaterMarkNum_, (long long)migrateWaterMarkTotalTimeCost_);
    return true;
}

bool WaterMarkClone::ShouldClone(const std::string& fileIdOldInClause, int64_t start)
{
    std::string querySql = "SELECT count(1) AS count FROM tab_analysis_watermark WHERE file_id IN " + fileIdOldInClause;

    int32_t totalNumber = BackupDatabaseUtils::QueryInt(sourceRdb_, querySql, CUSTOM_COUNT);
    MEDIA_INFO_LOG("QueryWaterMarkNumber, totalNumber = %{public}d", totalNumber);

    if (totalNumber <= 0) {
        int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
        migrateWaterMarkTotalTimeCost_ += end - start;
        return false;
    }
    return true;
}

void WaterMarkClone::ProcessWaterMarkTbls(std::vector<AnalysisWaterMarkTbl>& waterMarkTbls)
{
    CHECK_AND_RETURN_LOG(!waterMarkTbls.empty(), "watermark tbls empty");

    auto newEnd = std::remove_if(waterMarkTbls.begin(), waterMarkTbls.end(),
        [this] (const AnalysisWaterMarkTbl& tbl) {
            if (!tbl.fileId.has_value()|| tbl.fileId.value() <= 0) {
                return true;
            }
            return photoInfoMap_.find(tbl.fileId.value()) == photoInfoMap_.end();
        });

    for (auto it = waterMarkTbls.begin(); it != newEnd; it++) {
        int32_t oldId = it->fileId.value();
        int32_t newId = photoInfoMap_.at(oldId).fileIdNew;
        if (newId <= 0) {
            it->fileId.reset();
            continue;
        }
        it->fileId = photoInfoMap_.at(oldId).fileIdNew;
    }

    waterMarkTbls.erase(newEnd, waterMarkTbls.end());
}

std::vector<AnalysisWaterMarkTbl> WaterMarkClone::QueryAnalysisWaterMarkTbl(
    const std::string& fileIdClause, const std::vector<std::string>& commonColumns)
{
    std::vector<AnalysisWaterMarkTbl> result;

    std::string inClause = BackupDatabaseUtils::JoinValues<std::string>(commonColumns, ", ");
    std::string querySql = "SELECT " + inClause + " FROM tab_analysis_watermark WHERE file_id IN " + fileIdClause;

    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(sourceRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql for watermark is null.");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AnalysisWaterMarkTbl analysisWaterMarkTbl;
        ParseAnalysisWaterMarkResultSet(resultSet, analysisWaterMarkTbl);
        result.emplace_back(analysisWaterMarkTbl);
    }

    resultSet->Close();
    return result;
}

void WaterMarkClone::ParseAnalysisWaterMarkResultSet(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    AnalysisWaterMarkTbl& analysisWaterMarkTbl)
{
    analysisWaterMarkTbl.fileId = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, WATERMARK_COL_FILE_ID);
    analysisWaterMarkTbl.status = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, WATERMARK_COL_STATUS);
    analysisWaterMarkTbl.type = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, WATERMARK_COL_TYPE);
    analysisWaterMarkTbl.valid_region_x = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        WATERMARK_COL_VALID_REGION_X);
    analysisWaterMarkTbl.valid_region_y = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        WATERMARK_COL_VALID_REGION_Y);
    analysisWaterMarkTbl.valid_region_width = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        WATERMARK_COL_VALID_REGION_WIDTH);
    analysisWaterMarkTbl.valid_region_height = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        WATERMARK_COL_VALID_REGION_HEIGHT);
    analysisWaterMarkTbl.algo_version = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        WATERMARK_COL_ALGO_VERSION);
}

void WaterMarkClone::BatchInsertWaterMark(const std::vector<AnalysisWaterMarkTbl>& waterMarkTbls)
{
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    std::unordered_set<int32_t> fileIdSet;
    valuesBuckets.reserve(waterMarkTbls.size());
    for (const auto& waterMarkTbl : waterMarkTbls) {
        valuesBuckets.push_back(CreateValuesBucketFromWaterMarkTbl(waterMarkTbl));
    }

    CHECK_AND_RETURN_LOG(!valuesBuckets.empty(), "No valid watermark data to insert skip batch insert");
    int64_t rowNum = 0;
    int32_t ret = BatchInsertWithRetry(ANALYSIS_WATERMARK_TABLE, valuesBuckets, rowNum);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to batch insert watermark records");

    for (const auto& waterMarkTbl : waterMarkTbls) {
        if (waterMarkTbl.fileId.has_value()) {
            fileIdSet.insert(waterMarkTbl.fileId.value());
        }
    }

    migrateWaterMarkNum_ += rowNum;
}

NativeRdb::ValuesBucket WaterMarkClone::CreateValuesBucketFromWaterMarkTbl(const AnalysisWaterMarkTbl& waterMarkTbl)
{
    NativeRdb::ValuesBucket values;

    PutIfPresent(values, WATERMARK_COL_FILE_ID, waterMarkTbl.fileId);
    PutIfPresent(values, WATERMARK_COL_STATUS, waterMarkTbl.status);
    PutIfPresent(values, WATERMARK_COL_TYPE, waterMarkTbl.type);
    PutIfPresent(values, WATERMARK_COL_VALID_REGION_X, waterMarkTbl.valid_region_x);
    PutIfPresent(values, WATERMARK_COL_VALID_REGION_Y, waterMarkTbl.valid_region_y);
    PutIfPresent(values, WATERMARK_COL_VALID_REGION_WIDTH, waterMarkTbl.valid_region_width);
    PutIfPresent(values, WATERMARK_COL_VALID_REGION_HEIGHT, waterMarkTbl.valid_region_height);
    PutIfPresent(values, WATERMARK_COL_ALGO_VERSION, waterMarkTbl.algo_version);

    return values;
}

int32_t WaterMarkClone::BatchInsertWithRetry(const std::string& tableName,
    std::vector<NativeRdb::ValuesBucket>& values, int64_t& rowNum)
{
    CHECK_AND_RETURN_RET(!values.empty(), E_OK);
    int32_t errCode = E_ERR;
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(destRdb_);
    std::function<int(void)> func = [&]()->int {
        errCode = trans.BatchInsert(rowNum, tableName, values, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        CHECK_AND_PRINT_LOG(errCode == E_OK, "InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.",
            errCode, (long)rowNum);
        return errCode;
    };
    errCode = trans.RetryTrans(func, true);
    CHECK_AND_PRINT_LOG(errCode == E_OK, "BatchInsertWithRetry: tans finish fail!, ret:%{public}d", errCode);
    return errCode;
}
}