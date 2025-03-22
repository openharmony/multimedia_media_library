/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "PhotoDayMonthYearOperation"

#include "photo_day_month_year_operation.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
const int32_t UPDATE_BATCH_SIZE = 200;

const std::string QUERY_NEED_UPDATE_FILE_IDS = ""
    "SELECT file_id FROM Photos "
    "WHERE"
    "  date_added = 0"
    "  OR date_taken = 0"
    "  OR date_day <> strftime( '%Y%m%d', date_taken / 1000, 'unixepoch', 'localtime' )"
    "  OR detail_time <> strftime( '%Y:%m:%d %H:%M:%S', date_taken / 1000, 'unixepoch', 'localtime' )";

const std::string UPDATE_DAY_MONTH_YEAR = ""
    "UPDATE Photos "
    "SET date_added ="
    " CASE"
    "  WHEN date_added <> 0 THEN"
    "  date_added "
    "  WHEN date_taken <> 0 THEN"
    "  date_taken "
    "  WHEN date_modified <> 0 THEN"
    "  date_modified ELSE strftime( '%s', 'now' ) "
    " END, "
    "date_taken ="
    " CASE"
    "  WHEN date_taken <> 0 THEN"
    "  date_taken "
    "  WHEN date_added <> 0 THEN"
    "  date_added "
    "  WHEN date_modified <> 0 THEN"
    "  date_modified ELSE strftime( '%s', 'now' ) "
    " END, "
    "date_day ="
    " CASE"
    "  WHEN date_taken <> 0 THEN"
    "  strftime( '%Y%m%d', date_taken / 1000, 'unixepoch', 'localtime' ) "
    "  WHEN date_added <> 0 THEN"
    "  strftime( '%Y%m%d', date_added / 1000, 'unixepoch', 'localtime' ) "
    "  WHEN date_modified <> 0 THEN"
    "  strftime( '%Y%m%d', date_modified / 1000, 'unixepoch', 'localtime' ) "
    "  ELSE strftime( '%Y%m%d', strftime( '%s', 'now' ) / 1000, 'unixepoch', 'localtime' ) "
    " END, "
    "date_month ="
    " CASE"
    "  WHEN date_taken <> 0 THEN"
    "  strftime( '%Y%m', date_taken / 1000, 'unixepoch', 'localtime' ) "
    "  WHEN date_added <> 0 THEN"
    "  strftime( '%Y%m', date_added / 1000, 'unixepoch', 'localtime' ) "
    "  WHEN date_modified <> 0 THEN"
    "  strftime( '%Y%m', date_modified / 1000, 'unixepoch', 'localtime' ) "
    "  ELSE strftime( '%Y%m', strftime( '%s', 'now' ) / 1000, 'unixepoch', 'localtime' ) "
    " END, "
    "date_year ="
    " CASE"
    "  WHEN date_taken <> 0 THEN"
    "  strftime( '%Y', date_taken / 1000, 'unixepoch', 'localtime' ) "
    "  WHEN date_added <> 0 THEN"
    "  strftime( '%Y', date_added / 1000, 'unixepoch', 'localtime' ) "
    "  WHEN date_modified <> 0 THEN"
    "  strftime( '%Y', date_modified / 1000, 'unixepoch', 'localtime' ) "
    "  ELSE strftime( '%Y', strftime( '%s', 'now' ) / 1000, 'unixepoch', 'localtime' ) "
    " END, "
    "detail_time ="
    " CASE"
    "  WHEN date_taken <> 0 THEN"
    "  strftime( '%Y:%m:%d %H:%M:%S', date_taken / 1000, 'unixepoch', 'localtime' ) "
    "  WHEN date_added <> 0 THEN"
    "  strftime( '%Y:%m:%d %H:%M:%S', date_added / 1000, 'unixepoch', 'localtime' ) "
    "  WHEN date_modified <> 0 THEN"
    "  strftime( '%Y:%m:%d %H:%M:%S', date_modified / 1000, 'unixepoch', 'localtime' ) "
    "  ELSE strftime( '%Y:%m:%d %H:%M:%S', strftime( '%s', 'now' ) / 1000, 'unixepoch', 'localtime' ) "
    " END, "
    "dirty ="
    " CASE"
    "  WHEN dirty = 0 THEN"
    "  2 ELSE dirty "
    " END "
    "WHERE"
    "  file_id IN ( ";

int32_t PhotoDayMonthYearOperation::UpdatePhotosDate(const std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    MEDIA_INFO_LOG("update photos date start");
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    bool cond = (rdbStore == nullptr || !rdbStore->CheckRdbStore());
    CHECK_AND_RETURN_RET_LOG(!cond, NativeRdb::E_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    auto resultSet = rdbStore->QueryByStep(QUERY_NEED_UPDATE_FILE_IDS);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, NativeRdb::E_ERROR, "query photos by step failed");

    std::vector<std::string> needUpdateFileIds;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        needUpdateFileIds.push_back(GetStringVal(PhotoColumn::MEDIA_ID, resultSet));
    }
    resultSet->Close();
    auto needChangedSize = needUpdateFileIds.size();
    CHECK_AND_RETURN_RET(needChangedSize > 0, NativeRdb::E_OK);

    int32_t ret = NativeRdb::E_OK;
    int64_t totalChanged = 0;
    for (size_t start = 0; start < needChangedSize; start += UPDATE_BATCH_SIZE) {
        size_t end = std::min(start + UPDATE_BATCH_SIZE, needChangedSize);
        std::stringstream updateSql;
        updateSql << UPDATE_DAY_MONTH_YEAR;
        for (size_t i = start; i < end; ++i) {
            if (i != start) {
                updateSql << ", ";
            }
            updateSql << needUpdateFileIds[i];
        }
        updateSql << " );";
        int64_t batchStart = MediaFileUtils::UTCTimeMilliSeconds();
        int64_t changedRowCount = 0;
        auto errCode = rdbStore->ExecuteForChangedRowCount(changedRowCount, updateSql.str());
        if (errCode != NativeRdb::E_OK) {
            ret = errCode;
            MEDIA_ERR_LOG("update photos date failed, errCode: %{public}d, batchStart: %{public}" PRId64
                ", cost: %{public}" PRId64,
                errCode, batchStart, MediaFileUtils::UTCTimeMilliSeconds() - batchStart);
        } else {
            totalChanged += changedRowCount;
            MEDIA_DEBUG_LOG("update photos date, batchStart: %{public}" PRId64 ", cost: %{public}" PRId64
                ", changedRowCount: %{public}" PRId64,
                batchStart, MediaFileUtils::UTCTimeMilliSeconds() - batchStart, changedRowCount);
        }
    }

    MEDIA_INFO_LOG("update photos date end, startTime: %{public}" PRId64 ", cost: %{public}" PRId64
        ", needChangedSize: %{public}zu, totalChanged: %{public}" PRId64,
        startTime, MediaFileUtils::UTCTimeMilliSeconds() - startTime, needChangedSize, totalChanged);
    return ret;
}

int32_t PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(const std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    MEDIA_INFO_LOG("update phots date start");
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    bool cond = (rdbStore == nullptr || !rdbStore->CheckRdbStore());
    CHECK_AND_RETURN_RET_LOG(!cond, NativeRdb::E_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");

    auto ret = UpdatePhotosDate(rdbStore);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret, "update day month year failed, ret=%{public}d", ret);
    MEDIA_INFO_LOG("update phots date end, startTime: %{public}" PRId64 ", cost: %{public}" PRId64, startTime,
        (MediaFileUtils::UTCTimeMilliSeconds() - startTime));
    return NativeRdb::E_OK;
}

int32_t PhotoDayMonthYearOperation::UpdatePhotosDate(NativeRdb::RdbStore &rdbStore)
{
    MEDIA_INFO_LOG("update photos date start");
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();

    auto resultSet = rdbStore.QueryByStep(QUERY_NEED_UPDATE_FILE_IDS);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, NativeRdb::E_ERROR, "query photos by step failed");

    std::vector<std::string> needUpdateFileIds;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        needUpdateFileIds.push_back(GetStringVal(PhotoColumn::MEDIA_ID, resultSet));
    }
    resultSet->Close();
    auto needChangedSize = needUpdateFileIds.size();
    CHECK_AND_RETURN_RET(needChangedSize > 0, NativeRdb::E_OK);

    std::stringstream updateSql;
    updateSql << UPDATE_DAY_MONTH_YEAR;
    for (size_t i = 0; i < needChangedSize; ++i) {
        if (i != 0) {
            updateSql << ", ";
        }
        updateSql << needUpdateFileIds[i];
    }
    updateSql << " );";
    int64_t changedRowCount = 0;
    auto errCode = rdbStore.ExecuteForChangedRowCount(changedRowCount, updateSql.str());
    CHECK_AND_RETURN_RET_LOG(errCode == NativeRdb::E_OK, errCode,
        "update photos date failed, errCode: %{public}d, startTime: %{public}" PRId64
        ", cost: %{public}" PRId64 ", needChangedSize: %{public}zu",
        errCode, startTime, MediaFileUtils::UTCTimeMilliSeconds() - startTime, needChangedSize);

    MEDIA_INFO_LOG("update photos date end, startTime: %{public}" PRId64 ", cost: %{public}" PRId64
        ", needChangedSize: %{public}zu, changedRowCount: %{public}" PRId64,
        startTime, MediaFileUtils::UTCTimeMilliSeconds() - startTime, needChangedSize, changedRowCount);
    return NativeRdb::E_OK;
}

int32_t PhotoDayMonthYearOperation::UpdatePhotosDateIdx(const std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    MEDIA_INFO_LOG("update photos date idx start");
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    bool cond = (rdbStore == nullptr || !rdbStore->CheckRdbStore());
    CHECK_AND_RETURN_RET_LOG(!cond, NativeRdb::E_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");

    auto ret = rdbStore->ExecuteSql(PhotoColumn::DROP_SCHPT_DAY_INDEX);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "drop idx date_day failed, ret=%{public}d", ret);

    ret = rdbStore->ExecuteSql(PhotoColumn::CREATE_SCHPT_DAY_INDEX);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "create idx date_day failed, ret=%{public}d", ret);

    ret = rdbStore->ExecuteSql(PhotoColumn::DROP_SCHPT_MONTH_COUNT_READY_INDEX);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "drop idx date_month failed, ret=%{public}d", ret);

    ret = rdbStore->ExecuteSql(PhotoColumn::CREATE_SCHPT_MONTH_COUNT_READY_INDEX);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "create idx date_month failed, ret=%{public}d", ret);

    ret = rdbStore->ExecuteSql(PhotoColumn::DROP_SCHPT_YEAR_COUNT_READY_INDEX);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "drop idx date_year failed, ret=%{public}d", ret);

    ret = rdbStore->ExecuteSql(PhotoColumn::CREATE_SCHPT_YEAR_COUNT_READY_INDEX);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret, "create idx date_year failed, ret=%{public}d", ret);

    MEDIA_INFO_LOG("update photos date idx end, startTime: %{public}" PRId64 ", cost: %{public}" PRId64, startTime,
        (MediaFileUtils::UTCTimeMilliSeconds() - startTime));
    return NativeRdb::E_OK;
}

std::pair<int32_t, std::vector<std::string>> PhotoDayMonthYearOperation::QueryNeedUpdateFileIds(const int32_t batchSize)
{
    MEDIA_DEBUG_LOG("Query need update fileIds start");

    std::vector<std::string> needUpdateFileIds;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr!");
        return { NativeRdb::E_ERROR, needUpdateFileIds };
    }

    const std::string sql = QUERY_NEED_UPDATE_FILE_IDS + " LIMIT " + std::to_string(batchSize);

    auto resultSet = rdbStore->QueryByStep(sql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("query need update fileIds by step failed!");
        return { NativeRdb::E_ERROR, needUpdateFileIds };
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        needUpdateFileIds.push_back(GetStringVal(PhotoColumn::MEDIA_ID, resultSet));
    }
    resultSet->Close();

    return { NativeRdb::E_OK, needUpdateFileIds };
}

int32_t PhotoDayMonthYearOperation::UpdateAbnormalDayMonthYear(std::vector<std::string> &fileIds)
{
    MEDIA_DEBUG_LOG("update abnormal day month year data start");

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, NativeRdb::E_ERROR, "rdbStore is nullptr!");

    auto needChangedSize = fileIds.size();
    CHECK_AND_RETURN_RET(needChangedSize > 0, NativeRdb::E_OK);

    std::stringstream updateSql;
    updateSql << UPDATE_DAY_MONTH_YEAR;
    for (size_t i = 0; i < needChangedSize; ++i) {
        if (i != 0) {
            updateSql << ", ";
        }
        updateSql << fileIds[i];
    }
    updateSql << " );";
    int64_t changedRowCount = 0;

    auto errCode = rdbStore->ExecuteForChangedRowCount(changedRowCount, updateSql.str());
    CHECK_AND_RETURN_RET_LOG(errCode == NativeRdb::E_OK, errCode,
        "update abnormal day month year data failed, errCode: %{public}d, needChangedSize: %{public}zu",
        errCode, needChangedSize);
    MEDIA_DEBUG_LOG(
        "update abnormal day month year data end, needChangedSize: %{public}zu, changedRowCount: %{public}" PRId64,
        needChangedSize, changedRowCount);
    return NativeRdb::E_OK;
}
} // namespace Media
} // namespace OHOS
