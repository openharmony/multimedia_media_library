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
#define MLOG_TAG "ForeGroundAnalysisMeta"
#include "foreground_analysis_meta.h"

#include "media_analysis_helper.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_utils.h"
#include "search_column.h"
#include "user_photography_info_column.h"
#include "vision_column.h"
#include "vision_total_column.h"

using namespace OHOS::NativeRdb;
using Uri = OHOS::Uri;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
const int FRONT_CV_MAX_LIMIT = 20;
const int FRONT_INDEX_MAX_LIMIT = 5000;
ForegroundAnalysisMeta::ForegroundAnalysisMeta(std::shared_ptr<NativeRdb::ResultSet> result)
{
    if (result == nullptr) {
        return;
    }
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int colIndex = 0;
        result->GetColumnIndex(FRONT_INDEX_LIMIT, colIndex);
        result->GetInt(colIndex, frontIndexLimit_);
        if (frontIndexLimit_ == 0) {
            frontIndexLimit_ = FRONT_INDEX_MAX_LIMIT;
        }
        result->GetColumnIndex(FRONT_INDEX_MODIFIED, colIndex);
        result->GetLong(colIndex, frontIndexModified_);
        result->GetColumnIndex(FRONT_INDEX_COUNT, colIndex);
        result->GetInt(colIndex, frontIndexCount_);
        result->GetColumnIndex(FRONT_CV_MODIFIED, colIndex);
        result->GetLong(colIndex, frontCvModified_);
        result->GetColumnIndex(FRONT_CV_COUNT, colIndex);
        result->GetInt(colIndex, frontCvCount_);
        isInit_ = true;
    }
}

ForegroundAnalysisMeta::~ForegroundAnalysisMeta() {}

int32_t ForegroundAnalysisMeta::GenerateOpType(MediaLibraryCommand &cmd)
{
    int errCode = E_OK;
    if (IsMetaDirtyed()) {
        errCode = RefreshMeta();
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("refresh err:%{public}d", errCode);
            return errCode;
        }
    }
    errCode = CheckCvAnalysisCondition(cmd);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("chk cv err:%{public}d", errCode);
        return errCode;
    }
    errCode = CheckIndexAnalysisCondition(cmd);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("chk index err:%{public}d", errCode);
        return errCode;
    }
    taskId_ = GetCurTaskId(cmd);
    return E_OK;
}

bool ForegroundAnalysisMeta::IsMetaDirtyed()
{
    std::time_t cvTime = frontCvModified_ / 1000;
    std::time_t indexTime = frontIndexModified_ / 1000;
    std::time_t curTime = MediaFileUtils::UTCTimeMilliSeconds() / 1000;
    std::tm cvTm = *std::localtime(&cvTime);
    std::tm indexTm = *std::localtime(&indexTime);
    std::tm curTm = *std::localtime(&curTime);
    return (cvTm.tm_year != curTm.tm_year) || (cvTm.tm_mon != curTm.tm_mon) || (cvTm.tm_mday != curTm.tm_mday) ||
        (indexTm.tm_year != curTm.tm_year) || (indexTm.tm_mon != curTm.tm_mon) || (indexTm.tm_mday != curTm.tm_mday) ||
        !isInit_;
}

int32_t ForegroundAnalysisMeta::RefreshMeta()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_ERR;
    }
    int64_t curMoified = MediaFileUtils::UTCTimeMilliSeconds();
    frontIndexModified_ = curMoified;
    frontCvModified_ = curMoified;
    frontIndexCount_ = 0;
    frontCvCount_ = 0;
    ValuesBucket valuesBucket;
    valuesBucket.Put(FRONT_CV_MODIFIED, frontCvModified_);
    valuesBucket.Put(FRONT_CV_COUNT, frontCvCount_);
    valuesBucket.Put(FRONT_INDEX_MODIFIED, frontIndexModified_);
    valuesBucket.Put(FRONT_INDEX_COUNT, frontIndexCount_);
    MEDIA_INFO_LOG("refresh cv meta, isIns:%{public}d", !isInit_);
    if (!isInit_) {
        int64_t outRowId = 0;
        int errCode = rdbStore->Insert(outRowId, USER_PHOTOGRAPHY_INFO_TABLE, valuesBucket);
        if (errCode == E_OK) {
            isInit_ = true;
        }
        return errCode;
    }
    int changedRows = 0;
    RdbPredicates predicates(USER_PHOTOGRAPHY_INFO_TABLE);
    return rdbStore->Update(changedRows, valuesBucket, predicates);
}

int32_t ForegroundAnalysisMeta::CheckCvAnalysisCondition(MediaLibraryCommand &cmd)
{
    if (frontCvCount_ >= FRONT_CV_MAX_LIMIT) {
        return E_OK;
    }
    std::vector<std::string> fileIds;
    int32_t errCode = QueryPendingAnalyzeFileIds(cmd, fileIds);
    if (errCode != E_OK) {
        return errCode;
    }
    if (!fileIds.empty()) {
        fileIds_ = std::move(fileIds);
        opType_ |= ForegroundAnalysisOpType::OCR_AND_LABEL;
        if (frontIndexCount_ < frontIndexLimit_) {
            opType_ |= ForegroundAnalysisOpType::SEARCH_INDEX;
        }
    }
    return E_OK;
}

int32_t ForegroundAnalysisMeta::CheckIndexAnalysisCondition(MediaLibraryCommand &cmd)
{
    if ((frontIndexCount_ >= frontIndexLimit_) || (opType_ & ForegroundAnalysisOpType::SEARCH_INDEX)) {
        return E_OK;
    }
    int32_t pengdIndexCount = 0;
    int32_t errCode = QueryPendingIndexCount(cmd, pengdIndexCount);
    if (errCode != E_OK) {
        return errCode;
    }
    if (pengdIndexCount > 0) {
        opType_ |= ForegroundAnalysisOpType::SEARCH_INDEX;
    }
    return E_OK;
}

void ForegroundAnalysisMeta::StartAnalysisService()
{
    if (opType_ == ForegroundAnalysisOpType::FOREGROUND_NOT_HANDLE) {
        return;
    }
    std::thread([taskId = taskId_, opType = opType_, fileIds = fileIds_]()-> void {
        MEDIA_INFO_LOG("prepare submit taskId:%{public}d, opType:%{public}d, size:%{public}u", taskId, opType,
            fileIds.size());
        if (opType & ForegroundAnalysisOpType::OCR_AND_LABEL) {
            MediaAnalysisHelper::StartForegroundAnalysisServiceSync(
                IMediaAnalysisService::ActivateServiceType::START_FOREGROUND_OCR, fileIds, taskId);
        }
        if (opType & ForegroundAnalysisOpType::SEARCH_INDEX) {
            const std::vector<std::string> tmp;
            MediaAnalysisHelper::StartForegroundAnalysisServiceSync(
                IMediaAnalysisService::ActivateServiceType::START_FOREGROUND_INDEX, tmp, taskId);
        }
    }).detach();
}

int32_t ForegroundAnalysisMeta::QueryPendingAnalyzeFileIds(MediaLibraryCommand &cmd, std::vector<std::string> &fileIds)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("db is null");
        return E_ERR;
    }
    std::string onClause = VISION_TOTAL_TABLE + "." + MediaColumn::MEDIA_ID + " = " + PhotoColumn::PHOTOS_TABLE + "." +
        MediaColumn::MEDIA_ID;
    std::string colmun = VISION_TOTAL_TABLE + "." + MediaColumn::MEDIA_ID;
    std::string whereClause = cmd.GetAbsRdbPredicates()->GetWhereClause();
    ValueObject valueObject;
    int32_t analysisType = AnalysisType::ANALYSIS_SEARCH_INDEX;
    if (cmd.GetValueBucket().GetObject(FOREGROUND_ANALYSIS_TYPE, valueObject)) {
        valueObject.GetInt(analysisType);
    }
    AppendAnalysisTypeOnWhereClause(analysisType, whereClause);
    std::string orderBy = " ORDER BY " + PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_DATE_MODIFIED;
    std::string limit = " LIMIT " + std::to_string(std::max(0, FRONT_CV_MAX_LIMIT - frontCvCount_));
    std::string sql = "SELECT " + colmun + " FROM " + VISION_TOTAL_TABLE + " INNER JOIN " + PhotoColumn::PHOTOS_TABLE +
        " ON " + onClause + " WHERE " + whereClause + orderBy + limit;
    auto result = rdbStore->QuerySql(sql, cmd.GetAbsRdbPredicates()->GetWhereArgs());
    if (result == nullptr) {
        MEDIA_ERR_LOG("query err");
        return E_ERR;
    }
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int fileId;
        int colIndex = 0;
        result->GetColumnIndex(MediaColumn::MEDIA_ID, colIndex);
        result->GetInt(colIndex, fileId);
        fileIds.push_back(std::to_string(fileId));
    }
    result->Close();
    if (fileIds.empty()) {
        MEDIA_INFO_LOG("no fileId match");
    } else {
        MEDIA_INFO_LOG("cv match cnt:%{public}u", fileIds.size());
    }
    return E_OK;
}

void ForegroundAnalysisMeta::AppendAnalysisTypeOnWhereClause(int32_t type, std::string &whereClause)
{
    if (!whereClause.empty()) {
        whereClause.append(" AND ");
    }
    static const std::map<int32_t, std::string> FRONT_ANALYSIS_WHERE_CLAUSE_MAP = {
        { ANALYSIS_SEARCH_INDEX, VISION_TOTAL_TABLE + "." + STATUS + " = 0" + " AND (" + VISION_TOTAL_TABLE + "." +
            OCR + " = 0 OR " + VISION_TOTAL_TABLE + "." + LABEL + " = 0)" },
    };
    std::string analysisTypeClause;
    auto it = FRONT_ANALYSIS_WHERE_CLAUSE_MAP.find(type);
    if (it != FRONT_ANALYSIS_WHERE_CLAUSE_MAP.end()) {
        analysisTypeClause = it->second;
    }
    if (analysisTypeClause.empty()) {
        whereClause.append(" 1 = 1 ");
    } else {
        whereClause.append(" (" + analysisTypeClause + ") ");
    }
}

int32_t ForegroundAnalysisMeta::QueryPendingIndexCount(MediaLibraryCommand &cmd, int32_t &count)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_ERR;
    }
    std::string onClause = SEARCH_TOTAL_TABLE + "." + MediaColumn::MEDIA_ID + " = " + PhotoColumn::PHOTOS_TABLE + "." +
        MediaColumn::MEDIA_ID;
    std::string colmun = "COUNT(1)";
    std::string whereClause = SEARCH_TOTAL_TABLE + "." + TBL_SEARCH_PHOTO_STATUS + " in (-1, 0)";
    std::string sql = "SELECT " + colmun + " FROM " + SEARCH_TOTAL_TABLE + " INNER JOIN " + PhotoColumn::PHOTOS_TABLE +
        " ON " + onClause + " WHERE " + whereClause;
    auto result = rdbStore->QuerySql(sql);
    if (result == nullptr) {
        MEDIA_ERR_LOG("query err");
        return E_ERR;
    }
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int colIndex = 0;
        result->GetInt(colIndex, count);
    }
    MEDIA_INFO_LOG("index match cnt:%{public}d", count);
    result->Close();
    return E_OK;
}

int32_t ForegroundAnalysisMeta::GetCurTaskId(MediaLibraryCommand &cmd)
{
    int32_t curTaskId = -1;
    ValueObject valueObject;
    if (cmd.GetValueBucket().GetObject(FOREGROUND_ANALYSIS_TASK_ID, valueObject)) {
        valueObject.GetInt(curTaskId);
    }
    return curTaskId;
}
}
}