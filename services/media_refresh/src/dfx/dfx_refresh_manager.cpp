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

#define MLOG_TAG "AccurateRefresh::DfxRefreshManager"

#include "dfx_refresh_manager.h"
#include "dfx_reporter.h"
#include "dfx_manager.h"
#include "photo_album_column.h"
#include "accurate_common_data.h"
#include "media_log.h"
#include <unordered_map>
#include <string>
#include <nlohmann/json.hpp>
#include "media_file_utils.h"
#include "parameter.h"
#include "parameters.h"

using namespace std;
using json = nlohmann::json;

namespace OHOS {
namespace Media::AccurateRefresh {

static const std::string KEY_HIVIEW_VERSION_TYPE = "const.logsystem.versiontype";

DfxRefreshManager::DfxRefreshManager(const std::string &targetBusiness): targetBusiness_(targetBusiness) {}


void DfxRefreshManager::SetOperationTotalTime(const std::string &tableName)
{
    int32_t currentOperationTime = MediaFileUtils::UTCTimeMilliSeconds() - OperationStartTime_;
    if (tableName == PhotoAlbumColumns::TABLE) {
        albumOperationTotalTime_ += currentOperationTime;
    } else {
        photoOperationTotalTime_ += currentOperationTime;
    }
}

void DfxRefreshManager::SetOperationStartTime()
{
    int64_t timestamp = MediaFileUtils::UTCTimeMilliSeconds();
    OperationStartTime_ = timestamp;
}

void DfxRefreshManager::SetOptEndTimeAndSql(std::string tableName)
{
    SetOperationTotalTime(tableName);
}

void DfxRefreshManager::SetOptEndTimeAndSql(MediaLibraryCommand &cmd)
{
    SetOperationTotalTime(cmd.GetTableName());
}

void DfxRefreshManager::SetOptEndTimeAndSql(
    const NativeRdb::AbsRdbPredicates &predicates)
{
    SetOperationTotalTime(predicates.GetTableName());
}

void DfxRefreshManager::SetAlbumIdAndOptTime(int32_t albumId, bool isHidden)
{
    int32_t currentOperationTime = MediaFileUtils::UTCTimeMilliSeconds() - OperationStartTime_;
    albumOperationTotalTime_ += currentOperationTime;
    if (isHidden) {
        if (albumHiddenInfoOperationTime_.size() <= MAX_ALBUM_OPERATION_SIZE) {
            albumHiddenInfoOperationTime_[albumId] = currentOperationTime;
        }
    } else {
        if (albumOperationTime_.size() <= MAX_ALBUM_OPERATION_SIZE) {
            albumOperationTime_[albumId] = currentOperationTime;
        }
    }
    if (albumIds_.size() <= MAX_ALBUM_ID_SIZE) {
        albumIds_.insert(albumId);
    }
}

void DfxRefreshManager::SetEndTotalTime()
{
    totalCostTime_ = endTime_ - startTime_;
    if (totalCostTime_ > MAX_COST_TIME_REPORT) {
        isReport_ = true;
    }
    if (totalCostTime_ > MAX_COST_TIME_PRINT_LOG && totalCostTime_ < MAX_COST_TIME_REPORT) {
        isPrintLog_ = true;
    }
}

std::string DfxRefreshManager::MapToJson(const std::unordered_map<int32_t, int32_t>& map)
{
    json j;
    for (const auto& pair : map) {
        j[std::to_string(pair.first)] = pair.second;
    }
    return j.dump();
}

std::string VectorToString(const std::vector<int32_t>& vec, const std::string& sep = ", ")
{
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < vec.size(); ++i) {
        ss << vec[i];
        if (i != vec.size() - 1) ss << sep;
    }
    ss << "]";
    return ss.str();
}

std::string DataPointToString(const AccurateRefreshDfxDataPoint& data)
{
    std::stringstream ss;
    ss << "AccurateRefreshDfxDataPoint {" << std::endl;
    ss << "  targetBusiness: \"" << data.targetBusiness << "\"," << std::endl;
    ss << "  sqlStr: \"" << data.sqlStr << "\"," << std::endl;
    ss << "  totalCostTime: " << data.totalCostTime << "," << std::endl;
    ss << "  standardCostTime: " << data.standardCostTime << "," << std::endl;
    ss << "  photoOperationTotalTime: " << data.photoOperationTotalTime << "," << std::endl;
    ss << "  albumOperationTotalTime: " << data.albumOperationTotalTime << "," << std::endl;
    ss << "  albumId: " << VectorToString(data.albumId) << "," << std::endl;
    ss << "  albumOperationTime: \"" << data.albumOperationTime << "\"," << std::endl;
    ss << "  albumHiddenInfoOperationTime: \"" << data.albumHiddenInfoOperationTime << "\"" << std::endl;
    ss << "}";
    return ss.str();
}

void DfxRefreshManager::SetStartTime()
{
    startTime_ = MediaFileUtils::UTCTimeMilliSeconds();
}

void DfxRefreshManager::SetAlbumId(int32_t albumId)
{
    if (albumIds_.size() <= MAX_ALBUM_ID_SIZE) {
        albumIds_.insert(albumId);
    }
}

void DfxRefreshManager::SetAlbumId(std::vector<int> albumIds)
{
    size_t remainingSpace = MAX_ALBUM_ID_SIZE - albumIds_.size();
    if (remainingSpace > 0) {
    // 只插入前 remainingSpace 个元素
    auto endIt = albumIds.begin() + std::min(remainingSpace, albumIds.size());
    albumIds_.insert(albumIds.begin(), endIt);
}
}

void DfxRefreshManager::SetEndTime()
{
    endTime_ = MediaFileUtils::UTCTimeMilliSeconds();
}

static bool IsBetaVersion()
{
    static const string versionType = system::GetParameter(KEY_HIVIEW_VERSION_TYPE, "unknown");
    static bool isBetaVersion = versionType.find("beta") != std::string::npos;
    return isBetaVersion;
}

void DfxRefreshManager::DfxRefreshReport()
{
    SetEndTotalTime();
    MEDIA_INFO_LOG("enter DfxRefreshReport totalCostTime_:%{public}d", static_cast<int>(totalCostTime_));
    AccurateRefreshDfxDataPoint reportData;
    auto albumOperationTime = albumOperationTime_;
    auto albumHiddenInfoOperationTime = albumHiddenInfoOperationTime_;
    reportData.totalCostTime = totalCostTime_;
    reportData.targetBusiness = targetBusiness_;
    reportData.standardCostTime = MAX_COST_TIME_REPORT;
    reportData.albumId = {albumIds_.begin(), albumIds_.end()};
    reportData.photoOperationTotalTime = photoOperationTotalTime_;
    reportData.albumOperationTotalTime = albumOperationTotalTime_;
    reportData.albumOperationTime = MapToJson(albumOperationTime);
    reportData.albumHiddenInfoOperationTime = MapToJson(albumHiddenInfoOperationTime);
    if (isReport_) {
        DfxManager::GetInstance()->HandleAccurateRefreshTimeOut(reportData);
    }
    if (isPrintLog_) {
        MEDIA_INFO_LOG("AccurateRefreshDfxDataPoint:%{public}s", DataPointToString(reportData).c_str());
    }
}

void DfxRefreshManager::QueryStatementReport(
    const std::string &targetBusiness, int32_t totalCostTime, const std::string &sqlStr)
{
    if (totalCostTime < MAX_COST_TIME_PRINT_LOG) {
        return;
    }
    AccurateRefreshDfxDataPoint reportData;
    reportData.totalCostTime = totalCostTime;
    reportData.targetBusiness = targetBusiness;
    reportData.standardCostTime = MAX_COST_TIME_REPORT;
    if (IsBetaVersion()) {
        if (sqlStr.size() > MAX_SQLSTR_SIZE) {
            reportData.sqlStr = sqlStr.substr(0, MAX_SQLSTR_SIZE);
        } else {
            reportData.sqlStr = sqlStr;
        }
    }
    if (totalCostTime > MAX_COST_TIME_PRINT_LOG && totalCostTime < MAX_COST_TIME_REPORT) {
        MEDIA_INFO_LOG("AccurateRefreshDfxDataPoint:%{public}s", DataPointToString(reportData).c_str());
        return;
    }
    DfxManager::GetInstance()->HandleAccurateRefreshTimeOut(reportData);
}

}  // namespace Media::AccurateRefresh
}  // namespace OHOS