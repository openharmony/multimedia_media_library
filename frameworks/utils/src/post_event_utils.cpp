/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "post_event_utils.h"

#include <unistd.h>

#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "media_log.h"
namespace OHOS {
namespace Media {
using namespace std;

const string OPT_CREATE = "CREATE";
const string OPT_THUMB = "THUMB";
const string OPT_SCAN = "SCAN";
const string OPT_QUERY = "QUERY";
static constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";

string PostEventUtils::GetOptType(const uint32_t &optType)
{
    string type = "";
    switch (optType) {
        case OptType::CREATE:
            type = OPT_CREATE;
            break;
        case OptType::THUMB:
            type = OPT_THUMB;
            break;
        case OptType::SCAN:
            type = OPT_SCAN;
            break;
        case OptType::QUERY:
            type = OPT_QUERY;
            break;
        default:
            break;
    }
    return type;
}

int32_t PostEventUtils::GetIntValue(const string &key, const VariantMap &map)
{
    int value = 0;
    auto iter = map.find(key);
    if (iter != map.end()) {
        if (holds_alternative<int32_t>(iter->second)) {
            return get<int32_t>(iter->second);
        }
    }
    return value;
}

int64_t PostEventUtils::GetInt64Value(const string &key, const VariantMap &map)
{
    int64_t value = 0;
    auto iter = map.find(key);
    if (iter != map.end()) {
        if (holds_alternative<int64_t>(iter->second)) {
            return get<int64_t>(iter->second);
        }
    }
    return value;
}

string PostEventUtils::GetStringValue(const string &key, const VariantMap &map)
{
    string value;
    auto iter = map.find(key);
    if (iter != map.end()) {
        if (holds_alternative<string>(iter->second)) {
            return get<string>(iter->second);
        }
    }
    return value;
}

void PostEventUtils::PostFileOptError(const VariantMap &error)
{
    uint32_t uid = getuid();
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_FILE_OPT_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "UID", uid,
        "ERR_FILE", GetStringValue(KEY_ERR_FILE, error),
        "LINE", GetIntValue(KEY_ERR_LINE, error),
        "ERROR_CODE", GetIntValue(KEY_ERR_CODE, error),
        "FILE", GetStringValue(KEY_OPT_FILE, error),
        "TYPE", GetOptType(GetIntValue(KEY_OPT_TYPE, error)),
        "CALLING_ID", IPCSkeleton::GetCallingUid());
    if (ret != 0) {
        MEDIA_ERR_LOG("PostFileOptError error:%{public}d", ret);
    }
}

void PostEventUtils::PostRecoveryOptError(const VariantMap &error)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_META_RECOVERY_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "ERR_FILE", GetStringValue(KEY_ERR_FILE, error),
        "LINE", GetIntValue(KEY_ERR_LINE, error),
        "ERROR_CODE", GetIntValue(KEY_ERR_CODE, error),
        "TYPE", GetOptType(GetIntValue(KEY_OPT_TYPE, error)));
    if (ret != 0) {
        MEDIA_ERR_LOG("PostFileOptError error:%{public}d", ret);
    }
}

void PostEventUtils::PostDbOptError(const VariantMap &error)
{
    uint32_t uid = getuid();
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DB_OPT_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "UID", uid,
        "ERR_FILE", GetStringValue(KEY_ERR_FILE, error),
        "LINE", GetIntValue(KEY_ERR_LINE, error),
        "ERROR_CODE", GetIntValue(KEY_ERR_CODE, error),
        "TYPE", GetOptType(GetIntValue(KEY_OPT_TYPE, error)),
        "CALLING_ID", IPCSkeleton::GetCallingUid());
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to PostDbOptError error:%{public}d", ret);
    }
}

void PostEventUtils::PostDbUpgradeError(const VariantMap &error)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DB_UPGRADE_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "ERR_FILE", GetStringValue(KEY_ERR_FILE, error),
        "LINE", GetIntValue(KEY_ERR_LINE, error));
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to PostDbUpgradeError err:%{public}d", ret);
    }
}

void PostEventUtils::PostThumbnailStat(const VariantMap &stat)
{
    uint32_t uid = getuid();
    thumbnailTimes_++;
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_THUMBNAIL_STAT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "UID", uid,
        "TIMES", thumbnailTimes_,
        "GNUMS", GetIntValue(KEY_GNUMS, stat),
        "ANUMS", GetIntValue(KEY_ANUMS, stat));
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to PostThumbnailStat error:%{public}d ", ret);
    }
}

void PostEventUtils::PostDbUpgradeStat(const VariantMap &stat)
{
    int32_t preVersion = GetIntValue(KEY_PRE_VERSION, stat);
    int32_t afterVersion = GetIntValue(KEY_AFTER_VERSION, stat);
    dbUpgradeTimes_++;
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DB_UPGRADE_STAT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PRE_VERSION", preVersion,
        "AFTER_VERSION", afterVersion,
        "COUNT", dbUpgradeTimes_);
    if (ret != 0) {
        MEDIA_ERR_LOG("PostDbUpgradeStat preVersion:%{public}d afterVersion:%{public}d error:%{public}d",
            preVersion, afterVersion, ret);
    }
}

void PostEventUtils::PostSyncStat()
{
    syncTimes_++;
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_SYNC_STAT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "TIMES", syncTimes_);
    if (ret != 0) {
        MEDIA_ERR_LOG("PostSyncStat ret:%{public}d", ret);
    }
}

void PostEventUtils::PostAgingStat(const VariantMap &stat)
{
    recycleTimes_++;
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_AGING_STAT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "TIMES", recycleTimes_,
        "COUNT", GetIntValue(KEY_COUNT, stat));
    if (ret != 0) {
        MEDIA_ERR_LOG("PostAgingStat error:%{public}d", ret);
    }
}

void PostEventUtils::PostMscFirstVisitStat(const VariantMap &stat)
{
    string photoId = GetStringValue(KEY_PHOTO_ID, stat);
    int64_t timeInterval = GetInt64Value(KEY_TIME_INTERVAL, stat);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_MSC_FIRST_VISIT_STAT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        KEY_PHOTO_ID, photoId,
        KEY_TIME_INTERVAL, timeInterval);
    if (ret != 0) {
        MEDIA_ERR_LOG("PostMscFirstVisitStat error:%{public}d", ret);
    }
}

void PostEventUtils::PostMscRequestPolicyStat(const VariantMap &stat)
{
    string callingPackage = GetStringValue(KEY_CALLING_PACKAGE, stat);
    int32_t highQualityCount = GetIntValue(KEY_HIGH_QUALITY_COUNT, stat);
    int32_t balanceQualityCount = GetIntValue(KEY_BALANCE_QUALITY_COUNT, stat);
    int32_t emergencyQualityCount = GetIntValue(KEY_EMERGENCY_QUALITY_COUNT, stat);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_MSC_REQUST_POLICY_STAT",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        KEY_CALLING_PACKAGE, callingPackage,
        KEY_HIGH_QUALITY_COUNT, highQualityCount,
        KEY_BALANCE_QUALITY_COUNT, balanceQualityCount,
        KEY_EMERGENCY_QUALITY_COUNT, emergencyQualityCount);
    if (ret != 0) {
        MEDIA_ERR_LOG("PostMscRequestPolicyStat error:%{public}d", ret);
    }
}

void PostEventUtils::PostMscTriggerRatioStat(const VariantMap &stat)
{
    int32_t thirdPartCount = GetIntValue(KEY_THIRD_PART_COUNT, stat);
    int32_t autoCount = GetIntValue(KEY_AUTO_COUNT, stat);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_MSC_TRIGGER_RATIO_STAT",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        KEY_THIRD_PART_COUNT, thirdPartCount,
        KEY_AUTO_COUNT, autoCount);
    if (ret != 0) {
        MEDIA_ERR_LOG("PostMscTriggerRatioStat error:%{public}d", ret);
    }
}

void PostEventUtils::PostMscTotalTimeCostStat(const VariantMap &stat)
{
    string photoId = GetStringValue(KEY_PHOTO_ID, stat);
    int64_t totalTimeCost = GetInt64Value(KEY_TOTAL_TIME_COST, stat);
    int32_t mediaType = GetIntValue(KEY_MEDIA_TYPE, stat);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_MSC_TOTAL_TIME_STAT",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        KEY_PHOTO_ID, photoId,
        KEY_TOTAL_TIME_COST, totalTimeCost,
        KEY_MEDIA_TYPE, mediaType);
    if (ret != 0) {
        MEDIA_ERR_LOG("PostMscTotalTimeCostStat error:%{public}d", ret);
    }
}

void PostEventUtils::PostMscResultStat(const VariantMap &stat)
{
    string photoId = GetStringValue(KEY_PHOTO_ID, stat);
    int32_t result = GetIntValue(KEY_RESULT, stat);
    int32_t mediaType = GetIntValue(KEY_MEDIA_TYPE, stat);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_MSC_RESULT_STAT",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        KEY_PHOTO_ID, photoId,
        KEY_RESULT, result,
        KEY_MEDIA_TYPE, mediaType);
    if (ret != 0) {
        MEDIA_ERR_LOG("PostMscResultStat error:%{public}d", ret);
    }
}

void PostEventUtils::PostDatabaseCorruption(const VariantMap &errMap)
{
    string date = GetStringValue(KEY_DB_CORRUPT, errMap);
    MEDIA_ERR_LOG("ReportDatabaseCorruption periodTime:%{public}s", date.c_str());
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "DATABASE_CORRUPTION_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "DATE", date);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportDatabaseCorruption error:%{public}d", ret);
    }
}

void PostEventUtils::PostErrorProcess(const uint32_t &errType, const VariantMap &error)
{
    switch (errType) {
        case ErrType::FILE_OPT_ERR:
        case ErrType::DB_OPT_ERR:
        case ErrType::DB_UPGRADE_ERR:
            break;
        case ErrType::DB_CORRUPT_ERR:
            PostDatabaseCorruption(error);
            break;
        case ErrType::RECOVERY_ERR:
            PostRecoveryOptError(error);
            break;
        default:
            PostFileOptError(error);
            PostDbOptError(error);
            PostDbUpgradeError(error);
            break;
    }
}

void PostEventUtils::PostCloudEnhanceStat(const VariantMap &stat)
{
    std::string photoId = GetStringValue(KEY_PHOTO_ID, stat);
    std::string completeType = GetStringValue(KEY_CLOUD_ENHANCEMENT_COMPLETE_TYPE, stat);
    int64_t totalTimeCost = GetInt64Value(KEY_TOTAL_TIME_COST, stat);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_CLOUDENHANCEMENT_STAT",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        KEY_PHOTO_ID, photoId,
        KEY_TOTAL_TIME_COST, totalTimeCost,
        KEY_CLOUD_ENHANCEMENT_COMPLETE_TYPE, completeType);
    if (ret != 0) {
        MEDIA_ERR_LOG("PostCloudEnhanceStat:%{public}d", ret);
    }
}

void PostEventUtils::PostStatProcess(const uint32_t &statType, const VariantMap &stat)
{
    switch (statType) {
        case StatType::THUMBNAIL_STAT:
        case StatType::DB_UPGRADE_STAT:
        case StatType::SYNC_STAT:
        case StatType::AGING_STAT:
            break;
        case StatType::MSC_FIRST_VISIT_STAT:
            PostMscFirstVisitStat(stat);
            break;
        case StatType::MSC_REQUEST_POLICY_STAT:
            PostMscRequestPolicyStat(stat);
            break;
        case StatType::MSC_TRIGGER_RATIO_STAT:
            PostMscTriggerRatioStat(stat);
            break;
        case StatType::MSC_TOTAL_TIME_COST_STAT:
            PostMscTotalTimeCostStat(stat);
            break;
        case StatType::MSC_RESULT_STAT:
            PostMscResultStat(stat);
            break;
        case StatType::CLOUD_ENHANCEMENT_GET_COUNT_STAT:
            PostCloudEnhanceStat(stat);
            break;
        default:
            PostThumbnailStat(stat);
            PostDbUpgradeStat(stat);
            PostSyncStat();
            PostAgingStat(stat);
            break;
    }
}
}  // namespace Media
}  // namespace OHOS
