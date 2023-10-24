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
static constexpr char MEDIA_LIBRARY[] = "";

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

void PostEventUtils::PostErrorProcess(const uint32_t &errType, const VariantMap &error)
{
    switch (errType) {
        case ErrType::FILE_OPT_ERR:
        case ErrType::DB_OPT_ERR:
        case ErrType::DB_UPGRADE_ERR:
            break;
        default:
            PostFileOptError(error);
            PostDbOptError(error);
            PostDbUpgradeError(error);
            break;
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
