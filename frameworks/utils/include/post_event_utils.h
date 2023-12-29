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
#ifndef POST_EVENT_UTILS_H
#define POST_EVENT_UTILS_H
#include <map>
#include <string>
#include <variant>

#include "singleton.h"
namespace OHOS {
namespace Media {
#define COMPILE_HIDDEN __attribute__ ((visibility ("hidden")))
const std::string KEY_OPT_TYPE = "optType";

const std::string KEY_ERR_FILE = "errFile";
const std::string KEY_ERR_LINE = "errLine";
const std::string KEY_ERR_CODE = "errCode";
const std::string KEY_OPT_FILE = "optFile";

const std::string KEY_GNUMS = "gnums";
const std::string KEY_ANUMS = "anums";

const std::string KEY_PRE_VERSION = "preVersion";
const std::string KEY_AFTER_VERSION = "afterVersion";

const std::string KEY_COUNT = "count";

const std::string KEY_TIME_INTERVAL = "TIME_INTERVAL";

const std::string KEY_CALLING_PACKAGE = "CALLING_PACKAGE";
const std::string KEY_HIGH_QUALITY_COUNT = "HIGH_QUALITY_COUNT";
const std::string KEY_BALANCE_QUALITY_COUNT = "BALANCE_QUALITY_COUNT";
const std::string KEY_EMERGENCY_QUALITY_COUNT = "EMERGENCY_QUALITY_COUNT";

const std::string KEY_THIRD_PART_COUNT = "THIRD_PART_COUNT";
const std::string KEY_AUTO_COUNT = "AUTO_COUNT";

const std::string KEY_PHOTO_ID = "PHOTO_ID";
const std::string KEY_TOTAL_TIME_COST = "TOTAL_TIME_COST";

const std::string KEY_RESULT = "RESULT";

enum OptType {
    CREATE = 0,
    THUMB,
    SCAN,
    QUERY,
};

enum ErrType {
    DEFAULT_ERR = 0,
    FILE_OPT_ERR,
    DB_OPT_ERR,
    DB_UPGRADE_ERR,
};

enum StatType {
    DEFAULT_STAT = 0,
    THUMBNAIL_STAT,
    DB_UPGRADE_STAT,
    SYNC_STAT,
    AGING_STAT,
    MSC_FIRST_VISIT_STAT,
    MSC_REQUEST_POLICY_STAT,
    MSC_TRIGGER_RATIO_STAT,
    MSC_TOTAL_TIME_COST_STAT,
    MSC_RESULT_STAT,
};
using VariantMap = std::map<std::string, std::variant<int32_t, int64_t, std::string>>;

class PostEventUtils : public Singleton<PostEventUtils> {
public:
    void PostErrorProcess(const uint32_t &errType, const VariantMap &error);
    void PostStatProcess(const uint32_t &statType, const VariantMap &stat);

private:
    COMPILE_HIDDEN std::string GetOptType(const uint32_t &optType);
    COMPILE_HIDDEN void PostFileOptError(const VariantMap &errMap);
    COMPILE_HIDDEN void PostDbOptError(const VariantMap &errMap);
    COMPILE_HIDDEN void PostDbUpgradeError(const VariantMap &errMap);
    COMPILE_HIDDEN void PostThumbnailStat(const VariantMap &stat);
    COMPILE_HIDDEN void PostDbUpgradeStat(const VariantMap &stat);
    COMPILE_HIDDEN void PostSyncStat();
    COMPILE_HIDDEN void PostAgingStat(const VariantMap &stat);
    COMPILE_HIDDEN void PostMscFirstVisitStat(const VariantMap &stat);
    COMPILE_HIDDEN void PostMscRequestPolicyStat(const VariantMap &stat);
    COMPILE_HIDDEN void PostMscTriggerRatioStat(const VariantMap &stat);
    COMPILE_HIDDEN void PostMscTotalTimeCostStat(const VariantMap &stat);
    COMPILE_HIDDEN void PostMscResultStat(const VariantMap &stat);
    
    COMPILE_HIDDEN int GetIntValue(const std::string &key, const VariantMap &map);
    COMPILE_HIDDEN int64_t GetInt64Value(const std::string &key, const VariantMap &map);
    COMPILE_HIDDEN std::string GetStringValue(const std::string &key, const VariantMap &map);

    COMPILE_HIDDEN uint32_t thumbnailTimes_ = 0;
    COMPILE_HIDDEN uint32_t dbUpgradeTimes_ = 0;
    COMPILE_HIDDEN uint32_t syncTimes_ = 0;
    COMPILE_HIDDEN uint32_t recycleTimes_ = 0;
};
} // namespace Media
} // namespace OHOS
#endif