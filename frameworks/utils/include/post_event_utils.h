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
};
using VariantMap = std::map<std::string, std::variant<int32_t, std::string>>;

class PostEventUtils : public Singleton<PostEventUtils> {
public:
    void PostErrorProcess(const uint32_t &errType, const VariantMap &error);
    void PostStatProcess(const uint32_t &statType, const VariantMap &stat);

private:
    std::string GetOptType(const uint32_t &optType);
    void PostFileOptError(const VariantMap &errMap);
    void PostDbOptError(const VariantMap &errMap);
    void PostDbUpgradeError(const VariantMap &errMap);
    void PostThumbnailStat(const VariantMap &stat);
    void PostDbUpgradeStat(const VariantMap &stat);
    void PostSyncStat();
    void PostAgingStat(const VariantMap &stat);
    
    int GetIntValue(const std::string &key, const VariantMap &map);
    std::string GetStringValue(const std::string &key, const VariantMap &map);

    uint32_t thumbnailTimes_ = 0;
    uint32_t dbUpgradeTimes_ = 0;
    uint32_t syncTimes_ = 0;
    uint32_t recycleTimes_ = 0;
};
} // namespace Media
} // namespace OHOS
#endif