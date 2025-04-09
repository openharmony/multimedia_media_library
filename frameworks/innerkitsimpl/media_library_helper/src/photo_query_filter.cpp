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

#include "photo_query_filter.h"

#include "base_column.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace std;

std::string PhotoQueryFilter::GetSqlWhereClause(const PhotoQueryFilter::Option option)
{
    PhotoQueryFilter::Config config {};
    switch (option) {
        case PhotoQueryFilter::Option::FILTER_VISIBLE:
            return GetSqlWhereClause(config);
            break;
        case PhotoQueryFilter::Option::FILTER_HIDDEN:
            config.hiddenConfig = PhotoQueryFilter::ConfigType::INCLUDE;
            return GetSqlWhereClause(config);
            break;
        case PhotoQueryFilter::Option::FILTER_TRASHED:
            config.trashedConfig = PhotoQueryFilter::ConfigType::INCLUDE;
            return GetSqlWhereClause(config);
            break;
        default:
            MEDIA_ERR_LOG("Invalid option: %{public}d", static_cast<int>(option));
            return "";
            break;
    }
}

std::string PhotoQueryFilter::GetSqlWhereClause(const PhotoQueryFilter::Config& config)
{
    string whereClause = "";
    if (config.syncStatusConfig != ConfigType::IGNORE) {
        whereClause += "sync_status = " + string(config.syncStatusConfig == ConfigType::INCLUDE ? "1" : "0");
    }
    if (config.cleanFlagConfig != ConfigType::IGNORE) {
        whereClause += " AND clean_flag = " + string(config.cleanFlagConfig == ConfigType::INCLUDE ? "1" : "0");
    }
    if (config.pendingConfig != ConfigType::IGNORE) {
        if (config.pendingConfig == ConfigType::INCLUDE) {
            whereClause += " AND time_pending > 0";
        } else {
            whereClause += " AND time_pending = 0";
        }
    }
    if (config.tempConfig != ConfigType::IGNORE) {
        whereClause += " AND is_temp = " + string(config.tempConfig == ConfigType::INCLUDE ? "1" : "0");
    }
    if (config.hiddenConfig != ConfigType::IGNORE) {
        whereClause += " AND hidden = " + string(config.hiddenConfig == ConfigType::INCLUDE ? "1" : "0");
    }
    if (config.trashedConfig != ConfigType::IGNORE) {
        if (config.trashedConfig == ConfigType::INCLUDE) {
            whereClause += " AND date_trashed > 0";
        } else {
            whereClause += " AND date_trashed = 0";
        }
    }
    if (config.burstCoverOnly != ConfigType::IGNORE) {
        whereClause += " AND burst_cover_level = " +
            string(config.burstCoverOnly == ConfigType::INCLUDE ? "1" : "0");
    }

    return whereClause;
}

void PhotoQueryFilter::ModifyPredicate(const PhotoQueryFilter::Option option, NativeRdb::RdbPredicates& predicate)
{
    PhotoQueryFilter::Config config {};
    switch (option) {
        case PhotoQueryFilter::Option::FILTER_VISIBLE:
            ModifyPredicate(config, predicate);
            break;
        case PhotoQueryFilter::Option::FILTER_HIDDEN:
            config.hiddenConfig = PhotoQueryFilter::ConfigType::INCLUDE;
            ModifyPredicate(config, predicate);
            break;
        case PhotoQueryFilter::Option::FILTER_TRASHED:
            config.trashedConfig = PhotoQueryFilter::ConfigType::INCLUDE;
            ModifyPredicate(config, predicate);
            break;
        default:
            MEDIA_ERR_LOG("Invalid option: %{public}d", static_cast<int>(option));
            break;
    }
}

void PhotoQueryFilter::ModifyPredicate(const PhotoQueryFilter::Config& config, NativeRdb::RdbPredicates& predicates)
{
    if (config.syncStatusConfig != ConfigType::IGNORE) {
        predicates.EqualTo("sync_status", config.syncStatusConfig == ConfigType::INCLUDE ? 1 : 0);
    }
    if (config.cleanFlagConfig != ConfigType::IGNORE) {
        predicates.EqualTo("clean_flag", config.cleanFlagConfig == ConfigType::INCLUDE ? 1 : 0);
    }
    if (config.pendingConfig != ConfigType::IGNORE) {
        if (config.pendingConfig == ConfigType::INCLUDE) {
            predicates.GreaterThan("time_pending", 0);
        } else {
            predicates.EqualTo("time_pending", 0);
        }
    }
    if (config.tempConfig != ConfigType::IGNORE) {
        predicates.EqualTo("is_temp", config.tempConfig == ConfigType::INCLUDE ? 1 : 0);
    }
    if (config.hiddenConfig != ConfigType::IGNORE) {
        predicates.EqualTo("hidden", config.hiddenConfig == ConfigType::INCLUDE ? 1 : 0);
    }
    if (config.trashedConfig != ConfigType::IGNORE) {
        if (config.trashedConfig == ConfigType::INCLUDE) {
            predicates.GreaterThan("date_trashed", 0);
        } else {
            predicates.EqualTo("date_trashed", 0);
        }
    }
    if (config.burstCoverOnly != ConfigType::IGNORE) {
        predicates.EqualTo("burst_cover_level", config.burstCoverOnly == ConfigType::INCLUDE ? 1 : 0);
    }
}
}  // namespace Media
}  // namespace OHOS