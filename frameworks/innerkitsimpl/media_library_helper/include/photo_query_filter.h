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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_HELPER_INCLUDE_PHOTO_QUERY_FILTER_H
#define FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_HELPER_INCLUDE_PHOTO_QUERY_FILTER_H

#include <string>

#include "rdb_predicates.h"

namespace OHOS::Media {

class PhotoQueryFilter {
public:
    enum class Option {
        CUSTOM_FILTER,
        FILTER_VISIBLE,
        FILTER_HIDDEN,
        FILTER_TRASHED,
    };

    enum class ConfigType {
        INCLUDE,
        EXCLUDE,
        IGNORE,
    };

    struct Config {
        ConfigType hiddenConfig = ConfigType::EXCLUDE;
        ConfigType trashedConfig = ConfigType::EXCLUDE;
        ConfigType tempConfig = ConfigType::EXCLUDE;
        ConfigType pendingConfig = ConfigType::EXCLUDE;
        ConfigType burstCoverOnly = ConfigType::INCLUDE;
        ConfigType syncStatusConfig = ConfigType::EXCLUDE;
        ConfigType cleanFlagConfig = ConfigType::EXCLUDE;
    };

    static std::string GetSqlWhereClause(const PhotoQueryFilter::Option option);
    static std::string GetSqlWhereClause(const PhotoQueryFilter::Config& config);

    template <class T>
    static void ModifyPredicate(const PhotoQueryFilter::Option option, T& predicate);

    template <class T>
    static void ModifyPredicate(const PhotoQueryFilter::Config& config, T& predicate);
};

}  // namespace Media
#endif // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_HELPER_INCLUDE_PHOTO_QUERY_FILTER_H