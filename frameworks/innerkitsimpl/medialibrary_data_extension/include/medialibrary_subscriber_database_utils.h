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


#ifndef MEDIALIBRARY_SUBSCRIBER_DATABASE_UTILS_H
#define MEDIALIBRARY_SUBSCRIBER_DATABASE_UTILS_H

#include <string>
#include <vector>

#include "rdb_helper.h"
#include "result_set.h"
#include "rdb_predicates.h"
#include "thumbnail_const.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MedialibrarySubscriberDatabaseUtils {
public:
    EXPORT static int32_t QueryThumbAstc(int32_t& thunmbAstcCount);
    EXPORT static int32_t QueryThumbTotal(int32_t& thunmbTotalCount);
private:
    static int32_t QueryInt(const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> &columns,
        const std::string &queryColumn, int32_t &value);
};
} // namespace Media
} // namespace OHOS

#endif  // MEDIALIBRARY_SUBSCRIBER_DATABASE_UTILS_H
