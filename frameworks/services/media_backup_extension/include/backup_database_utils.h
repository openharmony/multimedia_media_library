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

#ifndef BACKUP_DATABASE_UTILS_H
#define BACKUP_DATABASE_UTILS_H

#include <string>

#include "rdb_helper.h"
#include "result_set.h"

namespace OHOS {
namespace Media {
class BackupDatabaseUtils {
public:
    static int32_t QueryInt(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &sql,
        const std::string &column);
};
} // namespace Media
} // namespace OHOS

#endif  // BACKUP_DATABASE_UTILS_H