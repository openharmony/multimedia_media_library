/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_BACKUP_TEST_DATABASE_UTILS_H
#define MEDIALIBRARY_BACKUP_TEST_DATABASE_UTILS_H

#include <string>

#include "rdb_store.h"

namespace OHOS::Media {
class DatabaseUtils {
public:
    static void ExecuteSql(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &bindArgs = {});
    static void ExecuteSqls(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::vector<std::string> &sqls);
    static int32_t QueryInt(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &columnName,
        const std::string &querySql, const std::vector<NativeRdb::ValueObject> &bindArgs = {});

    std::shared_ptr<NativeRdb::RdbStore> GetRdbStore(const std::string &dbPath);
};
}  // namespace OHOS::Media
#endif  // MEDIALIBRARY_BACKUP_TEST_DATABASE_UTILS_H