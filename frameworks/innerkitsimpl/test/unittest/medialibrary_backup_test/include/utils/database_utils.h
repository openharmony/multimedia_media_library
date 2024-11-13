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
#include "media_log.h"
#include "backup_database_utils.h"

namespace OHOS::Media {
class DatabaseUtils {
public:
    std::shared_ptr<NativeRdb::RdbStore> GetRdbStore(const std::string &dbPath)
    {
        NativeRdb::RdbStoreConfig config(dbPath);
        config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
        config.SetHaMode(NativeRdb::HAMode::MANUAL_TRIGGER);
        config.SetAllowRebuild(true);
        // NativeRdb::RdbOpenCallback helper = *this;
        int errCode = 0;
        RdbCallback cb;
        std::shared_ptr<NativeRdb::RdbStore> rdbStorePtr = NativeRdb::RdbHelper::GetRdbStore(config, 1, cb, errCode);
        MEDIA_INFO_LOG("RdbStore instance. errCode: %{public}d, dbPath: %{public}s", errCode, dbPath.c_str());
        return rdbStorePtr;
    }
};
}  // namespace OHOS::Media
#endif  // MEDIALIBRARY_BACKUP_TEST_DATABASE_UTILS_H