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

#include "backup_database_utils.h"

#include "backup_const.h"
#include "media_log.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {

int32_t BackupDatabaseUtils::QueryInt(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &sql,
    const std::string &column)
{
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdb_ is nullptr, Maybe init failed.");
        return 0;
    }
    auto resultSet = rdbStore->QuerySql(sql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val(column, resultSet);
    return result;
}
} // namespace Media
} // namespace OHOS