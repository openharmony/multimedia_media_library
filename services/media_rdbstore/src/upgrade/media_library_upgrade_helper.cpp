/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Upgrade"

#include "media_library_upgrade_helper.h"
#include "medialibrary_upgrade_utils.h"
#include "media_log.h"
#include <algorithm>

namespace OHOS {
namespace Media {
constexpr int32_t MAX_TRY_TIMES = 30;
constexpr int32_t MAX_BUSY_TRY_TIMES = 2;
constexpr int32_t TRANSACTION_WAIT_INTERVAL = 50; // in milliseconds.

int32_t UpgradeHelper::ExecSqlWithRetry(std::function<int32_t()> execSql)
{
    int32_t currentTime = 0;
    int32_t busyRetryTime = 0;
    int32_t err = NativeRdb::E_OK;
    while (busyRetryTime < MAX_BUSY_TRY_TIMES && currentTime <= MAX_TRY_TIMES) {
        err = execSql();
        switch (err) {
            case NativeRdb::E_OK:
                return err;
            case NativeRdb::E_SQLITE_LOCKED:
                std::this_thread::sleep_for(std::chrono::milliseconds(TRANSACTION_WAIT_INTERVAL));
                currentTime++;
                MEDIA_ERR_LOG("execSql busy, err: %{public}d, currentTime: %{public}d", err, currentTime);
                break;
            case NativeRdb::E_SQLITE_BUSY:
            case NativeRdb::E_DATABASE_BUSY:
                busyRetryTime++;
                MEDIA_ERR_LOG("execSql busy, err:%{public}d, busyRetryTime:%{public}d", err, busyRetryTime);
                break;
            default:
                MEDIA_ERR_LOG("execSql failed, err: %{public}d, currentTime: %{public}d", err, currentTime);
                return err;
        }
    }
    return err;
}

std::vector<std::pair<int32_t, int32_t>> UpgradeHelper::ExecuteCommands(
    const std::vector<std::shared_ptr<ISqlCommand>>& commands, NativeRdb::RdbStore& store, bool needSkip)
{
    std::vector<std::pair<int32_t, int32_t>> errResult = {};
    int32_t ret = NativeRdb::E_OK;
    for (size_t i = 0; i < commands.size(); i++) {
        const auto& cmd = commands[i];
        if (cmd == nullptr) {
            MEDIA_ERR_LOG("Command is null");
            return errResult;
        }

        std::string sql = cmd->GetSql();
        std::vector<NativeRdb::ValueObject> bindArgs = cmd->GetArgs();

        ret = bindArgs.empty() ? ExecSqlWithRetry([&]() { return store.ExecuteSql(sql); }) :
            ExecSqlWithRetry([&]() { return store.ExecuteSql(sql, bindArgs); });
        if (ret == NativeRdb::E_OK) continue;
        MEDIA_ERR_LOG("Execute SQL failed: %{public}s, ret: %{public}d", sql.c_str(), ret);
        errResult.emplace_back(std::make_pair(i, ret));
        if (needSkip) {
            return errResult;
        }
    }
    return errResult;
}
} // namespace Media
} // namespace OHOS