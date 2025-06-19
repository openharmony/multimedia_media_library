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

#ifndef SA_OPS_CONNECTION_MANAGER_H
#define SA_OPS_CONNECTION_MANAGER_H

#include <memory>
#include <mutex>
#include <unordered_map>
#include "sa_ops_connection.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
class SAOpsConnectionManager {
public:
    static SAOpsConnectionManager &GetInstance()
    {
        static SAOpsConnectionManager instance;
        return instance;
    }
    int32_t TaskOpsSync(const std::string& ops, int32_t saId, const std::string& taskName, const std::string& extra);

private:
    SAOpsConnectionManager();
    SAOpsConnectionManager(const SAOpsConnectionManager&) = delete;  // 禁止拷贝
    SAOpsConnectionManager& operator=(const SAOpsConnectionManager&) = delete;  // 禁止赋值
    std::shared_ptr<SAOpsConnection> GetConnection(int32_t saId);

    std::unordered_map<int32_t, std::shared_ptr<SAOpsConnection>> connections_;
    std::mutex mutex_;
};
} // MediaBgtaskSchedule
} // OHOS
#endif // SA_OPS_CONNECTION_MANAGER_H
