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

#ifndef APP_TASK_OPS_PROXY_H
#define APP_TASK_OPS_PROXY_H

#include <iremote_proxy.h>
#include "imml_task_ops.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
class AppTaskOpsProxy : public IRemoteProxy<IMmlTaskOps> {
public:
    explicit AppTaskOpsProxy(const sptr<IRemoteObject>& remote) : IRemoteProxy<IMmlTaskOps>(remote) {}
    virtual ~AppTaskOpsProxy() {}

    ErrCode DoTaskOps(const std::string &ops, const std::string &taskName, const std::string &taskExtra,
        int32_t &funcResult) override;

private:
    static inline BrokerDelegator<AppTaskOpsProxy> delegator_;
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS
#endif // APP_TASK_OPS_PROXY_H
