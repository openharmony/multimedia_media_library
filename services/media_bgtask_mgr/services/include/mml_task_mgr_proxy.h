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

#ifndef OHOS_MEDIABGTASKSCHEDULE_MMLTASKMGRPROXY_H
#define OHOS_MEDIABGTASKSCHEDULE_MMLTASKMGRPROXY_H

#include <iremote_proxy.h>
#include "imml_task_mgr.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

class MmlTaskMgrProxy : public IRemoteProxy<IMmlTaskMgr> {
public:
    explicit MmlTaskMgrProxy(const sptr<IRemoteObject>& remote) : IRemoteProxy<IMmlTaskMgr>(remote) {}
    virtual ~MmlTaskMgrProxy() {}

    virtual ErrCode ReportTaskComplete(const std::string& task_name) override;
    virtual ErrCode ModifyTask(const std::string& task_name, const std::string& modifyInfo) override;

private:
    static inline BrokerDelegator<MmlTaskMgrProxy> delegator_;
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS
#endif // OHOS_MEDIABGTASKSCHEDULE_MMLTASKMGRPROXY_H

