/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef NOTIFYCHANGE_FUZZER_H
#define NOTIFYCHANGE_FUZZER_H

#define FUZZ_PROJECT_NAME "mediabgtaskmgrappbgtaskschedulestub_fuzzer"

#define private public
#include "app_bgtask_schedule_stub.h"
#undef private

namespace OHOS {
namespace MediaBgtaskSchedule {
const int32_t E_OK = 0;
class AppBgTaskScheduleStubFuzz : public AppBgTaskScheduleStub {
public:
    ErrCode ReportTaskComplete(const std::string &task_name, int32_t &funcResult) override
    {
        funcResult = 1;
        return E_OK;
    }

    ErrCode ModifyTask(const std::string &task_name, const std::string &modifyInfo, int32_t &funcResult) override
    {
        funcResult = 1;
        return E_OK;
    }
};

} // namespace MediaBgtaskSchedule
} // namespace OHOS

#endif
