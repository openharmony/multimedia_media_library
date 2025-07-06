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

#include "mediabgtaskmgrappbgtaskschedulestub_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "media_bgtask_mgr_log.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;
const uint32_t uint32Count = 1;
const int MIN_SIZE = sizeof(uint32_t) * uint32Count;

FuzzedDataProvider *FDP = nullptr;

static void AppBgTaskScheduleStubFuzzerTest()
{
    // 如何启动服务
    AppBgTaskScheduleStubFuzz scheduleStub;
    uint32_t code = FDP->ConsumeIntegralInRange<int32_t>(0, 2);
    MessageParcel data = MessageParcel();
    MessageParcel reply = MessageParcel();
    MessageOption option = MessageOption();
    scheduleStub.OnRemoteRequest(code, data, reply, option);
    scheduleStub.CmdReportTaskComplete(data, reply);
    scheduleStub.CmdModifyTask(data, reply);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (data == nullptr || size < OHOS::MIN_SIZE) {
        return 0;
    }
    OHOS::FDP = &fdp;

    /* Run your code on data */
    OHOS::AppBgTaskScheduleStubFuzzerTest();
    return 0;
}
