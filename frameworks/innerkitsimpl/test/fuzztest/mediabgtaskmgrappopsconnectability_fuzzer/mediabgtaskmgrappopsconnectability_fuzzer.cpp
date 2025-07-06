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

#include "mediabgtaskmgrappopsconnectability_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "app_ops_connect_ability.h"
#include "app_ops_connection.h"
#include "app_task_ops_proxy.h"
#undef private
#include "media_bgtask_mgr_log.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;

const int32_t NUM_BYTES = 1;
const int32_t INT32_COUNT = 4;
const int8_t BOOL_COUNT = 1;
const int8_t STRING_COUNT = 6;
const int MIN_SIZE = sizeof(int32_t) * INT32_COUNT + sizeof(int8_t) * (BOOL_COUNT + STRING_COUNT);

const std::shared_ptr<AppOpsConnectAbility> ability_ = DelayedSingleton<AppOpsConnectAbility>::GetInstance();

FuzzedDataProvider *FDP = nullptr;

/**
 * ConnectAbility DoConnect TaskOpsSync DisconnectAbility
 */
static void AppOpsConnectAbilityFuzzerTest()
{
    AppSvcInfo svcName;
    svcName.bundleName = "bundleName";
    svcName.abilityName = "abilityName";
    int32_t userId = FDP->ConsumeIntegral<int32_t>();
    svcName.userId = userId;
    std::string ops = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string taskName = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string extra = FDP->ConsumeBytesAsString(NUM_BYTES);
    ability_->ConnectAbility(svcName, ops, taskName, extra);
    ability_->TaskOpsSync(svcName, ops, taskName, extra);

    userId = FDP->ConsumeBool() ? userId : FDP->ConsumeIntegral<int32_t>();
    ability_->DisconnectAbility(userId);
}

static void AppOpsConnectionFuzzerTest()
{
    AppSvcInfo svcName;
    svcName.bundleName = "bundleName";
    svcName.abilityName = "abilityName";
    int32_t userId = FDP->ConsumeIntegral<int32_t>();
    AppOpsConnection appConnection(svcName, userId);

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject;
    int32_t resultCode = FDP->ConsumeIntegral<int32_t>();
    appConnection.OnAbilityConnectDone(element, remoteObject, resultCode);

    std::string ops = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string taskName = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string extra = FDP->ConsumeBytesAsString(NUM_BYTES);
    appConnection.TaskOpsSync(ops, taskName, extra);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::FDP = &fdp;
    if (data == nullptr || size < OHOS::MIN_SIZE) {
        return 0;
    }
    /* Run your code on data */
    OHOS::AppOpsConnectAbilityFuzzerTest();
    OHOS::AppOpsConnectionFuzzerTest();
    return 0;
}
