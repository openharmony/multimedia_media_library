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

#include "mediabgtaskmgrsaopsconnection_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "sa_ops_connection.h"
#include "sa_ops_connection_manager.h"
#undef private

#include <vector>
#include "media_bgtask_utils.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;

const int32_t NUM_BYTES = 1;

const int32_t INT32_COUNT = 1;
const uint32_t uint32Count = 3;
const int64_t int64Count = 13;
const int8_t BOOL_COUNT = 1;
const int8_t STRING_COUNT = 3;
const int MIN_SIZE = sizeof(int32_t) * INT32_COUNT  + sizeof(int8_t) * (BOOL_COUNT + STRING_COUNT);

FuzzedDataProvider *FDP = nullptr;

static void SAOpsConnectionManagerFuzzerTest()
{
    SAOpsConnectionManager &instance =  SAOpsConnectionManager::GetInstance();
    int32_t saId = FDP->ConsumeIntegral<int32_t>();
    instance.TaskOpsSync("ops", saId, "taskName", "extra");
}

static void SAOpsConnectionFuzzerTest()
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    std::string taskName = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string ops = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string extra = FDP->ConsumeBytesAsString(NUM_BYTES);
    connection.taskName_ = taskName;
    connection.ops_ = ops;
    connection.extra_ = extra;
    MessageParcel data;
    MessageParcel reply;
    connection.InputParaSet(data);
    connection.OutputParaGet(reply);

    connection.IsSAConnected();
    connection.IsSALoaded();
    connection.LoadSAExtensionSync();

    connection.TaskOpsSync(ops, taskName, extra);

    bool isSync = FDP->ConsumeBool();
    connection.GetSAExtensionProxy(isSync);

    int32_t systemAbilityId = FDP->ConsumeBool() ? 0 : -1;
    sptr<IRemoteObject> remoteObject;
    connection.OnSystemAbilityRemove(systemAbilityId, "");
    connection.OnSystemAbilityLoadSuccess(systemAbilityId, remoteObject);
    connection.OnSystemAbilityLoadFail(systemAbilityId);
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
    OHOS::SAOpsConnectionManagerFuzzerTest();
    OHOS::SAOpsConnectionFuzzerTest();
    return 0;
}
