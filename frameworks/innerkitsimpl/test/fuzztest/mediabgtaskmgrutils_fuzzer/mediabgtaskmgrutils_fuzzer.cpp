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

#include "mediabgtaskmgrutils_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "media_bgtask_utils.h"
#include <cstdlib>
#include <string>
#include "parameters.h"
#include "string_ex.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS {
using namespace MediaBgtaskSchedule;

const int32_t INT32_COUNT = 3;
const int8_t STRING_COUNT = 8;
const int MIN_SIZE = sizeof(int32_t) * INT32_COUNT + sizeof(int8_t) * STRING_COUNT;

FuzzedDataProvider *FDP = nullptr;

static inline MediaBgtaskSchedule::TaskOps FuzzTaskOps()
{
    int32_t value = FDP->ConsumeIntegralInRange<int32_t>(-1, 1);
    if (value >= static_cast<int32_t>(MediaBgtaskSchedule::TaskOps::NONE) &&
        value <= static_cast<int32_t>(MediaBgtaskSchedule::TaskOps::STOP)) {
        return static_cast<MediaBgtaskSchedule::TaskOps>(value);
    }
    return MediaBgtaskSchedule::TaskOps::STOP;
}

static inline std::string FuzzTaskOpsValue()
{
    int32_t value = FDP->ConsumeIntegralInRange<int32_t>(-1, 1);   // 扰动值加大
    switch (static_cast<MediaBgtaskSchedule::TaskOps>(value)) {
        case MediaBgtaskSchedule::TaskOps::START:
            return "start";
        case MediaBgtaskSchedule::TaskOps::STOP:
            return "stop";
        default:
            return FDP->ConsumeBytesAsString(1);
    }
}

static inline std::string FuzzUri()
{
    int32_t value = FDP->ConsumeIntegralInRange<int32_t>(0, 1);
    if (value == 0) {
        return "";
    }
    return FDP->ConsumeRemainingBytesAsString() + "/";
}

static void MediaBgTaskUtilsFuzzerTest()
{
    std::string key = FDP->ConsumeBytesAsString(1);
    std::string value = FDP->ConsumeBytesAsString(4);
    system::SetParameter(key, value);
    MediaBgTaskUtils::IsParamTrueOrLtZero(key);

    TaskOps ops = FuzzTaskOps();
    MediaBgTaskUtils::TaskOpsToString(ops);

    std::string str = FuzzTaskOpsValue();
    MediaBgTaskUtils::StringToTaskOps(str);

    std::string isNum = FDP->ConsumeBytesAsString(1);
    MediaBgTaskUtils::IsNumber(isNum);

    std::string fileUri = FuzzUri();
    MediaBgTaskUtils::DesensitizeUri(fileUri);
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
    OHOS::MediaBgTaskUtilsFuzzerTest();
    return 0;
}
