/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
 *
 * epfs.h, keep same with fs/epfs/epfs.h
 *
 */

#ifndef OHOS_MEDIALIBRARY_CPU_UTILS_H
#define OHOS_MEDIALIBRARY_CPU_UTILS_H

#include <cstdint>

namespace OHOS {
namespace Media {
enum CpuAffinityType : int32_t {
    CPU_IDX_DEFAULT = -1,
    CPU_IDX_0 = 0,
    CPU_IDX_1,
    CPU_IDX_2,
    CPU_IDX_3,
    CPU_IDX_4,
    CPU_IDX_5,
    CPU_IDX_6,
    CPU_IDX_7,
    CPU_IDX_8,
    CPU_IDX_9,
    CPU_IDX_10,
    CPU_IDX_11,
};

class CpuUtils {
public:
    CpuUtils() = delete;
    ~CpuUtils() = delete;

    static void SlowDown();
    static void ResetCpu();

    static void SetSelfThreadAffinity(CpuAffinityType cpuAffinityType);
    static void ResetSelfThreadAffinity();
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_CPU_UTILS_H
