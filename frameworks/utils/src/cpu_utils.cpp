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
 */

#include "cpu_utils.h"

#include <cerrno>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include "media_log.h"

namespace OHOS {
namespace Media {
void CpuUtils::SlowDown()
{
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    for (int cpu = CpuAffinityType::CPU_IDX_0; cpu <= CpuAffinityType::CPU_IDX_6; cpu++) {
        CPU_SET(cpu, &cpuSet);
    }
    CHECK_AND_PRINT_LOG(sched_setaffinity(0, sizeof(cpuSet), &cpuSet) >= 0,
        "set thread affinity failed, errno %{public}d", errno);
}

void CpuUtils::ResetCpu()
{
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CHECK_AND_PRINT_LOG(sched_setaffinity(0, sizeof(cpuSet), &cpuSet) >= 0,
        "set thread affinity failed, errno %{public}d", errno);
}

void CpuUtils::SetSelfThreadAffinity(CpuAffinityType cpuAffinityType)
{
    if (cpuAffinityType < CpuAffinityType::CPU_IDX_0) {
        return;
    }

    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    for (int cpu = CpuAffinityType::CPU_IDX_0; cpu <= cpuAffinityType; cpu++) {
        CPU_SET(cpu, &cpuSet);
    }
    CHECK_AND_WARN_LOG(pthread_setaffinity_np(pthread_self(), sizeof(cpuSet), &cpuSet) == 0,
        "Set affinity failed, errno %{public}d, cpuAffinityType:%{public}d", errno, cpuAffinityType);
}

void CpuUtils::ResetSelfThreadAffinity()
{
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CHECK_AND_WARN_LOG(pthread_setaffinity_np(pthread_self(), sizeof(cpuSet), &cpuSet) == 0,
        "Reset affinity failed, errno %{public}d", errno);
}
} // namespace Media
} // namespace OHOS
