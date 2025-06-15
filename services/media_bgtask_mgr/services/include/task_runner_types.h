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

#ifndef MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_RUNNER_TYPES_H
#define MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_RUNNER_TYPES_H

#include <string>

namespace OHOS {
namespace MediaBgtaskSchedule {
enum TaskOps {
    NONE = -1,
    START,
    STOP,
};

struct AppSvcInfo {
    std::string bundleName;
    std::string abilityName;
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS
#endif // MEDIA_BGTASK_MGR_SERVICES_INCLUDE_TASK_RUNNER_TYPES_H
