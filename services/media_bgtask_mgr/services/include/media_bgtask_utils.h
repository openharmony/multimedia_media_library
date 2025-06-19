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

#ifndef MEDIA_BGTASK_MGR_SERVICES_INCLUDE_MEDIA_BGTASK_UTILS_H
#define MEDIA_BGTASK_MGR_SERVICES_INCLUDE_MEDIA_BGTASK_UTILS_H

#include <time.h>

#include <string>
#include "task_runner_types.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
class MediaBgTaskUtils {
public:
    // 如果key存在，如果场景返回true：
    // 1、值为true
    // 2、值为数字且大于0
    // 其余场景返回false
    static bool IsParamTrueOrLtZero(std::string key);
    static bool IsStrTrueOrLtZero(std::string key);

    static std::string TaskOpsToString(TaskOps ops);
    static TaskOps StringToTaskOps(const std::string& str);

    static std::string DesensitizeUri(const std::string &fileUri);
    static time_t GetNowTime();

    static bool IsNumber(const std::string& str);
};
}  // namespace MediaBgtaskSchedule
}  // namespace OHOS

#endif  // MEDIA_BGTASK_MGR_SERVICES_INCLUDE_MEDIA_BGTASK_UTILS_H
