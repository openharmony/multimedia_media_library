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

#ifndef OHOS_MEDIA_CLOUD_SYNC_SYS_UTILS_H
#define OHOS_MEDIA_CLOUD_SYNC_SYS_UTILS_H

#include <cstdint>
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
enum {
    CPU_IDX_0 = 0,
    CPU_IDX_1,
    CPU_IDX_2,
    CPU_IDX_3,
    CPU_IDX_4,
    CPU_IDX_5,
    CPU_IDX_6,
    CPU_IDX_7,
};

class EXPORT SysUtils {
public:
    static void SlowDown();
    static void ResetCpu();
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_SYS_UTILS_H