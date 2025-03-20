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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_OPERATION_CODE_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_OPERATION_CODE_H

namespace OHOS::Media::CloudSync {
enum GLOBAL_CODE {
    OPERATION_CODE_BASE = 1,
};

enum class CloudMediaOperationCode : uint32_t {
    CMD_UPDATE_DIRTY_FOR_CLOUD_CHECK = OPERATION_CODE_BASE,
    CMD_FINISH_CHECK,
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_OPERATION_CODE_H