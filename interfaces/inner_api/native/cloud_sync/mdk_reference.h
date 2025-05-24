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
#ifndef OHOS_MEDIA_CLOUD_SYNC_RELATION_H
#define OHOS_MEDIA_CLOUD_SYNC_RELATION_H
#include <string>

#define EXPORT __attribute__ ((visibility ("default")))

namespace OHOS::Media::CloudSync {
struct MDKReference {
    std::string recordId;    // 记录id
    std::string recordType;  // 记录的type
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_RELATION_H