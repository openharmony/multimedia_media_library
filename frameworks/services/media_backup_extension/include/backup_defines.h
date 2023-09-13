/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_BACKUP_DEFINES_H_
#define OHOS_MEDIA_BACKUP_DEFINES_H_

#include <vector>
#include <string>
#include <stdint.h>

namespace OHOS {
namespace Media {
struct FileInfo {
    std::string filePath;
    std::string displayName;
    int64_t _size;
    int64_t duration;
    int64_t recycledTime;
    int32_t hidden;
    int32_t is_hw_favorite;
    int32_t fileType;
    int32_t orientation;
    int64_t showDateToken;
    int32_t height;
    int32_t width;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_BACKUP_DEFINES_H_
