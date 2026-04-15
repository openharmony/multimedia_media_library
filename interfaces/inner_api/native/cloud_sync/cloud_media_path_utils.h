/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PATH_UTILS_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PATH_UTILS_H

#include <string>

namespace OHOS::Media::CloudSync {
class CloudMediaPathUtils {
public:
    /**
     * @brief FindStoragePath is used to find the real storage path.
     * If the input storagePath is a lake path, it will return the corresponding path in lake,
     * If the input storagePath is a doc path, it will return the corresponding path in docs,
     * If the input storagePath is a cloud path, it will return the corresponding path in media,
     * otherwise return the input storagePath.
     */
    static std::string FindStoragePath(const std::string &storagePath, const int32_t userId);
    /**
     * @brief FindStoragePath is used to find the real storage path.
     * If the fileSourceType is lake, it will return the corresponding path in lake based on storagePath,
     * If the fileSourceType is doc, it will return the corresponding path in docs based on storagePath,
     * otherwise, it will return the corresponding path in media based on cloudPath.
     */
    static std::string FindStoragePath(const int32_t fileSourceType,
                                       const std::string &cloudPath,
                                       const std::string &storagePath,
                                       const int32_t userId);
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PATH_UTILS_H
