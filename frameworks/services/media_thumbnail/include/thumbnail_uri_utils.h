/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_URI_UTILS_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_URI_UTILS_H_

#include "pixel_map.h"

namespace OHOS {
namespace Media {
class ThumbnailUriUtils {
public:
    ThumbnailUriUtils() = delete;
    virtual ~ThumbnailUriUtils() = delete;
    static bool ParseFileUri(const std::string &uriString, std::string &outFileId,
        std::string &ourNetworkId);
    static bool ParseThumbnailInfo(const std::string &uriString,
        std::string &outFileId, Size &outSize, std::string &ourNetworkId);
    static bool ParseThumbnailInfo(const std::string &uriString);
private:
    static void SplitKeyValue(const std::string &keyValue, std::string &key, std::string &value);

    static void SplitKeys(const std::string &query, std::vector<std::string> &keys);
    static bool IsNumber(const std::string &str);
    static void ParseThumbnailKey(const std::string &key, const std::string &value, std::string &outAction,
        int &outWidth, int &outHeight);
    static std::string GetNetworkIdFromUri(const std::string &uri);
    static std::string GetIdFromUri(const std::string &uri);
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_URI_UTILS_H_
