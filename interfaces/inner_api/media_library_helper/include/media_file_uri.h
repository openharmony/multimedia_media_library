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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_FILE_URI_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_FILE_URI_H_

#include <string>
#include <unordered_map>

#include "medialibrary_db_const.h"
#include "uri.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
const std::string MEDIA_FILE_URI_EMPTY = "empty";
class MediaFileUri : public OHOS::Uri {
    std::string networkId_ { MEDIA_FILE_URI_EMPTY };
    std::string fileId_ { MEDIA_FILE_URI_EMPTY };
    std::unordered_map<std::string, std::string> queryMap_;
    std::string MediaFileUriConstruct(MediaType mediaType, const std::string &networkId,
                                      const std::string &fileId, const int32_t &apiVersion);
public:
    explicit MediaFileUri(const std::string &uriStr) : Uri(uriStr) {}
    explicit MediaFileUri(MediaType mediaType,
                          const std::string &fileId,
                          const std::string &networkId = "",
                          const int32_t &apiVersion = MEDIA_API_VERSION_V9) : Uri(
                          MediaFileUriConstruct(mediaType, fileId, networkId, apiVersion)) {}
    ~MediaFileUri() = default;

    std::string GetNetworkId();
    std::string GetFileId();
    std::string GetFilePath();
    std::unordered_map<std::string, std::string> &GetQueryKeys();
    bool IsValid();
    bool IsApi10();
    static MediaType GetMediaTypeFromUri(const std::string &uri);
    static std::string GetPathFirstDentry(Uri &uri);
    static std::string GetPathSecondDentry(Uri &uri);
    static void RemoveAllFragment(std::string &uri);
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_FILE_URI_H_
