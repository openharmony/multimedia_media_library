/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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
#ifndef OHOS_MEDIALIBRARY_PERMISSION_HEADER_REQ_H
#define OHOS_MEDIALIBRARY_PERMISSION_HEADER_REQ_H

#include <stdint.h>
#include <string>
#include <unordered_map>
#include "media_permission_policy_type.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class PermissionHeaderReq {
private:
    // Three groups of header authentication parameters
    // accross account check
    int32_t userId_ = -1;
    // db permission check
    std::string fileId_ = "";
    int32_t uriType_ = -1;
    //openfile api header check
    std::string openUri_ = "";
    std::string openMode_ = "";

    std::vector<std::vector<PermissionType>> permissionPolicy_;
    bool isDBBypass_ = false;

    std::unordered_map<std::string, std::string> headerReq_;
    void setUserId(int32_t userId);
    void setPermissionPolicy(std::vector<std::vector<PermissionType>>& permissionPolicy);
    void setDBBypass(bool isDBBypass);
public:
    PermissionHeaderReq() = default;
    PermissionHeaderReq(int32_t userId) : userId_(userId) {}
    PermissionHeaderReq(const std::string& fileId, int32_t uriType);
    PermissionHeaderReq(const std::string& openUri, const std::string& openMode);
    PermissionHeaderReq(const std::string& fileId, int32_t uriType,
        const std::string& openUri, const std::string& openMode);
    EXPORT static PermissionHeaderReq convertToPermissionHeaderReq(const std::unordered_map<std::string,
        std::string>& req, int32_t userId, std::vector<std::vector<PermissionType>>& permissionPolicy, bool isDBBypass);
    std::string getFileId() const;
    int32_t getUriType() const;
    std::string getOpenUri() const;
    std::string getOpenMode() const;
    int32_t getUserId() const;
    std::vector<std::vector<PermissionType>> getPermissionPolicy() const;
    bool getIsDBBypass() const;
    EXPORT static const std::string FILE_ID_KEY;
    EXPORT static const std::string URI_TYPE_KEY;
    EXPORT static const std::string OPEN_URI_KEY;
    EXPORT static const std::string OPEN_MODE_KEY;
};
} // namespace OHOS::Media
#endif  // OHOS_MEDIALIBRARY_PERMISSION_HEADER_REQ_H