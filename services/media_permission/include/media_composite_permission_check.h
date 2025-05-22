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
#ifndef OHOS_MEDIALIBRARY_COMPOSITE_PERMISSION_CHECK_H
#define OHOS_MEDIALIBRARY_COMPOSITE_PERMISSION_CHECK_H

#include "media_permission_check.h"
#include "medialibrary_asset_operations.h"

namespace OHOS::Media {
// Corresponds to the inner vector in the permission map.
// Authentication succeeds only when all permissions in the singlePermChecks_ element are met.
class SinglePermissionCheck : public PermissionCheck {
private:
    std::vector<std::shared_ptr<PermissionCheck>> singlePermChecks_;
    std::mutex mutex_;
public:
    void AddCheck(std::shared_ptr<PermissionCheck> check);
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

// Corresponding to the outer vector in the permission map, compositePermChecks_ consists of singlePermChecks_ elements.
// If any group of elements passes the verification, the authentication is successful.
class CompositePermissionCheck : public PermissionCheck {
private:
    std::vector<std::shared_ptr<SinglePermissionCheck>> compositePermChecks_;
    std::mutex mutex_;
public:
    void AddCheck(std::shared_ptr<SinglePermissionCheck> check);
    int32_t CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data) override;
};

class MediaLibraryAssetOperationsWrapper : public MediaLibraryAssetOperations {
public:
    static std::shared_ptr<FileAsset> GetFileAssetByUriWrapper(const std::string &fileUri, bool isPhoto,
        const std::vector<std::string> &columns, const std::string &pendingStatus = "")
    {
        return MediaLibraryAssetOperations::GetFileAssetByUri(fileUri, isPhoto, columns, pendingStatus);
    }
};
} // namespace OHOS::Media
#endif  // OHOS_MEDIALIBRARY_COMPOSITE_PERMISSION_CHECK_H