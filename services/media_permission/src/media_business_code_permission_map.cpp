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
#include <string>
#include "media_permission_check.h"
#include "media_system_api_permission_check.h"
#include "media_private_permission_check.h"
#include "media_read_permission_check.h"
#include "media_write_permission_check.h"

using namespace std;
namespace OHOS::Media {
/* Map the API code to the required permissions.
 * (1)If the API code is not in the mapping table, the API cannot be executed.
 *    If vector is empty, no permission is required, for example, the close API.
 * (2)The outer nested vector indicates the OR relationship. That is,
 *    if any set of permissions is satisfied, it is considered to have the permission to execute the API.
 * (3)A single inner vector indicates the AND relationship. That is,
 *    an API can be executed only when all permissions are met.
 * For example, the {{SYSTEMAPI_PERM, WRITE_PERM}, {CLOUDFILE_SYNC}},
 *   must have the system and write permissions, or must have the device-cloud permission.
 */
std::unordered_map<uint32_t, std::vector<std::vector<PermissionType>>> PermissionCheck::businessCodeToPermissions = {
    // MEDIA_BUSINESS_CODE_START begin
    {static_cast<uint32_t>(MediaLibraryBusinessCode::REMOVE_FORM_INFO), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::REMOVE_GALLERY_FORM_INFO), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_FORM_INFO), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_GALLERY_FORM_INFO), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::CLONE_ASSET), {{WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::REVERT_TO_ORIGINAL), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_OPEN), {{}}},
    // ASSETS_BUSINESS_CODE_START begin
    {static_cast<uint32_t>(MediaLibraryBusinessCode::COMMIT_EDITED_ASSET), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_PUBLIC_CREATE_ASSET), {{WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ASSET), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_PUBLIC_CREATE_ASSET_FOR_APP), {{WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ASSET_FOR_APP), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ASSET_FOR_APP_WITH_MODE),
        {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ASSET_FOR_APP_WITH_ALBUM),
        {{SYSTEMAPI_PERM, WRITE_PERM, READ_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYS_TRASH_PHOTOS), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_TRASH_PHOTO), {{WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::DELETE_PHOTOS_COMPLETED), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    // ALBUMS_BUSINESS_CODE_START begin
    {static_cast<uint32_t>(MediaLibraryBusinessCode::DELETE_HIGH_LIGHT_ALBUMS), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ALBUM), {{SYSTEMAPI_PERM, WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_DELETE_PHOTO_ALBUMS), {{SYSTEMAPI_PERM, WRITE_PERM}}},
};

// API blacklist for deprecated read or write permission
std::unordered_set<uint32_t> PermissionCheck::deprecatedReadPermissionSet = {
    static_cast<uint32_t>(MediaLibraryBusinessCode::CLONE_ASSET),
    static_cast<uint32_t>(MediaLibraryBusinessCode::COMMIT_EDITED_ASSET),
    static_cast<uint32_t>(MediaLibraryBusinessCode::REVERT_TO_ORIGINAL),
    static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_GALLERY_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::REMOVE_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::REMOVE_GALLERY_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::DELETE_HIGH_LIGHT_ALBUMS),
};
std::unordered_set<uint32_t> PermissionCheck::deprecatedWritePermissionSet = {
    static_cast<uint32_t>(MediaLibraryBusinessCode::CLONE_ASSET),
    static_cast<uint32_t>(MediaLibraryBusinessCode::COMMIT_EDITED_ASSET),
    static_cast<uint32_t>(MediaLibraryBusinessCode::REVERT_TO_ORIGINAL),
    static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_GALLERY_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::REMOVE_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::REMOVE_GALLERY_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::DELETE_HIGH_LIGHT_ALBUMS),
};
// API whitelist for check grant operation permission
std::unordered_set<uint32_t> PermissionCheck::grantOperationPermissionSet = {
    static_cast<uint32_t>(MediaLibraryBusinessCode::MEDIA_BUSINESS_CODE_START)};
// API whitelist for check media tool operation permission
std::unordered_set<uint32_t> PermissionCheck::mediaToolOperationPermissionSet = {
    static_cast<uint32_t>(MediaLibraryBusinessCode::MEDIA_BUSINESS_CODE_START)};
}  // namespace OHOS::Media
