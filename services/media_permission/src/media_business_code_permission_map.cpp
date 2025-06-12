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
// API blacklist for deprecated read or write permission
std::unordered_set<uint32_t> PermissionCheck::deprecatedReadPermissionSet = {
    static_cast<uint32_t>(MediaLibraryBusinessCode::QUERY_PHOTO_STATUS),
    static_cast<uint32_t>(MediaLibraryBusinessCode::GET_PHOTO_INDEX),
    static_cast<uint32_t>(MediaLibraryBusinessCode::GET_ANALYSIS_PROCESS),
    static_cast<uint32_t>(MediaLibraryBusinessCode::GET_HIGHLIGHT_ALBUM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::QUERY_CLOUD_ENHANCEMENT_TASK_STATE),
    static_cast<uint32_t>(MediaLibraryBusinessCode::SYNC_CLOUD_ENHANCEMENT_TASK_STATUS),
    static_cast<uint32_t>(MediaLibraryBusinessCode::GET_CLOUD_ENHANCEMENT_PAIR),
    static_cast<uint32_t>(MediaLibraryBusinessCode::GET_FACE_ID),
    static_cast<uint32_t>(MediaLibraryBusinessCode::QUEUE_GET_CLOUDMEDIA_ASSET_STATUS),
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
    static_cast<uint32_t>(MediaLibraryBusinessCode::UPDATE_GALLERY_FORM_INFO),
    static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_SET_ORDER_POSITION),
    static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_GET_ORDER_POSITION),
    static_cast<uint32_t>(MediaLibraryBusinessCode::SUBMIT_CLOUD_ENHANCEMENT_TASKS),
    static_cast<uint32_t>(MediaLibraryBusinessCode::PRIORITIZE_CLOUD_ENHANCEMENT_TASK),
    static_cast<uint32_t>(MediaLibraryBusinessCode::CANCEL_CLOUD_ENHANCEMENT_TASKS),
    static_cast<uint32_t>(MediaLibraryBusinessCode::CANCEL_ALL_CLOUD_ENHANCEMENT_TASKS),
    static_cast<uint32_t>(MediaLibraryBusinessCode::SET_HIGH_LIGHT_USER_ACTION_DATA),
    static_cast<uint32_t>(MediaLibraryBusinessCode::SET_SUBTITLE),
};
// API whitelist for check grant operation permission
std::unordered_set<uint32_t> PermissionCheck::grantOperationPermissionSet = {
    static_cast<uint32_t>(MediaLibraryBusinessCode::MEDIA_BUSINESS_CODE_START)};
// API whitelist for check media tool operation permission
std::unordered_set<uint32_t> PermissionCheck::mediaToolOperationPermissionSet = {
    static_cast<uint32_t>(MediaLibraryBusinessCode::MEDIA_BUSINESS_CODE_START)};
}  // namespace OHOS::Media
