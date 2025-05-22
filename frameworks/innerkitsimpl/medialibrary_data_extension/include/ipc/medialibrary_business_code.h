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

#ifndef OHOS_MEDIA_BUSINESS_CODE_H
#define OHOS_MEDIA_BUSINESS_CODE_H

namespace OHOS::Media {

enum class MediaLibraryBusinessCode : uint32_t {
    MEDIA_BUSINESS_CODE_START = 0,
    REMOVE_FORM_INFO = 3,
    REMOVE_GALLERY_FORM_INFO,
    SAVE_FORM_INFO,
    SAVE_GALLERY_FORM_INFO,
    CLONE_ASSET,
    REVERT_TO_ORIGINAL,
    PAH_OPEN,
    ASSETS_BUSINESS_CODE_START = 10000,
    COMMIT_EDITED_ASSET,
    PAH_PUBLIC_CREATE_ASSET,
    PAH_SYSTEM_CREATE_ASSET,
    PAH_PUBLIC_CREATE_ASSET_FOR_APP,
    PAH_SYSTEM_CREATE_ASSET_FOR_APP,
    PAH_SYSTEM_CREATE_ASSET_FOR_APP_WITH_MODE,
    PAH_SYSTEM_CREATE_ASSET_FOR_APP_WITH_ALBUM,
    PAH_SYS_TRASH_PHOTOS,
    PAH_DELETE_PHOTOS,
    DELETE_PHOTOS_COMPLETED,
    ALBUMS_BUSINESS_CODE_START = 20000,
    DELETE_HIGH_LIGHT_ALBUMS,
    PAH_SYSTEM_CREATE_ALBUM,
    PAH_DELETE_PHOTO_ALBUMS,
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_BUSINESS_CODE_H