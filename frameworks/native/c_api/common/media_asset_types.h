/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_NATIVE_INCLUDE_MEDIA_ASSET_TYPES_H
#define FRAMEWORKS_NATIVE_INCLUDE_MEDIA_ASSET_TYPES_H

namespace OHOS {
namespace Media {

enum class AssetChangeOperation {
    CREATE_FROM_SCRATCH,
    CREATE_FROM_URI,
    GET_WRITE_CACHE_HANDLER,
    ADD_RESOURCE,
    SET_EDIT_DATA,
    SET_FAVORITE,
    SET_HIDDEN,
    SET_TITLE,
    SET_USER_COMMENT,
    SET_MOVING_PHOTO_EFFECT_MODE,
    SET_PHOTO_QUALITY_AND_PHOTOID,
    SET_LOCATION,
    SET_CAMERA_SHOT_KEY,
    SAVE_CAMERA_PHOTO,
    ADD_FILTERS,
    DISCARD_CAMERA_PHOTO,
};

enum class AddResourceMode {
    DEFAULT = -1,
    DATA_BUFFER,
    FILE_URI,
};

} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_NATIVE_INCLUDE_MEDIA_ASSET_TYPES_H