/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_ANI_CLASSNAME_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_ANI_CLASSNAME_H

#include <string>

namespace OHOS {
namespace Media {

static const std::string PHOTO_ACCESS_HELPER_CLASS_SPACE = "L@ohos/file/photoAccessHelper/photoAccessHelper/";
static const std::string USER_FILE_MANAGER_CLASS_SPACE = "L@ohos/filemanagement/userFileManager/userFileManager/";

static const std::string ANI_CLASS_FILE_ASSET_INFO = PHOTO_ACCESS_HELPER_CLASS_SPACE + "FileAssetInfoHandle";
static const std::string ANI_CLASS_CLOUD_ENHANCEMENT = PHOTO_ACCESS_HELPER_CLASS_SPACE + "CloudEnhancementHandle;";
static const std::string ANI_CLASS_FETCH_RESULT = PHOTO_ACCESS_HELPER_CLASS_SPACE + "FetchResultHandle;";
static const std::string PAH_ANI_CLASS_PHOTO_ALBUM_HANDLE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "AlbumHandle;";
static const std::string ANI_CLASS_PHOTO_ASSET = PHOTO_ACCESS_HELPER_CLASS_SPACE + "PhotoAssetHandle;";
static const std::string ANI_CLASS_PHOTO_ACCESS_HELPER = PHOTO_ACCESS_HELPER_CLASS_SPACE + "PhotoAccessHelperHandle;";
static const std::string ANI_CLASS_PHOTO_PROXY = PHOTO_ACCESS_HELPER_CLASS_SPACE + "PhotoProxyHandle;";
static const std::string ANI_CLASS_SIZE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "SizeImpl;";
static const std::string ANI_CLASS_MOVING_PHOTO = PHOTO_ACCESS_HELPER_CLASS_SPACE + "MovingPhotoHandle;";
static const std::string ANI_CLASS_MEDIA_ALBUM_CHANGE_REQUEST =
    PHOTO_ACCESS_HELPER_CLASS_SPACE + "MediaAlbumChangeRequest;";
static const std::string ANI_CLASS_MEDIA_ASSET_CHANGE_REQUEST =
    PHOTO_ACCESS_HELPER_CLASS_SPACE + "MediaAssetChangeRequest;";
static const std::string ANI_CLASS_MEDIA_ASSETS_CHANGE_REQUEST =
    PHOTO_ACCESS_HELPER_CLASS_SPACE + "MediaAssetsChangeRequest;";

static const std::string ANI_CLASS_ENUM_PHOTO_TYPE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "PhotoType;";
static const std::string ANI_CLASS_ENUM_PHOTO_SUBTYPE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "PhotoSubtype;";
static const std::string ANI_CLASS_ENUM_DYNAMIC_RANGE_TYPE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "DynamicRangeType;";
static const std::string ANI_CLASS_ENUM_POSITION_TYPE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "PositionType;";
static const std::string ANI_CLASS_ENUM_ALBUM_TYPE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "AlbumType;";
static const std::string ANI_CLASS_ENUM_ALBUM_SUBTYPE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "AlbumSubtype;";
static const std::string ANI_CLASS_ENUM_NOTIFY_TYPE = PHOTO_ACCESS_HELPER_CLASS_SPACE + "NotifyType;";
static const std::string ANI_CLASS_ENUM_MOVING_PHOTO_EFFECT_MODE =
    PHOTO_ACCESS_HELPER_CLASS_SPACE + "MovingPhotoEffectMode;";
static const std::string ANI_CLASS_ENUM_CLOUD_ENHANCEMENT_TASK_STAGE =
    PHOTO_ACCESS_HELPER_CLASS_SPACE + "CloudEnhancementTaskStage;";

static const std::string UFM_ANI_CLASS_PHOTO_ALBUM_HANDLE = USER_FILE_MANAGER_CLASS_SPACE + "AlbumHandle;";
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_ANI_SRC_INCLUDE_ANI_CLASSNAME_H