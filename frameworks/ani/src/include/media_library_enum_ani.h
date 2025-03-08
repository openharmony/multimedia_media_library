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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_LIBRARY_ENUM_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_LIBRARY_ENUM_ANI_H

#include <string>
#include "ani.h"
#include "userfile_manager_types.h"
#include "media_asset_data_handler_capi.h"

namespace OHOS {
namespace Media {

enum EnumTypeInt32 {
    PhotoTypeAni,
    PhotoSubtypeAni,
    DynamicRangeTypeAni,
    PositionTypeAni,
    AnalysisTypeAni,
    RecommendationTypeAni,
    DeliveryModeAni,
    CompatibleModeAni,
    SourceModeAni,
    PhotoPermissionTypeAni,
    HideSensitiveTypeAni,
    AuthorizationModeAni,
    CompleteButtonTextAni,
    WatermarkTypeAni,
    HiddenPhotosDisplayModeAni,
    AlbumTypeAni,
    AlbumSubtypeAni,
    RequestPhotoTypeAni,
    NotifyTypeAni,
    ResourceTypeAni,
    ImageFileTypeAni,
    MovingPhotoEffectModeAni,
    VideoEnhancementTypeAni,
    HighlightAlbumInfoTypeAni,
    HighlightUserActionTypeAni,
    ThumbnailTypeAni,
    CloudEnhancementTaskStageAni,
    CloudEnhancementStateAni,
};

enum EnumTypeString {
    PhotoKeysAni,
    AlbumKeysAni,
    DefaultChangeUriAni,
    PhotoViewMIMETypesAni,
};

class MediaLibraryEnumAni {
public:
    static ani_status EnumGetValueInt32(ani_env *env, EnumTypeInt32 enumType, ani_int enumIndex, int32_t &value);
    static ani_status EnumGetValueString(ani_env *env, EnumTypeString enumType, ani_int enumIndex, std::string &value);

    static bool EnumGetIndex(MediaType value, ani_int &enumIndex);
    static bool EnumGetIndex(PhotoSubType value, ani_int &enumIndex);
    static bool EnumGetIndex(DynamicRangeType value, ani_int &enumIndex);
    static bool EnumGetIndex(PhotoPositionType value, ani_int &enumIndex);
    static bool EnumGetIndex(PhotoAlbumType value, ani_int &enumIndex);
    static bool EnumGetIndex(PhotoAlbumSubType value, ani_int &enumIndex);
    static bool EnumGetIndex(NotifyType value, ani_int &enumIndex);
    static bool EnumGetIndex(MovingPhotoEffectMode value, ani_int &enumIndex);
    static bool EnumGetIndex(CloudEnhancementTaskStage value, ani_int &enumIndex);
};

} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_LIBRARY_ENUM_ANI_H