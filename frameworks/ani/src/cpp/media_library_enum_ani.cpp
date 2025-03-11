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

#include "media_library_enum_ani.h"

#include "ani_class_name.h"
#include "medialibrary_ani_utils.h"

namespace OHOS {
namespace Media {

static const std::map<EnumTypeInt32, std::string> ENUM_TYPE_MAP_INT32 = {
    {EnumTypeInt32::PhotoTypeAni, ANI_CLASS_ENUM_PHOTO_TYPE},
    {EnumTypeInt32::PhotoSubtypeAni, ANI_CLASS_ENUM_PHOTO_SUBTYPE},
    {EnumTypeInt32::DynamicRangeTypeAni, ANI_CLASS_ENUM_DYNAMIC_RANGE_TYPE},
    {EnumTypeInt32::PositionTypeAni, ANI_CLASS_ENUM_POSITION_TYPE},
    {EnumTypeInt32::AnalysisTypeAni, ANI_CLASS_ENUM_ANALYSIS_TYPE},
    {EnumTypeInt32::RecommendationTypeAni, ANI_CLASS_ENUM_RECOMMENDATION_TYPE},
    {EnumTypeInt32::DeliveryModeAni, ANI_CLASS_ENUM_DELIVERY_MODE},
    {EnumTypeInt32::CompatibleModeAni, ANI_CLASS_ENUM_COMPATIBLE_MODE},
    {EnumTypeInt32::SourceModeAni, ANI_CLASS_ENUM_SOURCE_MODE},
    {EnumTypeInt32::PhotoPermissionTypeAni, ANI_CLASS_ENUM_PHOTO_PERMISSION_TYPE},
    {EnumTypeInt32::HideSensitiveTypeAni, ANI_CLASS_ENUM_HIDE_SENSITIVE_TYPE},
    {EnumTypeInt32::AuthorizationModeAni, ANI_CLASS_ENUM_AUTHORIZATION_MODE},
    {EnumTypeInt32::CompleteButtonTextAni, ANI_CLASS_ENUM_COMPLETE_BUTTON_TEXT},
    {EnumTypeInt32::WatermarkTypeAni, ANI_CLASS_ENUM_WATERMARK_TYPE},
    {EnumTypeInt32::HiddenPhotosDisplayModeAni, ANI_CLASS_ENUM_HIDDEN_PHOTOS_DISPLAY_MODE},
    {EnumTypeInt32::AlbumTypeAni, ANI_CLASS_ENUM_ALBUM_TYPE},
    {EnumTypeInt32::AlbumSubtypeAni, ANI_CLASS_ENUM_ALBUM_SUBTYPE},
    {EnumTypeInt32::RequestPhotoTypeAni, ANI_CLASS_ENUM_REQUEST_PHOTO_TYPE},
    {EnumTypeInt32::NotifyTypeAni, ANI_CLASS_ENUM_NOTIFY_TYPE},
    {EnumTypeInt32::ResourceTypeAni, ANI_CLASS_ENUM_RESOURCE_TYPE},
    {EnumTypeInt32::ImageFileTypeAni, ANI_CLASS_ENUM_IMAGE_FILE_TYPE},
    {EnumTypeInt32::MovingPhotoEffectModeAni, ANI_CLASS_ENUM_MOVING_PHOTO_EFFECT_MODE},
    {EnumTypeInt32::VideoEnhancementTypeAni, ANI_CLASS_ENUM_VIDEO_ENHANCEMENT_TYPE},
    {EnumTypeInt32::HighlightAlbumInfoTypeAni, ANI_CLASS_ENUM_HIGHLIGHT_ALBUM_INFO_TYPE},
    {EnumTypeInt32::HighlightUserActionTypeAni, ANI_CLASS_ENUM_HIGHLIGHT_USER_ACTION_TYPE},
    {EnumTypeInt32::ThumbnailTypeAni, ANI_CLASS_ENUM_THUMBNAIL_TYPE},
    {EnumTypeInt32::CloudEnhancementTaskStageAni, ANI_CLASS_ENUM_CLOUD_ENHANCEMENT_TASK_STAGE},
    {EnumTypeInt32::CloudEnhancementStateAni, ANI_CLASS_ENUM_CLOUD_ENHANCEMENT_STATE},
};

static const std::map<EnumTypeString, std::string> ENUM_TYPE_MAP_STRING = {
    {EnumTypeString::PhotoKeysAni, ANI_CLASS_ENUM_PHOTO_KEYS},
    {EnumTypeString::AlbumKeysAni, ANI_CLASS_ENUM_ALBUM_KEYS},
    {EnumTypeString::DefaultChangeUriAni, ANI_CLASS_ENUM_DEFAULT_CHANGE_URI},
    {EnumTypeString::PhotoViewMIMETypesAni, ANI_CLASS_ENUM_PHOTO_VIEW_MIME_TYPES},
};

static const std::map<MediaType, int32_t> ANI_MEDIATYPE_INDEX_MAP = {
    {MediaType::MEDIA_TYPE_IMAGE, 0},
    {MediaType::MEDIA_TYPE_VIDEO, 1},
};

static const std::map<PhotoSubType, int32_t> ANI_PHOTOSUBTYPE_INDEX_MAP = {
    {PhotoSubType::DEFAULT, 0},
    {PhotoSubType::SCREENSHOT, 1},
    {PhotoSubType::MOVING_PHOTO, 2},
    {PhotoSubType::BURST, 3},
};

static const std::map<DynamicRangeType, int32_t> ANI_DYNAMICRANGETYPE_INDEX_MAP = {
    {DynamicRangeType::SDR, 0},
    {DynamicRangeType::HDR, 1},
};

static const std::map<PhotoPositionType, int32_t> ANI_PHOTOPOSITIONTYPE_INDEX_MAP = {
    {PhotoPositionType::LOCAL, 0},
    {PhotoPositionType::CLOUD, 1},
};

static const std::map<PhotoAlbumType, int32_t> ANI_PHOTOALBUMTYPE_INDEX_MAP = {
    {PhotoAlbumType::USER, 0},
    {PhotoAlbumType::SYSTEM, 1},
    {PhotoAlbumType::SMART, 2},
};

static const std::map<PhotoAlbumSubType, int32_t> ANI_PHOTOALBUMSUBTYPE_INDEX_MAP = {
    {PhotoAlbumSubType::USER_GENERIC, 0},
    {PhotoAlbumSubType::FAVORITE, 1},
    {PhotoAlbumSubType::VIDEO, 2},
    {PhotoAlbumSubType::HIDDEN, 3},
    {PhotoAlbumSubType::TRASH, 4},
    {PhotoAlbumSubType::SCREENSHOT, 5},
    {PhotoAlbumSubType::CAMERA, 6},
    {PhotoAlbumSubType::IMAGE, 7},
    {PhotoAlbumSubType::CLOUD_ENHANCEMENT, 8},
    {PhotoAlbumSubType::SOURCE_GENERIC, 9},
    {PhotoAlbumSubType::CLASSIFY, 10},
    {PhotoAlbumSubType::GEOGRAPHY_LOCATION, 11},
    {PhotoAlbumSubType::GEOGRAPHY_CITY, 12},
    {PhotoAlbumSubType::SHOOTING_MODE, 13},
    {PhotoAlbumSubType::PORTRAIT, 14},
    {PhotoAlbumSubType::GROUP_PHOTO, 15},
    {PhotoAlbumSubType::HIGHLIGHT, 16},
    {PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS, 17},
    {PhotoAlbumSubType::ANY, 18},
};

static const std::map<NotifyType, int32_t> ANI_NOTIFYTYPE_INDEX_MAP = {
    {NotifyType::NOTIFY_ADD, 0},
    {NotifyType::NOTIFY_UPDATE, 1},
    {NotifyType::NOTIFY_REMOVE, 2},
    {NotifyType::NOTIFY_ALBUM_ADD_ASSET, 3},
    {NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, 4},
};

static const std::map<MovingPhotoEffectMode, int32_t> ANI_MOVINGPHOTOEFFECTMODE_INDEX_MAP = {
    {MovingPhotoEffectMode::DEFAULT, 0},
    {MovingPhotoEffectMode::BOUNCE_PLAY, 1},
    {MovingPhotoEffectMode::LOOP_PLAY, 2},
    {MovingPhotoEffectMode::LONG_EXPOSURE, 3},
    {MovingPhotoEffectMode::MULTI_EXPOSURE, 4},
    {MovingPhotoEffectMode::CINEMA_GRAPH, 5},
    {MovingPhotoEffectMode::IMAGE_ONLY, 6},
};

static const std::map<CloudEnhancementTaskStage, int32_t> ANI_CLOUDENHANCEMENTTASKSTAGE_INDEX_MAP = {
    {CloudEnhancementTaskStage::TASK_STAGE_EXCEPTION, 0},
    {CloudEnhancementTaskStage::TASK_STAGE_PREPARING, 1},
    {CloudEnhancementTaskStage::TASK_STAGE_UPLOADING, 2},
    {CloudEnhancementTaskStage::TASK_STAGE_EXECUTING, 3},
    {CloudEnhancementTaskStage::TASK_STAGE_DOWNLOADING, 4},
    {CloudEnhancementTaskStage::TASK_STAGE_FAILED, 5},
    {CloudEnhancementTaskStage::TASK_STAGE_COMPLETED, 6},
};

ani_status MediaLibraryEnumAni::EnumGetValueInt32(ani_env *env, EnumTypeInt32 enumType, ani_enum_item enumItem,
    int32_t &value)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ENUM_TYPE_MAP_INT32.find(enumType);
    CHECK_COND_RET(it != ENUM_TYPE_MAP_INT32.end(), ANI_INVALID_ARGS, "Invalid enumType: %{public}d", enumType);

    ani_enum aniEnum {};
    CHECK_STATUS_RET(env->FindEnum(it->second.c_str(), &aniEnum), "FindEnum failed");

    ani_int aniInt {};
    CHECK_STATUS_RET(env->EnumItem_GetValue_Int(enumItem, &aniInt), "EnumItem_GetValue_Int failed");
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetInt32(env, aniInt, value), "GetInt32 failed");
    return ANI_OK;
}

ani_status MediaLibraryEnumAni::EnumGetValueString(ani_env *env, EnumTypeString enumType, ani_enum_item enumItem,
    std::string &value)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ENUM_TYPE_MAP_STRING.find(enumType);
    CHECK_COND_RET(it != ENUM_TYPE_MAP_STRING.end(), ANI_INVALID_ARGS, "Invalid enumType: %{public}d", enumType);

    ani_enum aniEnum {};
    CHECK_STATUS_RET(env->FindEnum(it->second.c_str(), &aniEnum), "FindEnum failed");

    ani_string aniString {};
    CHECK_STATUS_RET(env->EnumItem_GetValue_String(enumItem, &aniString), "EnumItem_GetValue_String failed");
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetString(env, aniString, value), "GetString failed");
    return ANI_OK;
}

bool MediaLibraryEnumAni::EnumGetIndex(MediaType value, ani_int &enumIndex)
{
    auto it = ANI_MEDIATYPE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_MEDIATYPE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

bool MediaLibraryEnumAni::EnumGetIndex(PhotoSubType value, ani_int &enumIndex)
{
    auto it = ANI_PHOTOSUBTYPE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_PHOTOSUBTYPE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

bool MediaLibraryEnumAni::EnumGetIndex(DynamicRangeType value, ani_int &enumIndex)
{
    auto it = ANI_DYNAMICRANGETYPE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_DYNAMICRANGETYPE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

bool MediaLibraryEnumAni::EnumGetIndex(PhotoPositionType value, ani_int &enumIndex)
{
    auto it = ANI_PHOTOPOSITIONTYPE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_PHOTOPOSITIONTYPE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

bool MediaLibraryEnumAni::EnumGetIndex(PhotoAlbumType value, ani_int &enumIndex)
{
    auto it = ANI_PHOTOALBUMTYPE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_PHOTOALBUMTYPE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

bool MediaLibraryEnumAni::EnumGetIndex(PhotoAlbumSubType value, ani_int &enumIndex)
{
    auto it = ANI_PHOTOALBUMSUBTYPE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_PHOTOALBUMSUBTYPE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

bool MediaLibraryEnumAni::EnumGetIndex(NotifyType value, ani_int &enumIndex)
{
    auto it = ANI_NOTIFYTYPE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_NOTIFYTYPE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

bool MediaLibraryEnumAni::EnumGetIndex(MovingPhotoEffectMode value, ani_int &enumIndex)
{
    auto it = ANI_MOVINGPHOTOEFFECTMODE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_MOVINGPHOTOEFFECTMODE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

bool MediaLibraryEnumAni::EnumGetIndex(CloudEnhancementTaskStage value, ani_int &enumIndex)
{
    auto it = ANI_CLOUDENHANCEMENTTASKSTAGE_INDEX_MAP.find(value);
    CHECK_COND_RET(it != ANI_CLOUDENHANCEMENTTASKSTAGE_INDEX_MAP.end(), false, "Unsupport enum: %{public}d", value);
    enumIndex = static_cast<ani_int>(it->second);
    return true;
}

} // namespace Media
} // namespace OHOS