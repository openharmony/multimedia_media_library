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

#ifndef INTERFACES_INNERKITS_SHOOTING_MODE_COLUMN_H
#define INTERFACES_INNERKITS_SHOOTING_MODE_COLUMN_H

#include <string>

#include "rdb_predicates.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {

#define EXPORT __attribute__ ((visibility ("default")))
/* ShootingMode album const values */
constexpr int32_t SHOOTING_MODE_TYPE = PhotoAlbumType::SMART;
constexpr int32_t SHOOTING_MODE_SUB_TYPE = PhotoAlbumSubType::SHOOTING_MODE;

/* ShootingMode tag value wrote by camera */
const std::string PORTRAIT_ALBUM_TAG = "23";
const std::string WIDE_APERTURE_ALBUM_TAG = "19";
const std::string NIGHT_SHOT_ALBUM_TAG = "7";
const std::string REAR_CAMERA_NIGHT_SHOT_TAG = "42";
const std::string MOVING_PICTURE_ALBUM_TAG = "20";
const std::string PRO_PHOTO_ALBUM_TAG = "2";
const std::string TAIL_LIGHT_ALBUM_TAG = "9";
const std::string LIGHT_GRAFFITI_TAG = "10";
const std::string SILKY_WATER_TAG = "11";
const std::string STAR_TRACK_TAG = "12";
const std::string HIGH_PIXEL_ALBUM_TAG = "53";
const std::string AI_HIGH_PIXEL_TAG = "52";
const std::string SUPER_MACRO_ALBUM_TAG = "47";
const std::string SLOW_MOTION_ALBUM_TAG = "TypeSlowMotion";
const std::string SUPER_SLOW_MOTION_ALBUM_TAG = "TypeSSlowMotion";
const std::string CAMERA_CUSTOM_SM_PANORAMA = "8";
const std::string CAMERA_CUSTOM_SM_PHOTO_STITCHING = "77";

/* ShootingMode value in medialibrary */
enum class ShootingModeAlbumType : int32_t {
    START = 1,
    PORTRAIT = 1,
    WIDE_APERTURE,
    NIGHT_SHOT,
    MOVING_PICTURE,
    PRO_PHOTO,
    SLOW_MOTION,
    LIGHT_PAINTING,
    HIGH_PIXEL,
    SUPER_MACRO,
    PANORAMA_MODE,
    BURST_MODE_ALBUM,
    FRONT_CAMERA_ALBUM,
    RAW_IMAGE_ALBUM,
    END = RAW_IMAGE_ALBUM
};

class ShootingModeAlbum {
public:
    template <class T>
    EXPORT static void GetMovingPhotoAlbumPredicates(const int32_t albumId, T& predicates,
        const bool hiddenState);

    template <class T>
    EXPORT static void GetBurstModeAlbumPredicates(T& predicates, const bool hiddenState);

    template <class T>
    EXPORT static void GetFrontCameraAlbumPredicates(T& predicates, const bool hiddenState);

    template <class T>
    EXPORT static void GetRAWImageAlbumPredicates(T& predicates, const bool hiddenState);

    template <class T>
    EXPORT static void GetGeneralShootingModeAlbumPredicates(const ShootingModeAlbumType type, T& predicates,
        const bool hiddenState);

    template <class T>
    EXPORT static void GetShootingModeAlbumPredicates(const int32_t albumId, const ShootingModeAlbumType type,
        T& predicates, const bool hiddenState);

    EXPORT static bool AlbumNameToShootingModeAlbumType(const std::string& albumName,
        ShootingModeAlbumType& parseResult);
    EXPORT static std::string GetQueryAssetsIndex(const ShootingModeAlbumType type);
    EXPORT static bool IsAssetInMovingPhotoAlbum(int32_t photoSubType, int32_t movingPhotoEffectMode);
    EXPORT static std::string MapShootingModeTagToShootingMode(const std::string& tag);

    // Get all shooting mode albums that the asset is in.
    EXPORT static std::vector<ShootingModeAlbumType> GetShootingModeAlbumOfAsset(int32_t photoSubType,
        const std::string& mimetype, int32_t movingPhotoEffectMode, const std::string& frontCamera,
        const std::string& shootingMode);
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_INNERKITS_SHOOTING_MODE_COLUMN_H