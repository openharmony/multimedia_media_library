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

#include "shooting_mode_column.h"

#include <string>

#include "abs_rdb_predicates.h"
#include "datashare_predicates.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_type_const.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "photo_query_filter.h"
#include "value_object.h"
#include "vision_column.h"

namespace OHOS::Media {
using namespace std;
using namespace NativeRdb;

template <class T>
void ShootingModeAlbum::GetMovingPhotoAlbumPredicates(T& predicates, const bool hiddenState)
{
    PhotoQueryFilter::Config config {};
    config.hiddenConfig = hiddenState ? PhotoQueryFilter::ConfigType::INCLUDE : PhotoQueryFilter::ConfigType::EXCLUDE;
    PhotoQueryFilter::ModifyPredicate(config, predicates);
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    predicates.Or();
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::MOVING_PHOTO_EFFECT_MODE,
        static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY));
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::DEFAULT));
    predicates.EndWrap();
    predicates.EndWrap();
}

template <class T>
void ShootingModeAlbum::Get3DGSAlbumPredicates(T& predicates, const bool hiddenState)
{
    PhotoQueryFilter::Config config {};
    config.hiddenConfig = hiddenState ? PhotoQueryFilter::ConfigType::INCLUDE : PhotoQueryFilter::ConfigType::EXCLUDE;
    PhotoQueryFilter::ModifyPredicate(config, predicates);
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::SPATIAL_3DGS));
}

template <class T>
void ShootingModeAlbum::GetBurstModeAlbumPredicates(T& predicates, const bool hiddenState)
{
    PhotoQueryFilter::Config config {};
    config.hiddenConfig = hiddenState ? PhotoQueryFilter::ConfigType::INCLUDE : PhotoQueryFilter::ConfigType::EXCLUDE;
    PhotoQueryFilter::ModifyPredicate(config, predicates);
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, to_string(static_cast<int32_t>(PhotoSubType::BURST)));
    predicates.IsNotNull(PhotoColumn::PHOTO_BURST_KEY);
}

template <class T>
void ShootingModeAlbum::GetFrontCameraAlbumPredicates(T& predicates, const bool hiddenState)
{
    PhotoQueryFilter::Config config {};
    config.hiddenConfig = hiddenState ? PhotoQueryFilter::ConfigType::INCLUDE : PhotoQueryFilter::ConfigType::EXCLUDE;
    PhotoQueryFilter::ModifyPredicate(config, predicates);
    predicates.EqualTo(PhotoColumn::PHOTO_FRONT_CAMERA, to_string(1));
}

template <class T>
void ShootingModeAlbum::GetRAWImageAlbumPredicates(T& predicates, const bool hiddenState)
{
    const string rawImageMimeType = "image/x-adobe-dng";
    PhotoQueryFilter::Config config {};
    config.hiddenConfig = hiddenState ? PhotoQueryFilter::ConfigType::INCLUDE : PhotoQueryFilter::ConfigType::EXCLUDE;
    PhotoQueryFilter::ModifyPredicate(config, predicates);
    predicates.EqualTo(MediaColumn::MEDIA_MIME_TYPE, rawImageMimeType);
}

template <class T>
void ShootingModeAlbum::GetGeneralShootingModeAlbumPredicates(const ShootingModeAlbumType type,
    T& predicates, const bool hiddenState)
{
    PhotoQueryFilter::Config config {};
    config.hiddenConfig = hiddenState ? PhotoQueryFilter::ConfigType::INCLUDE : PhotoQueryFilter::ConfigType::EXCLUDE;
    PhotoQueryFilter::ModifyPredicate(config, predicates);
    predicates.EqualTo(PhotoColumn::PHOTO_SHOOTING_MODE, to_string(static_cast<int32_t>(type)));
}

template <class T>
void ShootingModeAlbum::GetShootingModeAlbumPredicates(const ShootingModeAlbumType type,
    T& predicates, const bool hiddenState)
{
    switch (type) {
        case ShootingModeAlbumType::MOVING_PICTURE: {
            GetMovingPhotoAlbumPredicates(predicates, hiddenState);
            return;
        }
        case ShootingModeAlbumType::BURST_MODE_ALBUM: {
            GetBurstModeAlbumPredicates(predicates, hiddenState);
            return;
        }
        case ShootingModeAlbumType::FRONT_CAMERA_ALBUM: {
            GetFrontCameraAlbumPredicates(predicates, hiddenState);
            return;
        }
        case ShootingModeAlbumType::RAW_IMAGE_ALBUM: {
            GetRAWImageAlbumPredicates(predicates, hiddenState);
            return;
        }
        case ShootingModeAlbumType::MP4_3DGS_ALBUM: {
            Get3DGSAlbumPredicates(predicates, hiddenState);
            return;
        }
        default: {
            GetGeneralShootingModeAlbumPredicates(type, predicates, hiddenState);
            return;
        }
    }
}

bool ShootingModeAlbum::AlbumNameToShootingModeAlbumType(const std::string& albumName,
    ShootingModeAlbumType& parseResult)
{
    int32_t albumValue = atoi(albumName.c_str());
    if (albumValue < static_cast<int32_t>(ShootingModeAlbumType::START) ||
        albumValue > static_cast<int32_t>(ShootingModeAlbumType::END)) {
        MEDIA_ERR_LOG("album name can not be converted to shooting mode album type, input: %{public}s",
            albumName.c_str());
        return false;
    }
    parseResult = static_cast<ShootingModeAlbumType>(albumValue);
    return true;
}

string ShootingModeAlbum::GetQueryAssetsIndex(const ShootingModeAlbumType type)
{
    static const std::unordered_map<ShootingModeAlbumType, std::string> SHOOTING_MODE_INDEX_MAP = {
        {ShootingModeAlbumType::PORTRAIT, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::WIDE_APERTURE, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::NIGHT_SHOT, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::MOVING_PICTURE, PhotoColumn::PHOTO_MOVING_PHOTO_ALBUM_INDEX},
        {ShootingModeAlbumType::PRO_PHOTO, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::SLOW_MOTION, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::LIGHT_PAINTING, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::HIGH_PIXEL, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::SUPER_MACRO, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::PANORAMA_MODE, PhotoColumn::PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX},
        {ShootingModeAlbumType::BURST_MODE_ALBUM, PhotoColumn::PHOTO_BURST_MODE_ALBUM_INDEX},
        {ShootingModeAlbumType::FRONT_CAMERA_ALBUM, PhotoColumn::PHOTO_FRONT_CAMERA_ALBUM_INDEX},
        {ShootingModeAlbumType::RAW_IMAGE_ALBUM, PhotoColumn::PHOTO_RAW_IMAGE_ALBUM_INDEX},
        {ShootingModeAlbumType::MP4_3DGS_ALBUM, PhotoColumn::PHOTO_BURST_MODE_ALBUM_INDEX},
    };
    if (SHOOTING_MODE_INDEX_MAP.find(type) == SHOOTING_MODE_INDEX_MAP.end()) {
        MEDIA_ERR_LOG("Shooting mode type %{public}d is not in the map", static_cast<int32_t>(type));
        return "";
    }
    return SHOOTING_MODE_INDEX_MAP.at(type);
}

bool ShootingModeAlbum::IsAssetInMovingPhotoAlbum(int32_t photoSubType, int32_t movingPhotoEffectMode)
{
    return photoSubType == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO) ||
        (photoSubType == static_cast<int32_t>(PhotoSubType::DEFAULT) &&
           movingPhotoEffectMode == static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY));
}

vector<ShootingModeAlbumType> ShootingModeAlbum::GetShootingModeAlbumOfAsset(int32_t photoSubType,
    const string& mimetype, int32_t movingPhotoEffectMode, const string& frontCamera, const string& shootingMode)
{
    vector<ShootingModeAlbumType> result;
    if (photoSubType == static_cast<int32_t>(PhotoSubType::BURST)) {
        result.push_back(ShootingModeAlbumType::BURST_MODE_ALBUM);
    }
    if (photoSubType == static_cast<int32_t>(PhotoSubType::SPATIAL_3DGS)) {
        result.push_back(ShootingModeAlbumType::MP4_3DGS_ALBUM);
    }
    if (mimetype == "image/x-adobe-dng") {
        result.push_back(ShootingModeAlbumType::RAW_IMAGE_ALBUM);
    }
    if (IsAssetInMovingPhotoAlbum(photoSubType, movingPhotoEffectMode)) {
        result.push_back(ShootingModeAlbumType::MOVING_PICTURE);
    }
    if (frontCamera == "1") { // "1" means photo is taken using front camera
        result.push_back(ShootingModeAlbumType::FRONT_CAMERA_ALBUM);
    }
    if (!shootingMode.empty()) {
        ShootingModeAlbumType type;
        if (AlbumNameToShootingModeAlbumType(shootingMode, type) &&
            type != ShootingModeAlbumType::MOVING_PICTURE &&
            type != ShootingModeAlbumType::BURST_MODE_ALBUM &&
            type != ShootingModeAlbumType::FRONT_CAMERA_ALBUM &&
            type != ShootingModeAlbumType::RAW_IMAGE_ALBUM &&
            type != ShootingModeAlbumType::MP4_3DGS_ALBUM) {
            result.push_back(type);
        }
    }
    return result;
}

string ShootingModeAlbum::MapShootingModeTagToShootingMode(const string& tag)
{
    static const std::unordered_map<std::string, std::string> SHOOTING_MODE_CAST_MAP = {
        {PORTRAIT_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::PORTRAIT))},
        {WIDE_APERTURE_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::WIDE_APERTURE))},
        {NIGHT_SHOT_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::NIGHT_SHOT))},
        {REAR_CAMERA_NIGHT_SHOT_TAG, to_string(static_cast<int>(ShootingModeAlbumType::NIGHT_SHOT))},
        {MOVING_PICTURE_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::MOVING_PICTURE))},
        {PRO_PHOTO_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::PRO_PHOTO))},
        {TAIL_LIGHT_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::LIGHT_PAINTING))},
        {LIGHT_GRAFFITI_TAG, to_string(static_cast<int>(ShootingModeAlbumType::LIGHT_PAINTING))},
        {SILKY_WATER_TAG, to_string(static_cast<int>(ShootingModeAlbumType::LIGHT_PAINTING))},
        {STAR_TRACK_TAG, to_string(static_cast<int>(ShootingModeAlbumType::LIGHT_PAINTING))},
        {AI_HIGH_PIXEL_TAG, to_string(static_cast<int>(ShootingModeAlbumType::HIGH_PIXEL))},
        {HIGH_PIXEL_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::HIGH_PIXEL))},
        {SUPER_MACRO_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::SUPER_MACRO))},
        {SLOW_MOTION_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::SLOW_MOTION))},
        {SUPER_SLOW_MOTION_ALBUM_TAG, to_string(static_cast<int>(ShootingModeAlbumType::SLOW_MOTION))},
        {CAMERA_CUSTOM_SM_PANORAMA, to_string(static_cast<int>(ShootingModeAlbumType::PANORAMA_MODE))},
        {CAMERA_CUSTOM_SM_PHOTO_STITCHING, to_string(static_cast<int>(ShootingModeAlbumType::PANORAMA_MODE))},
    };

    auto it = SHOOTING_MODE_CAST_MAP.find(tag);
    if (it != SHOOTING_MODE_CAST_MAP.end()) {
        return it->second;
    }
    return "";
}

template void ShootingModeAlbum::GetMovingPhotoAlbumPredicates<DataShare::DataSharePredicates>(
    DataShare::DataSharePredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetMovingPhotoAlbumPredicates<NativeRdb::RdbPredicates>(
    NativeRdb::RdbPredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::Get3DGSAlbumPredicates<DataShare::DataSharePredicates>(
    DataShare::DataSharePredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::Get3DGSAlbumPredicates<NativeRdb::RdbPredicates>(
    NativeRdb::RdbPredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetBurstModeAlbumPredicates<DataShare::DataSharePredicates>(
    DataShare::DataSharePredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetBurstModeAlbumPredicates<NativeRdb::RdbPredicates>(
    NativeRdb::RdbPredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetFrontCameraAlbumPredicates<DataShare::DataSharePredicates>(
    DataShare::DataSharePredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetFrontCameraAlbumPredicates<NativeRdb::RdbPredicates>(
    NativeRdb::RdbPredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetRAWImageAlbumPredicates<DataShare::DataSharePredicates>(
    DataShare::DataSharePredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetRAWImageAlbumPredicates<NativeRdb::RdbPredicates>(
    NativeRdb::RdbPredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetGeneralShootingModeAlbumPredicates<DataShare::DataSharePredicates>(
    const ShootingModeAlbumType type, DataShare::DataSharePredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetGeneralShootingModeAlbumPredicates<NativeRdb::RdbPredicates>(
    const ShootingModeAlbumType type, NativeRdb::RdbPredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetShootingModeAlbumPredicates<DataShare::DataSharePredicates>(
    const ShootingModeAlbumType type, DataShare::DataSharePredicates& predicates, const bool hiddenState);

template void ShootingModeAlbum::GetShootingModeAlbumPredicates<NativeRdb::RdbPredicates>(
    const ShootingModeAlbumType type, NativeRdb::RdbPredicates& predicates, const bool hiddenState);

} // namespace OHOS::Media