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

#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
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
const std::string SUPER_MACRO_ALBUM_TAG = "47";
const std::string SLOW_MOTION_ALBUM_TAG = "TypeSlowMotion";
const std::string SUPER_SLOW_MOTION_ALBUM_TAG = "TypeSSlowMotion";

/* ShootingMode value in medialibrary */
const std::string PORTRAIT_ALBUM = "1";
const std::string WIDE_APERTURE_ALBUM = "2";
const std::string NIGHT_SHOT_ALBUM = "3";
const std::string MOVING_PICTURE_ALBUM = "4";
const std::string PRO_PHOTO_ALBUM = "5";
const std::string SLOW_MOTION_ALBUM = "6";
const std::string LIGHT_PAINTING_ALBUM = "7";
const std::string HIGH_PIXEL_ALBUM = "8";
const std::string SUPER_MACRO_ALBUM = "9";
};
} // namespace OHOS::Media
#endif // INTERFACES_INNERKITS_SHOOTING_MODE_COLUMN_H