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

#include "exif_rotate_utils.h"

#include "media_log.h"

namespace OHOS {
namespace Media {

const std::unordered_map<std::string, int32_t> EXIF_ROTATE_TYPE_MAP = {
    {"Top-left", static_cast<int32_t>(ExifRotateType::TOP_LEFT)},
    {"Top-right", static_cast<int32_t>(ExifRotateType::TOP_RIGHT)},
    {"Bottom-right", static_cast<int32_t>(ExifRotateType::BOTTOM_RIGHT)},
    {"Bottom-left", static_cast<int32_t>(ExifRotateType::BOTTOM_LEFT)},
    {"Left-top", static_cast<int32_t>(ExifRotateType::LEFT_TOP)},
    {"Right-top", static_cast<int32_t>(ExifRotateType::RIGHT_TOP)},
    {"Right-bottom", static_cast<int32_t>(ExifRotateType::RIGHT_BOTTOM)},
    {"Left-bottom", static_cast<int32_t>(ExifRotateType::LEFT_BOTTOM)},
};

const std::unordered_map<int32_t, int32_t> ORIENTATION_EXIF_ROTATE_TYPE_MAP = {
    {0, static_cast<int32_t>(ExifRotateType::TOP_LEFT)},
    {180, static_cast<int32_t>(ExifRotateType::BOTTOM_RIGHT)},
    {90, static_cast<int32_t>(ExifRotateType::RIGHT_TOP)},
    {270, static_cast<int32_t>(ExifRotateType::LEFT_BOTTOM)},
};

const std::unordered_map<int32_t, FlipAndRotateInfo> EXIF_ROTATE_INFO_MAP = {
    {static_cast<int32_t>(ExifRotateType::TOP_LEFT), {false, false, 0}},
    {static_cast<int32_t>(ExifRotateType::TOP_RIGHT), {true, false, 0}},
    {static_cast<int32_t>(ExifRotateType::BOTTOM_RIGHT), {false, false, 180}},
    {static_cast<int32_t>(ExifRotateType::BOTTOM_LEFT), {false, true, 0}},
    {static_cast<int32_t>(ExifRotateType::LEFT_TOP), {true, false, 270}},
    {static_cast<int32_t>(ExifRotateType::RIGHT_TOP), {false, false, 90}},
    {static_cast<int32_t>(ExifRotateType::RIGHT_BOTTOM), {true, false, 90}},
    {static_cast<int32_t>(ExifRotateType::LEFT_BOTTOM), {false, false, 270}},
};

bool ExifRotateUtils::ConvertOrientationKeyToExifRotate(const std::string &key, int32_t &exifRotate)
{
    auto it = EXIF_ROTATE_TYPE_MAP.find(key);
    CHECK_AND_RETURN_RET_LOG(it != EXIF_ROTATE_TYPE_MAP.end(), false,
        "ExifRotate key:%{public}s is invalid", key.c_str());
    exifRotate = it->second;
    return true;
}

bool ExifRotateUtils::ConvertOrientationToExifRotate(int32_t orientation, int32_t &exifRotate)
{
    auto it = ORIENTATION_EXIF_ROTATE_TYPE_MAP.find(orientation);
    CHECK_AND_RETURN_RET_LOG(it != ORIENTATION_EXIF_ROTATE_TYPE_MAP.end(), false,
        "Orientation:%{public}d is invalid", orientation);
    exifRotate = it->second;
    return true;
}

bool ExifRotateUtils::IsExifRotateWithFlip(int32_t exifRotate)
{
    return exifRotate == static_cast<int32_t>(ExifRotateType::TOP_RIGHT) ||
        exifRotate == static_cast<int32_t>(ExifRotateType::BOTTOM_LEFT) ||
        exifRotate == static_cast<int32_t>(ExifRotateType::LEFT_TOP) ||
        exifRotate == static_cast<int32_t>(ExifRotateType::RIGHT_BOTTOM);
}

bool ExifRotateUtils::GetFlipAndRotateInfo(int32_t exifRotate, FlipAndRotateInfo &info)
{
    auto it = EXIF_ROTATE_INFO_MAP.find(exifRotate);
    CHECK_AND_RETURN_RET_LOG(it != EXIF_ROTATE_INFO_MAP.end(), false, "ExifRotate:%{public}d is invalid", exifRotate);
    info = it->second;
    return true;
}
} // namespace Media
} // namespace OHOS