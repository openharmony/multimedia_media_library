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
 *
 * epfs.h, keep same with fs/epfs/epfs.h
 *
 */

#ifndef OHOS_MEDIALIBRARY_EXIF_ROTATE_UTILS_H
#define OHOS_MEDIALIBRARY_EXIF_ROTATE_UTILS_H

#include <string>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

enum class ExifRotateType : int32_t {
    TOP_LEFT = 1,
    TOP_RIGHT = 2,
    BOTTOM_RIGHT = 3,
    BOTTOM_LEFT = 4,
    LEFT_TOP = 5,
    RIGHT_TOP = 6,
    RIGHT_BOTTOM = 7,
    LEFT_BOTTOM = 8,
};

struct FlipAndRotateInfo {
    bool isLeftAndRightFlip {false};
    bool isUpAndDownFlip {false};
    int32_t orientation {0};
};

class EXPORT ExifRotateUtils {
public:
    ExifRotateUtils() = delete;
    virtual ~ExifRotateUtils() = delete;

    static bool ConvertOrientationKeyToExifRotate(const std::string &key, int32_t &exifRotate);
    static bool ConvertOrientationToExifRotate(int32_t orientation, int32_t &exifRotate);
    static bool IsExifRotateWithFlip(int32_t exifRotate);
    static bool GetFlipAndRotateInfo(int32_t exifRotate, FlipAndRotateInfo &info);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_EXIF_ROTATE_UTILS_H