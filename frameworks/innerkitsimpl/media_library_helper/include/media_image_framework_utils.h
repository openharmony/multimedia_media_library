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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_IMAGE_FRAMEWORK_UTILS_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_IMAGE_FRAMEWORK_UTILS_H_

#include "image_source.h"
#include "picture.h"

#include "exif_rotate_utils.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT MediaImageFrameWorkUtils {
public:
    MediaImageFrameWorkUtils() = delete;
    virtual ~MediaImageFrameWorkUtils() = delete;

    static int32_t GetExifRotate(const std::unique_ptr<ImageSource> &imageSource, int32_t &exifRotate);
    static int32_t GetOrientationKey(const std::unique_ptr<ImageSource> &imageSource, std::string &orientationKey);
    static int32_t GetExifRotate(const std::shared_ptr<Picture> picture, int32_t &exifRotate);
    static int32_t GetOrientationKey(const std::shared_ptr<Picture> picture, std::string &orientationKey);
    static int32_t GetExifRotate(const std::string &path, int32_t &exifRotate);
    static bool FlipAndRotatePixelMap(PixelMap &pixelMap, int32_t exifRotate);
    static bool FlipAndRotatePixelMap(PixelMap &pixelMap, const FlipAndRotateInfo &info);
    static HdrMode ConvertImageHdrTypeToHdrMode(ImageHdrType hdrType);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_IMAGE_FRAMEWORK_UTILS_H_