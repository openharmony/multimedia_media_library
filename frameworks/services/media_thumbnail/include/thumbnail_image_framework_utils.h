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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_IMAGE_FRAMEWORK_UTILS_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_IMAGE_FRAMEWORK_UTILS_H_

#include "picture.h"
#include "surface_buffer.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class ThumbnailImageFrameWorkUtils {
public:
    EXPORT ThumbnailImageFrameWorkUtils() = delete;
    EXPORT virtual ~ThumbnailImageFrameWorkUtils() = delete;

    EXPORT static bool IsYuvPixelMap(std::shared_ptr<PixelMap> pixelMap);
    EXPORT static std::shared_ptr<Picture> CopyPictureSource(std::shared_ptr<Picture> picture);
    EXPORT static std::shared_ptr<PixelMap> CopyPixelMapSource(std::shared_ptr<PixelMap> pixelMap);
    EXPORT static int32_t GetPictureOrientation(std::shared_ptr<Picture> picture, int32_t &orientation);

private:
    EXPORT static std::shared_ptr<PixelMap> CopyNormalPixelmap(std::shared_ptr<PixelMap> pixelMap);
    EXPORT static std::shared_ptr<PixelMap> CopyYuvPixelmap(std::shared_ptr<PixelMap> pixelMap);
    EXPORT static std::shared_ptr<PixelMap> CopyYuvPixelmapWithSurfaceBuffer(std::shared_ptr<PixelMap> pixelMap);
    EXPORT static std::shared_ptr<PixelMap> CopyNoSurfaceBufferYuvPixelmap(std::shared_ptr<PixelMap> pixelMap);
    EXPORT static void SetPixelMapYuvInfo(sptr<SurfaceBuffer> &surfaceBuffer,
        std::shared_ptr<PixelMap> pixelMap, bool isHdr);
    EXPORT static void CopySurfaceBufferInfo(sptr<SurfaceBuffer> &source, sptr<SurfaceBuffer> &dst);
    EXPORT static bool GetSbStaticMetadata(const sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &staticMetadata);
    EXPORT static bool GetSbDynamicMetadata(const sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &dynamicMetadata);
    EXPORT static bool SetSbStaticMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &staticMetadata);
    EXPORT static bool SetSbDynamicMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &dynamicMetadata);
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_IMAGE_FRAMEWORK_UTILS_H_
