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

#include "media_image_framework_utils.h"

#include "exif_metadata.h"
#include "post_proc.h"

#include "medialibrary_errno.h"
#include "media_exif.h"
#include "media_log.h"

using namespace std;

namespace OHOS {
namespace Media {

int32_t MediaImageFrameWorkUtils::GetExifRotate(
    const std::unique_ptr<ImageSource> &imageSource, int32_t &exifRotate)
{
    std::string orientationKey;
    int32_t err = GetOrientationKey(imageSource, orientationKey);
    CHECK_AND_RETURN_RET(err == E_OK, err);
    CHECK_AND_RETURN_RET_LOG(ExifRotateUtils::ConvertOrientationKeyToExifRotate(orientationKey, exifRotate),
        E_ERR, "Convert orientation to exif rotate failed, orientation value:%{public}s", orientationKey.c_str());
    return E_OK;
}

int32_t MediaImageFrameWorkUtils::GetOrientationKey(const std::unique_ptr<ImageSource> &imageSource,
    std::string &orientationKey)
{
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, E_ERR, "ImageSource is nullptr");
    auto exifMetadata = imageSource->GetExifMetadata();
    CHECK_AND_RETURN_RET_LOG(exifMetadata != nullptr, E_ERR, "ExifMetadata is nullptr");

    int32_t err = exifMetadata->GetValue(PHOTO_DATA_IMAGE_ORIENTATION, orientationKey);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "Get exif rotate value failed, err:%{public}d", err);
    return E_OK;
}

int32_t MediaImageFrameWorkUtils::GetExifRotate(
    const std::shared_ptr<Picture> picture, int32_t &exifRotate)
{
    std::string orientationKey;
    int32_t err = GetOrientationKey(picture, orientationKey);
    CHECK_AND_RETURN_RET(err == E_OK, err);
    CHECK_AND_RETURN_RET_LOG(ExifRotateUtils::ConvertOrientationKeyToExifRotate(orientationKey, exifRotate),
        E_ERR, "Convert orientation to exif rotate failed, orientation value:%{public}s", orientationKey.c_str());
    return E_OK;
}

int32_t MediaImageFrameWorkUtils::GetOrientationKey(const std::shared_ptr<Picture> picture, std::string &orientationKey)
{
    CHECK_AND_RETURN_RET_LOG(picture != nullptr, E_ERR, "Picture is nullptr");
    std::shared_ptr<ExifMetadata> exifMetadata = picture->GetExifMetadata();
    CHECK_AND_RETURN_RET_LOG(exifMetadata != nullptr, E_ERR, "ExifMetadata is nullptr");

    int32_t err = exifMetadata->GetValue(PHOTO_DATA_IMAGE_ORIENTATION, orientationKey);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "Get exif rotate value failed, err:%{public}d", err);
    return E_OK;
}

int32_t MediaImageFrameWorkUtils::GetExifRotate(const std::string &path, int32_t &exifRotate)
{
    uint32_t err = 0;
    SourceOptions opts;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, err);
    CHECK_AND_RETURN_RET_LOG(err == 0 && imageSource != nullptr,
        E_ERR, "CreateImageSource failed, error:%{public}u", err);
    return GetExifRotate(imageSource, exifRotate);
}

bool MediaImageFrameWorkUtils::FlipAndRotatePixelMap(PixelMap &pixelMap, int32_t exifRotate)
{
    FlipAndRotateInfo info;
    CHECK_AND_RETURN_RET_LOG(ExifRotateUtils::GetFlipAndRotateInfo(exifRotate, info),
        false, "GetFlipAndRotateInfo failed, exifRotate:%{public}d", exifRotate);
    return FlipAndRotatePixelMap(pixelMap, info);
}

bool MediaImageFrameWorkUtils::FlipAndRotatePixelMap(PixelMap &pixelMap, const FlipAndRotateInfo &info)
{
    if (info.isLeftAndRightFlip || info.isUpAndDownFlip) {
        pixelMap.flip(info.isLeftAndRightFlip, info.isUpAndDownFlip);
    }

    if (info.orientation != 0) {
        PostProc::RotateInRectangularSteps(pixelMap, static_cast<float>(info.orientation), true);
    }
    return true;
}
} // namespace Media
} // namespace OHOS