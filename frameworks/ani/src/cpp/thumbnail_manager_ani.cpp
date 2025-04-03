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

#include "thumbnail_manager_ani.h"

#include <memory>
#include <mutex>
#include <sys/mman.h>
#include <sys/stat.h>

#include "ashmem.h"
#include "image_source.h"
#include "image_type.h"
#include "media_file_uri.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "media_log.h"
#include "pixel_map.h"
#include "post_proc.h"
#include "securec.h"
#include "string_ex.h"
#include "thumbnail_const.h"
#include "unique_fd.h"
#include "userfilemgr_uri.h"
#include "userfile_manager_types.h"
#include "uv.h"
#include "userfile_client.h"

#ifdef IMAGE_PURGEABLE_PIXELMAP
#include "purgeable_pixelmap_builder.h"
#endif

using namespace std;

namespace OHOS {
namespace Media {

static int OpenThumbnail(const string &path, ThumbnailType type)
{
    if (!path.empty()) {
        string sandboxPath = GetSandboxPath(path, type);
        int fd = -1;
        if (!sandboxPath.empty()) {
            fd = open(sandboxPath.c_str(), O_RDONLY);
        }
        if (fd > 0) {
            return fd;
        }
    }
    return E_ERR;
}

static int32_t GetPixelMapFromServer(const string &uriStr, const Size &size, const string &path)
{
    string openUriStr = uriStr + "?" + MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" +
        MEDIA_DATA_DB_WIDTH + "=" + to_string(size.width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" +
        to_string(size.height);
    if (IsAsciiString(path)) {
        openUriStr += "&" + THUMBNAIL_PATH + "=" + path;
    }
    Uri openUri(openUriStr);
    return UserFileClient::OpenFile(openUri, "R");
}

static PixelMapPtr CreateThumbnailByAshmem(UniqueFd &uniqueFd, const Size &size)
{
    MediaLibraryTracer tracer;
    tracer.Start("CreateThumbnailByAshmem");

    Media::InitializationOptions option = {
        .size = size,
    };
    PixelMapPtr pixel = Media::PixelMap::Create(option);
    if (pixel == nullptr) {
        MEDIA_ERR_LOG("Can not create pixel");
        return nullptr;
    }

    UniqueFd dupFd = UniqueFd(dup(uniqueFd.Get()));
    MMapFdPtr mmapFd(dupFd.Get(), false);
    if (!mmapFd.IsValid()) {
        MEDIA_ERR_LOG("Can not mmap by fd");
        return nullptr;
    }
    auto memSize = static_cast<int32_t>(mmapFd.GetFdSize());

    void* fdPtr = new int32_t();
    *static_cast<int32_t*>(fdPtr) = dupFd.Release();
    pixel->SetPixelsAddr(mmapFd.GetFdPtr(), fdPtr, memSize, Media::AllocatorType::SHARE_MEM_ALLOC, nullptr);
    return pixel;
}

static bool IfSizeEqualsRatio(const Size &imageSize, const Size &targetSize)
{
    if (imageSize.height <= 0 || targetSize.height <= 0) {
        return false;
    }

    float imageSizeScale = static_cast<float>(imageSize.width) / static_cast<float>(imageSize.height);
    float targetSizeScale = static_cast<float>(targetSize.width) / static_cast<float>(targetSize.height);
    if (imageSizeScale - targetSizeScale > FLOAT_EPSILON || targetSizeScale - imageSizeScale > FLOAT_EPSILON) {
        return false;
    } else {
        return true;
    }
}

static PixelMapPtr DecodeThumbnail(const UniqueFd &uniqueFd, const Size &size)
{
    MediaLibraryTracer tracer;
    tracer.Start("ImageSource::CreateImageSource");
    SourceOptions opts;
    uint32_t err = 0;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(uniqueFd.Get(), opts, err);
    if (imageSource == nullptr) {
        MEDIA_ERR_LOG("CreateImageSource err %{public}d", err);
        return nullptr;
    }

    ImageInfo imageInfo;
    err = imageSource->GetImageInfo(0, imageInfo);
    if (err != E_OK) {
        MEDIA_ERR_LOG("GetImageInfo err %{public}d", err);
        return nullptr;
    }

    bool isEqualsRatio = IfSizeEqualsRatio(imageInfo.size, size);
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = isEqualsRatio ? size : imageInfo.size;
    unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("CreatePixelMap err %{public}d", err);
        return nullptr;
    }

    PostProc postProc;
    if (size.width != DEFAULT_ORIGINAL && !isEqualsRatio && !postProc.CenterScale(size, *pixelMap)) {
        MEDIA_ERR_LOG("CenterScale failed, size: %{public}d * %{public}d, imageInfo size: %{public}d * %{public}d",
            size.width, size.height, imageInfo.size.width, imageInfo.size.height);
        return nullptr;
    }

    // Make the ashmem of pixelmap to be purgeable after the operation on ashmem.
    // And then make the pixelmap subject to PurgeableManager's control.
#ifdef IMAGE_PURGEABLE_PIXELMAP
    PurgeableBuilder::MakePixelMapToBePurgeable(pixelMap, imageSource, decodeOpts, size);
#endif
    return pixelMap;
}

unique_ptr<PixelMap> ThumbnailManagerAni::QueryThumbnail(const string &uriStr, const Size &size, const string &path)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryThumbnail uri:" + uriStr);
    tracer.Start("DataShare::OpenFile");
    ThumbnailType thumbType = GetThumbType(size.width, size.height);
    if (MediaFileUri::GetMediaTypeFromUri(uriStr) == MediaType::MEDIA_TYPE_AUDIO &&
        (thumbType == ThumbnailType::MTH || thumbType == ThumbnailType::YEAR)) {
        thumbType = ThumbnailType::THUMB;
    }
    UniqueFd uniqueFd(OpenThumbnail(path, thumbType));
    if (uniqueFd.Get() == E_ERR) {
        uniqueFd = UniqueFd(GetPixelMapFromServer(uriStr, size, path));
        if (uniqueFd.Get() < 0) {
            MEDIA_ERR_LOG("queryThumb is null, errCode is %{public}d", uniqueFd.Get());
            return nullptr;
        }
        return DecodeThumbnail(uniqueFd, size);
    }
    tracer.Finish();
    if (thumbType == ThumbnailType::MTH || thumbType == ThumbnailType::YEAR) {
        return CreateThumbnailByAshmem(uniqueFd, size);
    } else {
        return DecodeThumbnail(uniqueFd, size);
    }
}

}
}
