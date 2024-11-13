/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_PICTURE_HANDLE_CLIENT_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_PICTURE_HANDLE_CLIENT_H

#include <optional>

#include "message_parcel.h"
#include "picture.h"
#include "surface_buffer.h"

namespace OHOS {
namespace Media {

static const int UINT32_LEN = sizeof(uint32_t);

class PictureHandlerClient {
public:
    static std::shared_ptr<Media::Picture> RequestPicture(const int32_t &fileId, int32_t &errCode);

private:
    static void FinishRequestPicture(const int32_t &fileId);
    static std::optional<uint32_t> ReadMessageLength(const int32_t &fd);
    static std::optional<std::pair<uint32_t, uint8_t*>> ReadMessage(uint8_t *addr, const uint32_t &msgLen);
    static std::unique_ptr<Media::Picture> ParsePicture(MessageParcel &pictureParcel, uint8_t *addr,
        const uint32_t &msgLen, int32_t &err);
    static int32_t ReadPicture(const int32_t &fd, const int32_t &fileId, std::shared_ptr<Media::Picture> &picture,
        int32_t &err);
    static std::shared_ptr<PixelMap> ReadPixelMap(MessageParcel &data, int32_t &err);
    static bool ReadAuxiliaryPicture(MessageParcel &data, std::unique_ptr<Media::Picture> &picture, int32_t &err);
    static bool ReadAuxiliaryPictureInfo(MessageParcel &data, AuxiliaryPictureInfo &auxiliaryPictureInfo);
    static bool ReadImageInfo(MessageParcel &data, ImageInfo &imageInfo);
    static bool ReadYuvDataInfo(MessageParcel &data, YUVDataInfo &yuvInfo);
    static bool ReadSurfaceBuffer(MessageParcel &data, std::unique_ptr<PixelMap> &pixelMap, int32_t &err);
    static BufferHandle* CreateBufferHandle(MessageParcel &data, const uint32_t &reserveFds,
        const uint32_t &reserveInts);
    static bool ReadBufferHandle(MessageParcel &data, sptr<SurfaceBuffer> &surfaceBuffer, int32_t &err);
    static bool ReadExifMetadata(MessageParcel &data, std::unique_ptr<Media::Picture> &picture);
    static bool ReadMaintenanceData(MessageParcel &data, std::unique_ptr<Media::Picture> &picture, int32_t &err);
    static int32_t RequestBufferHandlerFd(const int32_t &fd);
};
}
}
#endif