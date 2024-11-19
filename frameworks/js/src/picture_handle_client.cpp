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

#include "picture_handle_client.h"

#include <cstdlib>
#include <fcntl.h>
#include <libexif/exif-entry.h>
#include <securec.h>
#include <sys/mman.h>
#include <unistd.h>
#include <optional>

#include "exif_metadata.h"
#include "image_type.h"
#include "image_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_utils.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "pixel_yuv.h"
#include "pixel_yuv_ext.h"
#include "userfilemgr_uri.h"
#include "userfile_client.h"
#include <fstream>

namespace OHOS {
namespace Media {
const int32_t MAX_VALUE = 100000000;
const int32_t COUNT_TWICE = 2;
const int32_t COUNT_THREE_TIMES = 3;
std::shared_ptr<Media::Picture> PictureHandlerClient::RequestPicture(const int32_t &fileId, int32_t &errCode)
{
    MEDIA_DEBUG_LOG("PictureHandlerClient::RequestPicture fileId: %{public}d", fileId);
    std::string uri = PhotoColumn::PHOTO_REQUEST_PICTURE;
    MediaFileUtils::UriAppendKeyValue(uri, MediaColumn::MEDIA_ID, std::to_string(fileId));
    Uri requestUri(uri);
    int32_t fd = UserFileClient::OpenFile(requestUri, MEDIA_FILEMODE_READONLY);
    if (fd < 0) {
        MEDIA_DEBUG_LOG("PictureHandlerClient::RequestPicture picture not exist");
        return nullptr;
    }
    std::shared_ptr<Media::Picture> picture = nullptr;
    int32_t ret = ReadPicture(fd, fileId, picture, errCode);
    if (ret != E_OK) {
        MEDIA_DEBUG_LOG("PictureHandlerClient::RequestPicture failed to ReadPicture");
        errCode = E_ERR;
        close(fd);
        return nullptr;
    }
    FinishRequestPicture(fileId);
    close(fd);
    return picture;
}

void PictureHandlerClient::FinishRequestPicture(const int32_t &fileId)
{
    MEDIA_DEBUG_LOG("PictureHandlerClient::FinishRequestPicture fileId: %{public}d", fileId);
    std::string uri = PAH_FINISH_REQUEST_PICTURE;
    MediaLibraryNapiUtils::UriAppendKeyValue(uri, API_VERSION, std::to_string(MEDIA_API_VERSION_V10));
    Uri finishRequestPictureUri(uri);

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::MEDIA_ID, fileId);
    UserFileClient::Insert(finishRequestPictureUri, valuesBucket);
}

// 获取消息总长度
std::optional<uint32_t> PictureHandlerClient::ReadMessageLength(const int32_t &fd)
{
    uint32_t msgLen = 0;
    void *msgLenAddr = mmap(nullptr, UINT32_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (msgLenAddr == MAP_FAILED) {
        MEDIA_ERR_LOG("Failed to map memory to read message length");
        return std::nullopt;
    }
    msgLen = *((uint32_t*)msgLenAddr);
    munmap(msgLenAddr, UINT32_LEN);
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadMessageLength msgLen: %{public}d", msgLen);
    return msgLen;
}

// 获取消息
std::optional<std::pair<uint32_t, uint8_t*>> PictureHandlerClient::ReadMessage(uint8_t *addr, const uint32_t &msgLen)
{
    uint32_t dataSize = *reinterpret_cast<const uint32_t*>(addr + UINT32_LEN);
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadMessage dataSize: %{public}d", dataSize);
    if (dataSize == 0) {
        MEDIA_ERR_LOG("PictureHandlerClient::ReadMessage picture is not exists");
        munmap(addr, msgLen);
        return std::nullopt;
    }

    uint8_t *pictureParcelData = static_cast<uint8_t *>(malloc(dataSize));
    if (pictureParcelData == nullptr) {
        MEDIA_ERR_LOG("Failed to allocate memory for pictureParcelData.");
        munmap(addr, msgLen);
        return std::nullopt;
    }

    if (memcpy_s((void*)pictureParcelData, dataSize, addr + UINT32_LEN * COUNT_THREE_TIMES, dataSize)) {
        MEDIA_ERR_LOG("Failed to memcpy_s pictureParcelData.");
        free(pictureParcelData);
        munmap(addr, msgLen);
        return std::nullopt;
    }
    return std::make_pair(dataSize, pictureParcelData);
}

// 解析图片
std::unique_ptr<Media::Picture> PictureHandlerClient::ParsePicture(MessageParcel &pictureParcel, uint8_t *addr,
    const uint32_t &msgLen, int32_t &err)
{
    MEDIA_DEBUG_LOG("PictureHandlerClient::ParsePicture read mainPixelMap");
    std::shared_ptr<PixelMap> mainPixelMap = ReadPixelMap(pictureParcel, err);
    if (mainPixelMap == nullptr) {
        MEDIA_ERR_LOG("PictureHandlerService::ParsePicture mainPixelMap is nullptr!");
        return nullptr;
    }
    std::unique_ptr<Media::Picture> picturePtr = Picture::Create(mainPixelMap);
    if (picturePtr == nullptr) {
        MEDIA_ERR_LOG("PictureHandlerService::ParsePicture picturePtr is nullptr!");
        munmap(addr, msgLen);
        return nullptr;
    }
    ReadExifMetadata(pictureParcel, picturePtr);
    bool ret = ReadMaintenanceData(pictureParcel, picturePtr, err);
    if (!ret) {
        MEDIA_ERR_LOG("Failed to ReadMaintenanceData");
        return nullptr;
    }
    return picturePtr;
}

int32_t PictureHandlerClient::ReadPicture(const int32_t &fd, const int32_t &fileId,
    std::shared_ptr<Media::Picture> &picture, int32_t &err)
{
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadPicture fd: %{public}d", fd);
    // 获取消息总长度
    auto msgLenOpt = ReadMessageLength(fd);
    if (!msgLenOpt.has_value()) {
        return E_ERR;
    }
    uint32_t msgLen = msgLenOpt.value();

    // 获取消息
    uint8_t *addr = (uint8_t*)mmap(nullptr, msgLen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        MEDIA_ERR_LOG("Failed to map memory to read message content");
        return E_ERR;
    }
    auto msgDataOpt = ReadMessage(addr, msgLen);
    if (!msgDataOpt.has_value()) {
        return E_ERR;
    }
    auto [dataSize, pictureParcelData] = msgDataOpt.value();

    // 读取auxiliaryPictureSize
    uint32_t auxiliaryPictureSize =  *reinterpret_cast<const uint32_t*>(addr + UINT32_LEN * COUNT_TWICE);
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadPicture auxiliaryPictureSize: %{public}d", auxiliaryPictureSize);

    // 解析图片
    MessageParcel pictureParcel;
    pictureParcel.ParseFrom(reinterpret_cast<uintptr_t>(pictureParcelData), dataSize);
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadPicture read mainPixelMap");
    std::unique_ptr<Media::Picture> picturePtr = ParsePicture(pictureParcel, addr, msgLen, err);
    if (picturePtr == nullptr) {
        return E_ERR;
    }
    for (size_t i = 1; i <= auxiliaryPictureSize; i++) {
        MEDIA_DEBUG_LOG("PictureHandlerClient::ReadPicture read auxiliaryPicture, index:%{public}zu", i);
        bool ret = ReadAuxiliaryPicture(pictureParcel, picturePtr, err);
        if (!ret) {
            return E_ERR;
        }
    }
    picture.reset(picturePtr.get());
    picturePtr.release();
    munmap(addr, msgLen);
    return E_OK;
}

std::shared_ptr<PixelMap> PictureHandlerClient::ReadPixelMap(MessageParcel &data, int32_t &err)
{
    ImageInfo imageInfo;
    ReadImageInfo(data, imageInfo);

    bool isYuv = data.ReadBool();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadPixelMap isYuv:%{public}d", isYuv);
    YUVDataInfo yuvInfo;
    if (isYuv) {
        ReadYuvDataInfo(data, yuvInfo);
    }

    bool editable = data.ReadBool();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadPixelMap editable:%{public}d", editable);

    std::unique_ptr<PixelMap> pixelMap;
    if (isYuv) {
#ifdef EXT_PIXEL
        pixelMap = std::make_unique<PixelYuvExt>();
#else
        pixelMap = std::make_unique<PixelYuv>();
#endif
    } else {
        pixelMap = std::make_unique<PixelMap>();
    }
    pixelMap->SetImageInfo(imageInfo);
    pixelMap->SetImageYUVInfo(yuvInfo);

    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadPixelMap read surface buffer");
    bool ret = ReadSurfaceBuffer(data, pixelMap, err);
    if (!ret) {
        MEDIA_ERR_LOG("Failed to ReadSurfaceBuffer");
        return nullptr;
    }
    return pixelMap;
}

bool PictureHandlerClient::ReadAuxiliaryPicture(MessageParcel &data, std::unique_ptr<Media::Picture> &picture,
    int32_t &err)
{
    AuxiliaryPictureInfo auxiliaryPictureInfo;
    ReadAuxiliaryPictureInfo(data, auxiliaryPictureInfo);
    std::shared_ptr<PixelMap> pixelMap = ReadPixelMap(data, err);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("PictureHandlerService::ReadAuxiliaryPicture pixelMap is nullptr!");
        return false;
    }
    std::unique_ptr<AuxiliaryPicture> uptr = AuxiliaryPicture::Create(pixelMap,
        auxiliaryPictureInfo.auxiliaryPictureType, auxiliaryPictureInfo.size);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture;
    auxiliaryPicture.reset(uptr.get());
    uptr.release();

    auxiliaryPicture->SetAuxiliaryPictureInfo(auxiliaryPictureInfo);

    int32_t metadataSize = 0;
    if (data.ReadInt32(metadataSize) && metadataSize >= 0 && metadataSize < MAX_VALUE) {
        MEDIA_DEBUG_LOG("PictureHandlerClient::ReadAuxiliaryPicture metadataSize: %{public}d", metadataSize);
        for (int i = 0; i < metadataSize; i++) {
            MetadataType type = static_cast<MetadataType>(data.ReadInt32());
            MEDIA_DEBUG_LOG("PictureHandlerClient::ReadAuxiliaryPicture type: %{public}d", type);
            std::shared_ptr<ImageMetadata> metadataPtr(nullptr);
            metadataPtr.reset(ExifMetadata::Unmarshalling(data));
            auxiliaryPicture->SetMetadata(type, metadataPtr);
        }
    } else {
        MEDIA_ERR_LOG("PictureHandlerClient::ReadAuxiliaryPicture metadataSize failed");
    }
    picture->SetAuxiliaryPicture(auxiliaryPicture);
    MEDIA_DEBUG_LOG("PictureHandler::ReadAuxiliaryPicture end");
    return true;
}

bool PictureHandlerClient::ReadAuxiliaryPictureInfo(MessageParcel &data, AuxiliaryPictureInfo &auxiliaryPictureInfo)
{
    auxiliaryPictureInfo.auxiliaryPictureType = static_cast<AuxiliaryPictureType>(data.ReadInt32());
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadAuxiliaryPictureInfo auxiliaryPictureType: %{public}d",
        auxiliaryPictureInfo.auxiliaryPictureType);

    auxiliaryPictureInfo.colorSpace = static_cast<ColorSpace>(data.ReadInt32());
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadAuxiliaryPictureInfo colorSpace: %{public}d",
        auxiliaryPictureInfo.colorSpace);

    auxiliaryPictureInfo.pixelFormat = static_cast<PixelFormat>(data.ReadInt32());
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadAuxiliaryPictureInfo pixelFormat: %{public}d",
        auxiliaryPictureInfo.pixelFormat);

    auxiliaryPictureInfo.rowStride = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadAuxiliaryPictureInfo rowStride: %{public}d",
        auxiliaryPictureInfo.rowStride);

    auxiliaryPictureInfo.size.height = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadAuxiliaryPictureInfo height: %{public}d",
        auxiliaryPictureInfo.size.height);

    auxiliaryPictureInfo.size.width = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadAuxiliaryPictureInfo width: %{public}d",
        auxiliaryPictureInfo.size.width);
    
    return true;
}

bool PictureHandlerClient::ReadImageInfo(MessageParcel &data, ImageInfo &imageInfo)
{
    imageInfo.size.width = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadImageInfo width: %{public}d", imageInfo.size.width);
    imageInfo.size.height = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadImageInfo height: %{public}d", imageInfo.size.height);
    imageInfo.pixelFormat = static_cast<PixelFormat>(data.ReadInt32());
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadImageInfo pixelFormat: %{public}d", imageInfo.pixelFormat);
    imageInfo.colorSpace = static_cast<ColorSpace>(data.ReadInt32());
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadImageInfo colorSpace: %{public}d", imageInfo.colorSpace);
    imageInfo.alphaType = static_cast<AlphaType>(data.ReadInt32());
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadImageInfo alphaType: %{public}d", imageInfo.alphaType);
    imageInfo.baseDensity = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadImageInfo baseDensity: %{public}d", imageInfo.baseDensity);
    return true;
}

bool PictureHandlerClient::ReadYuvDataInfo(MessageParcel &data, YUVDataInfo &info)
{
    info.imageSize.width = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo width: %{public}d", info.imageSize.width);
    info.imageSize.height = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo height: %{public}d", info.imageSize.height);
    info.yWidth = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo yWidth: %{public}d", info.yWidth);
    info.yHeight = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo yHeight: %{public}d", info.yHeight);
    info.uvWidth = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo uvWidth: %{public}d", info.uvWidth);
    info.uvHeight = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo uvHeight: %{public}d", info.uvHeight);
    info.yStride = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo yStride: %{public}d", info.yStride);
    info.uStride = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo uStride: %{public}d", info.uStride);
    info.vStride = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo vStride: %{public}d", info.vStride);
    info.uvStride = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo uvStride: %{public}d", info.uvStride);
    info.yOffset = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo yOffset: %{public}d", info.yOffset);
    info.uOffset = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo uOffset: %{public}d", info.uOffset);
    info.vOffset = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo vOffset: %{public}d", info.vOffset);
    info.uvOffset = data.ReadUint32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadYuvDataInfo uvOffset: %{public}d", info.uvOffset);
    return true;
}

bool PictureHandlerClient::ReadSurfaceBuffer(MessageParcel &data, std::unique_ptr<PixelMap> &pixelMap, int32_t &err)
{
    bool hasBufferHandle = data.ReadBool();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadSurfaceBuffer hasBufferHandle: %{public}d", hasBufferHandle);
    if (!hasBufferHandle) {
        return false;
    }
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    bool ret = ReadBufferHandle(data, surfaceBuffer, err);
    if (!ret) {
        return false;
    }
    void* nativeBuffer = surfaceBuffer.GetRefPtr();
    OHOS::RefBase *ref = reinterpret_cast<OHOS::RefBase *>(nativeBuffer);
    ref->IncStrongRef(ref);
    pixelMap->SetPixelsAddr(static_cast<uint8_t*>(surfaceBuffer->GetVirAddr()), nativeBuffer,
        pixelMap->GetByteCount(), AllocatorType::DMA_ALLOC, nullptr);
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadSurfaceBuffer end");
    return true;
}

BufferHandle* PictureHandlerClient::CreateBufferHandle(MessageParcel &data, const uint32_t &reserveFds,
    const uint32_t &reserveInts)
{
    size_t handleSize = sizeof(BufferHandle) + (sizeof(int32_t) * (reserveFds + reserveInts));
    BufferHandle *handle = static_cast<BufferHandle *>(malloc(handleSize));
    if (handle == nullptr) {
        MEDIA_ERR_LOG("PictureHandlerClient::CreateBufferHandle malloc BufferHandle failed");
        return nullptr;
    }
    memset_s(handle, handleSize, 0, handleSize);

    handle->reserveFds = reserveFds;
    handle->reserveInts = reserveInts;
    handle->width = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::CreateBufferHandle width: %{public}d", handle->width);
    handle->stride = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::CreateBufferHandle stride: %{public}d", handle->stride);
    handle->height = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::CreateBufferHandle height: %{public}d", handle->height);
    handle->size = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::CreateBufferHandle size: %{public}d", handle->size);
    handle->format = data.ReadInt32();
    MEDIA_DEBUG_LOG("PictureHandlerClient::CreateBufferHandle format: %{public}d", handle->format);
    handle->usage = data.ReadUint64();
    handle->phyAddr = data.ReadUint64();
    return handle;
}

bool PictureHandlerClient::ReadBufferHandle(MessageParcel &data, sptr<SurfaceBuffer> &surfaceBuffer, int32_t &err)
{
    uint32_t reserveFds = 0;
    bool readReserveFdsRet = data.ReadUint32(reserveFds);
    if (reserveFds < 0 || reserveFds > static_cast<uint32_t>(MAX_VALUE)) {
        return false;
    }
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadBufferHandle reserveFds: %{public}d", reserveFds);
    uint32_t reserveInts = 0;
    bool reserveIntsRet = data.ReadUint32(reserveInts);
    if (reserveInts < 0 || reserveInts > static_cast<uint32_t>(MAX_VALUE)) {
        return false;
    }
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadBufferHandle reserveInts: %{public}d", reserveInts);
    BufferHandle *handle = CreateBufferHandle(data, reserveFds, reserveInts);
    if (handle == nullptr) {
        return false;
    }
    int32_t fd = RequestBufferHandlerFd(data.ReadInt32());
    if (fd < 0) {
        MEDIA_ERR_LOG("PictureHandlerClient::ReadBufferHandle fd: %{public}d", fd);
        err = E_ERR;
        close(fd);
        return false;
    }
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadBufferHandle fd: %{public}d", fd);
    handle->fd = dup(fd);
    close(fd);
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadBufferHandle handle->fd: %{public}d", handle->fd);
    if (readReserveFdsRet) {
        for (uint32_t i = 0; i < reserveFds; i++) {
            int32_t reserveFd = RequestBufferHandlerFd(data.ReadInt32());
            if (reserveFd < 0) {
                err = E_ERR;
                MEDIA_ERR_LOG("PictureHandlerClient::ReadBufferHandle reserveFd: %{public}d", reserveFd);
                return false;
            }
            MEDIA_DEBUG_LOG("PictureHandlerClient::ReadBufferHandle reserve[%{public}d]: %{public}d", i, reserveFd);
            handle->reserve[i] = dup(reserveFd);
            close(reserveFd);
        }
    }

    if (reserveIntsRet) {
        for (uint32_t j = 0; j < handle->reserveInts; j++) {
            handle->reserve[reserveFds + j] = data.ReadInt32();
        }
    }
    surfaceBuffer->SetBufferHandle(handle);
    return true;
}

bool PictureHandlerClient::ReadExifMetadata(MessageParcel &data, std::unique_ptr<Media::Picture> &picture)
{
    bool hasExifMetadata = data.ReadBool();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadExifMetadata hasExifMetadata:%{public}d", hasExifMetadata);
    if (!hasExifMetadata) {
        return true;
    }
    ExifMetadata *exifMetadataPtr = ExifMetadata::Unmarshalling(data);
    auto exifMetadata = std::shared_ptr<ExifMetadata>(exifMetadataPtr);
    picture->SetExifMetadata(exifMetadata);
    return true;
}

bool PictureHandlerClient::ReadMaintenanceData(MessageParcel &data, std::unique_ptr<Media::Picture> &picture,
    int32_t &err)
{
    bool hasMaintenanceData = data.ReadBool();
    MEDIA_DEBUG_LOG("PictureHandlerClient::ReadMaintenanceData hasMaintenanceData:%{public}d", hasMaintenanceData);
    if (!hasMaintenanceData) {
        return true;
    }
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    bool ret = ReadBufferHandle(data, surfaceBuffer, err);
    if (!ret) {
        return false;
    }
    return picture->SetMaintenanceData(surfaceBuffer);
}

int32_t PictureHandlerClient::RequestBufferHandlerFd(const int32_t &fd)
{
    std::string uri = PhotoColumn::PHOTO_REQUEST_PICTURE_BUFFER;
    MediaFileUtils::UriAppendKeyValue(uri, "fd", std::to_string(fd));
    MEDIA_DEBUG_LOG("PictureHandlerClient::RequestBufferHandlerFd uri: %{public}s", uri.c_str());
    Uri requestUri(uri);
    return UserFileClient::OpenFile(requestUri, MEDIA_FILEMODE_READONLY);
}
}
}