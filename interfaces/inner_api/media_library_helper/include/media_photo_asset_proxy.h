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

#ifndef INNER_API_MEDIA_LIBRARY_HELPER_INCLUDE_MEDIA_PHOTO_ASSET_PROXY_H
#define INNER_API_MEDIA_LIBRARY_HELPER_INCLUDE_MEDIA_PHOTO_ASSET_PROXY_H

#include <string>
#include <memory>

#include "datashare_helper.h"
#include "file_asset.h"
#include "photo_proxy.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
// 相机拍摄类型，由相机框架传入
enum class CameraShotType : int32_t {
    IMAGE  = 0, // 图片
    VIDEO, // 视频
    MOVING_PHOTO, // 动态照片
    BURST, // 连拍照片
};

class VideoAttrs : public RefBase {
public:
    VideoAttrs() {}
    virtual ~VideoAttrs() = default;

    virtual int32_t GetVideoSize() = 0;
};

class PhotoAssetProxy {
public:
    PhotoAssetProxy();
    PhotoAssetProxy(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, CameraShotType cameraShotType,
        uint32_t callingUid, int32_t userId, uint32_t callingTokenId);
    ~PhotoAssetProxy();

    EXPORT std::unique_ptr<FileAsset> GetFileAsset();
    EXPORT std::string GetPhotoAssetUri();
    EXPORT void AddPhotoProxy(const sptr<PhotoProxy> &photoProxy);
    EXPORT int32_t GetVideoFd();
    EXPORT void NotifyVideoSaveFinished();

private:
    void CreatePhotoAsset(const sptr<PhotoProxy> &photoProxy);
    static int SaveImage(int fd, const std::string &uri, const std::string &photoId, void *output, size_t writeSize);
    static int PackAndSaveImage(int fd, const std::string &uri, const sptr<PhotoProxy> &photoProxy);
    DataShare::DataShareValuesBucket HandleAssetValues(const sptr<PhotoProxy> &photoProxy,
        const std::string &displayName, const MediaType &mediaType);
    static int32_t AddProcessImage(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
        const sptr<PhotoProxy> &photoProxy, int32_t fileId, int32_t subType);
    static int SaveLowQualityPhoto(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    const sptr<PhotoProxy> &photoProxy, int32_t fileId, int32_t subType);
    static void DealWithLowQualityPhoto(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper, int fd,
        const std::string &uri, const sptr<PhotoProxy> &photoProxy);
    static void SetShootingModeAndGpsInfo(const uint8_t *data, uint32_t size,
        const sptr<PhotoProxy> &photoProxy, int fd);
    static std::string LocationValueToString(double value);
    
    static void SetPhotoIdForAsset(const sptr<PhotoProxy> &photoProxy, DataShare::DataShareValuesBucket &values);
    static std::string GetPhotoIdForAsset(const sptr<PhotoProxy> &photoProxy);

    sptr<PhotoProxy> photoProxy_;
    int32_t fileId_ {0};
    std::string uri_;
    CameraShotType cameraShotType_ = CameraShotType::IMAGE;
    uint32_t callingUid_ {0};
    int32_t userId_ {0};
    uint32_t callingTokenId_ {0};
    PhotoSubType subType_ = PhotoSubType::DEFAULT;
    bool isMovingPhotoVideoSaved_ = false;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
};
} // Media
} // OHOS
#endif // INNER_API_MEDIA_LIBRARY_HELPER_INCLUDE_MEDIA_PHOTO_ASSET_PROXY_H