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

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
// 相机拍摄类型，由相机框架传入
enum class CameraShotType : int32_t {
    IMAGE  = 0, // 图片
    VIDEO, // 视频
    MOVING_PHOTO, // 动态照片
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
        uint32_t callingUid, int32_t userId);
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
    static int32_t UpdatePhotoQuality(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
        const sptr<PhotoProxy> &photoProxy, int32_t fileId, int32_t subType);
    static void DealWithLowQualityPhoto(std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper, int fd,
        const std::string &uri, const sptr<PhotoProxy> &photoProxy);

    sptr<PhotoProxy> photoProxy_;
    int32_t fileId_;
    std::string uri_;
    CameraShotType cameraShotType_;
    uint32_t callingUid_;
    int32_t userId_;
    PhotoSubType subType_;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
};
} // Media
} // OHOS
#endif // INNER_API_MEDIA_LIBRARY_HELPER_INCLUDE_MEDIA_PHOTO_ASSET_PROXY_H