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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_MANAGER_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_MANAGER_H

#include <mutex>
#include <vector>
#include <map>

#include "datashare_helper.h"
#include "media_asset_data_handler_capi.h"
#include "media_asset_base_capi.h"

namespace OHOS {
namespace Media {
using MediaAssetDataHandlerPtr = std::shared_ptr<CapiMediaAssetDataHandler>;

enum class MultiStagesCapturePhotoStatus {
    QUERY_INNER_FAIL = 0,
    HIGH_QUALITY_STATUS,
    LOW_QUALITY_STATUS,
};

struct RequestSourceAsyncContext {
    int fileId = -1; // default value of request file id
    std::string requestUri;
    std::string photoId;
    std::string displayName;
    std::string mediaPath;
    std::string callingPkgName;
    std::string requestId;
    std::string destUri;
    NativeOnDataPrepared onDataPreparedHandler;
    NativeRequestOptions requestOptions;
    ReturnDataType returnDataType;
    OH_MediaLibrary_OnImageDataPrepared onRequestImageDataPreparedHandler;
    OH_MediaLibrary_OnMovingPhotoDataPrepared onRequestMovingPhotoDataPreparedHandler;
    MultiStagesCapturePhotoStatus photoQuality = MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
    bool needsExtraInfo;
};

struct AssetHandler {
    std::string photoId;
    std::string requestId;
    std::string requestUri;
    std::string destUri;
    MediaAssetDataHandlerPtr dataHandler;

    AssetHandler(const std::string &photoId, const std::string &requestId, const std::string &uri,
        const std::string &destUri, const MediaAssetDataHandlerPtr &handler)
        : photoId(photoId), requestId(requestId), requestUri(uri), destUri(destUri), dataHandler(handler) {}
};

class MultiStagesTaskObserver : public DataShare::DataShareObserver {
public:
    MultiStagesTaskObserver(int fileId)
        : fileId_(fileId) {};
    void OnChange(const ChangeInfo &changelnfo) override;

private:
    std::map<std::string, AssetHandler *> GetAssetHandlers(const std::string uriString);

private:
    int fileId_;
};

class MediaAssetManager {
public:
    virtual ~MediaAssetManager() = default;

public:
    virtual bool NativeCancelRequest(const std::string &requestId) = 0;
    virtual std::string NativeRequestImage(const char* photoUri, const NativeRequestOptions &requestOptions,
        const char* destPath, const NativeOnDataPrepared &callback) = 0;
    virtual std::string NativeRequestVideo(const char* videoUri, const NativeRequestOptions &requestOptions,
        const char* destUri, const NativeOnDataPrepared &callback) = 0;

    virtual MediaLibrary_ErrorCode NativeRequestImageSource(OH_MediaAsset* mediaAsset,
        NativeRequestOptions requestOptions, MediaLibrary_RequestId* requestId,
        OH_MediaLibrary_OnImageDataPrepared callback) = 0;
    virtual MediaLibrary_ErrorCode NativeRequestMovingPhoto(OH_MediaAsset* mediaAsset,
        NativeRequestOptions requestOptions, MediaLibrary_RequestId* requestId,
        OH_MediaLibrary_OnMovingPhotoDataPrepared callback) = 0;
};

class __attribute__((visibility("default"))) MediaAssetManagerFactory {
public:
    static std::shared_ptr<MediaAssetManager> CreateMediaAssetManager();
private:
    MediaAssetManagerFactory() = default;
    ~MediaAssetManagerFactory() = default;
};
} // Media
} // OHOS
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_MANAGER_H
