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

#include "media_asset_manager_capi.h"

#include <cstring>
#include <securec.h>

#include "media_log.h"
#include "media_asset_base_capi.h"
#include "media_asset_data_handler_capi.h"
#include "media_asset_magic.h"

using namespace OHOS::Media;

struct MediaAssetMangerObject : public OH_MediaAssetManager {
    explicit MediaAssetMangerObject(const std::shared_ptr<MediaAssetManager> &manager)
        : manager_(manager) {}
    ~MediaAssetMangerObject() = default;

    const std::shared_ptr<MediaAssetManager> manager_ = nullptr;
};

void OH_MediaAssetManager_Convert(const MediaLibrary_RequestOptions &srcRequestOption,
    NativeRequestOptions &dstRequestOption)
{
    dstRequestOption.deliveryMode = static_cast<NativeDeliveryMode>(srcRequestOption.deliveryMode);
}

OH_MediaAssetManager *OH_MediaAssetManager_Create(void)
{
    std::shared_ptr<MediaAssetManager> manager = MediaAssetManagerFactory::CreateMediaAssetManager();
    CHECK_AND_PRINT_LOG(manager != nullptr, "failed to MediaAssetManagerFactory::CreateMediaAssetManager");
    MediaAssetMangerObject *object = new(std::nothrow) MediaAssetMangerObject(manager);
    CHECK_AND_PRINT_LOG(object != nullptr, "failed to new MediaAssetMangerObject");
    return object;
}

MediaLibrary_RequestId OH_MediaAssetManager_RequestImageForPath(OH_MediaAssetManager* manager, const char* uri,
    MediaLibrary_RequestOptions requestOptions, const char* destPath, OH_MediaLibrary_OnDataPrepared callback)
{
    CHECK_AND_PRINT_LOG(manager != nullptr, "input manager is nullptr!");
    struct MediaAssetMangerObject *managerObj = reinterpret_cast<MediaAssetMangerObject *>(manager);
    CHECK_AND_PRINT_LOG(managerObj->manager_ != nullptr, "manager_ is null");
    CHECK_AND_PRINT_LOG(uri != nullptr, "uri is null");
    CHECK_AND_PRINT_LOG(destPath != nullptr, "destPath is null");
    CHECK_AND_PRINT_LOG(callback != nullptr, "callback is null");
    NativeRequestOptions nativeRequestOptions;
    OH_MediaAssetManager_Convert(requestOptions, nativeRequestOptions);
    NativeOnDataPrepared nativeCallback = reinterpret_cast<NativeOnDataPrepared>(callback);
    std::string requestIdStr = managerObj->manager_->NativeRequestImage(uri, nativeRequestOptions, destPath,
        nativeCallback);
    MediaLibrary_RequestId requestId;
    strncpy_s(requestId.requestId, UUID_STR_LENGTH, requestIdStr.c_str(), UUID_STR_LENGTH);
    return requestId;
}

MediaLibrary_RequestId OH_MediaAssetManager_RequestVideoForPath(OH_MediaAssetManager* manager, const char* uri,
    MediaLibrary_RequestOptions requestOptions, const char* destPath, OH_MediaLibrary_OnDataPrepared callback)
{
    CHECK_AND_PRINT_LOG(manager != nullptr, "input manager is nullptr!");
    struct MediaAssetMangerObject *managerObj = reinterpret_cast<MediaAssetMangerObject *>(manager);
    CHECK_AND_PRINT_LOG(managerObj->manager_ != nullptr, "manager_ is null");
    CHECK_AND_PRINT_LOG(uri != nullptr, "uri is null");
    CHECK_AND_PRINT_LOG(destPath != nullptr, "destPath is null");
    CHECK_AND_PRINT_LOG(callback != nullptr, "callback is null");
    NativeRequestOptions nativeRequestOptions;
    OH_MediaAssetManager_Convert(requestOptions, nativeRequestOptions);
    NativeOnDataPrepared nativeCallback = reinterpret_cast<NativeOnDataPrepared>(callback);
    std::string requestIdStr = managerObj->manager_->NativeRequestVideo(uri, nativeRequestOptions, destPath,
        nativeCallback);
    MediaLibrary_RequestId requestId;
    strncpy_s(requestId.requestId, UUID_STR_LENGTH, requestIdStr.c_str(), UUID_STR_LENGTH);
    return requestId;
}

bool OH_MediaAssetManager_CancelRequest(OH_MediaAssetManager* manager, const MediaLibrary_RequestId requestId)
{
    CHECK_AND_PRINT_LOG(manager != nullptr, "input manager is nullptr!");
    struct MediaAssetMangerObject *managerObj = reinterpret_cast<MediaAssetMangerObject *>(manager);
    CHECK_AND_PRINT_LOG(managerObj->manager_ != nullptr, "manager_ is null");
    CHECK_AND_PRINT_LOG(strlen(requestId.requestId) > 0, "requestId is empty");
    return managerObj->manager_->NativeCancelRequest(requestId.requestId);
}