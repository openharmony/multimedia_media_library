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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_MANAGER_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_MANAGER_NAPI_H

#include <mutex>
#include <vector>
#include <map>

#include "data_ability_helper.h"
#include "data_ability_observer_stub.h"
#include "data_ability_predicates.h"
#include "media_asset_data_handler.h"
#include "media_file_utils.h"
#include "media_library_napi.h"
#include "napi_base_context.h"
#include "napi_error.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
using MediaAssetDataHandlerPtr = std::shared_ptr<NapiMediaAssetDataHandler>;
enum class MultiStagesCapturePhotoStatus {
    QUERY_INNER_FAIL = 0,
    HIGH_QUALITY_STATUS,
    LOW_QUALITY_STATUS,
};

struct MediaAssetManagerAsyncContext : NapiError {
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;

    size_t argc = ARGS_FIVE;
    napi_value argv[ARGS_FIVE] = {nullptr};
    int fileId = -1; // default value of request file id
    std::string photoUri;
    std::string photoId;
    std::string displayName;
    std::string photoPath;
    std::string callingPkgName;
    std::string requestId;
    napi_value requestIdNapiValue;
    napi_value dataHandler;
    napi_ref dataHandlerRef;
    std::string destUri;
    DeliveryMode deliveryMode;
    SourceMode sourceMode;
    ReturnDataType returnDataType;
    bool hasReadPermission;
    bool needsExtraInfo;
    MultiStagesCapturePhotoStatus photoQuality = MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
};

struct AssetHandler {
    std::string photoId;
    std::string requestId;
    std::string requestUri;
    MediaAssetDataHandlerPtr dataHandler;
    napi_threadsafe_function threadSafeFunc;
    MultiStagesCapturePhotoStatus photoQuality = MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
    bool needsExtraInfo;

    AssetHandler(const std::string &photoId, const std::string &requestId, const std::string &uri,
        const MediaAssetDataHandlerPtr &handler, napi_threadsafe_function func)
        : photoId(photoId), requestId(requestId), requestUri(uri), dataHandler(handler), threadSafeFunc(func) {}
};

class MultiStagesTaskObserver : public DataShare::DataShareObserver {
public:
    MultiStagesTaskObserver(int fileId)
        : fileId_(fileId) {};
    void OnChange(const ChangeInfo &changelnfo) override;
private:
    int fileId_;
};

class MediaAssetManagerNapi {
public:
    MediaAssetManagerNapi() = default;
    ~MediaAssetManagerNapi() = default;
    EXPORT static napi_value Init(napi_env env, napi_value exports);
    static MultiStagesCapturePhotoStatus QueryPhotoStatus(int fileId, const string& photoUri,
        std::string &photoId, bool hasReadPermission);
    static void NotifyMediaDataPrepared(AssetHandler *assetHandler);
    static void NotifyDataPreparedWithoutRegister(napi_env env,
        const unique_ptr<MediaAssetManagerAsyncContext> &asyncContext);
    static void OnDataPrepared(napi_env env, napi_value cb, void *context, void *data);
    static void RegisterTaskObserver(napi_env env, const unique_ptr<MediaAssetManagerAsyncContext> &asyncContext);
    static void GetByteArrayNapiObject(const std::string &requestUri, napi_value &arrayBuffer, bool isSource,
        napi_env env);
    static void GetImageSourceNapiObject(const std::string &fileUri, napi_value &imageSourceNapiObj, bool isSource,
        napi_env env);
    static void WriteDataToDestPath(std::string requestUri, std::string destUri, napi_value& resultNapiValue,
        bool isSource, napi_env env);

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalizeHint);
    static bool InitUserFileClient(napi_env env, napi_callback_info info);
    static napi_status ParseRequestMediaArgs(napi_env env, napi_callback_info info,
        unique_ptr<MediaAssetManagerAsyncContext> &asyncContext);
    static napi_value JSRequestImage(napi_env env, napi_callback_info info);
    static napi_value JSRequestImageData(napi_env env, napi_callback_info info);
    static napi_value JSRequestMovingPhoto(napi_env env, napi_callback_info info);
    static napi_value JSRequestVideoFile(napi_env env, napi_callback_info info);
    static napi_value JSCancelRequest(napi_env env, napi_callback_info info);
    static napi_value JSLoadMovingPhoto(napi_env env, napi_callback_info info);
    static void ProcessImage(const int fileId, const int deliveryMode, const std::string &packageName);
    static void CancelProcessImage(const std::string &photoId);
    static void AddImage(const int fileId, DeliveryMode deliveryMode);
    static void OnHandleRequestImage(napi_env env, const unique_ptr<MediaAssetManagerAsyncContext> &asyncContext);
    static void OnHandleRequestVideo(napi_env env, const unique_ptr<MediaAssetManagerAsyncContext> &asyncContext);
    static void SendFile(napi_env env, int srcFd, int destFd, napi_value &result, off_t fileSize);
    static int32_t GetFdFromSandBoxUri(const std::string &sandBoxUri);
public:
    std::mutex sMediaAssetMutex_;
};
} // Media
} // OHOS
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_MANAGER_NAPI_H
