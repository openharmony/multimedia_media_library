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
enum class MultiStagesCapturePhotoStatus {
    QUERY_INNER_FAIL = 0,
    HIGH_QUALITY_STATUS,
    LOW_QUALITY_STATUS,
};

struct RequestImageAsyncContext {
    size_t argc = ARGS_FOUR;
    napi_value argv[ARGS_FOUR] = {nullptr};
    napi_value thisVar = nullptr;
    int fileId = -1; // default value of request file id
    std::string photoUri;
    std::string displayName;
    std::string photoPath;
    DeliveryMode deliveryMode;
    SourceMode sourceMode;
    ReturnDataType returnDataType;
};

class MultiStagesTaskObserver : public DataShare::DataShareObserver {
public:
    MultiStagesTaskObserver(std::string uri, int fileId, SourceMode sourceMode)
        : requestUri_(uri), fileId_(fileId), sourceMode_(sourceMode) {};
    void OnChange(const ChangeInfo &changelnfo) override;
private:
    std::string requestUri_;
    int fileId_;
    SourceMode sourceMode_;
};

class MediaAssetManagerNapi {
public:
    MediaAssetManagerNapi() = default;
    ~MediaAssetManagerNapi() = default;
    EXPORT static napi_value Init(napi_env env, napi_value exports);
    static napi_env GetMediaAssetManagerJsEnv();
    static void SetMediaAssetManagerJsEnv(napi_env env);
    static MultiStagesCapturePhotoStatus queryPhotoStatus(int fileId);
    static void notifyImageDataPrepared(const std::string requstUri, SourceMode sourceMode);
    static void notifyDataPreparedWithoutRegister(std::string &requestUri, napi_value napiMediaDataHandler,
        ReturnDataType returnDataType, SourceMode sourceMode);
    static void RequestImage(std::string photoId);
    static void DeleteInProcessMapRecord(const std::string &requestUri);

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);
    static bool InitUserFileClient(napi_env env, napi_callback_info info);
    static napi_status ParseRequestImageArgs(napi_env env, napi_callback_info info,
        unique_ptr<RequestImageAsyncContext> &asyncContext);
    static napi_value JSRequestImage(napi_env env, napi_callback_info info);
    static napi_value JSRequestImageData(napi_env env, napi_callback_info info);
    static void RegisterTaskObserver(const std::string &photoUri, const int fileId, napi_value napiMediaDataHandler,
        ReturnDataType returnDataType, SourceMode sourceMode);
    static void ProcessImage(const int fileId);
    static void AddImage(const int fileId, DeliveryMode deliveryMode);
    static void onHandleRequestImage(const unique_ptr<RequestImageAsyncContext> &asyncContext);
    static void GetByteArrayNapiObject(std::string requestUri, napi_value& arrayBuffer, bool isSource);
    static void GetImageSourceNapiObject(std::string fileUri, napi_value& imageSourceNapiObj, bool isSource);
public:
    static napi_env env_;
    std::mutex sMediaAssetMutex_;
};
} // OHOS
} // Media
#endif // INTERFACES KITS JS MEDIALIBRARY INCLUDE_MEDIA_ASSET_MANAGER_NAPL_H
