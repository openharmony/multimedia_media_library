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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MOVING_PHOTO_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MOVING_PHOTO_NAPI_H

#include <memory>

#include "media_asset_data_handler.h"
#include "media_asset_manager_napi.h"
#include "media_library_napi.h"

namespace OHOS {
namespace Media {
struct MovingPhotoAsyncContext : public NapiError {
    enum RequestContentMode {
        WRITE_TO_SANDBOX,
        WRITE_TO_ARRAY_BUFFER,
        UNDEFINED,
    };

    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;

    std::string movingPhotoUri;
    SourceMode sourceMode;
    CompatibleMode compatibleMode;
    std::function<void(int, int, std::string)> callback;
    std::string requestId;
    ResourceType resourceType;
    std::string destImageUri;
    std::string destVideoUri;
    std::string destLivePhotoUri;
    std::string destMetadataUri;
    RequestContentMode requestContentMode = UNDEFINED;
    void* arrayBufferData = nullptr;
    size_t arrayBufferLength = 0;
};

struct MovingPhotoParam {
    std::string requestId;
    CompatibleMode compatibleMode;
};

class MovingPhotoNapi {
public:
    MovingPhotoNapi(const std::string& photoUri) : photoUri_(photoUri) {};
    ~MovingPhotoNapi() = default;
    EXPORT static napi_value Init(napi_env env, napi_value exports);
    static int32_t OpenReadOnlyFile(const string& uri, bool isReadImage);
    static int32_t OpenReadOnlyLivePhoto(const string& destLivePhotoUri);
    static int32_t OpenReadOnlyMetadata(const string& movingPhotoUri);
    static napi_value NewMovingPhotoNapi(napi_env env, const string& photoUri, SourceMode sourceMode,
        MovingPhotoParam movingPhotoParam,
        const std::function<void(int, int, std::string)> cb = [](int, int, std::string) {});
    std::string GetUri();
    SourceMode GetSourceMode();
    void SetSourceMode(SourceMode sourceMode);
    std::string GetRequestId();
    void SetRequestId(const std::string requestId);
    CompatibleMode GetCompatibleMode();
    void SetCompatibleMode(const CompatibleMode compatibleMode);
    void SetMovingPhotoCallback(const std::function<void(int, int, std::string)> callback);
    std::function<void(int, int, std::string)> GetMovingPhotoCallback();
    static int32_t DoMovingPhotoTranscode(napi_env env, int32_t &videoFd, MovingPhotoAsyncContext* context);
    static void OnProgress(napi_env env, napi_value cb, void *context, void *data);
    static int32_t GetFdFromUri(const std::string &sandBoxUri);
    static void SubRequestContent(int32_t fd, MovingPhotoAsyncContext* context);
    static void CallRequestContentCallBack(napi_env env, MovingPhotoAsyncContext* context);
private:
    EXPORT static napi_value Constructor(napi_env env, napi_callback_info info);
    EXPORT static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    EXPORT static napi_value JSRequestContent(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetUri(napi_env env, napi_callback_info info);

    static thread_local napi_ref constructor_;
    std::string photoUri_;
    SourceMode sourceMode_ = SourceMode::EDITED_MODE;
    CompatibleMode compatibleMode_ = CompatibleMode::COMPATIBLE_FORMAT_MODE;
    std::string requestId_;
};

} // Media
} // OHOS
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MOVING_PHOTO_NAPI_H