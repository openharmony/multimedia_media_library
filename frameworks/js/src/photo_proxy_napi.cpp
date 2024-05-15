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

#include "photo_proxy_napi.h"

#include "medialibrary_napi_log.h"
#include "napi_error.h"

namespace OHOS {
namespace Media {
thread_local napi_ref PhotoProxyNapi::sConstructor_ = nullptr;
thread_local sptr<PhotoProxy> PhotoProxyNapi::sPhotoProxy_ = nullptr;
PhotoProxyNapi::PhotoProxyNapi() : env_(nullptr), wrapper_(nullptr)
{
}

PhotoProxyNapi::~PhotoProxyNapi()
{
    NAPI_DEBUG_LOG("~PhotoProxyNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (photoProxy_) {
        photoProxy_ = nullptr;
    }
}

// Constructor callback
napi_value PhotoProxyNapi::PhotoProxyNapiConstructor(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("PhotoProxyNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoProxyNapi> obj = std::make_unique<PhotoProxyNapi>();
        obj->env_ = env;
        obj->photoProxy_ = sPhotoProxy_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           PhotoProxyNapi::PhotoProxyNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            NAPI_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    NAPI_ERR_LOG("PhotoProxyNapiConstructor call Failed!");
    return result;
}

void PhotoProxyNapi::PhotoProxyNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    NAPI_DEBUG_LOG("PhotoProxyNapiDestructor is called");
    PhotoProxyNapi* deferredPhotoProxy = reinterpret_cast<PhotoProxyNapi*>(nativeObject);
    if (deferredPhotoProxy != nullptr) {
        delete deferredPhotoProxy;
    }
}

napi_value PhotoProxyNapi::Init(napi_env env, napi_value exports)
{
    NAPI_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    status = napi_define_class(env, PHOTO_PROXY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        PhotoProxyNapiConstructor, nullptr, 0, nullptr, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, PHOTO_PROXY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    NAPI_ERR_LOG("Init call Failed!");
    return nullptr;
}
} // Media
} // OHOS