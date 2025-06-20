/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "AlbumOrderNapi"

#include "album_order_napi.h"
#include <nlohmann/json.hpp>

#include "fetch_file_result_napi.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils_ext.h"
#include "medialibrary_tracer.h"
#include "result_set_utils.h"
#include "userfile_client.h"
#include "album_operation_uri.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS::Media {
thread_local AlbumOrder *AlbumOrderNapi::pOrderData_ = nullptr;
thread_local napi_ref AlbumOrderNapi::photoAccessConstructor_ = nullptr;
static const string PHOTOACCESS_ALBUM_ORDER_CLASS = "PhotoAccessAlbumOrder";
std::mutex AlbumOrderNapi::mutex_;

using CompleteCallback = napi_async_complete_callback;

AlbumOrderNapi::AlbumOrderNapi() : env_(nullptr) {}

AlbumOrderNapi::~AlbumOrderNapi() = default;

napi_value AlbumOrderNapi::PhotoAccessInit(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = PHOTOACCESS_ALBUM_ORDER_CLASS,
        .ref = &photoAccessConstructor_,
        .constructor = AlbumOrderNapiConstructor,
        .props = {
            DECLARE_NAPI_GETTER_SETTER("albumId", JSGetAlbumId, JSSetAlbumId),
            DECLARE_NAPI_GETTER_SETTER("albumOrder", JSGetAlbumOrder, JSSetAlbumOrder),
            DECLARE_NAPI_GETTER_SETTER("orderSection", JSGetOrderSection, JSSetOrderSection),
            DECLARE_NAPI_GETTER_SETTER("orderType", JSGetOrderType, JSSetOrderType),
            DECLARE_NAPI_GETTER_SETTER("orderStatus", JSGetOrderStatus, JSSetOrderStatus),
        }
    };

    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value AlbumOrderNapi::CreateAlbumOrderNapi(napi_env env, unique_ptr<AlbumOrder> &orderData)
{
    if (orderData == nullptr) {
        NAPI_ERR_LOG("Unsupported album order data");
        return nullptr;
    }
    if (photoAccessConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        AlbumOrderNapi::PhotoAccessInit(env, exports);
    }

    napi_value constructor;
    napi_ref constructorRef = photoAccessConstructor_;
    CHECK_ARGS(env, napi_get_reference_value(env, constructorRef, &constructor), JS_E_INNER_FAIL);

    napi_value result = nullptr;
    pOrderData_ = orderData.release();
    CHECK_ARGS(env, napi_new_instance(env, constructor, 0, nullptr, &result), JS_E_INNER_FAIL);
    pOrderData_ = nullptr;
    return result;
}

int32_t AlbumOrderNapi::GetAlbumId() const
{
    return albumOrderPtr->GetAlbumId();
}

int32_t AlbumOrderNapi::GetAlbumOrder() const
{
    return albumOrderPtr->GetAlbumOrder();
}

int32_t AlbumOrderNapi::GetOrderSection() const
{
    return albumOrderPtr->GetOrderSection();
}

int32_t AlbumOrderNapi::GetOrderType() const
{
    return albumOrderPtr->GetOrderType();
}

int32_t AlbumOrderNapi::GetOrderStatus() const
{
    return albumOrderPtr->GetOrderStatus();
}

shared_ptr<AlbumOrder> AlbumOrderNapi::GetAlbumOrderInstance() const
{
    return albumOrderPtr;
}

void AlbumOrderNapi::SetAlbumOrderNapiProperties()
{
    albumOrderPtr = shared_ptr<AlbumOrder>(pOrderData_);
}

// Constructor callback
napi_value AlbumOrderNapi::AlbumOrderNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_E_INNER_FAIL);

    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr), JS_E_INNER_FAIL);
    if (thisVar == nullptr) {
        NapiError::ThrowError(env, JS_E_PARAM_INVALID, "Failed to get cb info");
        return result;
    }

    unique_ptr<AlbumOrderNapi> obj = make_unique<AlbumOrderNapi>();
    obj->env_ = env;
    if (pOrderData_ != nullptr) {
        obj->SetAlbumOrderNapiProperties();
    }
    CHECK_ARGS(env, napi_wrap(env, thisVar, reinterpret_cast<void *>(obj.get()),
        AlbumOrderNapi::AlbumOrderNapiDestructor, nullptr, nullptr), JS_E_INNER_FAIL);
    obj.release();
    return thisVar;
}

void AlbumOrderNapi::AlbumOrderNapiDestructor(napi_env env, void *nativeObject, void *finalizeHint)
{
    auto *order = reinterpret_cast<AlbumOrderNapi*>(nativeObject);
    lock_guard<mutex> lockGuard(mutex_);
    if (order != nullptr) {
        delete order;
        order = nullptr;
    }
}

napi_value UnwrapAlbumOrderObject(napi_env env, napi_callback_info info, AlbumOrderNapi** obj)
{
    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_E_INNER_FAIL);

    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr), JS_E_INNER_FAIL);
    if (thisVar == nullptr) {
        NapiError::ThrowError(env, JS_E_PARAM_INVALID, "Failed to get cb info");
        return result;
    }

    CHECK_ARGS(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(obj)), JS_E_INNER_FAIL);
    if (obj == nullptr) {
        NapiError::ThrowError(env, JS_E_PARAM_INVALID, "Failed to get album order napi object");
        return result;
    }

    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_E_INNER_FAIL);
    return result;
}

napi_value GetInt32Arg(napi_env env, napi_callback_info info, AlbumOrderNapi** obj, int32_t &value)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_E_INNER_FAIL);
    CHECK_COND(env, argc == ARGS_ONE, JS_E_PARAM_INVALID);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_E_INNER_FAIL);
    napi_valuetype valueType = napi_undefined;
    if ((thisVar == nullptr) || (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok) || (valueType != napi_number)) {
        NapiError::ThrowError(env, JS_E_PARAM_INVALID, "Invalid arguments type!");
        return result;
    }

    CHECK_ARGS(env, napi_get_value_int32(env, argv[PARAM0], &value), JS_E_INNER_FAIL);
    CHECK_ARGS(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(obj)), JS_E_INNER_FAIL);
    if (obj == nullptr) {
        NapiError::ThrowError(env, JS_E_PARAM_INVALID, "Failed to get album order napi object");
        return result;
    }

    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_E_INNER_FAIL);
    return result;
}

napi_value AlbumOrderNapi::JSGetAlbumId(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapAlbumOrderObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetAlbumId(), &jsResult), JS_E_INNER_FAIL);
    return jsResult;
}

napi_value AlbumOrderNapi::JSSetAlbumId(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    int32_t albumId;
    CHECK_COND(env, GetInt32Arg(env, info, &obj, albumId), JS_E_PARAM_INVALID);
    obj->albumOrderPtr->SetAlbumId(albumId);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_E_INNER_FAIL);
    return result;
}

napi_value AlbumOrderNapi::JSGetAlbumOrder(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapAlbumOrderObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetAlbumOrder(), &jsResult), JS_E_INNER_FAIL);
    return jsResult;
}

napi_value AlbumOrderNapi::JSSetAlbumOrder(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    int32_t albumOrder;
    CHECK_COND(env, GetInt32Arg(env, info, &obj, albumOrder), JS_E_PARAM_INVALID);
    obj->albumOrderPtr->SetAlbumOrder(albumOrder);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_E_INNER_FAIL);
    return result;
}

napi_value AlbumOrderNapi::JSGetOrderSection(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapAlbumOrderObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetOrderSection(), &jsResult), JS_E_INNER_FAIL);
    return jsResult;
}

napi_value AlbumOrderNapi::JSSetOrderSection(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    int32_t orderSection;
    CHECK_COND(env, GetInt32Arg(env, info, &obj, orderSection), JS_E_PARAM_INVALID);
    obj->albumOrderPtr->SetOrderSection(orderSection);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_E_INNER_FAIL);
    return result;
}

napi_value AlbumOrderNapi::JSGetOrderType(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapAlbumOrderObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetOrderType(), &jsResult), JS_E_INNER_FAIL);
    return jsResult;
}

napi_value AlbumOrderNapi::JSSetOrderType(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    int32_t orderType;
    CHECK_COND(env, GetInt32Arg(env, info, &obj, orderType), JS_E_PARAM_INVALID);
    obj->albumOrderPtr->SetOrderType(orderType);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_E_INNER_FAIL);
    return result;
}

napi_value AlbumOrderNapi::JSGetOrderStatus(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapAlbumOrderObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetOrderStatus(), &jsResult), JS_E_INNER_FAIL);
    return jsResult;
}

napi_value AlbumOrderNapi::JSSetOrderStatus(napi_env env, napi_callback_info info)
{
    AlbumOrderNapi *obj = nullptr;
    int32_t orderStatus;
    CHECK_COND(env, GetInt32Arg(env, info, &obj, orderStatus), JS_E_PARAM_INVALID);
    obj->albumOrderPtr->SetOrderStatus(orderStatus);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_E_INNER_FAIL);
    return result;
}
} // namespace OHOS::Media