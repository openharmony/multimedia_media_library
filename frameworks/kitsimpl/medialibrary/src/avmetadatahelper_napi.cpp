/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "avmetadatahelper_napi.h"
#include <climits>
#include "medialibrary_napi_log.h"
#include "pixel_map_napi.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace OHOS {
namespace Media {
thread_local napi_ref AVMetadataHelperNapi::constructor_ = nullptr;
static const char CLASS_NAME[] = "AVMetadataHelper";
struct AVMetadataHelperAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef = nullptr;
    int32_t status = 0;
    int32_t key = 0;
    int32_t timeMs = 0;
    int32_t option = OHOS::Media::AV_META_QUERY_NEXT_SYNC;
    std::string valueStr = "";
    std::string uriStr = "";
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = nullptr;
    OHOS::Media::PixelMapParams pixelMapParams;
    std::shared_ptr<OHOS::Media::AVMetadataHelper> nativeAVMetadataHelper = nullptr;
    AVMetadataHelperNapi *objectInfo = nullptr;
    std::string debugInfo = "";
};

static std::string GetStringArgument(napi_env env, napi_value value)
{
    std::string strValue = "";
    size_t bufLength = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &bufLength);
    if (status == napi_ok && bufLength > 0 && bufLength < PATH_MAX) {
        char *buffer =  reinterpret_cast<char *>(malloc((bufLength + 1) * sizeof(char)));
        if (buffer == nullptr) {
            NAPI_ERR_LOG("no memory");
            return strValue;
        }

        status = napi_get_value_string_utf8(env, value, buffer, bufLength + 1, &bufLength);
        if (status == napi_ok) {
            strValue = buffer;
        }
        free(buffer);
        buffer = nullptr;
    }
    return strValue;
}

static void CommonCallbackRoutine(napi_env env, AVMetadataHelperAsyncContext* &asyncContext,
    const napi_value &valueParam)
{
    constexpr int32_t paramCnt = 2;
    napi_value result[paramCnt] = { nullptr };
    napi_value retVal;

    napi_get_undefined(env, &result[0]);
    napi_get_undefined(env, &result[1]);
    if (asyncContext->status != 0) {
        result[0] = valueParam;
    } else {
        result[1] = valueParam;
    }

    if (asyncContext->deferred) {
        if (asyncContext->status != 0) {
            napi_reject_deferred(env, asyncContext->deferred, result[0]);
        } else {
            napi_resolve_deferred(env, asyncContext->deferred, result[1]);
        }
    } else {
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, paramCnt, result, &retVal);
        napi_delete_reference(env, asyncContext->callbackRef);
    }
    napi_delete_async_work(env, asyncContext->work);

    delete asyncContext;
    asyncContext = nullptr;
}

static napi_status CreateError(napi_env env, int32_t errCode, const std::string &errMsg, napi_value &errVal)
{
    napi_get_undefined(env, &errVal);

    napi_value msgValStr = nullptr;
    napi_status status = napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &msgValStr);
    if (status != napi_ok || msgValStr == nullptr) {
        NAPI_ERR_LOG("create error message str fail, status: %{private}d", status);
        return napi_invalid_arg;
    }

    status = napi_create_error(env, nullptr, msgValStr, &errVal);
    if (status != napi_ok || errVal == nullptr) {
        NAPI_ERR_LOG("create error fail, status: %{private}d", status);
        return napi_invalid_arg;
    }

    napi_value codeStr = nullptr;
    status = napi_create_string_utf8(env, "code", NAPI_AUTO_LENGTH, &codeStr);
    if (status != napi_ok || codeStr == nullptr) {
        NAPI_ERR_LOG("create code str fail, status: %{private}d", status);
        return napi_invalid_arg;
    }

    napi_value errCodeVal = nullptr;
    status = napi_create_int32(env, errCode, &errCodeVal);
    if (status != napi_ok || errCodeVal == nullptr) {
        NAPI_ERR_LOG("create error code number val fail, status: %{private}d", status);
        return napi_invalid_arg;
    }

    status = napi_set_property(env, errVal, codeStr, errCodeVal);
    if (status != napi_ok) {
        NAPI_ERR_LOG("set error code property fail, status: %{private}d", status);
        return napi_invalid_arg;
    }

    napi_value nameStr = nullptr;
    status = napi_create_string_utf8(env, "name", NAPI_AUTO_LENGTH, &nameStr);
    if (status != napi_ok || nameStr == nullptr) {
        NAPI_ERR_LOG("create name str fail, status: %{private}d", status);
        return napi_invalid_arg;
    }

    napi_value errNameVal = nullptr;
    status = napi_create_string_utf8(env, "BusinessError", NAPI_AUTO_LENGTH, &errNameVal);
    if (status != napi_ok || errNameVal == nullptr) {
        NAPI_ERR_LOG("create BusinessError str fail, status: %{private}d", status);
        return napi_invalid_arg;
    }

    status = napi_set_property(env, errVal, nameStr, errNameVal);
    if (status != napi_ok) {
        NAPI_ERR_LOG("set error name property fail, status: %{private}d", status);
        return napi_invalid_arg;
    }

    return napi_ok;
}

static void GetPixelMapAsyncCallbackComplete(napi_env env, napi_status status,
    AVMetadataHelperAsyncContext *asyncContext)
{
    napi_value valueParam = nullptr;

    if (asyncContext == nullptr) {
        NAPI_ERR_LOG("AVMetadataHelperAsyncContext is nullptr!");
        return;
    }

    if (status == napi_ok) {
        if (asyncContext->pixelMap != nullptr) {
            valueParam = Media::PixelMapNapi::CreatePixelMap(env, asyncContext->pixelMap);
            asyncContext->status = 0;
        } else {
            (void)CreateError(env, -1, "Failed to fetchPixelMap", valueParam);
            asyncContext->status = -1;
        }
    } else {
        (void)CreateError(env, -1, "Failed to fetchPixelMap", valueParam);
        asyncContext->status = -1;
    }
    CommonCallbackRoutine(env, asyncContext, valueParam);
}

static void SetFunctionAsyncCallbackComplete(napi_env env, napi_status status,
    AVMetadataHelperAsyncContext *asyncContext)
{
    napi_value valueParam = nullptr;
    napi_get_undefined(env, &valueParam);

    if (asyncContext == nullptr) {
        NAPI_ERR_LOG("AVMetadataHelperAsyncContext is nullptr!");
        return;
    }

    NAPI_INFO_LOG("async context status : %{private}d, status : %{private}d", asyncContext->status, status);
    if (status == napi_ok) {
        if (asyncContext->status != 0) {
            (void)CreateError(env, -1, asyncContext->debugInfo, valueParam);
        }
    } else {
        asyncContext->status = -1;
        (void)CreateError(env, -1, asyncContext->debugInfo, valueParam);
    }

    CommonCallbackRoutine(env, asyncContext, valueParam);
}

static void GetStringValueAsyncCallbackComplete(napi_env env, napi_status status,
    AVMetadataHelperAsyncContext *asyncContext)
{
    napi_value valueParam = nullptr;
    napi_get_undefined(env, &valueParam);

    if (asyncContext == nullptr) {
        NAPI_ERR_LOG("AVMetadataHelperAsyncContext is nullptr!");
        return;
    }

    NAPI_INFO_LOG("async context status : %{private}d, status : %{private}d", asyncContext->status, status);

    if (status == napi_ok) {
        status = napi_create_string_utf8(
            env, asyncContext->valueStr.c_str(), NAPI_AUTO_LENGTH, &valueParam);
        if (status != napi_ok) {
            (void)CreateError(env, -1, "Failed to resolve metadata", valueParam);
            asyncContext->status = -1;
        } else {
            asyncContext->status = 0;
        }
    } else {
        (void)CreateError(env, -1, "Failed to resolve metadata", valueParam);
        asyncContext->status = -1;
    }
    CommonCallbackRoutine(env, asyncContext, valueParam);
}

static void GetPixelMapInfo(napi_env env, napi_value configObj, std::string type, int32_t &result)
{
    napi_value item = nullptr;
    bool exist = false;
    napi_status status = napi_has_named_property(env, configObj, type.c_str(), &exist);
    if (status != napi_ok || !exist) {
        NAPI_ERR_LOG("can not find named property, status: %{private}d", status);
        return;
    }

    if (napi_get_named_property(env, configObj, type.c_str(), &item) != napi_ok) {
        NAPI_ERR_LOG("get named property fail");
        return;
    }

    if (napi_get_value_int32(env, item, &result) != napi_ok) {
        NAPI_ERR_LOG("get property value fail");
    }
}

static void GetPixelMapSize(napi_env env, napi_value args, int32_t &width, int32_t &height)
{
    GetPixelMapInfo(env, args, "width", width);
    GetPixelMapInfo(env, args, "height", height);
}

AVMetadataHelperNapi::AVMetadataHelperNapi()
{
}

AVMetadataHelperNapi::~AVMetadataHelperNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
        wrapper_ = nullptr;
    }
    nativeAVMetadataHelper_ = nullptr;
}

napi_value AVMetadataHelperNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("setSource", SetSource),
        DECLARE_NAPI_FUNCTION("resolveMetadata", ResolveMetadata),
        DECLARE_NAPI_FUNCTION("fetchVideoScaledPixelMapByTime", FetchVideoScaledPixelMapByTime),
        DECLARE_NAPI_FUNCTION("fetchVideoPixelMapByTime", FetchVideoPixelMapByTime),
        DECLARE_NAPI_FUNCTION("release", Release)
    };

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getAVMetadataHelper", CreateAVMetadataHelper),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME, NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    if (status != napi_ok) {
        NAPI_ERR_LOG("define class fail, status: %{private}d", status);
        return nullptr;
    }

    status = napi_create_reference(env, constructor, 1, &constructor_);
    if (status != napi_ok) {
        NAPI_ERR_LOG("create reference fail, status: %{private}d", status);
        return nullptr;
    }

    status = napi_set_named_property(env, exports, CLASS_NAME, constructor);
    if (status != napi_ok) {
        NAPI_ERR_LOG("set named property fail, status: %{private}d", status);
        return nullptr;
    }

    status = napi_define_properties(env, exports, sizeof(static_prop) / sizeof(static_prop[0]), static_prop);
    if (status != napi_ok) {
        NAPI_ERR_LOG("define properties fail, status: %{private}d", status);
        return nullptr;
    }

    NAPI_DEBUG_LOG("Init success");
    return exports;
}

napi_value AVMetadataHelperNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value jsThis = nullptr;
    size_t argCount = 0;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    if (status != napi_ok) {
        NAPI_ERR_LOG("get callback info fail, status: %{private}d", status);
        return result;
    }

    AVMetadataHelperNapi *avMetadataHelperNapi = new(std::nothrow) AVMetadataHelperNapi();
    if (avMetadataHelperNapi == nullptr) {
        NAPI_ERR_LOG("no memory");
        return result;
    }

    avMetadataHelperNapi->env_ = env;
    avMetadataHelperNapi->nativeAVMetadataHelper_ = OHOS::Media::AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (avMetadataHelperNapi->nativeAVMetadataHelper_ == nullptr) {
        delete avMetadataHelperNapi;
        NAPI_ERR_LOG("nativeAVMetadataHelper_ no memory");
        return result;
    }

    status = napi_wrap(env, jsThis, reinterpret_cast<void *>(avMetadataHelperNapi),
        AVMetadataHelperNapi::Destructor, nullptr, &(avMetadataHelperNapi->wrapper_));
    if (status != napi_ok) {
        delete avMetadataHelperNapi;
        NAPI_ERR_LOG("native wrap fail, status: %{private}d", status);
        return result;
    }

    return jsThis;
}

void AVMetadataHelperNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    (void)env;
    (void)finalize;
    if (nativeObject != nullptr) {
        delete reinterpret_cast<AVMetadataHelperNapi *>(nativeObject);
    }
    NAPI_DEBUG_LOG("Destructor success");
}

napi_value AVMetadataHelperNapi::CreateAVMetadataHelper(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value constructor = nullptr;
    napi_status status = napi_get_reference_value(env, constructor_, &constructor);
    if (status != napi_ok) {
        NAPI_ERR_LOG("get reference value fail, status: %{private}d", status);
        napi_get_undefined(env, &result);
        return result;
    }

    status = napi_new_instance(env, constructor, 0, nullptr, &result);
    if (status != napi_ok) {
        NAPI_ERR_LOG("new instance fail, status: %{private}d", status);
        napi_get_undefined(env, &result);
        return result;
    }

    NAPI_DEBUG_LOG("CreateAVMetadataHelper success");
    return result;
}

napi_value AVMetadataHelperNapi::SetSource(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);

    size_t argc = 2; // 2 agrs
    napi_value argv[2] = {0}; // 2 agrs
    napi_value thisVar = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 2, "SetSource requires 2 parameter maximum"); // 2 agrs

    std::unique_ptr<AVMetadataHelperAsyncContext> asyncContext = std::make_unique<AVMetadataHelperAsyncContext>();

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&asyncContext->objectInfo));
    if (status != napi_ok || asyncContext->objectInfo == nullptr) {
        NAPI_ERR_LOG("SetSource get napi error, status: %{private}d", status);
        return undefinedResult;
    }

    const int32_t refCount = 1;
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == 0 && valueType == napi_string) {
            asyncContext->uriStr = GetStringArgument(env, argv[i]);
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &asyncContext->callbackRef);
        } else {
            NAPI_ERR_LOG("SetSource type mismatch, valueType: %{private}d", valueType);
        }
    }

    NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, undefinedResult);

    napi_value resource = nullptr;
    NAPI_CREATE_RESOURCE_NAME(env, resource, "SetSource");

    asyncContext->debugInfo = std::string("Failed to set source: ") + asyncContext->uriStr;
    asyncContext->nativeAVMetadataHelper = asyncContext->objectInfo->nativeAVMetadataHelper_;
    status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            auto context = static_cast<AVMetadataHelperAsyncContext*>(data);
            if (context->nativeAVMetadataHelper != nullptr) {
                context->status = context->nativeAVMetadataHelper->SetSource(context->uriStr);
            }
        },
        reinterpret_cast<napi_async_complete_callback>(SetFunctionAsyncCallbackComplete),
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        NAPI_ERR_LOG("SetSource async work error, status: %{private}d", status);
        napi_get_undefined(env, &undefinedResult);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return undefinedResult;
}

napi_value AVMetadataHelperNapi::ResolveMetadata(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);

    size_t argc = 2; // 2 agrs
    napi_value argv[2] = {0}; // 2 agrs
    napi_value thisVar = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 2, "ResolveMetadata requires 2 parameter maximum"); // 2 agrs

    std::unique_ptr<AVMetadataHelperAsyncContext> asyncContext = std::make_unique<AVMetadataHelperAsyncContext>();

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&asyncContext->objectInfo));
    if (status != napi_ok || asyncContext->objectInfo == nullptr) {
        NAPI_ERR_LOG("ResolveMetadata get napi error, status: %{private}d", status);
        return undefinedResult;
    }

    const int32_t refCount = 1;
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == 0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &asyncContext->key);
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &asyncContext->callbackRef);
        } else {
            NAPI_ERR_LOG("ResolveMetadata type mismatch, valueType: %{private}d", valueType);
        }
    }

    NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, undefinedResult);

    napi_value resource = nullptr;
    NAPI_CREATE_RESOURCE_NAME(env, resource, "ResolveMetadata");

    asyncContext->nativeAVMetadataHelper = asyncContext->objectInfo->nativeAVMetadataHelper_;
    status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            auto context = static_cast<AVMetadataHelperAsyncContext*>(data);
            if (context->nativeAVMetadataHelper != nullptr) {
                context->valueStr = context->nativeAVMetadataHelper->ResolveMetadata(context->key);
                context->status = 0;
            }
        },
        reinterpret_cast<napi_async_complete_callback>(GetStringValueAsyncCallbackComplete),
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        NAPI_ERR_LOG("ResolveMetadata async work error, status: %{private}d", status);
        napi_get_undefined(env, &undefinedResult);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return undefinedResult;
}

napi_value AVMetadataHelperNapi::FetchVideoScaledPixelMapByTime(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);

    size_t argc = 3; // 3 agrs
    napi_value argv[3] = {0}; // 3 agrs
    napi_value thisVar = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 3, "FetchVideoScaledPixelMapByTime requires 3 parameter maximum"); // 3 agrs

    std::unique_ptr<AVMetadataHelperAsyncContext> asyncContext = std::make_unique<AVMetadataHelperAsyncContext>();

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&asyncContext->objectInfo));
    if (status != napi_ok || asyncContext->objectInfo == nullptr) {
        NAPI_ERR_LOG("FetchVideoScaledPixelMapByTime get napi error, status: %{private}d", status);
        return undefinedResult;
    }

    const int32_t refCount = 1;
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == 0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &asyncContext->timeMs);
        } else if (i == 1 && valueType == napi_object) {
            GetPixelMapSize(env, argv[i], asyncContext->pixelMapParams.dstWidth,
                asyncContext->pixelMapParams.dstHeight);
        } else if (i == 2 && valueType == napi_function) { // 2 param
            napi_create_reference(env, argv[i], refCount, &asyncContext->callbackRef);
        }
    }

    NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, undefinedResult);

    napi_value resource = nullptr;
    NAPI_CREATE_RESOURCE_NAME(env, resource, "FetchVideoScaledPixelMapByTime");

    asyncContext->nativeAVMetadataHelper = asyncContext->objectInfo->nativeAVMetadataHelper_;
    status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            auto context = static_cast<AVMetadataHelperAsyncContext*>(data);
            if (context->nativeAVMetadataHelper != nullptr) {
                context->pixelMap = context->nativeAVMetadataHelper->FetchFrameAtTime(context->timeMs,
                    context->option, context->pixelMapParams);
            }
        },
        reinterpret_cast<napi_async_complete_callback>(GetPixelMapAsyncCallbackComplete),
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        NAPI_ERR_LOG("FetchVideoScaledPixelMapByTime async work error, status: %{private}d", status);
        napi_get_undefined(env, &undefinedResult);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return undefinedResult;
}

napi_value AVMetadataHelperNapi::FetchVideoPixelMapByTime(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);

    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 2, "FetchVideoPixelMapByTime requires 2 parameter maximum"); // 2 agrs

    std::unique_ptr<AVMetadataHelperAsyncContext> asyncContext = std::make_unique<AVMetadataHelperAsyncContext>();

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&asyncContext->objectInfo));
    if (status != napi_ok || asyncContext->objectInfo == nullptr) {
        NAPI_ERR_LOG("FetchVideoPixelMapByTime get napi error, status: %{private}d", status);
        return undefinedResult;
    }

    const int32_t refCount = 1;
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == 0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &asyncContext->timeMs);
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &asyncContext->callbackRef);
        } else {
            NAPI_ERR_LOG("FetchVideoPixelMapByTime type mismatch, valueType: %{private}d", valueType);
        }
    }

    NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, undefinedResult);

    napi_value resource = nullptr;
    NAPI_CREATE_RESOURCE_NAME(env, resource, "FetchVideoPixelMapByTime");

    asyncContext->nativeAVMetadataHelper = asyncContext->objectInfo->nativeAVMetadataHelper_;
    status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            auto context = static_cast<AVMetadataHelperAsyncContext*>(data);
            if (context->nativeAVMetadataHelper != nullptr) {
                context->pixelMap = context->nativeAVMetadataHelper->FetchFrameAtTime(context->timeMs,
                    context->option, context->pixelMapParams);
            }
        },
        reinterpret_cast<napi_async_complete_callback>(GetPixelMapAsyncCallbackComplete),
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        NAPI_ERR_LOG("FetchVideoPixelMapByTime async work error, status: %{private}d", status);
        napi_get_undefined(env, &undefinedResult);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return undefinedResult;
}

napi_value AVMetadataHelperNapi::Release(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);

    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 1, "Release requires 1 parameter maximum");

    std::unique_ptr<AVMetadataHelperAsyncContext> asyncContext = std::make_unique<AVMetadataHelperAsyncContext>();

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&asyncContext->objectInfo));
    if (status != napi_ok || asyncContext->objectInfo == nullptr) {
        NAPI_ERR_LOG("Release get napi error, status: %{private}d", status);
        return undefinedResult;
    }

    if (argc == 1) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[0], &valueType);

        const int32_t refCount = 1;
        if (valueType == napi_function) {
            napi_create_reference(env, argv[0], refCount, &asyncContext->callbackRef);
        } else {
            NAPI_ERR_LOG("Release type mismatch, valueType: %{private}d", valueType);
        }
    }

    NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, undefinedResult);

    napi_value resource = nullptr;
    NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

    asyncContext->debugInfo = "Failed to release";
    asyncContext->nativeAVMetadataHelper = asyncContext->objectInfo->nativeAVMetadataHelper_;
    status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            auto context = static_cast<AVMetadataHelperAsyncContext*>(data);
            if (context->nativeAVMetadataHelper != nullptr) {
                context->nativeAVMetadataHelper->Release();
                context->status = 0;
            }
        },
        reinterpret_cast<napi_async_complete_callback>(SetFunctionAsyncCallbackComplete),
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Release async work error, status: %{private}d", status);
        napi_get_undefined(env, &undefinedResult);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return undefinedResult;
}
}  // namespace Media
}  // namespace OHOS