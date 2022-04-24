/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "fetch_file_result_napi.h"
#include "medialibrary_napi_log.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
using namespace std;

namespace OHOS {
namespace Media {
thread_local napi_ref FetchFileResultNapi::sConstructor_ = nullptr;
thread_local FetchResult *FetchFileResultNapi::sFetchFileResult_ = nullptr;
std::shared_ptr<AppExecFwk::DataAbilityHelper> FetchFileResultNapi::sAbilityHelper = nullptr;

FetchFileResultNapi::FetchFileResultNapi()
    : env_(nullptr), wrapper_(nullptr) {}

FetchFileResultNapi::~FetchFileResultNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
        wrapper_ = nullptr;
    }
    fetchFileResult_ = nullptr;
    abilityHelper_ = nullptr;
}

void FetchFileResultNapi::FetchFileResultNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    FetchFileResultNapi *fetchFileResultObj = reinterpret_cast<FetchFileResultNapi*>(nativeObject);
    if (fetchFileResultObj != nullptr) {
        delete fetchFileResultObj;
        fetchFileResultObj = nullptr;
    }
}

napi_value FetchFileResultNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor fetch_file_result_props[] = {
        DECLARE_NAPI_FUNCTION("getCount", JSGetCount),
        DECLARE_NAPI_FUNCTION("isAfterLast", JSIsAfterLast),
        DECLARE_NAPI_FUNCTION("getFirstObject", JSGetFirstObject),
        DECLARE_NAPI_FUNCTION("getNextObject", JSGetNextObject),
        DECLARE_NAPI_FUNCTION("getLastObject", JSGetLastObject),
        DECLARE_NAPI_FUNCTION("getPositionObject", JSGetPositionObject),
        DECLARE_NAPI_FUNCTION("getAllObject", JSGetAllObject),
        DECLARE_NAPI_FUNCTION("close", JSClose)
    };

    status = napi_define_class(env, FETCH_FILE_RESULT_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                               FetchFileResultNapiConstructor, nullptr,
                               sizeof(fetch_file_result_props) / sizeof(fetch_file_result_props[PARAM0]),
                               fetch_file_result_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, FETCH_FILE_RESULT_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    NAPI_DEBUG_LOG("Init success");
    return nullptr;
}

// Constructor callback
napi_value FetchFileResultNapi::FetchFileResultNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status == napi_ok && thisVar != nullptr) {
        unique_ptr<FetchFileResultNapi> obj = make_unique<FetchFileResultNapi>();
        if (obj != nullptr) {
            obj->env_ = env;

            if (sFetchFileResult_ != nullptr) {
                unique_ptr<FetchResult> fetchRes = make_unique<FetchResult>(
                    move(sFetchFileResult_->resultset_));
                obj->fetchFileResult_ = std::move(fetchRes);
                obj->fetchFileResult_->isContain_ = sFetchFileResult_->isContain_;
                obj->fetchFileResult_->isClosed_ = sFetchFileResult_->isClosed_;
                obj->fetchFileResult_->count_ = sFetchFileResult_->count_;
                obj->fetchFileResult_->networkId_ = sFetchFileResult_->networkId_;
                obj->abilityHelper_ = sAbilityHelper;
                fetchRes.release();
            } else {
                NAPI_ERR_LOG("No native instance assigned yet");
                return result;
            }

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               FetchFileResultNapi::FetchFileResultNapiDestructor, nullptr, &(obj->wrapper_));
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                NAPI_ERR_LOG("Failure wrapping js to native napi, status: %{public}d", status);
            }
        }
    }
    return result;
}

napi_value FetchFileResultNapi::CreateFetchFileResult(napi_env env, FetchResult &fileResult,
    std::shared_ptr<AppExecFwk::DataAbilityHelper> abilityHelper)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sAbilityHelper = abilityHelper;
        sFetchFileResult_ = &fileResult;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sFetchFileResult_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            NAPI_ERR_LOG("Failed to create fetch file result instance, status: %{private}d", status);
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

std::shared_ptr<AppExecFwk::DataAbilityHelper> FetchFileResultNapi::GetDataAbilityHelper() const
{
    return abilityHelper_;
}

napi_value FetchFileResultNapi::JSGetCount(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FetchFileResultNapi* obj = nullptr;
    int32_t count = 0;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("JSGetCount Invalid arguments!, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSGetCount thisVar == nullptr");
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        count = obj->fetchFileResult_->GetCount();
        napi_create_int32(env, count, &jsResult);
    } else {
        NAPI_ERR_LOG("JSGetCount obj == nullptr, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSGetCount obj == nullptr");
    }

    return jsResult;
}

napi_value FetchFileResultNapi::JSIsAfterLast(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FetchFileResultNapi* obj = nullptr;
    bool isAfterLast = false;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("JSIsAfterLast Invalid arguments!, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSIsAfterLast thisVar == nullptr");
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        isAfterLast = obj->fetchFileResult_->IsAtLastRow();
        napi_get_boolean(env, isAfterLast, &jsResult);
    } else {
        NAPI_ERR_LOG("JSIsAfterLast obj == nullptr, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSIsAfterLast obj == nullptr");
    }

    return jsResult;
}

static void GetPositionObjectCompleteCallback(napi_env env, napi_status status, FetchFileResultAsyncContext* context)
{
    napi_value jsFileAsset = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->fileAsset != nullptr) {
        jsFileAsset = FileAssetNapi::CreateFileAsset(env, *(context->fileAsset),
                                                     context->objectInfo->GetDataAbilityHelper());
        if (jsFileAsset == nullptr) {
            NAPI_ERR_LOG("Failed to get file asset napi object");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                "Failed to create js object for FileAsset");
        } else {
            jsContext->data = jsFileAsset;
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        NAPI_ERR_LOG("No file asset found!");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain fileAsset from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value FetchFileResultNapi::JSGetFirstObject(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetFirstObject");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                context->fileAsset = context->objectInfo->fetchFileResult_->GetFirstObject();
            },
            reinterpret_cast<napi_async_complete_callback>(GetPositionObjectCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    } else {
        NAPI_ERR_LOG("JSGetFirstObject obj == nullptr, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSGetFirstObject obj == nullptr");
    }

    return result;
}

napi_value FetchFileResultNapi::JSGetNextObject(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetNextObject");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                context->fileAsset = context->objectInfo->fetchFileResult_->GetNextObject();
            },
            reinterpret_cast<napi_async_complete_callback>(GetPositionObjectCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    } else {
        NAPI_ERR_LOG("JSGetNextObject obj == nullptr, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSGetNextObject obj == nullptr");
    }

    return result;
}

napi_value FetchFileResultNapi::JSGetLastObject(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetLastObject");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                context->fileAsset = context->objectInfo->fetchFileResult_->GetLastObject();
            },
            reinterpret_cast<napi_async_complete_callback>(GetPositionObjectCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    } else {
        NAPI_ERR_LOG("JSGetLastObject obj == nullptr, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSGetLastObject obj == nullptr");
    }

    return result;
}

napi_value FetchFileResultNapi::JSGetPositionObject(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_valuetype type = napi_undefined;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameter maximum");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        // Check the arguments and their types
        napi_typeof(env, argv[PARAM0], &type);
        if (type == napi_number) {
            napi_get_value_int32(env, argv[PARAM0], &(asyncContext->position));
        } else {
            NAPI_ERR_LOG("Argument mismatch, type: %{private}d", type);
            return result;
        }

        if (argc == ARGS_TWO) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM1], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetPositionObject");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                context->fileAsset = context->objectInfo->fetchFileResult_->GetObjectAtPosition(context->position);
            },
            reinterpret_cast<napi_async_complete_callback>(GetPositionObjectCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    } else {
        NAPI_ERR_LOG("JSGetPositionObject obj == nullptr, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSGetPositionObject obj == nullptr");
    }

    return result;
}

static void GetAllObjectCompleteCallback(napi_env env, napi_status status, FetchFileResultAsyncContext* context)
{
    napi_value jsFileAsset = nullptr;
    napi_value jsFileArray = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (!context->fileAssetArray.empty() && (napi_create_array(env, &jsFileArray) == napi_ok)) {
        size_t len = context->fileAssetArray.size();
        size_t i = 0;
        for (i = 0; i < len; i++) {
            jsFileAsset = FileAssetNapi::CreateFileAsset(env, *(context->fileAssetArray[i]),
                                                         context->objectInfo->GetDataAbilityHelper());
            if (jsFileAsset == nullptr || napi_set_element(env, jsFileArray, i, jsFileAsset) != napi_ok) {
                NAPI_ERR_LOG("Failed to get file asset napi object");
                napi_get_undefined(env, &jsContext->data);
                MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                    "Failed to create js object for FileAsset");
                break;
            }
        }

        if (i == len) {
            jsContext->data = jsFileArray;
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        NAPI_ERR_LOG("No file asset found!");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain fileAsset array from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

std::shared_ptr<FetchResult> FetchFileResultNapi::GetFetchResultObject()
{
    return fetchFileResult_;
}

void GetAllObjectFromFetchResult(const FetchFileResultAsyncContext &asyncContext)
{
    unique_ptr<FileAsset> fAsset = nullptr;
    FetchFileResultAsyncContext *context = const_cast<FetchFileResultAsyncContext *>(&asyncContext);

    fAsset = context->objectInfo->GetFetchResultObject()->GetFirstObject();
    while (fAsset != nullptr) {
        context->fileAssetArray.push_back(move(fAsset));
        fAsset = context->objectInfo->GetFetchResultObject()->GetNextObject();
    }
}

napi_value FetchFileResultNapi::JSGetAllObject(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAllObject");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                GetAllObjectFromFetchResult(*context);
            },
            reinterpret_cast<napi_async_complete_callback>(GetAllObjectCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    } else {
        NAPI_ERR_LOG("JSGetAllObject obj == nullptr, status: %{private}d", status);
        NAPI_ASSERT(env, false, "JSGetAllObject obj == nullptr");
    }

    return result;
}

napi_value FetchFileResultNapi::JSClose(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FetchFileResultNapi* obj = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments!, status: %{private}d", status);
        return jsResult;
    }

    status = napi_remove_wrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_create_int32(env, SUCCESS, &jsResult);
    } else {
        NAPI_INFO_LOG("JSClose obj == nullptr");
    }

    NAPI_DEBUG_LOG("JSClose OUT!");
    return jsResult;
}
} // namespace Media
} // namespace OHOS
