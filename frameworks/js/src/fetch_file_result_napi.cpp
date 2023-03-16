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
#define MLOG_TAG "FetchResultNapi"

#include "fetch_file_result_napi.h"

#include "album_napi.h"
#include "hitrace_meter.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "smart_album_napi.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
using namespace std;

namespace OHOS {
namespace Media {
thread_local napi_ref FetchFileResultNapi::sConstructor_ = nullptr;

thread_local napi_ref FetchFileResultNapi::userFileMgrConstructor_ = nullptr;

FetchFileResultNapi::FetchFileResultNapi()
    : env_(nullptr) {}

FetchFileResultNapi::~FetchFileResultNapi()
{
    propertyPtr = nullptr;
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

void FetchFileResultNapi::GetFetchResult(unique_ptr<FetchFileResultNapi> &obj)
{
    switch (sFetchResType_) {
        case FetchResType::TYPE_FILE:
            obj->propertyPtr->fetchFileResult_ =
                make_shared<FetchResult<FileAsset>>(move(sFetchFileResult_->resultset_));
            obj->propertyPtr->fetchFileResult_->SetInfo(sFetchFileResult_);
            obj->propertyPtr->typeMask_ = obj->propertyPtr->fetchFileResult_->typeMask_;
            break;
        case FetchResType::TYPE_ALBUM:
            obj->propertyPtr->fetchAlbumResult_ =
                make_shared<FetchResult<AlbumAsset>>(move(sFetchAlbumResult_->resultset_));
            obj->propertyPtr->fetchAlbumResult_->SetInfo(sFetchAlbumResult_);
            obj->propertyPtr->typeMask_ = obj->propertyPtr->fetchAlbumResult_->typeMask_;
            break;
        case FetchResType::TYPE_SMARTALBUM:
            obj->propertyPtr->fetchSmartAlbumResult_ =
                make_shared<FetchResult<SmartAlbumAsset>>(move(sFetchSmartAlbumResult_->resultset_));
            obj->propertyPtr->fetchSmartAlbumResult_->SetInfo(sFetchSmartAlbumResult_);
            obj->propertyPtr->typeMask_ = obj->propertyPtr->fetchSmartAlbumResult_->typeMask_;
            break;
        default:
            NAPI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

// Constructor callback
napi_value FetchFileResultNapi::FetchFileResultNapiConstructor(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("FetchFileResultNapiConstructor");

    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Get Js obj failed, status: %{public}d, (thisVar == nullptr) = %{public}d",
            status, (thisVar == nullptr));
        return result;
    }

    unique_ptr<FetchFileResultNapi> obj = make_unique<FetchFileResultNapi>();
    if (obj == nullptr) {
        NAPI_ERR_LOG("Get FetchFileResultNapi failed");
        return result;
    }
    obj->env_ = env;
    obj->propertyPtr = make_shared<FetchResultProperty>();
    GetFetchResult(obj);
    obj->propertyPtr->fetchResType_ = sFetchResType_;
    status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                       FetchFileResultNapi::FetchFileResultNapiDestructor, nullptr, nullptr);
    if (status == napi_ok) {
        obj.release();
        return thisVar;
    } else {
        NAPI_ERR_LOG("Failure wrapping js to native napi, status: %{public}d", status);
    }
    return result;
}

FetchResType FetchFileResultNapi::GetFetchResType()
{
    return propertyPtr->fetchResType_;
}

napi_value FetchFileResultNapi::CreateFetchFileResult(napi_env env, unique_ptr<FetchResult<FileAsset>> fileResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("CreateFetchFileResult");
    napi_value constructor;
    napi_ref constructorRef = (fileResult->resultNapiType_ == ResultNapiType::TYPE_USERFILE_MGR) ?
        (userFileMgrConstructor_) : (sConstructor_);
    NAPI_CALL(env, napi_get_reference_value(env, constructorRef, &constructor));
    sFetchResType_ = fileResult->fetchResType_;
    sFetchFileResult_ = move(fileResult);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));
    sFetchFileResult_ = nullptr;
    return result;
}

napi_value FetchFileResultNapi::CreateFetchFileResult(napi_env env, unique_ptr<FetchResult<AlbumAsset>> fileResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("CreateFetchFileResult");
    napi_value constructor;
    napi_ref constructorRef = (fileResult->resultNapiType_ == ResultNapiType::TYPE_USERFILE_MGR) ?
        (userFileMgrConstructor_) : (sConstructor_);
    NAPI_CALL(env, napi_get_reference_value(env, constructorRef, &constructor));
    sFetchResType_ = fileResult->fetchResType_;
    sFetchAlbumResult_ = move(fileResult);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));
    sFetchAlbumResult_ = nullptr;
    return result;
}

napi_value FetchFileResultNapi::CreateFetchFileResult(napi_env env, unique_ptr<FetchResult<SmartAlbumAsset>> fileResult)
{
    MediaLibraryTracer tracer;
    tracer.Start("CreateFetchFileResult");
    napi_value constructor;
    napi_ref constructorRef = (fileResult->resultNapiType_ == ResultNapiType::TYPE_USERFILE_MGR) ?
        (userFileMgrConstructor_) : (sConstructor_);
    NAPI_CALL(env, napi_get_reference_value(env, constructorRef, &constructor));
    sFetchResType_ = fileResult->fetchResType_;
    sFetchSmartAlbumResult_ = move(fileResult);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));
    sFetchSmartAlbumResult_ = nullptr;
    return result;
}

std::shared_ptr<FetchResult<FileAsset>> FetchFileResultNapi::GetFetchFileResult() const
{
    return propertyPtr->fetchFileResult_;
}

napi_value FetchFileResultNapi::UserFileMgrInit(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = UFM_FETCH_FILE_RESULT_CLASS_NAME,
        .ref = &userFileMgrConstructor_,
        .constructor = FetchFileResultNapiConstructor,
        .props = {
            DECLARE_NAPI_FUNCTION("getCount", JSGetCount),
            DECLARE_NAPI_FUNCTION("isAfterLast", JSIsAfterLast),
            DECLARE_NAPI_FUNCTION("getFirstObject", JSGetFirstObject),
            DECLARE_NAPI_FUNCTION("getNextObject", JSGetNextObject),
            DECLARE_NAPI_FUNCTION("getLastObject", JSGetLastObject),
            DECLARE_NAPI_FUNCTION("getPositionObject", JSGetPositionObject),
            DECLARE_NAPI_FUNCTION("close", JSClose)
        }
    };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

static bool CheckIfFFRNapiNotEmpty(FetchFileResultNapi* obj)
{
    if (obj == nullptr) {
        NAPI_INFO_LOG("FetchFileResultNapi is nullptr");
        return false;
    }
    if (obj->CheckIfPropertyPtrNull()) {
        NAPI_INFO_LOG("PropertyPtr in FetchFileResultNapi is nullptr");
        return false;
    }
    return true;
}

napi_value FetchFileResultNapi::JSGetCount(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FetchFileResultNapi* obj = nullptr;
    int32_t count = 0;
    napi_value thisVar = nullptr;

    MediaLibraryTracer tracer;
    tracer.Start("JSGetCount");

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("JSGetCount Invalid arguments!, status: %{public}d", status);
        NAPI_ASSERT(env, false, "JSGetCount thisVar == nullptr");
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && CheckIfFFRNapiNotEmpty(obj)) {
        switch (obj->GetFetchResType()) {
            case FetchResType::TYPE_FILE:
                count = obj->GetFetchFileResultObject()->GetCount();
                break;
            case FetchResType::TYPE_ALBUM:
                count = obj->GetFetchAlbumResultObject()->GetCount();
                break;
            case FetchResType::TYPE_SMARTALBUM:
                count = obj->GetFetchSmartAlbumResultObject()->GetCount();
                break;
            default:
                NAPI_ERR_LOG("unsupported FetchResType");
                break;
        }
        napi_create_int32(env, count, &jsResult);
    } else {
        NAPI_ERR_LOG("JSGetCount obj == nullptr, status: %{public}d", status);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSIsAfterLast");

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("JSIsAfterLast Invalid arguments!, status: %{public}d", status);
        NAPI_ASSERT(env, false, "JSIsAfterLast thisVar == nullptr");
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && CheckIfFFRNapiNotEmpty(obj)) {
        switch (obj->GetFetchResType()) {
            case FetchResType::TYPE_FILE:
                isAfterLast = obj->GetFetchFileResultObject()->IsAtLastRow();
                break;
            case FetchResType::TYPE_ALBUM:
                isAfterLast = obj->GetFetchAlbumResultObject()->IsAtLastRow();
                break;
            case FetchResType::TYPE_SMARTALBUM:
                isAfterLast = obj->GetFetchSmartAlbumResultObject()->IsAtLastRow();
                break;
            default:
                NAPI_ERR_LOG("unsupported FetchResType");
                break;
        }
        napi_get_boolean(env, isAfterLast, &jsResult);
    } else {
        NAPI_ERR_LOG("JSIsAfterLast obj == nullptr, status: %{public}d", status);
        NAPI_ASSERT(env, false, "JSIsAfterLast obj == nullptr");
    }

    return jsResult;
}

static void GetNapiResFromAsset(napi_env env, FetchFileResultAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    napi_value jsAsset;
    switch (context->objectPtr->fetchResType_) {
        case FetchResType::TYPE_FILE:
            jsAsset = FileAssetNapi::CreateFileAsset(env, context->fileAsset);
            break;
        case FetchResType::TYPE_ALBUM:
            jsAsset = AlbumNapi::CreateAlbumNapi(env, context->albumAsset);
            break;
        case FetchResType::TYPE_SMARTALBUM:
            jsAsset = SmartAlbumNapi::CreateSmartAlbumNapi(env, context->smartAlbumAsset);
            break;
        default:
            NAPI_ERR_LOG("unsupported FetchResType");
            break;
    }

    if (jsAsset == nullptr) {
        NAPI_ERR_LOG("Failed to get file asset napi object");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
            "Failed to create js object for FileAsset");
    } else {
        jsContext->data = jsAsset;
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    }
}

static void GetPositionObjectCompleteCallback(napi_env env, napi_status status, FetchFileResultAsyncContext* context)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetPositionObjectCompleteCallback");

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    GetNapiResFromAsset(env, context, jsContext);

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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetFirstObject");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter");
    napi_get_undefined(env, &result);

    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && CheckIfFFRNapiNotEmpty(asyncContext->objectInfo)) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetFirstObject", asyncContext);
        
        asyncContext->objectPtr = asyncContext->objectInfo->propertyPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "propertyPtr is nullptr");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                context->GetFirstAsset();
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
        NAPI_ERR_LOG("JSGetFirstObject obj == nullptr, status: %{public}d", status);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetNextObject");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && CheckIfFFRNapiNotEmpty(asyncContext->objectInfo)) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetNextObject", asyncContext);

        asyncContext->objectPtr = asyncContext->objectInfo->propertyPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "propertyPtr is nullptr");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                context->GetNextObject();
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
        NAPI_ERR_LOG("JSGetNextObject obj == nullptr, status: %{public}d", status);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetLastObject");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && CheckIfFFRNapiNotEmpty(asyncContext->objectInfo)) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetLastObject", asyncContext);

        asyncContext->objectPtr = asyncContext->objectInfo->propertyPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "propertyPtr is nullptr");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                context->GetLastObject();
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
        NAPI_ERR_LOG("JSGetLastObject obj == nullptr, status: %{public}d", status);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetPositionObject");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameter maximum");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && CheckIfFFRNapiNotEmpty(asyncContext->objectInfo)) {
        // Check the arguments and their types
        napi_typeof(env, argv[PARAM0], &type);
        if (type == napi_number) {
            napi_get_value_int32(env, argv[PARAM0], &(asyncContext->position));
        } else {
            NAPI_ERR_LOG("Argument mismatch, type: %{public}d", type);
            return result;
        }

        if (argc == ARGS_TWO) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM1], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetPositionObject", asyncContext);

        asyncContext->objectPtr = asyncContext->objectInfo->propertyPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "propertyPtr is nullptr");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FetchFileResultAsyncContext*>(data);
                context->GetObjectAtPosition();
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
        NAPI_ERR_LOG("JSGetPositionObject obj == nullptr, status: %{public}d", status);
        NAPI_ASSERT(env, false, "JSGetPositionObject obj == nullptr");
    }

    return result;
}

static napi_value GetAsset(napi_env env, vector<std::unique_ptr<FileAsset>> &array, int index)
{
    return FileAssetNapi::CreateFileAsset(env, array[index]);
}

static napi_value GetAsset(napi_env env, vector<std::unique_ptr<AlbumAsset>> &array, int index)
{
    return AlbumNapi::CreateAlbumNapi(env, array[index]);
}

static napi_value GetAsset(napi_env env, vector<std::unique_ptr<SmartAlbumAsset>> &array, int index)
{
    return SmartAlbumNapi::CreateSmartAlbumNapi(env, array[index]);
}

template<class T>
static void GetAssetFromArray(napi_env env, FetchFileResultAsyncContext* context, T& array,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    napi_value jsFileArray = nullptr;
    napi_create_array_with_length(env, array.size(), &jsFileArray);
    napi_value jsFileAsset = nullptr;
    size_t i = 0;
    for (i = 0; i < array.size(); i++) {
        jsFileAsset = GetAsset(env, array, i);
        if ((jsFileAsset == nullptr) || (napi_set_element(env, jsFileArray, i, jsFileAsset) != napi_ok)) {
            NAPI_ERR_LOG("Failed to get file asset napi object");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                "Failed to create js object");
            break;
        }
    }
    if (i == array.size()) {
        jsContext->data = jsFileArray;
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    }
}

static void GetAllObjectCompleteCallback(napi_env env, napi_status status, FetchFileResultAsyncContext* context)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetAllObjectCompleteCallback");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    switch (context->objectPtr->fetchResType_) {
        case FetchResType::TYPE_FILE:
            GetAssetFromArray(env, context, context->fileAssetArray, jsContext);
            break;
        case FetchResType::TYPE_ALBUM:
            GetAssetFromArray(env, context, context->fileAlbumArray, jsContext);
            break;
        case FetchResType::TYPE_SMARTALBUM:
            GetAssetFromArray(env, context, context->fileSmartAlbumArray, jsContext);
            break;
        default:
            NAPI_ERR_LOG("unsupported FetchResType");
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

std::shared_ptr<FetchResult<FileAsset>> FetchFileResultNapi::GetFetchFileResultObject()
{
    return propertyPtr->fetchFileResult_;
}

std::shared_ptr<FetchResult<AlbumAsset>> FetchFileResultNapi::GetFetchAlbumResultObject()
{
    return propertyPtr->fetchAlbumResult_;
}

std::shared_ptr<FetchResult<SmartAlbumAsset>> FetchFileResultNapi::GetFetchSmartAlbumResultObject()
{
    return propertyPtr->fetchSmartAlbumResult_;
}

void GetAllObjectFromFetchResult(const FetchFileResultAsyncContext &asyncContext)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetAllObjectFromFetchResult");

    FetchFileResultAsyncContext *context = const_cast<FetchFileResultAsyncContext *>(&asyncContext);
    context->GetAllObjectFromFetchResult();
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetAllObject");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    unique_ptr<FetchFileResultAsyncContext> asyncContext = make_unique<FetchFileResultAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && CheckIfFFRNapiNotEmpty(asyncContext->objectInfo)) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAllObject", asyncContext);

        asyncContext->objectPtr = asyncContext->objectInfo->propertyPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "propertyPtr is nullptr");

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
        NAPI_ERR_LOG("JSGetAllObject obj == nullptr, status: %{public}d", status);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSClose");

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments!, status: %{public}d", status);
        return jsResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        obj->propertyPtr = nullptr;
    }
    status = napi_remove_wrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        napi_create_int32(env, SUCCESS, &jsResult);
    } else {
        NAPI_INFO_LOG("JSClose obj == nullptr");
    }

    NAPI_DEBUG_LOG("JSClose OUT!");
    return jsResult;
}

void FetchFileResultAsyncContext::GetFirstAsset()
{
    switch (objectPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            fileAsset = objectPtr->fetchFileResult_->GetFirstObject();
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            albumAsset = objectPtr->fetchAlbumResult_->GetFirstObject();
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            smartAlbumAsset = objectPtr->fetchSmartAlbumResult_->GetFirstObject();
            break;
        }
        default:
            NAPI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

void FetchFileResultAsyncContext::GetObjectAtPosition()
{
    switch (objectPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            fileAsset = objectPtr->fetchFileResult_->GetObjectAtPosition(position);
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            albumAsset = objectPtr->fetchAlbumResult_->GetObjectAtPosition(position);
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            smartAlbumAsset = objectPtr->fetchSmartAlbumResult_->GetObjectAtPosition(position);
            break;
        }
        default:
            NAPI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

void FetchFileResultAsyncContext::GetLastObject()
{
    switch (objectPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            fileAsset = objectPtr->fetchFileResult_->GetLastObject();
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            albumAsset = objectPtr->fetchAlbumResult_->GetLastObject();
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            smartAlbumAsset = objectPtr->fetchSmartAlbumResult_->GetLastObject();
            break;
        }
        default:
            NAPI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

void FetchFileResultAsyncContext::GetNextObject()
{
    switch (objectPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            fileAsset = objectPtr->fetchFileResult_->GetNextObject();
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            albumAsset = objectPtr->fetchAlbumResult_->GetNextObject();
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            smartAlbumAsset = objectPtr->fetchSmartAlbumResult_->GetNextObject();
            break;
        }
        default:
            NAPI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

void FetchFileResultAsyncContext::GetAllObjectFromFetchResult()
{
    switch (objectPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            auto fetchResult = objectPtr->fetchFileResult_;
            auto file = fetchResult->GetFirstObject();
            while (file != nullptr) {
                fileAssetArray.push_back(move(file));
                    file = fetchResult->GetNextObject();
            }
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            auto fetchResult = objectPtr->fetchAlbumResult_;
            auto album = fetchResult->GetFirstObject();
            while (album != nullptr) {
                fileAlbumArray.push_back(move(album));
                album = fetchResult->GetNextObject();
            }
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            auto fetchResult = objectPtr->fetchSmartAlbumResult_;
            auto smartAlbum = fetchResult->GetFirstObject();
            while (smartAlbum != nullptr) {
                fileSmartAlbumArray.push_back(move(smartAlbum));
                smartAlbum = fetchResult->GetNextObject();
            }
            break;
        }
        default:
            NAPI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

bool FetchFileResultNapi::CheckIfPropertyPtrNull()
{
    return propertyPtr == nullptr;
}
} // namespace Media
} // namespace OHOS