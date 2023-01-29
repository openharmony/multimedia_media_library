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
#define MLOG_TAG "SmartAlbumNapi"

#include "smart_album_napi.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "media_file_utils.h"
#include "userfile_client.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace OHOS {
namespace Media {
using namespace std;
thread_local napi_ref SmartAlbumNapi::sConstructor_ = nullptr;
thread_local SmartAlbumAsset *SmartAlbumNapi::sAlbumData_ = nullptr;
using CompleteCallback = napi_async_complete_callback;

thread_local napi_ref SmartAlbumNapi::userFileMgrConstructor_ = nullptr;

SmartAlbumNapi::SmartAlbumNapi()
    : env_(nullptr) {}

SmartAlbumNapi::~SmartAlbumNapi() = default;

void SmartAlbumNapi::SmartAlbumNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    SmartAlbumNapi *album = reinterpret_cast<SmartAlbumNapi*>(nativeObject);
    if (album != nullptr) {
        delete album;
        album = nullptr;
    }
}

napi_value SmartAlbumNapi::Init(napi_env env, napi_value exports)
{
    NAPI_DEBUG_LOG("SmartAlbumNapi::Init");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor album_props[] = {
        DECLARE_NAPI_GETTER("albumId", JSGetSmartAlbumId),
        DECLARE_NAPI_GETTER("albumUri", JSGetSmartAlbumUri),
        DECLARE_NAPI_GETTER_SETTER("albumName", JSGetSmartAlbumName, JSSmartAlbumNameSetter),
        DECLARE_NAPI_GETTER("albumTag", JSGetSmartAlbumTag),
        DECLARE_NAPI_GETTER("size", JSGetSmartAlbumCapacity),
        DECLARE_NAPI_GETTER("categoryId", JSGetSmartAlbumCategoryId),
        DECLARE_NAPI_GETTER("categoryName", JSGetSmartAlbumCategoryName),
        DECLARE_NAPI_GETTER("coverUri", JSGetSmartAlbumCoverUri),
        DECLARE_NAPI_FUNCTION("commitModify", JSCommitModify),
        DECLARE_NAPI_FUNCTION("addAsset", JSAddAsset),
        DECLARE_NAPI_FUNCTION("removeAsset", JSRemoveAsset),
        DECLARE_NAPI_FUNCTION("getFileAssets", JSGetSmartAlbumFileAssets)
    };

    status = napi_define_class(env, SMART_ALBUM_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                               SmartAlbumNapiConstructor, nullptr,
                               sizeof(album_props) / sizeof(album_props[PARAM0]),
                               album_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, SMART_ALBUM_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    NAPI_DEBUG_LOG("SmartAlbumNapi::Init nullptr, status: %{public}d", status);
    return nullptr;
}

napi_value SmartAlbumNapi::UserFileMgrInit(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = USERFILEMGR_SMART_ALBUM_NAPI_CLASS_NAME,
        .ref = &userFileMgrConstructor_,
        .constructor = SmartAlbumNapiConstructor,
        .props = {
            DECLARE_NAPI_GETTER_SETTER("albumName", JSGetSmartAlbumName, JSSmartAlbumNameSetter),
            DECLARE_NAPI_GETTER("albumUri", JSGetSmartAlbumUri),
            DECLARE_NAPI_GETTER("dateModified", JSGetSmartAlbumDateModified),
            DECLARE_NAPI_GETTER("count", JSGetSmartAlbumCapacity),
            DECLARE_NAPI_GETTER("coverUri", JSGetSmartAlbumCoverUri),
            DECLARE_NAPI_FUNCTION("getPhotoAssets", UserFileMgrGetAssets),
            DECLARE_NAPI_FUNCTION("delete", UserFileMgrDeleteAsset),
            DECLARE_NAPI_FUNCTION("recover", UserFileMgrRecoverAsset),
        }
    };

    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

void SmartAlbumNapi::SetSmartAlbumNapiProperties()
{
    smartAlbumAssetPtr = std::shared_ptr<SmartAlbumAsset>(sAlbumData_);
    NAPI_INFO_LOG("SetSmartAlbumNapiProperties name = %{public}s",
        smartAlbumAssetPtr->GetAlbumName().c_str());
}

// Constructor callback
napi_value SmartAlbumNapi::SmartAlbumNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<SmartAlbumNapi> obj = std::make_unique<SmartAlbumNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            if (sAlbumData_ != nullptr) {
                obj->SetSmartAlbumNapiProperties();
            }
            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               SmartAlbumNapi::SmartAlbumNapiDestructor, nullptr, nullptr);
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

napi_value SmartAlbumNapi::CreateSmartAlbumNapi(napi_env env, unique_ptr<SmartAlbumAsset> &albumData)
{
    if (albumData == nullptr) {
        return nullptr;
    }

    napi_value constructor;
    napi_ref constructorRef = (albumData->GetTypeMask().empty()) ? (sConstructor_) : (userFileMgrConstructor_);
    NAPI_CALL(env, napi_get_reference_value(env, constructorRef, &constructor));

    napi_value result = nullptr;
    sAlbumData_ = albumData.release();
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));
    sAlbumData_ = nullptr;
    return result;
}

std::string SmartAlbumNapi::GetSmartAlbumName() const
{
    return smartAlbumAssetPtr->GetAlbumName();
}

int32_t SmartAlbumNapi::GetAlbumPrivateType() const
{
    return smartAlbumAssetPtr->GetAlbumPrivateType();
}

std::string SmartAlbumNapi::GetSmartAlbumUri() const
{
    return smartAlbumAssetPtr->GetAlbumUri();
}

int32_t SmartAlbumNapi::GetSmartAlbumId() const
{
    return smartAlbumAssetPtr->GetAlbumId();
}
void SmartAlbumNapi::SetAlbumCapacity(int32_t albumCapacity)
{
    smartAlbumAssetPtr->SetAlbumCapacity(albumCapacity);
}

std::string SmartAlbumNapi::GetNetworkId() const
{
    return MediaFileUtils::GetNetworkIdFromUri(GetSmartAlbumUri());
}

std::string SmartAlbumNapi::GetTypeMask() const
{
    return smartAlbumAssetPtr->GetTypeMask();
}

napi_value SmartAlbumNapi::JSGetSmartAlbumId(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    int32_t id;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if ((status != napi_ok) || (thisVar == nullptr)) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        id = obj->GetSmartAlbumId();
        status = napi_create_int32(env, id, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumName(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string name = "";
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if ((status != napi_ok) || (thisVar == nullptr)) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        name = obj->GetSmartAlbumName();
        NAPI_DEBUG_LOG("JSGetSmartAlbumName name = %{public}s", name.c_str());
        status = napi_create_string_utf8(env, name.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSSmartAlbumNameSetter(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    size_t res = 0;
    char buffer[FILENAME_MAX];
    SmartAlbumNapi* obj = nullptr;
    napi_value thisVar = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_get_undefined(env, &jsResult);
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires 1 parameter");

    if (thisVar == nullptr || napi_typeof(env, argv[PARAM0], &valueType) != napi_ok
        || valueType != napi_string) {
        NAPI_ERR_LOG("Invalid arguments type! valueType: %{public}d", valueType);
        return jsResult;
    }

    napi_get_value_string_utf8(env, argv[PARAM0], buffer, FILENAME_MAX, &res);

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        obj->smartAlbumAssetPtr->SetAlbumName(std::string(buffer));
    }

    return jsResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumTag(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string albumTag = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumTag = obj->smartAlbumAssetPtr->GetAlbumTag();
        status = napi_create_string_utf8(env, albumTag.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumCapacity(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    int32_t albumCapacity;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumCapacity = obj->smartAlbumAssetPtr->GetAlbumCapacity();
        status = napi_create_int32(env, albumCapacity, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumCategoryId(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    int32_t categoryId;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        categoryId = obj->smartAlbumAssetPtr->GetCategoryId();
        status = napi_create_int32(env, categoryId, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumCategoryName(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string categoryName = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        categoryName = obj->smartAlbumAssetPtr->GetCategoryName();
        status = napi_create_string_utf8(env, categoryName.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumCoverUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string coverUri = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        coverUri = obj->smartAlbumAssetPtr->GetCoverUri();
        status = napi_create_string_utf8(env, coverUri.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string albumUri = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumUri = obj->GetSmartAlbumUri();
        status = napi_create_string_utf8(env, albumUri.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }
    return undefinedResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumDateModified(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value undefinedResult = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if ((status != napi_ok) || (thisVar == nullptr)) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }
    SmartAlbumNapi* obj = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        int64_t dateModified = obj->smartAlbumAssetPtr->GetAlbumDateModified();
        napi_value jsResult = nullptr;
        status = napi_create_int64(env, dateModified, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }
    return undefinedResult;
}

static void CommitModifyNative(const SmartAlbumNapiAsyncContext &albumContext)
{
    SmartAlbumNapiAsyncContext *context = const_cast<SmartAlbumNapiAsyncContext *>(&albumContext);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    int32_t changedRows;
    NAPI_DEBUG_LOG("CommitModifyNative = %{pubilc}s", context->objectPtr->GetAlbumName().c_str());
    if (MediaFileUtils::CheckDisplayName(context->objectPtr->GetAlbumName())) {
        valuesBucket.Put(SMARTALBUM_DB_NAME, context->objectPtr->GetAlbumName());
        predicates.SetWhereClause(SMARTALBUM_DB_ID + " = " + std::to_string(context->objectPtr->GetAlbumId()));
        Uri commitModifyUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMOPRN +
                            "/" + MEDIA_SMARTALBUMOPRN_MODIFYALBUM);
        changedRows = UserFileClient::Update(commitModifyUri, predicates, valuesBucket);
    } else {
        changedRows = JS_E_DISPLAYNAME;
    }
    context->changedRows = changedRows;
}
static void JSAddAssetExecute(SmartAlbumNapiAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    Uri addAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
    for (int32_t id : context->assetIds) {
        DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, context->objectPtr->GetAlbumId());
        valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, id);
        context->changedRows = UserFileClient::Insert(addAssetUri, valuesBucket);
    }
}

static void JSRemoveAssetExecute(SmartAlbumNapiAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    Uri removeAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
    for (int32_t id : context->assetIds) {
        DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, context->objectPtr->GetAlbumId());
        valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, id);
        context->changedRows = UserFileClient::Insert(removeAssetUri, context->valuesBucket);
    }
}

static void JSCommitModifyCompleteCallback(napi_env env, napi_status status, SmartAlbumNapiAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->changedRows != -1) {
        napi_create_int32(env, context->changedRows, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Failed to obtain fetchFileResult from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static void JSAddAssetCompleteCallback(napi_env env, napi_status status, SmartAlbumNapiAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->changedRows != -1 && context->changedRows != 0) {
        napi_create_int32(env, context->changedRows, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Failed to obtain fetchFileResult from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static void JSRemoveAssetCompleteCallback(napi_env env, napi_status status, SmartAlbumNapiAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->changedRows != -1 && context->changedRows != 0) {
        napi_create_int32(env, context->changedRows, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Failed to obtain fetchFileResult from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static napi_value ConvertCommitJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    SmartAlbumNapiAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

static napi_value GetAssetIds(napi_env env, napi_value param, SmartAlbumNapiAsyncContext &context)
{
    uint32_t arraySize = 0;
    if (!MediaLibraryNapiUtils::IsArrayForNapiValue(env, param, arraySize)) {
        NAPI_ERR_LOG("GetAssetIds get args fail, not array");
        return nullptr;
    }
    string uri = "";
    for (uint32_t i = 0; i < arraySize; i++) {
        napi_value jsValue = nullptr;
        int32_t result;
        if ((napi_get_element(env, param, i, &jsValue)) != napi_ok) {
            NAPI_ERR_LOG("GetAssetIds get args fail");
            return nullptr;
        }
        if (napi_get_value_int32(env, jsValue, &result) != napi_ok) {
            NAPI_ERR_LOG("get ids value fail");
            return nullptr;
        } else {
            NAPI_ERR_LOG("GetAssetIds id = %{public}d", result);
            context.assetIds.push_back(result);
        }
    }
    napi_value res;
    napi_get_undefined(env, &res);
    return res;
}

napi_value GetJSArgsForAsset(napi_env env, size_t argc,
                             const napi_value argv[],
                             SmartAlbumNapiAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0) {
            napi_value res = GetAssetIds(env, argv[PARAM0], asyncContext);
            CHECK_NULL_PTR_RETURN_UNDEFINED(env, res, result, "Failed to obtain arguments ids");
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value SmartAlbumNapi::JSAddAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameter maximum");
    napi_get_undefined(env, &result);
    std::unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = std::make_unique<SmartAlbumNapiAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "JSAddAsset fail ");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSAddAsset", asyncContext);

        asyncContext->objectPtr = asyncContext->objectInfo->smartAlbumAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "SmartAlbumAsset is nullptr");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<SmartAlbumNapiAsyncContext*>(data);
                JSAddAssetExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSAddAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value SmartAlbumNapi::JSRemoveAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameter maximum");
    napi_get_undefined(env, &result);
    std::unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = std::make_unique<SmartAlbumNapiAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "JSRemoveAsset fail ");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSRemoveAsset", asyncContext);

        asyncContext->objectPtr = asyncContext->objectInfo->smartAlbumAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "SmartAlbumAsset is nullptr");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<SmartAlbumNapiAsyncContext*>(data);
                JSRemoveAssetExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSRemoveAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value SmartAlbumNapi::JSCommitModify(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE), "requires 1 parameter maximum");
    napi_get_undefined(env, &result);
    std::unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = std::make_unique<SmartAlbumNapiAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertCommitJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "JSCommitModify fail ");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCommitModify", asyncContext);

        asyncContext->objectPtr = asyncContext->objectInfo->smartAlbumAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "SmartAlbumAsset is nullptr");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<SmartAlbumNapiAsyncContext*>(data);
                CommitModifyNative(*context);
            },
            reinterpret_cast<CompleteCallback>(JSCommitModifyCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void GetFetchOptionsParam(napi_env env, napi_value arg, const SmartAlbumNapiAsyncContext &context, bool &err)
{
    SmartAlbumNapiAsyncContext *asyncContext = const_cast<SmartAlbumNapiAsyncContext *>(&context);
    CHECK_NULL_PTR_RETURN_VOID(asyncContext, "Async context is null");
    char buffer[PATH_MAX];
    size_t res;
    uint32_t len = 0;
    napi_value property = nullptr;
    napi_value stringItem = nullptr;
    bool present = false;
    bool boolResult = false;

    napi_has_named_property(env, arg, "selections", &present);
    if (present) {
        if (napi_get_named_property(env, arg, "selections", &property) != napi_ok
            || napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok) {
            NAPI_ERR_LOG("Could not get the string argument!");
            err = true;
            return;
        } else {
            asyncContext->selection = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }

    napi_has_named_property(env, arg, "order", &present);
    if (present) {
        if (napi_get_named_property(env, arg, "order", &property) != napi_ok
            || napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok) {
            NAPI_ERR_LOG("Could not get the string argument!");
            err = true;
            return;
        } else {
            asyncContext->order = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }

    napi_has_named_property(env, arg, "selectionArgs", &present);
    if (present && napi_get_named_property(env, arg, "selectionArgs", &property) == napi_ok &&
        napi_is_array(env, property, &boolResult) == napi_ok && boolResult) {
        napi_get_array_length(env, property, &len);
        for (size_t i = 0; i < len; i++) {
            napi_get_element(env, property, i, &stringItem);
            napi_get_value_string_utf8(env, stringItem, buffer, PATH_MAX, &res);
            asyncContext->selectionArgs.push_back(std::string(buffer));
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
    } else {
        NAPI_ERR_LOG("Could not get the string argument!");
        err = true;
    }
}

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    SmartAlbumNapiAsyncContext &asyncContext)
{
    string str = "";
    std::vector<string> strArr;
    string order = "";
    bool err = false;
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            GetFetchOptionsParam(env, argv[PARAM0], asyncContext, err);
            if (err) {
                NAPI_ASSERT(env, false, "type mismatch");
            }
        } else if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

static void UpdateSelection(SmartAlbumNapiAsyncContext *context)
{
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        context->predicates.EqualTo(SMARTALBUMMAP_DB_ALBUM_ID, context->objectPtr->GetAlbumId());
        if (context->objectPtr->GetAlbumId() == TRASH_ALBUM_ID_VALUES) {
            context->predicates.NotEqualTo(MEDIA_DATA_DB_DATE_TRASHED, "0");
        } else {
            context->predicates.EqualTo(MEDIA_DATA_DB_DATE_TRASHED, "0");
        }
        MediaLibraryNapiUtils::UpdateMediaTypeSelections(context);
    } else {
        string trashPrefix;
        if (context->objectPtr->GetAlbumId() == TRASH_ALBUM_ID_VALUES) {
            trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " <> ? AND " + SMARTALBUMMAP_DB_ALBUM_ID + " = ? ";
        } else {
            trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? AND " + SMARTALBUMMAP_DB_ALBUM_ID + " = ? ";
        }
        MediaLibraryNapiUtils::AppendFetchOptionSelection(context->selection, trashPrefix);
        context->selectionArgs.emplace_back("0");
        context->selectionArgs.emplace_back(std::to_string(context->objectPtr->GetAlbumId()));
    }
}

static void GetFileAssetsNative(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetFileAssetsNative");

    auto context = static_cast<SmartAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    UpdateSelection(context);
    context->predicates.SetWhereClause(context->selection);
    context->predicates.SetWhereArgs(context->selectionArgs);
    context->predicates.SetOrder(context->order);
    if (context->fetchColumn.empty()) {
        context->fetchColumn.push_back("*");
    }
    string queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX +
        (MediaFileUtils::GetNetworkIdFromUri(context->objectPtr->GetAlbumUri())) +
        MEDIALIBRARY_DATA_URI_IDENTIFIER + "/" + MEDIA_ALBUMOPRN_QUERYALBUM + "/" + ASSETMAP_VIEW_NAME;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(queryUri, context->typeMask);
    Uri uri(queryUri);
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn);
    context->fetchResult = std::make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchResult->SetNetworkId(
        MediaFileUtils::GetNetworkIdFromUri(context->objectPtr->GetAlbumUri()));
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        context->fetchResult->resultNapiType_ = context->resultNapiType;
    }
}

static void JSGetFileAssetsCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetFileAssetsCompleteCallback");

    auto context = static_cast<SmartAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->fetchResult != nullptr) {
        if (context->fetchResult->GetCount() < 0) {
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                "find no data by options");
        } else {
            napi_value fetchRes = FetchFileResultNapi::CreateFetchFileResult(env, move(context->fetchResult));
            if (fetchRes == nullptr) {
                NAPI_ERR_LOG("Failed to get file asset napi object");
                napi_get_undefined(env, &jsContext->data);
                MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                    "Failed to create js object for FetchFileResult");
            } else {
                jsContext->data = fetchRes;
                napi_get_undefined(env, &jsContext->error);
                jsContext->status = true;
            }
        }
    } else {
        NAPI_ERR_LOG("No fetch file result found!");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Failed to obtain fetchFileResult from DB");
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumFileAssets(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    constexpr int maxArgs = 2;
    size_t argc = maxArgs;
    napi_value argv[maxArgs] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, ((argc == ARGS_ZERO) || (argc == ARGS_ONE) || (argc == ARGS_TWO)),
                "requires 2 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = std::make_unique<SmartAlbumNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    asyncContext->resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        asyncContext->objectPtr = asyncContext->objectInfo->smartAlbumAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "SmartAlbumAsset is nullptr");

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetSmartAlbumFileAssets",
            GetFileAssetsNative, JSGetFileAssetsCompleteCallback);
    }

    return result;
}

napi_value SmartAlbumNapi::UserFileMgrGetAssets(napi_env env, napi_callback_info info)
{
    napi_value ret = nullptr;
    unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = make_unique<SmartAlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");

    asyncContext->mediaTypes.push_back(MEDIA_TYPE_IMAGE);
    asyncContext->mediaTypes.push_back(MEDIA_TYPE_VIDEO);
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseAssetFetchOptCallback(env, info, asyncContext), asyncContext,
        JS_ERR_PARAMETER_INVALID);
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    asyncContext->typeMask = asyncContext->objectInfo->GetTypeMask();

    asyncContext->objectPtr = asyncContext->objectInfo->smartAlbumAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, ret, "SmartAlbumAsset is nullptr");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrGetAssets", GetFileAssetsNative,
        JSGetFileAssetsCompleteCallback);
}

static void JSRecoverAssetExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSRecoverAssetExecute");

    auto context = static_cast<SmartAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    string recoverUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(recoverUri, context->typeMask);
    Uri recoverAssetUri(recoverUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, context->objectPtr->GetAlbumId());
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, stoi(MediaLibraryNapiUtils::GetFileIdFromUri(context->uri)));
    int retVal = UserFileClient::Insert(recoverAssetUri, valuesBucket);
    context->SaveError(retVal);
}

static void JSRecoverAssetCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSRecoverAssetCompleteCallback");

    SmartAlbumNapiAsyncContext *context = static_cast<SmartAlbumNapiAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
        Media::MediaType mediaType = MediaLibraryNapiUtils::GetMediaTypeFromUri(context->uri);
        string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
        Uri modifyNotify(notifyUri);
        UserFileClient::NotifyChange(modifyNotify);
    } else {
        context->HandleError(env, jsContext->error);
    }
    if (context->work != nullptr) {
        tracer.Finish();
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
            context->work, *jsContext);
    }

    delete context;
}

napi_value SmartAlbumNapi::UserFileMgrRecoverAsset(napi_env env, napi_callback_info info)
{
    napi_value ret = nullptr;
    unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = make_unique<SmartAlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");

    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, asyncContext->uri),
        asyncContext, JS_ERR_PARAMETER_INVALID);
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    asyncContext->typeMask = asyncContext->objectInfo->GetTypeMask();
    asyncContext->objectPtr = asyncContext->objectInfo->smartAlbumAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, ret, "SmartAlbumAsset is nullptr");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrGetAssets", JSRecoverAssetExecute,
        JSRecoverAssetCompleteCallback);
}

static void JSDeleteAssetExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteAssetExecute");

    auto context = static_cast<SmartAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    string deleteId = MediaLibraryNapiUtils::GetFileIdFromUri(context->uri);
    string deleteUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET + "/" + deleteId;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(deleteUri, context->typeMask);
    Uri deleteAssetUri(deleteUri);
    int retVal = UserFileClient::Delete(deleteAssetUri, {});
    context->SaveError(retVal);
}

static void JSDeleteAssetCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteAssetCompleteCallback");

    SmartAlbumNapiAsyncContext *context = static_cast<SmartAlbumNapiAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
        Media::MediaType mediaType = MediaLibraryNapiUtils::GetMediaTypeFromUri(context->uri);
        string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
        Uri modifyNotify(notifyUri);
        UserFileClient::NotifyChange(modifyNotify);
    } else {
        context->HandleError(env, jsContext->error);
    }
    if (context->work != nullptr) {
        tracer.Finish();
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
            context->work, *jsContext);
    }

    delete context;
}

napi_value SmartAlbumNapi::UserFileMgrDeleteAsset(napi_env env, napi_callback_info info)
{
    napi_value ret = nullptr;
    unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = make_unique<SmartAlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");

    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, asyncContext->uri),
        asyncContext, JS_ERR_PARAMETER_INVALID);
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    asyncContext->typeMask = asyncContext->objectInfo->GetTypeMask();

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrGetAssets", JSDeleteAssetExecute,
        JSDeleteAssetCompleteCallback);
}
} // namespace Media
} // namespace OHOS
