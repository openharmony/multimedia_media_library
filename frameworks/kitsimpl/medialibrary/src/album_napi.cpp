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

#include "album_napi.h"
#include "hilog/log.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "AlbumNapi"};
}

namespace OHOS {
namespace Media {
using namespace std;
napi_ref AlbumNapi::sConstructor_ = nullptr;
AlbumAsset *AlbumNapi::sAlbumData_ = nullptr;
std::shared_ptr<AppExecFwk::DataAbilityHelper> AlbumNapi::sAbilityHelper = nullptr;

AlbumNapi::AlbumNapi()
    : env_(nullptr), wrapper_(nullptr)
{
    albumId_ = DEFAULT_ALBUM_ID;
    albumName_ = DEFAULT_ALBUM_NAME;
    albumPath_ = DEFAULT_ALBUM_PATH;
    albumDateModified_ = DEFAULT_ALBUM_DATE_MODIFIED;
    albumVirtual_ = DEFAULT_ALBUM_VIRTUAL;
    albumRelativePath_ = DEFAULT_ALBUM_RELATIVE_PATH;
}

AlbumNapi::~AlbumNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void AlbumNapi::AlbumNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    AlbumNapi *album = reinterpret_cast<AlbumNapi*>(nativeObject);
    if (album != nullptr) {
        album->~AlbumNapi();
    }
}

napi_value AlbumNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor album_props[] = {
        DECLARE_NAPI_GETTER("albumId", JSGetAlbumId),
        DECLARE_NAPI_GETTER_SETTER("albumName", JSGetAlbumName, JSAlbumNameSetter),
        DECLARE_NAPI_GETTER_SETTER("path", JSGetAlbumPath, JSSetAlbumPath),
        DECLARE_NAPI_GETTER("dateModified", JSGetAlbumDateModified),
        DECLARE_NAPI_GETTER("virtual", JSGetAlbumVirtual),
        DECLARE_NAPI_GETTER("relativePath", JSGetAlbumRelativePath),
        DECLARE_NAPI_FUNCTION("getFileAssets", JSGetAlbumFileAssets)
    };

    status = napi_define_class(env, ALBUM_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                               AlbumNapiConstructor, nullptr,
                               sizeof(album_props) / sizeof(album_props[PARAM0]),
                               album_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, ALBUM_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }

    return nullptr;
}

void AlbumNapi::SetAlbumNapiProperties(const AlbumAsset &albumData)
{
    this->albumId_ = albumData.GetAlbumId();
    this->albumName_ = albumData.GetAlbumName();
    this->albumPath_ = albumData.GetAlbumPath();
    this->albumDateModified_ = albumData.GetAlbumDateModified();
    this->albumVirtual_ = albumData.GetAlbumVirtual();
    this->albumRelativePath_ = albumData.GetAlbumRelativePath();
}

// Constructor callback
napi_value AlbumNapi::AlbumNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<AlbumNapi> obj = std::make_unique<AlbumNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            obj->abilityHelper_ = sAbilityHelper;
            if (sAlbumData_ != nullptr) {
                obj->SetAlbumNapiProperties(*sAlbumData_);
            }

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               AlbumNapi::AlbumNapiDestructor, nullptr, &(obj->wrapper_));
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                HiLog::Error(LABEL, "Failure wrapping js to native napi");
            }
        }
    }

    return result;
}

napi_value AlbumNapi::CreateAlbumNapi(napi_env env, AlbumAsset &albumData,
    std::shared_ptr<AppExecFwk::DataAbilityHelper> abilityHelper)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sAlbumData_ = &albumData;
        sAbilityHelper = abilityHelper;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sAlbumData_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            HiLog::Error(LABEL, "Failed to create album asset instance");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

std::shared_ptr<AppExecFwk::DataAbilityHelper> AlbumNapi::GetDataAbilityHelper() const
{
    return abilityHelper_;
}

std::string AlbumNapi::GetAlbumName() const
{
    return albumName_;
}

std::string AlbumNapi::GetAlbumPath() const
{
    return albumPath_;
}

int32_t AlbumNapi::GetAlbumId() const
{
    return albumId_;
}

napi_value AlbumNapi::JSGetAlbumId(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi* obj = nullptr;
    int32_t id;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        id = obj->albumId_;
        status = napi_create_int32(env, id, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value AlbumNapi::JSGetAlbumName(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi* obj = nullptr;
    std::string name = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        name = obj->albumName_;
        status = napi_create_string_utf8(env, name.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value AlbumNapi::JSAlbumNameSetter(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    size_t res = 0;
    char buffer[FILENAME_MAX];
    AlbumNapi* obj = nullptr;
    napi_value thisVar = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_get_undefined(env, &jsResult);
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires 1 parameter");

    if (thisVar == nullptr || napi_typeof(env, argv[PARAM0], &valueType) != napi_ok
        || valueType != napi_string) {
        HiLog::Error(LABEL, "Invalid arguments type!");
        return jsResult;
    }

    napi_get_value_string_utf8(env, argv[PARAM0], buffer, FILENAME_MAX, &res);

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        obj->albumName_ = std::string(buffer);
    }

    return jsResult;
}

napi_value AlbumNapi::JSSetAlbumPath(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    size_t res = 0;
    char buffer[PATH_MAX];
    AlbumNapi* obj = nullptr;
    napi_value thisVar = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_get_undefined(env, &jsResult);
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires 1 parameter");

    if (thisVar == nullptr || napi_typeof(env, argv[PARAM0], &valueType) != napi_ok
        || valueType != napi_string) {
        HiLog::Error(LABEL, "Invalid arguments type!");
        return jsResult;
    }

    napi_get_value_string_utf8(env, argv[PARAM0], buffer, PATH_MAX, &res);

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        obj->albumPath_ = std::string(buffer);
    }

    return jsResult;
}

napi_value AlbumNapi::JSGetAlbumPath(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi* obj = nullptr;
    std::string path = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        path = obj->albumPath_;
        status = napi_create_string_utf8(env, path.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value AlbumNapi::JSGetAlbumDateModified(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi* obj = nullptr;
    int64_t dateModified;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        dateModified = obj->albumDateModified_;
        status = napi_create_int64(env, dateModified, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value AlbumNapi::JSGetAlbumVirtual(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi* obj = nullptr;
    bool virtualAlbum = false;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        virtualAlbum = obj->albumVirtual_;
        status = napi_get_boolean(env, virtualAlbum, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value AlbumNapi::JSGetAlbumRelativePath(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi* obj = nullptr;
    std::string relativePath = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        relativePath = obj->albumRelativePath_;
        status = napi_create_string_utf8(env, relativePath.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

static void GetFetchOptionsParam(napi_env env, napi_value arg, const AlbumNapiAsyncContext &context, bool &err)
{
    AlbumNapiAsyncContext *asyncContext = const_cast<AlbumNapiAsyncContext *>(&context);
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
            HiLog::Error(LABEL, "Could not get the string argument!");
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
            HiLog::Error(LABEL, "Could not get the string argument!");
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
        napi_is_array(env, property, &boolResult) == napi_ok && boolResult == true) {
        napi_get_array_length(env, property, &len);
        for (size_t i = 0; i < len; i++) {
            napi_get_element(env, property, i, &stringItem);
            napi_get_value_string_utf8(env, stringItem, buffer, PATH_MAX, &res);
            asyncContext->selectionArgs.push_back(std::string(buffer));
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
    } else {
        HiLog::Error(LABEL, "Could not get the string argument!");
        err = true;
    }
}

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    AlbumNapiAsyncContext &asyncContext)
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

static void GetFileAssetsNative(napi_env env, const AlbumNapiAsyncContext &albumContext)
{
    AlbumNapiAsyncContext *context = const_cast<AlbumNapiAsyncContext *>(&albumContext);
    NativeRdb::DataAbilityPredicates predicates;

    context->selection += " AND ";
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    predicates.OrderByAsc(context->order);
    predicates.EqualTo(MEDIA_DATA_DB_PARENT_ID, std::to_string(context->objectInfo->GetAlbumId()));
    predicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, std::to_string(MEDIA_TYPE_ALBUM));

    std::vector<std::string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI);

    std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> resultSet =
        context->objectInfo->GetDataAbilityHelper()->Query(uri, columns, predicates);

    context->fetchResult = std::make_unique<FetchResult>(resultSet);
}

static void GetFileAssetsCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<AlbumNapiAsyncContext*>(data);
    napi_value fetchRes = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    GetFileAssetsNative(env, *context);

    if (context->fetchResult != nullptr) {
        fetchRes = FetchFileResultNapi::CreateFetchFileResult(env, *(context->fetchResult));
        if (fetchRes == nullptr) {
            HiLog::Error(LABEL, "Failed to get file asset napi object");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                "Failed to create js object for FetchFileResult");
        } else {
            jsContext->data = fetchRes;
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        HiLog::Error(LABEL, "No fetch file result found!");
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

napi_value AlbumNapi::JSGetAlbumFileAssets(napi_env env, napi_callback_info info)
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
    std::unique_ptr<AlbumNapiAsyncContext> asyncContext = std::make_unique<AlbumNapiAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAlbumFileAssets");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            GetFileAssetsCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}
} // namespace Media
} // namespace OHOS
