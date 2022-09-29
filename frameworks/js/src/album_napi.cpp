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
#define MLOG_TAG "AlbumNapi"

#include "album_napi.h"
#include "medialibrary_napi_log.h"
#include "media_file_utils.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::DataShare;
thread_local napi_ref AlbumNapi::sConstructor_ = nullptr;
thread_local AlbumAsset *AlbumNapi::sAlbumData_ = nullptr;
std::shared_ptr<DataShare::DataShareHelper> AlbumNapi::sMediaDataHelper_ = nullptr;
using CompleteCallback = napi_async_complete_callback;

thread_local napi_ref AlbumNapi::userFileMgrConstructor_ = nullptr;

AlbumNapi::AlbumNapi()
    : env_(nullptr)
{
    albumId_ = DEFAULT_ALBUM_ID;
    albumName_ = DEFAULT_ALBUM_NAME;
    albumUri_ = DEFAULT_ALBUM_URI;
    albumDateModified_ = DEFAULT_ALBUM_DATE_MODIFIED;
    count_ = DEFAULT_COUNT;
    albumRelativePath_ = DEFAULT_ALBUM_RELATIVE_PATH;
    coverUri_ = DEFAULT_COVERURI;
    albumPath_ = DEFAULT_ALBUM_PATH;
    albumVirtual_ = DEFAULT_ALBUM_VIRTUAL;
}

AlbumNapi::~AlbumNapi() = default;

void AlbumNapi::AlbumNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    AlbumNapi *album = reinterpret_cast<AlbumNapi*>(nativeObject);
    if (album != nullptr) {
        delete album;
        album = nullptr;
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
        DECLARE_NAPI_GETTER("albumUri", JSGetAlbumUri),
        DECLARE_NAPI_GETTER("dateModified", JSGetAlbumDateModified),
        DECLARE_NAPI_GETTER("count", JSGetCount),
        DECLARE_NAPI_GETTER("relativePath", JSGetAlbumRelativePath),
        DECLARE_NAPI_GETTER("coverUri", JSGetCoverUri),
        DECLARE_NAPI_FUNCTION("commitModify", JSCommitModify),
        DECLARE_NAPI_GETTER_SETTER("path", JSGetAlbumPath, JSSetAlbumPath),
        DECLARE_NAPI_GETTER("virtual", JSGetAlbumVirtual),
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

napi_value AlbumNapi::UserFileMgrInit(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = USERFILEMGR_ALBUM_NAPI_CLASS_NAME,
        .ref = &userFileMgrConstructor_,
        .constructor = AlbumNapiConstructor,
        .props = {
            DECLARE_NAPI_FUNCTION("getFileAssets", UserFileMgrGetAssets),
            DECLARE_NAPI_FUNCTION("commitModify", UserFileMgrCommitModify),
            DECLARE_NAPI_GETTER_SETTER("albumName", JSGetAlbumName, JSAlbumNameSetter),
            DECLARE_NAPI_GETTER("albumUri", JSGetAlbumUri),
            DECLARE_NAPI_GETTER("dateModified", JSGetAlbumDateModified),
            DECLARE_NAPI_GETTER("count", JSGetCount),
            DECLARE_NAPI_GETTER("relativePath", JSGetAlbumRelativePath),
            DECLARE_NAPI_GETTER("coverUri", JSGetCoverUri)
        }
    };

    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

void AlbumNapi::SetAlbumNapiProperties(const AlbumAsset &albumData)
{
    this->albumId_ = albumData.GetAlbumId();
    this->albumName_ = albumData.GetAlbumName();
    this->albumUri_ = albumData.GetAlbumUri();
    this->albumDateModified_ = albumData.GetAlbumDateModified();
    this->count_ = albumData.GetCount();
    this->albumRelativePath_ = albumData.GetAlbumRelativePath();
    this->coverUri_ = albumData.GetCoverUri();

    this->albumPath_ = albumData.GetAlbumPath();
    this->albumVirtual_ = albumData.GetAlbumVirtual();
    this->typeMask_ = albumData.GetAlbumTypeMask();
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
            obj->abilityHelper_ = sMediaDataHelper_;
            if (sAlbumData_ != nullptr) {
                obj->SetAlbumNapiProperties(*sAlbumData_);
            }

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               AlbumNapi::AlbumNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                NAPI_ERR_LOG("Failure wrapping js to native napi. status: %{public}d", status);
            }
        }
    }

    return result;
}

napi_value AlbumNapi::CreateAlbumNapi(napi_env env, AlbumAsset &albumData,
    std::shared_ptr<DataShare::DataShareHelper> abilityHelper)
{
    napi_value constructor;
    napi_ref constructorRef = (albumData.GetAlbumTypeMask().empty()) ? (sConstructor_) : (userFileMgrConstructor_);
    NAPI_CALL(env, napi_get_reference_value(env, constructorRef, &constructor));

    napi_value result = nullptr;
    sAlbumData_ = &albumData;
    sMediaDataHelper_ = abilityHelper;
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));
    sAlbumData_ = nullptr;
    return result;
}

std::shared_ptr<DataShare::DataShareHelper> AlbumNapi::GetMediaDataHelper() const
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

std::string AlbumNapi::GetNetworkId() const
{
    return MediaFileUtils::GetNetworkIdFromUri(albumUri_);
}

std::string AlbumNapi::GetTypeMask() const
{
    return typeMask_;
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
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
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
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
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
        NAPI_ERR_LOG("Invalid arguments type! valueType: %{public}d", valueType);
        return jsResult;
    }

    napi_get_value_string_utf8(env, argv[PARAM0], buffer, FILENAME_MAX, &res);

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        obj->albumName_ = std::string(buffer);
    } else {
        NAPI_ERR_LOG("status = %{public}d", status);
    }
    return jsResult;
}
napi_value AlbumNapi::JSGetAlbumUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi* obj = nullptr;
    std::string uri = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        uri = obj->albumUri_;
        status = napi_create_string_utf8(env, uri.c_str(), NAPI_AUTO_LENGTH, &jsResult);
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
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
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
napi_value AlbumNapi::JSGetCount(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi *obj = nullptr;
    int32_t count;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        count = obj->count_;
        status = napi_create_int32(env, count, &jsResult);
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
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
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
napi_value AlbumNapi::JSGetCoverUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    AlbumNapi* obj = nullptr;
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
        coverUri = obj->coverUri_;
        status = napi_create_string_utf8(env, coverUri.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
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
        NAPI_ERR_LOG("Invalid arguments type! type: %{public}d", valueType);
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
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
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
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
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

static void GetFetchOptionsParam(napi_env env, napi_value arg, const AlbumNapiAsyncContext &context, bool &err)
{
    AlbumNapiAsyncContext *asyncContext = const_cast<AlbumNapiAsyncContext *>(&context);
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
    AlbumNapiAsyncContext &asyncContext)
{
    string str = "";
    std::vector<string> strArr;
    string order = "";
    bool err = false;
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
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
static napi_value ConvertCommitJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    AlbumNapiAsyncContext &asyncContext)
{
    string str = "";
    vector<string> strArr;
    string order = "";
    bool err = false;
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            GetFetchOptionsParam(env, argv[PARAM0], asyncContext, err);
            if (err) {
                NAPI_ERR_LOG("fetch options retrieval failed. err %{public}d", err);
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
static void GetFileAssetsNative(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetFileAssetsNative");

    AlbumNapiAsyncContext *context = static_cast<AlbumNapiAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    DataShare::DataSharePredicates predicates;

    string trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? ";
    MediaLibraryNapiUtils::AppendFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.emplace_back("0");

    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    MediaLibraryNapiUtils::AppendFetchOptionSelection(context->selection, prefix);
    context->selectionArgs.emplace_back(to_string(MEDIA_TYPE_ALBUM));

    string idPrefix = MEDIA_DATA_DB_BUCKET_ID + " = ? ";
    MediaLibraryNapiUtils::AppendFetchOptionSelection(context->selection, idPrefix);
    context->selectionArgs.emplace_back(std::to_string(context->objectInfo->GetAlbumId()));

    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    predicates.SetOrder(context->order);
    std::vector<std::string> columns;

    string queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX +
        context->objectInfo->GetNetworkId() + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(queryUri, context->typeMask);
    NAPI_DEBUG_LOG("queryUri is = %{public}s", queryUri.c_str());
    Uri uri(queryUri);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> resultSet =
        context->objectInfo->GetMediaDataHelper()->Query(uri, predicates, columns);
    context->fetchResult = std::make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchResult->networkId_ = context->objectInfo->GetNetworkId();
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        context->fetchResult->resultNapiType_ = context->resultNapiType;
    }
}

static void JSGetFileAssetsCompleteCallback(napi_env env, napi_status status, void*data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetFileAssetsCompleteCallback");

    AlbumNapiAsyncContext *context = static_cast<AlbumNapiAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->fetchResult != nullptr) {
        if (context->fetchResult->GetCount() < 0) {
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                                                         "find no data by options");
        } else {
            napi_value fetchRes = FetchFileResultNapi::CreateFetchFileResult(env, move(context->fetchResult),
                context->objectInfo->sMediaDataHelper_);
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

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static void CommitModifyNative(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("CommitModifyNative");

    auto *context = static_cast<AlbumNapiAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto objectInfo = context->objectInfo;
    if (!MediaFileUtils::CheckTitle(objectInfo->GetAlbumName())) {
        context->error = JS_ERR_DISPLAYNAME_INVALID;
        NAPI_ERR_LOG("album name invalid = %{public}s", objectInfo->GetAlbumName().c_str());
        return;
    }

    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_TITLE, objectInfo->GetAlbumName());
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({ std::to_string(objectInfo->GetAlbumId()) });

    string updateUri = MEDIALIBRARY_DATA_URI;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(updateUri, context->typeMask);
    Uri uri(updateUri);
    auto helper = objectInfo->GetMediaDataHelper();
    int changedRows = helper->Update(uri, predicates, valuesBucket);
    if (changedRows > 0) {
        DataSharePredicates filePredicates;
        DataShareValuesBucket fileValuesBucket;
        fileValuesBucket.Put(MEDIA_DATA_DB_BUCKET_NAME, objectInfo->GetAlbumName());
        filePredicates.SetWhereClause(MEDIA_DATA_DB_BUCKET_ID + " = ? ");
        filePredicates.SetWhereArgs({ std::to_string(objectInfo->GetAlbumId()) });

        string fileUriStr = MEDIALIBRARY_DATA_URI;
        MediaLibraryNapiUtils::UriAddFragmentTypeMask(fileUriStr, context->typeMask);
        Uri fileUri(fileUriStr);
        changedRows = helper->Update(fileUri, filePredicates, fileValuesBucket);
    }
    context->SaveError(changedRows);
    context->changedRows = changedRows;
}

static void JSCommitModifyCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModifyCompleteCallback");

    AlbumNapiAsyncContext *context = static_cast<AlbumNapiAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->error == ERR_DEFAULT) {
        napi_create_int32(env, context->changedRows, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
        auto contextUri = make_unique<Uri>(MEDIALIBRARY_ALBUM_URI);
        context->objectInfo->GetMediaDataHelper()->NotifyChange(*contextUri);
    } else {
        napi_get_undefined(env, &jsContext->data);
        context->HandleError(env, jsContext->error);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetAlbumFileAssets");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, ((argc == ARGS_ZERO) || (argc == ARGS_ONE) || (argc == ARGS_TWO)),
                "requires 2 parameter maximum");
    napi_get_undefined(env, &result);

    std::unique_ptr<AlbumNapiAsyncContext> asyncContext = std::make_unique<AlbumNapiAsyncContext>();
    asyncContext->resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetAlbumFileAssets",
            GetFileAssetsNative, JSGetFileAssetsCompleteCallback);
    }

    return result;
}
napi_value AlbumNapi::JSCommitModify(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModify");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE), "requires 1 parameter maximum");
    napi_get_undefined(env, &result);

    std::unique_ptr<AlbumNapiAsyncContext> asyncContext = std::make_unique<AlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertCommitJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "JSCommitModify fail ");

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSCommitModify", CommitModifyNative,
            JSCommitModifyCompleteCallback);
    }

    return result;
}

napi_value AlbumNapi::UserFileMgrGetAssets(napi_env env, napi_callback_info info)
{
    napi_value ret = nullptr;
    unique_ptr<AlbumNapiAsyncContext> asyncContext = make_unique<AlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    NAPI_ASSERT(env, MediaLibraryNapiUtils::ParseArgsTypeFetchOptCallback(env, info, asyncContext) == napi_ok,
        "Failed to parse js args");
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    asyncContext->typeMask = asyncContext->objectInfo->GetTypeMask();

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrGetAssets", GetFileAssetsNative,
        JSGetFileAssetsCompleteCallback);
}

napi_value AlbumNapi::UserFileMgrCommitModify(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrCommitModify");

    napi_value ret = nullptr;
    unique_ptr<AlbumNapiAsyncContext> asyncContext = make_unique<AlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    NAPI_ASSERT(env, MediaLibraryNapiUtils::ParseArgsOnlyCallBack(env, info, asyncContext) == napi_ok,
        "Failed to parse js args");
    asyncContext->typeMask = asyncContext->objectInfo->GetTypeMask();

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrCommitModify", CommitModifyNative,
        JSCommitModifyCompleteCallback);
}
} // namespace Media
} // namespace OHOS
