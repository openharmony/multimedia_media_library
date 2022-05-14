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

#include "media_library_napi.h"

#include <sys/sendfile.h>
#include "media_file_utils.h"
#include "medialibrary_peer_info.h"
#include "medialibrary_data_ability.h"
#include "media_data_ability_const.h"
#include "medialibrary_napi_log.h"
#include "smart_album_napi.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "uv.h"
#include "string_ex.h"
#include "ohos/aafwk/base/string_wrapper.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
unique_ptr<ChangeListenerNapi> g_listObj = nullptr;
bool g_isNewApi = false;
const int32_t NUM_2 = 2;
const int32_t NUM_3 = 3;

static map<string, ListenerType> ListenerTypeMaps = {
    {"audioChange", AUDIO_LISTENER},
    {"videoChange", VIDEO_LISTENER},
    {"imageChange", IMAGE_LISTENER},
    {"fileChange", FILE_LISTENER},
    {"albumChange", ALBUM_LISTENER},
    {"deviceChange", DEVICE_LISTENER},
    {"remoteFileChange", REMOTEFILE_LISTENER}
};

thread_local napi_ref MediaLibraryNapi::sConstructor_ = nullptr;
std::shared_ptr<DataShare::DataShareHelper> MediaLibraryNapi::sDataShareHelper_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sMediaTypeEnumRef_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sFileKeyEnumRef_ = nullptr;
using CompleteCallback = napi_async_complete_callback;
using Context = MediaLibraryAsyncContext* ;
bool MediaLibraryNapi::isStageMode_ = false;

MediaLibraryNapi::MediaLibraryNapi()
    : env_(nullptr), wrapper_(nullptr) {}

MediaLibraryNapi::~MediaLibraryNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
        wrapper_ = nullptr;
    }
}

void MediaLibraryNapi::MediaLibraryNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    MediaLibraryNapi *mediaLibrary = reinterpret_cast<MediaLibraryNapi*>(nativeObject);
    if (mediaLibrary != nullptr) {
        delete mediaLibrary;
        mediaLibrary = nullptr;
    }
}

napi_value MediaLibraryNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor media_library_properties[] = {
        DECLARE_NAPI_FUNCTION("getPublicDirectory", JSGetPublicDirectory),
        DECLARE_NAPI_FUNCTION("getFileAssets", JSGetFileAssets),
        DECLARE_NAPI_FUNCTION("getAlbums", JSGetAlbums),
        DECLARE_NAPI_FUNCTION("createAsset", JSCreateAsset),
        DECLARE_NAPI_FUNCTION("deleteAsset", JSDeleteAsset),
        DECLARE_NAPI_FUNCTION("on", JSOnCallback),
        DECLARE_NAPI_FUNCTION("off", JSOffCallback),
        DECLARE_NAPI_FUNCTION("release", JSRelease),
        DECLARE_NAPI_FUNCTION("getPrivateAlbum", JSGetPrivateAlbum),
        DECLARE_NAPI_FUNCTION("createSmartAlbum", JSCreateSmartAlbum),
        DECLARE_NAPI_FUNCTION("deleteSmartAlbum", JSDeleteSmartAlbum),
        DECLARE_NAPI_FUNCTION("getActivePeers", JSGetActivePeers),
        DECLARE_NAPI_FUNCTION("getAllPeers", JSGetAllPeers),
        DECLARE_NAPI_FUNCTION("storeMediaAsset", JSStoreMediaAsset),
        DECLARE_NAPI_FUNCTION("startImagePreview", JSStartImagePreview),
        DECLARE_NAPI_FUNCTION("getMediaRemoteStub", JSGetMediaRemoteStub)
    };
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getMediaLibrary", GetMediaLibraryNewInstance),
        DECLARE_NAPI_PROPERTY("MediaType", CreateMediaTypeEnum(env)),
        DECLARE_NAPI_PROPERTY("FileKey", CreateFileKeyEnum(env)),
        DECLARE_NAPI_PROPERTY("DirectoryType", CreateDirectoryTypeEnum(env)),
        DECLARE_NAPI_PROPERTY("PrivateAlbumType", CreatePrivateAlbumTypeEnum(env))
    };
    napi_value ctorObj;
    napi_status status = napi_define_class(env, MEDIA_LIB_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
        MediaLibraryNapiConstructor, nullptr,
        sizeof(media_library_properties) / sizeof(media_library_properties[PARAM0]),
        media_library_properties, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, MEDIA_LIB_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok && napi_define_properties(env, exports,
                sizeof(static_prop) / sizeof(static_prop[PARAM0]), static_prop) == napi_ok) {
                return exports;
            }
        }
    }
    return nullptr;
}

shared_ptr<DataShare::DataShareHelper> MediaLibraryNapi::GetDataShareHelper(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, argv[0], isStageMode_);

    if (status != napi_ok){

    } else {
        if (isStageMode_) {
            auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[0]);
            if (context == nullptr) {
                NAPI_ERR_LOG("Failed to get native context instance");
                return nullptr;
            }
            AppExecFwk::Want want;
            want.SetElementName("com.ohos.medialibrary.medialibrarydata", "DataShareExtAbility");
            dataShareHelper = DataShare::DataShareHelper::Creator(context, want, std::make_shared<Uri>("datashare://com.ohos.medialibrary.medialibrarydata.datashare"));
	}
    }
    return dataShareHelper;
}

// Constructor callback
napi_value MediaLibraryNapi::MediaLibraryNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Error while obtaining js environment information, status: %{private}d", status);
        return result;
    }

    unique_ptr<MediaLibraryNapi> obj = make_unique<MediaLibraryNapi>();
    if (obj != nullptr) {

        obj->env_ = env;
        if (g_isNewApi) {
            // Initialize the ChangeListener object
            if (g_listObj == nullptr) {
                g_listObj = make_unique<ChangeListenerNapi>(env);
            }

            if (obj->sDataShareHelper_ == nullptr) {
                obj->sDataShareHelper_ = GetDataShareHelper(env, info);
                CHECK_NULL_PTR_RETURN_UNDEFINED(env, obj->sDataShareHelper_, result, "Helper creation failed");
            }
        }

        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           MediaLibraryNapi::MediaLibraryNapiDestructor, nullptr, &(obj->wrapper_));
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            NAPI_ERR_LOG("Failed to wrap the native media lib client object with JS, status: %{private}d", status);
        }
    }
    return result;
}

napi_value MediaLibraryNapi::GetMediaLibraryNewInstance(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("GetMediaLibraryNewInstance IN");
    napi_value result = nullptr;
    napi_value ctor;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    napi_status status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        g_isNewApi = true;
        status = napi_new_instance(env, ctor, argc, argv, &result);
        if (status == napi_ok) {
            return result;
        } else {
            NAPI_ERR_LOG("New instance could not be obtained status: %{private}d", status);
        }
    } else {
            NAPI_ERR_LOG("status = %{private}d", status);
    }

    napi_get_undefined(env, &result);
    NAPI_DEBUG_LOG("GetMediaLibraryNewInstance OUT");
    return result;
}

static napi_status AddIntegerNamedProperty(napi_env env, napi_value object,
    const string &name, int32_t enumValue)
{
    napi_value enumNapiValue;
    napi_status status = napi_create_int32(env, enumValue, &enumNapiValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, object, name.c_str(), enumNapiValue);
    }
    return status;
}

napi_value MediaLibraryNapi::CreateMediaTypeEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status == napi_ok) {
        string propName;
        for (unsigned int i = MEDIA_TYPE_DEFAULT; i < mediaTypesEnum.size(); i++) {
            propName = mediaTypesEnum[i];
            status = AddIntegerNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                NAPI_ERR_LOG("Failed to add named prop! ret = %{private}d", status);
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        // The reference count is for creating Media Type Enum Reference
        int refCount = 1;
        status = napi_create_reference(env, result, refCount, &sMediaTypeEnumRef_);
        if (status == napi_ok) {
            return result;
        }
    }

    NAPI_ERR_LOG("Failed to created object for media type enum! status: %{private}d", status);
    napi_get_undefined(env, &result);
    return result;
}

napi_value MediaLibraryNapi::CreateDirectoryTypeEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status == napi_ok) {
        string propName;
        for (unsigned int i = 0; i < directoryEnum.size(); i++) {
            propName = directoryEnum[i];
            status = AddIntegerNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                NAPI_ERR_LOG("Failed to add named prop! status: %{private}d", status);
                break;
            }
        }
    }
    if (status == napi_ok) {
        int refCount = 1;
        // The reference count is for creating Media Type Enum Reference
        status = napi_create_reference(env, result, refCount, &sMediaTypeEnumRef_);
        if (status == napi_ok) {
            return result;
        }
    }

    NAPI_ERR_LOG("Failed to created object for directory enum! status: %{private}d", status);
    napi_get_undefined(env, &result);
    return result;
}

static napi_status AddStringNamedProperty(napi_env env, napi_value object,
    const string &name, string enumValue)
{
    napi_value enumNapiValue;
    napi_status status = napi_create_string_utf8(env, enumValue.c_str(), NAPI_AUTO_LENGTH, &enumNapiValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, object, name.c_str(), enumNapiValue);
    }
    return status;
}

napi_value MediaLibraryNapi::CreateFileKeyEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status == napi_ok) {
        string propName;
        for (unsigned int i = 0; i < fileKeyEnum.size(); i++) {
            propName = fileKeyEnum[i];
            status = AddStringNamedProperty(env, result, propName, fileKeyEnumValues[i]);
            if (status != napi_ok) {
                NAPI_ERR_LOG("Failed to add named prop! status: %{private}d", status);
                break;
            }
        }
    }

    if (status == napi_ok) {
        int refCount = 1;
        // The reference count is for creating File Key Enum Reference
        status = napi_create_reference(env, result, refCount, &sFileKeyEnumRef_);
        if (status == napi_ok) {
            return result;
        }
    }

    NAPI_ERR_LOG("Failed to created object for file key enum! status: %{private}d", status);
    napi_get_undefined(env, &result);
    return result;
}

napi_value MediaLibraryNapi::CreatePrivateAlbumTypeEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status == napi_ok) {
        string propName;
        for (unsigned int i = 0; i < privateAlbumTypeNameEnum.size(); i++) {
            propName = privateAlbumTypeNameEnum[i];
            status = AddIntegerNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                NAPI_ERR_LOG("Failed to add named prop! status: %{private}d", status);
                break;
            }
        }
    }

    if (status == napi_ok) {
        int refCount = 1;
        // The reference count is for creating File Key Enum Reference
        status = napi_create_reference(env, result, refCount, &sFileKeyEnumRef_);
        if (status == napi_ok) {
            return result;
        }
    }

    NAPI_ERR_LOG("Failed to created object for file key enum! status: %{private}d", status);
    napi_get_undefined(env, &result);
    return result;
}

static void DealWithCommonParam(napi_env env, napi_value arg,
    const MediaLibraryAsyncContext &context, bool &err, bool &present)
{
    MediaLibraryAsyncContext *asyncContext = const_cast<MediaLibraryAsyncContext *>(&context);
    CHECK_NULL_PTR_RETURN_VOID(asyncContext, "Async context is null");
    char buffer[PATH_MAX];
    size_t res = 0;
    napi_value property = nullptr;
    napi_has_named_property(env, arg, "selections", &present);
    if (present) {
        if ((napi_get_named_property(env, arg, "selections", &property) != napi_ok) ||
            (napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok)) {
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
        if ((napi_get_named_property(env, arg, "order", &property) != napi_ok) ||
            (napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok)) {
            NAPI_ERR_LOG("Could not get the string argument!");
            err = true;
            return;
        } else {
            asyncContext->order = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }

    napi_has_named_property(env, arg, "uri", &present);
    if (present) {
        if ((napi_get_named_property(env, arg, "uri", &property) != napi_ok)||
            (napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok)) {
            NAPI_ERR_LOG("Could not get the uri property!");
            err = true;
            return;
        }
        asyncContext->uri = buffer;
        CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        present = false;
    }

    napi_has_named_property(env, arg, "networkId", &present);
    if (present) {
        if ((napi_get_named_property(env, arg, "networkId", &property) != napi_ok) ||
            (napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok)) {
            NAPI_ERR_LOG("Could not get the networkId string argument!");
            err = true;
            return;
        } else {
            asyncContext->networkId = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }
}

static void GetFetchOptionsParam(napi_env env, napi_value arg, const MediaLibraryAsyncContext &context, bool &err)
{
    MediaLibraryAsyncContext *asyncContext = const_cast<MediaLibraryAsyncContext *>(&context);
    CHECK_NULL_PTR_RETURN_VOID(asyncContext, "Async context is null");
    napi_value property = nullptr, stringItem = nullptr;
    bool present = false;
    DealWithCommonParam(env, arg, context, err, present);
    napi_has_named_property(env, arg, "selectionArgs", &present);
    if (present && napi_get_named_property(env, arg, "selectionArgs", &property) == napi_ok) {
        uint32_t len = 0;
        napi_get_array_length(env, property, &len);
        char buffer[PATH_MAX];
        for (size_t i = 0; i < len; i++) {
            napi_get_element(env, property, i, &stringItem);
            size_t res = 0;
            napi_get_value_string_utf8(env, stringItem, buffer, PATH_MAX, &res);
            asyncContext->selectionArgs.push_back(string(buffer));
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
    } else {
        NAPI_ERR_LOG("Could not get the string argument!");
        err = true;
    }
}

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    MediaLibraryAsyncContext &asyncContext)
{
    bool err = false;
    const int32_t refCount = 1;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            GetFetchOptionsParam(env, argv[PARAM0], asyncContext, err);
        } else if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
        if (err) {
            NAPI_ERR_LOG("fetch options retrieval failed, err: %{private}d", err);
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_value result;
    napi_get_boolean(env, true, &result);
    return result;
}

static void GetPublicDirectoryCallbackComplete(napi_env env, napi_status status,
                                               MediaLibraryAsyncContext *context)
{
    NAPI_DEBUG_LOG("GetPublicDirectoryCompleteCallback IN");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    unsigned int dirIndex = context->dirType;
    if (context->error == ERR_DEFAULT) {
        napi_create_string_utf8(env, directoryEnumValues[dirIndex].c_str(), NAPI_AUTO_LENGTH, &jsContext->data);
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
    } else {
        NAPI_DEBUG_LOG("dirIndex is illegal");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error, "dirIndex is illegal");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    NAPI_DEBUG_LOG("GetPublicDirectoryCompleteCallback OUT");
    delete context;
}

napi_value MediaLibraryNapi::JSGetPublicDirectory(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0}, thisVar = nullptr, resource = nullptr;
    const int32_t refCount = 1;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        for (size_t i = PARAM0; i < argc; i++) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[i], &valueType);

            if (i == PARAM0 && valueType == napi_number) {
                napi_get_value_uint32(env, argv[i], &asyncContext->dirType);
            } else if (i == PARAM1 && valueType == napi_function) {
                napi_create_reference(env, argv[i], refCount, &asyncContext->callbackRef);
                break;
            } else {
                NAPI_ASSERT(env, false, "type mismatch");
            }
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetPublicDirectory");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                unsigned int dirIndex = context->dirType;
                if (dirIndex < directoryEnumValues.size()) {
                    context->directoryRelativePath = directoryEnumValues[dirIndex];
                } else {
                    context->error = ERR_INVALID_OUTPUT;
                }
            },
            reinterpret_cast<CompleteCallback>(GetPublicDirectoryCallbackComplete),
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

static void GetFileAssetsExecute(MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    if (!context->uri.empty()) {
        NAPI_ERR_LOG("context->uri is = %{private}s", context->uri.c_str());
        context->networkId = MediaLibraryDataAbilityUtils::GetNetworkIdFromUri(context->uri);
        string fileId = MediaLibraryDataAbilityUtils::GetIdFromUri(context->uri);
        if (!fileId.empty()) {
            string idPrefix = MEDIA_DATA_DB_ID + " = ? ";
            MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, idPrefix);
            context->selectionArgs.insert(context->selectionArgs.begin(), fileId);
        }
    }
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, prefix);
    context->selectionArgs.insert(context->selectionArgs.begin(), to_string(MEDIA_TYPE_ALBUM));

    string trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.insert(context->selectionArgs.begin(), "0");

    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    predicates.SetOrder(context->order);

    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    }
    NAPI_DEBUG_LOG("queryUri is = %{private}s", queryUri.c_str());
    Uri uri(queryUri);
    shared_ptr<AbsSharedResultSet> resultSet;

    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        resultSet = context->objectInfo->sDataShareHelper_->Query(uri, columns, predicates);
        if (resultSet != nullptr) {
            // Create FetchResult object using the contents of resultSet
            context->fetchFileResult = make_unique<FetchResult>(move(resultSet));
            context->fetchFileResult->networkId_ = context->networkId;
            return;
        } else {
            NAPI_ERR_LOG("Query for get fileAssets failed");
        }
    }
    context->error = ERR_INVALID_OUTPUT;
}

static void GetFileAssetsAsyncCallbackComplete(napi_env env, napi_status status,
                                               MediaLibraryAsyncContext *context)
{
    napi_value fileResult = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);

    if (context->error != ERR_DEFAULT) {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Query for get fileAssets failed");
    } else {
        // Create FetchResult object using the contents of resultSet
        if (context->fetchFileResult != nullptr) {
            fileResult = FetchFileResultNapi::CreateFetchFileResult(env, *(context->fetchFileResult),
                                                                    context->objectInfo->sDataShareHelper_);
            if (context->fetchFileResult->GetCount() < 0) {
                MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                                                             "find no data by options");
            } else if (fileResult == nullptr) {
                MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                    "Failed to create js object for Fetch File Result");
            } else {
                jsContext->data = fileResult;
                jsContext->status = true;
                napi_get_undefined(env, &jsContext->error);
            }
        } else {
            NAPI_ERR_LOG("No fetch file result found!");
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Failed to obtain Fetch File Result");
        }
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSGetFileAssets(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetFileAssets");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                GetFileAssetsExecute(context);
            },
            reinterpret_cast<CompleteCallback>(GetFileAssetsAsyncCallbackComplete),
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
static string getNetworkId(const string& selfId)
{
    return "";
}

static string GetFileMediaTypeUri(MediaType mediaType, const string &networkId)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return uri + MEDIALIBRARY_TYPE_AUDIO_URI;
            break;
        case MEDIA_TYPE_VIDEO:
            return uri + MEDIALIBRARY_TYPE_VIDEO_URI;
            break;
        case MEDIA_TYPE_IMAGE:
            return uri + MEDIALIBRARY_TYPE_IMAGE_URI;
            break;
        case MEDIA_TYPE_ALBUM:
            return uri + MEDIALIBRARY_TYPE_ALBUM_URI;
            break;
        case MEDIA_TYPE_SMARTALBUM:
            return uri + MEDIALIBRARY_TYPE_SMART_URI;
            break;
        case MEDIA_TYPE_FILE:
        default:
            return uri + MEDIALIBRARY_TYPE_FILE_URI;
            break;
    }
}

using ValVariant = variant<int, int64_t, string>;
ValVariant GetValFromColumn(string columnName, shared_ptr<DataShare::DataShareResultSet> &resultSet,
    ResultSetDataType type)
{
    int index;
    ValVariant cellValue;
    int integerVal;
    string stringVal;
    int64_t longVaL;

    resultSet->GetColumnIndex(columnName, index);
    switch (type) {
        case TYPE_STRING:
            resultSet->GetString(index, stringVal);
            cellValue = stringVal;
            break;
        case TYPE_INT32:
            resultSet->GetInt(index, integerVal);
            cellValue = integerVal;
            break;
        case TYPE_INT64:
            resultSet->GetLong(index, longVaL);
            cellValue = longVaL;
            break;
        default:
            NAPI_ERR_LOG("No type: type %{private}d", type);
            cellValue = "Notype";
            break;
    }
    return cellValue;
}

ValVariant GetValFromColumn(string columnName, shared_ptr<DataShare::DataShareResultSet> &resultSet,
    ResultSetDataType type)
{
    int index;
    ValVariant cellValue;
    int integerVal;
    string stringVal;
    int64_t longVaL;

    resultSet->GetColumnIndex(columnName, index);
    switch (type) {
        case TYPE_STRING:
            resultSet->GetString(index, stringVal);
            cellValue = stringVal;
            break;
        case TYPE_INT32:
            resultSet->GetInt(index, integerVal);
            cellValue = integerVal;
            break;
        case TYPE_INT64:
            resultSet->GetLong(index, longVaL);
            cellValue = longVaL;
            break;
        default:
            NAPI_ERR_LOG("No type: type %{private}d", type);
            cellValue = "Notype";
            break;
    }
    return cellValue;
}

static void SetAlbumCoverUri(MediaLibraryAsyncContext *context, unique_ptr<AlbumAsset> &album)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_BUCKET_ID, std::to_string(album->GetAlbumId()));
    predicates.OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);
    predicates.Limit(1);
    vector<string> columns;
    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
        NAPI_DEBUG_LOG("querycoverUri is = %{private}s", queryUri.c_str());
    }
    Uri uri(queryUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet = context->objectInfo->sDataShareHelper_->Query(
        uri, columns, predicates);
    unique_ptr<FetchResult> fetchFileResult = make_unique<FetchResult>(move(resultSet));
    fetchFileResult->networkId_ = context->networkId;
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    string coverUri = fileAsset->GetUri();
    album->SetCoverUri(coverUri);
    NAPI_DEBUG_LOG("coverUri is = %{private}s", album->GetCoverUri().c_str());
}

void SetAlbumData(AlbumAsset* albumData, shared_ptr<DataShare::DataShareResultSet> resultSet,
    const string &networkId)
{
    // Get album id index and value
    albumData->SetAlbumId(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_BUCKET_ID, resultSet, TYPE_INT32)));

    // Get album title index and value
    albumData->SetAlbumName(get<string>(GetValFromColumn(MEDIA_DATA_DB_TITLE, resultSet, TYPE_STRING)));

    // Get album asset count index and value
    albumData->SetCount(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_COUNT, resultSet, TYPE_INT32)));
    albumData->SetAlbumUri(GetFileMediaTypeUri(MEDIA_TYPE_ALBUM, networkId) +
        "/" + to_string(albumData->GetAlbumId()));
    // Get album relativePath index and value
    albumData->SetAlbumRelativePath(get<string>(GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH,
                                                                 resultSet, TYPE_STRING)));
    albumData->SetAlbumDateModified(get<int64_t>(GetValFromColumn(MEDIA_DATA_DB_DATE_MODIFIED,
                                                                  resultSet, TYPE_INT64)));
}

void SetAlbumData(AlbumAsset* albumData, shared_ptr<DataShare::DataShareResultSet> resultSet,
    const string &networkId)
{
    // Get album id index and value
    albumData->SetAlbumId(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_BUCKET_ID, resultSet, TYPE_INT32)));

    // Get album title index and value
    albumData->SetAlbumName(get<string>(GetValFromColumn(MEDIA_DATA_DB_TITLE, resultSet, TYPE_STRING)));

    // Get album asset count index and value
    albumData->SetCount(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_COUNT, resultSet, TYPE_INT32)));
    albumData->SetAlbumUri(GetFileMediaTypeUri(MEDIA_TYPE_ALBUM, networkId) +
        "/" + to_string(albumData->GetAlbumId()));
    // Get album relativePath index and value
    albumData->SetAlbumRelativePath(get<string>(GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH,
                                                                 resultSet, TYPE_STRING)));
    albumData->SetAlbumDateModified(get<int64_t>(GetValFromColumn(MEDIA_DATA_DB_DATE_MODIFIED,
                                                                  resultSet, TYPE_INT64)));
}

static void GetResultDataExecute(MediaLibraryAsyncContext *context)
{
    NAPI_ERR_LOG("GetResultDataExecute IN");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    DataShare::DataSharePredicates predicates;
    DataShare::DataSharePredicates sharePredicates;
    if (context->objectInfo->sDataShareHelper_ == nullptr) {
        context->error = ERR_INVALID_OUTPUT;
    }
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    if (!context->order.empty()) {
        predicates.SetOrder(context->order);
    }
    sharePredicates.SetWhereClause(context->selection);
    sharePredicates.SetWhereArgs(context->selectionArgs);
    if (!context->order.empty()) {
        sharePredicates.SetOrder(context->order);
    }

    vector<string> columns;
    string queryUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId +
            MEDIALIBRARY_DATA_URI_IDENTIFIER + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;
        NAPI_DEBUG_LOG("queryAlbumUri is = %{private}s", queryUri.c_str());
    }
    Uri uri(queryUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet = context->objectInfo->sDataShareHelper_->Query(
        uri, columns, sharePredicates);

    if (resultSet == nullptr) {
        NAPI_ERR_LOG("GetMediaResultData resultSet is nullptr");
        return;
    }

    resultSet->GoToFirstRow();
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<AlbumAsset> albumData = make_unique<AlbumAsset>();
        if (albumData != nullptr) {
             NAPI_ERR_LOG("resultSet 1 id is %{public}d", get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_BUCKET_ID, resultSet, TYPE_INT32)));
             SetAlbumData(albumData.get(), resultSet , context->networkId);
             SetAlbumCoverUri(context, albumData);
             context->albumNativeArray.push_back(move(albumData));
	}
    }
/*
    shared_ptr<DataShare::DataShareResultSet> mediaResultSet = context->objectInfo->sDataShareHelper_->Query(
        uri, columns, predicates);

    if (mediaResultSet == nullptr) {
        NAPI_ERR_LOG("GetMediaResultData resultSet is nullptr");
        return;
    }

    while (mediaResultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<AlbumAsset> albumData = make_unique<AlbumAsset>();
        if (albumData != nullptr) {
            NAPI_ERR_LOG("resultSet 2 id is %{public}d", get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_BUCKET_ID, resultSet, TYPE_INT32)));
            SetAlbumData(albumData.get(), mediaResultSet , context->networkId);
            SetAlbumCoverUri(context, albumData);
            context->albumNativeArray.push_back(move(albumData));
        }
    }
    */
}

static void AlbumsAsyncCallbackComplete(napi_env env, napi_status status,
                                        MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->error);
    if (context->error != ERR_DEFAULT) {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Query for get fileAssets failed");
    } else {
        if (context->albumNativeArray.empty()) {
            napi_value albumNoArray = nullptr;
            napi_create_array(env, &albumNoArray);
            jsContext->status = true;
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumNoArray;
        } else {
            napi_value albumArray = nullptr;
            napi_create_array(env, &albumArray);
            for (size_t i = 0; i < context->albumNativeArray.size(); i++) {
                napi_value albumNapiObj = AlbumNapi::CreateAlbumNapi(env, *(context->albumNativeArray[i]),
                    context->objectInfo->sDataShareHelper_);
                napi_set_element(env, albumArray, i, albumNapiObj);
            }
            jsContext->status = true;
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumArray;
        }
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSGetAlbums(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAlbums");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                GetResultDataExecute(context);
            },
            reinterpret_cast<CompleteCallback>(AlbumsAsyncCallbackComplete),
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

static void getFileAssetById(int32_t id, const string& networkId, MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    vector<string> columns;
    DataShare::DataSharePredicates predicates;

    predicates.EqualTo(MEDIA_DATA_DB_ID, to_string(id));

    Uri uri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet;

    if (context->objectInfo->sDataShareHelper_ != nullptr
        && ((resultSet = context->objectInfo->sDataShareHelper_->Query(uri, columns, predicates)) != nullptr)) {
        // Create FetchResult object using the contents of resultSet
        context->fetchFileResult = make_unique<FetchResult>(move(resultSet));
        context->fetchFileResult->networkId_ = networkId;
        if (context->fetchFileResult != nullptr && context->fetchFileResult->GetCount() >= 1) {
            context->fileAsset = context->fetchFileResult->GetFirstObject();

            Media::MediaType mediaType = context->fileAsset->GetMediaType();
            string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
            Uri modifyNotify(notifyUri);
            context->objectInfo->sDataShareHelper_->NotifyChange(modifyNotify);
        }
    }
}

static void JSCreateAssetCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    NAPI_DEBUG_LOG("JSCreateAssetCompleteCallback IN");

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_value jsFileAsset = nullptr;

    if (context->error == ERR_DEFAULT) {
        if (context->fileAsset == nullptr) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Obtain file asset failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            jsFileAsset = FileAssetNapi::CreateFileAsset(env, *(context->fileAsset),
                                                         context->objectInfo->sDataShareHelper_);
            if (jsFileAsset == nullptr) {
                NAPI_ERR_LOG("Failed to get file asset napi object");
                napi_get_undefined(env, &jsContext->data);
                MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                    "Failed to create js object for FileAsset");
            } else {
                NAPI_DEBUG_LOG("JSCreateAssetCompleteCallback jsFileAsset != nullptr");
                jsContext->data = jsFileAsset;
                napi_get_undefined(env, &jsContext->error);
                jsContext->status = true;
            }
        }
    } else {
        NAPI_ERR_LOG("JSCreateAssetCompleteCallback context->error %{private}d", context->error);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "File asset creation failed");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    NAPI_DEBUG_LOG("JSCreateAssetCompleteCallback OUT");
    delete context;
}

static bool CheckTitlePrams(MediaLibraryAsyncContext *context)
{
    if (context == nullptr) {
        NAPI_ERR_LOG("Async context is null");
        return false;
    }
    ValueObject valueObject;
    string title = "";
    if (context->valuesBucket.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(title);
    }
    if (title.empty()) {
        return false;
    }
    return true;
}

static string GetFirstDirName(const string& relativePath)
{
    string firstDirName = "";
    if (!relativePath.empty()) {
        string::size_type pos = relativePath.find_first_of('/');
        if (pos == relativePath.length()) {
            return relativePath;
        }
        firstDirName = relativePath.substr(0, pos + 1);
        NAPI_DEBUG_LOG("firstDirName substr = %{private}s", firstDirName.c_str());
    }
    return firstDirName;
}

static bool IsDirectory(const string& dirName)
{
    struct stat statInfo {};
    if (stat((ROOT_MEDIA_DIR + dirName).c_str(), &statInfo) == SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return true;
        }
    }

    return false;
}

static bool CheckTypeOfType(const std::string& firstDirName, int32_t fileMediaType)
{
    NAPI_DEBUG_LOG("CheckTypeOfType IN");
    // "CDSA/"
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[0].c_str())) {
        if (fileMediaType == MEDIA_TYPE_IMAGE || fileMediaType == MEDIA_TYPE_VIDEO) {
            return true;
        } else {
            return false;
        }
    }
    // "Movies/"
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[1].c_str())) {
        if (fileMediaType == MEDIA_TYPE_VIDEO) {
            return true;
        } else {
            return false;
        }
    }
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[NUM_2].c_str())) {
        if (fileMediaType == MEDIA_TYPE_IMAGE || fileMediaType == MEDIA_TYPE_VIDEO) {
            return true;
        } else {
            NAPI_INFO_LOG("CheckTypeOfType RETURN FALSE");
            return false;
        }
    }
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[NUM_3].c_str())) {
        if (fileMediaType == MEDIA_TYPE_AUDIO) {
            return true;
        } else {
            return false;
        }
    }
    NAPI_DEBUG_LOG("CheckTypeOfType END");
    return true;
}
static bool CheckRelativePathPrams(MediaLibraryAsyncContext *context)
{
    if (context == nullptr) {
        NAPI_ERR_LOG("Async context is null");
        return false;
    }
    ValueObject valueObject;
    string relativePath = "";
    if (context->valuesBucket.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relativePath);
    }
    int32_t fileMediaType = 0;
    context->valuesBucket.GetObject(MEDIA_DATA_DB_MEDIA_TYPE, valueObject);
    valueObject.GetInt(fileMediaType);
    if (relativePath.empty()) {
        NAPI_DEBUG_LOG("CheckRelativePathPrams relativePath is empty");
        return false;
    }

    if (IsDirectory(relativePath)) {
        NAPI_DEBUG_LOG("CheckRelativePathPrams relativePath exist return true");
        return true;
    }

    string firstDirName = GetFirstDirName(relativePath);
    if (!firstDirName.empty() && IsDirectory(firstDirName)) {
        NAPI_DEBUG_LOG("CheckRelativePathPrams firstDirName exist return true");
        return true;
    }

    if (!firstDirName.empty()) {
        NAPI_DEBUG_LOG("firstDirName = %{private}s", firstDirName.c_str());
        for (unsigned int i = 0; i < directoryEnumValues.size(); i++) {
            NAPI_DEBUG_LOG("directoryEnumValues%{private}d = %{private}s", i, directoryEnumValues[i].c_str());
            if (!strcmp(firstDirName.c_str(), directoryEnumValues[i].c_str())) {
                return CheckTypeOfType(firstDirName, fileMediaType);
            }
        }
        NAPI_DEBUG_LOG("firstDirName = %{private}s", firstDirName.c_str());
    }
    NAPI_DEBUG_LOG("CheckRelativePathPrams return false");
    return false;
}

napi_value GetJSArgsForCreateAsset(napi_env env, size_t argc, const napi_value argv[],
                                   MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    int32_t fileMediaType = 0;
    size_t res = 0;
    char relativePathBuffer[PATH_MAX];
    char titleBuffer[PATH_MAX];
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &fileMediaType);
        } else if (i == PARAM1 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], titleBuffer, PATH_MAX, &res);
            NAPI_DEBUG_LOG("displayName = %{private}s", string(titleBuffer).c_str());
        } else if (i == PARAM2 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], relativePathBuffer, PATH_MAX, &res);
            NAPI_DEBUG_LOG("relativePath = %{private}s", string(relativePathBuffer).c_str());
        } else if (i == PARAM3 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
        } else {
            NAPI_DEBUG_LOG("type mismatch, valueType: %{private}d", valueType);
            return result;
    }
    }

    context->valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, fileMediaType);
    context->valuesBucket.PutString(MEDIA_DATA_DB_NAME, string(titleBuffer));
    context->valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, string(relativePathBuffer));
    NAPI_DEBUG_LOG("GetJSArgsForCreateAsset END");
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

static void JSCreateAssetExecute(MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (!CheckTitlePrams(context)) {
        context->error = ERR_DISPLAY_NAME_INVALID;
        return;
    }
    if (!CheckRelativePathPrams(context)) {
        context->error = ERR_RELATIVE_PATH_NOT_EXIST_OR_INVALID;
        return;
    }
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        Uri createFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);
        int index = context->objectInfo->sDataShareHelper_->Insert(createFileUri, context->valuesBucket);
        if (index < 0) {
            context->error = index;
        } else {
            getFileAssetById(index, "", context);
        }
    } else {
        context->error = ERR_INVALID_OUTPUT;
    }
}

napi_value MediaLibraryNapi::JSCreateAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_FORE;
    napi_value argv[ARGS_FORE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_THREE || argc == ARGS_FORE), "requires 4 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCreateAsset(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCreateAsset");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                JSCreateAssetExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSCreateAssetCompleteCallback),
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

static void JSModifyAssetCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri updateAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);

        DataShare::DataShareValueObject valueObject;
        string notifyUri;
        context->valuesBucket.GetObject(MEDIA_DATA_DB_URI, valueObject);
        valueObject.GetString(notifyUri);
        size_t index = notifyUri.rfind('/');
        if (index != string::npos) {
            notifyUri = notifyUri.substr(0, index);
        }

        int retVal = context->objectInfo->sDataShareHelper_->Insert(updateAssetUri,
            context->valuesBucket);
        if (retVal < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "File asset modification failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, retVal, &jsContext->data);
            jsContext->status = true;
            napi_get_undefined(env, &jsContext->error);
            Uri modifyNotify(notifyUri);
            context->objectInfo->sDataShareHelper_->NotifyChange(modifyNotify);
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForModifyAsset(napi_env env, size_t argc, const napi_value argv[],
                                   MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    FileAssetNapi *fileAssetObj = nullptr;
    size_t res = 0;
    char buffer[PATH_MAX];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_object) {
            napi_unwrap(env, argv[i], reinterpret_cast<void**>(&fileAssetObj));
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, string(buffer));

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSModifyAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForModifyAsset(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSModifyAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSModifyAssetCompleteCallback),
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

static void JSDeleteAssetExecute(MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri deleteAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET);

        DataShare::DataShareValueObject valueObject;
        string notifyUri;
        string mediaType;
        context->valuesBucket.GetObject(MEDIA_DATA_DB_URI, valueObject);
        valueObject.GetString(notifyUri);
        size_t index = notifyUri.rfind('/');
        if (index != string::npos) {
            notifyUri = notifyUri.substr(0, index);
            size_t indexType = notifyUri.rfind('/');
            if (indexType != string::npos) {
                mediaType = notifyUri.substr(indexType + 1);
            }
        }
        notifyUri = MEDIALIBRARY_DATA_URI + "/" + mediaType;
        NAPI_DEBUG_LOG("JSDeleteAssetExcute notifyUri = %{private}s", notifyUri.c_str());
        int retVal = context->objectInfo->sDataShareHelper_->Insert(deleteAssetUri,
            context->valuesBucket);
        if (retVal < 0) {
            context->error = retVal;
        } else {
            context->retVal = retVal;
            Uri deleteNotify(notifyUri);
            context->objectInfo->sDataShareHelper_->NotifyChange(deleteNotify);
        }
    } else {
        context->error = ERR_INVALID_OUTPUT;
    }
}

static void JSDeleteAssetCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        NAPI_DEBUG_LOG("Delete result = %{private}d", context->retVal);
        napi_create_int32(env, context->retVal, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForDeleteAsset(napi_env env, size_t argc, const napi_value argv[],
                                   MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    size_t res = 0;
    char buffer[PATH_MAX];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, string(buffer));

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSDeleteAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForDeleteAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                JSDeleteAssetExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSDeleteAssetCompleteCallback),
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

static void JSOpenAssetCompleteCallback(napi_env env, napi_status status,
                                        MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        DataShare::DataShareValueObject valueObject;
        string fileUri = "";
        string mode = MEDIA_FILEMODE_READONLY;

        if (context->valuesBucket.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
            valueObject.GetString(fileUri);
        }

        if (context->valuesBucket.GetObject(MEDIA_FILEMODE, valueObject)) {
            valueObject.GetString(mode);
        }

        Uri openFileUri(fileUri);
        int32_t retVal = context->objectInfo->sDataShareHelper_->OpenFile(openFileUri, mode);
        if (retVal <= 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "File open asset failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, retVal, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForOpenAsset(napi_env env, size_t argc, const napi_value argv[],
                                 MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    size_t res = 0;
    char buffer1[PATH_MAX], buffer2[SIZE];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer1, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer2, SIZE, &res);
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, string(buffer1));
    context->valuesBucket.PutString(MEDIA_FILEMODE, string(buffer2));

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSOpenAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 3 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForOpenAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSOpenAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSOpenAssetCompleteCallback),
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

static void JSCloseAssetCompleteCallback(napi_env env, napi_status status,
                                         MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri closeAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);
        ValueObject valueObject;
        int fd = 0;

        if (context->valuesBucket.GetObject(MEDIA_FILEDESCRIPTOR, valueObject)) {
            valueObject.GetInt(fd);
        }

        int32_t retVal = close(fd);
        if (retVal == DATA_ABILITY_SUCCESS) {
            retVal = context->objectInfo->sDataShareHelper_->Insert(closeAssetUri, context->valuesBucket);
            if (retVal == DATA_ABILITY_SUCCESS) {
                napi_create_int32(env, DATA_ABILITY_SUCCESS, &jsContext->data);
                napi_get_undefined(env, &jsContext->error);
                jsContext->status = true;
            }
        }
        if (retVal != DATA_ABILITY_SUCCESS) {
            NAPI_ERR_LOG("negative ret %{private}d", retVal);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                                                         "File close asset failed");
            napi_get_undefined(env, &jsContext->data);
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForCloseAsset(napi_env env, size_t argc, const napi_value argv[],
                                  MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    size_t res = 0;
    char buffer[PATH_MAX];
    int32_t fd = 0;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &fd);
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, string(buffer));
    context->valuesBucket.PutInt(MEDIA_FILEDESCRIPTOR, fd);

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSCloseAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 3 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCloseAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCloseAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSCloseAssetCompleteCallback),
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

static void JSCreateAlbumCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri createAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);

        int albumId = context->objectInfo->sDataShareHelper_->Insert(createAlbumUri,
            context->valuesBucket);
        if (albumId < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, albumId,
                "Create Album failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, albumId, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }

    delete context;
}

napi_value GetJSArgsForCreateAlbum(napi_env env, size_t argc, const napi_value argv[],
    MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    AlbumNapi *albumNapiObj = nullptr;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            napi_unwrap(env, argv[i], reinterpret_cast<void**>(&albumNapiObj));
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, albumNapiObj->GetAlbumPath());

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSCreateAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCreateAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCreateAlbum");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSCreateAlbumCompleteCallback),
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

static void JSModifyAlbumCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri modifyAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_MODIFYALBUM);

        int retVal = context->objectInfo->sDataShareHelper_->Insert(modifyAlbumUri,
            context->valuesBucket);
        if (retVal < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "Modify Album failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, retVal, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForModifyAlbum(napi_env env, size_t argc, const napi_value argv[],
    MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    AlbumNapi *albumNapiObj = nullptr;
    int32_t albumId = 0;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &albumId);
        } else if (i == PARAM1 && valueType == napi_object) {
            napi_unwrap(env, argv[i], reinterpret_cast<void**>(&albumNapiObj));
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutInt(MEDIA_DATA_DB_ID, albumId);
    context->valuesBucket.PutString(MEDIA_DATA_DB_BUCKET_NAME, albumNapiObj->GetAlbumName());

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSModifyAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 3 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForModifyAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSModifyAlbum");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSModifyAlbumCompleteCallback),
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

static void JSDeleteAlbumCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri deleteAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_DELETEALBUM);

        int retVal = context->objectInfo->sDataShareHelper_->Insert(deleteAlbumUri,
            context->valuesBucket);
        if (retVal < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "Delete Album failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, retVal, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForDeleteAlbum(napi_env env, size_t argc, const napi_value argv[],
    MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    int32_t albumId = 0;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &albumId);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutInt(MEDIA_DATA_DB_ID, albumId);

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSDeleteAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForDeleteAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteAlbum");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSDeleteAlbumCompleteCallback),
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

void ChangeListenerNapi::OnChange(const MediaChangeListener &listener, const napi_ref cbRef)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }

    UvChangeMsg *msg = new (std::nothrow) UvChangeMsg(env_, cbRef);
    if (msg == nullptr) {
        delete work;
        return;
    }
    work->data = reinterpret_cast<void *>(msg);

    int ret = uv_queue_work(loop, work, [](uv_work_t *w) {}, [](uv_work_t *w, int s) {
            // js thread
            if (w == nullptr) {
                return;
            }

            UvChangeMsg *msg = reinterpret_cast<UvChangeMsg *>(w->data);
            do {
                if (msg == nullptr) {
                    NAPI_ERR_LOG("UvChangeMsg is null");
                    break;
                }
                napi_env env = msg->env_;
                napi_value result[ARGS_TWO] = { nullptr };
                napi_get_undefined(env, &result[PARAM0]);
                napi_get_undefined(env, &result[PARAM1]);
                napi_value jsCallback = nullptr;
                napi_status status = napi_get_reference_value(env, msg->ref_, &jsCallback);
                if (status != napi_ok) {
                    NAPI_ERR_LOG("Create reference fail, status: %{private}d", status);
                    break;
                }
                napi_value retVal = nullptr;
                napi_call_function(env, nullptr, jsCallback, ARGS_TWO, result, &retVal);
                if (status != napi_ok) {
                    NAPI_ERR_LOG("CallJs napi_call_function fail, status: %{private}d", status);
                    break;
                }
            } while (0);
            delete msg;
            delete w;
        }
    );
    if (ret != 0) {
        NAPI_ERR_LOG("Failed to execute libuv work queue, ret: %{private}d", ret);
        delete msg;
        delete work;
    }
}

int32_t MediaLibraryNapi::GetListenerType(const std::string &str) const
{
    auto iter = ListenerTypeMaps.find(str);
    if (iter == ListenerTypeMaps.end()) {
        NAPI_ERR_LOG("Invalid Listener Type %{private}s", str.c_str());
        return INVALID_LISTENER;
    }

    return iter->second;
}

void MediaLibraryNapi::RegisterChange(napi_env env, const std::string &type, ChangeListenerNapi &listObj)
{
    NAPI_DEBUG_LOG("Register change type = %{private}s", type.c_str());

    int32_t typeEnum = GetListenerType(type);
    switch (typeEnum) {
        case AUDIO_LISTENER:
            listObj.audioDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_AUDIO);
            sDataShareHelper_->RegisterObserver(Uri(MEDIALIBRARY_AUDIO_URI), listObj.audioDataObserver_);
            break;
        case VIDEO_LISTENER:
            listObj.videoDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_VIDEO);
            sDataShareHelper_->RegisterObserver(Uri(MEDIALIBRARY_VIDEO_URI), listObj.videoDataObserver_);
            break;
        case IMAGE_LISTENER:
            listObj.imageDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_IMAGE);
            sDataShareHelper_->RegisterObserver(Uri(MEDIALIBRARY_IMAGE_URI), listObj.imageDataObserver_);
            break;
        case FILE_LISTENER:
            listObj.fileDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_FILE);
            sDataShareHelper_->RegisterObserver(Uri(MEDIALIBRARY_FILE_URI), listObj.fileDataObserver_);
            break;
        case SMARTALBUM_LISTENER:
            listObj.smartAlbumDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_SMARTALBUM);
            sDataShareHelper_->RegisterObserver(Uri(MEDIALIBRARY_SMARTALBUM_CHANGE_URI),
                                              listObj.smartAlbumDataObserver_);
            break;
        case DEVICE_LISTENER:
            listObj.deviceDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_DEVICE);
            sDataShareHelper_->RegisterObserver(Uri(MEDIALIBRARY_DEVICE_URI), listObj.deviceDataObserver_);
            break;
        case REMOTEFILE_LISTENER:
            listObj.remoteFileDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_REMOTEFILE);
            sDataShareHelper_->RegisterObserver(Uri(MEDIALIBRARY_REMOTEFILE_URI), listObj.remoteFileDataObserver_);
            break;
        case ALBUM_LISTENER:
            listObj.albumDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_ALBUM);
            sDataShareHelper_->RegisterObserver(Uri(MEDIALIBRARY_ALBUM_URI), listObj.albumDataObserver_);
            break;
        default:
            NAPI_ERR_LOG("Invalid Media Type!");
    }
}

napi_value MediaLibraryNapi::JSOnCallback(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    char buffer[SIZE];
    string type;
    const int32_t refCount = 1;
    MediaLibraryNapi *obj = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        NAPI_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string ||
            napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
            return undefinedResult;
        }

        if (napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res) != napi_ok) {
            NAPI_ERR_LOG("Failed to get value string utf8 for type");
            return undefinedResult;
        }
        type = string(buffer);

        napi_create_reference(env, argv[PARAM1], refCount, &g_listObj->cbOnRef_);

        obj->RegisterChange(env, type, *g_listObj);
    }

    return undefinedResult;
}

void MediaLibraryNapi::UnregisterChange(napi_env env, const string &type, ChangeListenerNapi &listObj)
{
    NAPI_DEBUG_LOG("Unregister change type = %{private}s", type.c_str());

    MediaType mediaType;
    int32_t typeEnum = GetListenerType(type);

    switch (typeEnum) {
        case AUDIO_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.audioDataObserver_, "Failed to obtain audio data observer");

            mediaType = MEDIA_TYPE_AUDIO;
            sDataShareHelper_->UnregisterObserver(Uri(MEDIALIBRARY_AUDIO_URI), listObj.audioDataObserver_);

            delete listObj.audioDataObserver_;
            listObj.audioDataObserver_ = nullptr;
            break;
        case VIDEO_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.videoDataObserver_, "Failed to obtain video data observer");

            mediaType = MEDIA_TYPE_VIDEO;
            sDataShareHelper_->UnregisterObserver(Uri(MEDIALIBRARY_VIDEO_URI), listObj.videoDataObserver_);

            delete listObj.videoDataObserver_;
            listObj.videoDataObserver_ = nullptr;
            break;
        case IMAGE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.imageDataObserver_, "Failed to obtain image data observer");

            mediaType = MEDIA_TYPE_IMAGE;
            sDataShareHelper_->UnregisterObserver(Uri(MEDIALIBRARY_IMAGE_URI), listObj.imageDataObserver_);

            delete listObj.imageDataObserver_;
            listObj.imageDataObserver_ = nullptr;
            break;
        case FILE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.fileDataObserver_, "Failed to obtain file data observer");

            mediaType = MEDIA_TYPE_FILE;
            sDataShareHelper_->UnregisterObserver(Uri(MEDIALIBRARY_FILE_URI), listObj.fileDataObserver_);

            delete listObj.fileDataObserver_;
            listObj.fileDataObserver_ = nullptr;
            break;
        case SMARTALBUM_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.smartAlbumDataObserver_, "Failed to obtain smart album data observer");

            mediaType = MEDIA_TYPE_SMARTALBUM;
            sDataShareHelper_->UnregisterObserver(Uri(MEDIALIBRARY_SMARTALBUM_CHANGE_URI),
                                                listObj.smartAlbumDataObserver_);

            delete listObj.smartAlbumDataObserver_;
            listObj.smartAlbumDataObserver_ = nullptr;
            break;
        case DEVICE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.deviceDataObserver_, "Failed to obtain device data observer");

            mediaType = MEDIA_TYPE_DEVICE;
            sDataShareHelper_->UnregisterObserver(Uri(MEDIALIBRARY_DEVICE_URI), listObj.deviceDataObserver_);

            delete listObj.deviceDataObserver_;
            listObj.deviceDataObserver_ = nullptr;
            break;
        case REMOTEFILE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.remoteFileDataObserver_, "Failed to obtain remote file data observer");

            mediaType = MEDIA_TYPE_REMOTEFILE;
            sDataShareHelper_->UnregisterObserver(Uri(MEDIALIBRARY_REMOTEFILE_URI), listObj.remoteFileDataObserver_);

            delete listObj.remoteFileDataObserver_;
            listObj.remoteFileDataObserver_ = nullptr;
            break;
        case ALBUM_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.albumDataObserver_, "Failed to obtain album data observer");

            mediaType = MEDIA_TYPE_ALBUM;
            sDataShareHelper_->UnregisterObserver(Uri(MEDIALIBRARY_REMOTEFILE_URI), listObj.albumDataObserver_);

            delete listObj.albumDataObserver_;
            listObj.albumDataObserver_ = nullptr;
            break;
        default:
            NAPI_ERR_LOG("Invalid Media Type");
            return;
    }

    if (listObj.cbOffRef_ != nullptr) {
        MediaChangeListener listener;
        listener.mediaType = mediaType;
        listObj.OnChange(listener, listObj.cbOffRef_);
    }
}

napi_value MediaLibraryNapi::JSOffCallback(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    char buffer[SIZE];
    const int32_t refCount = 1;
    string type;
    MediaLibraryNapi *obj = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, ARGS_ONE <= argc && argc<= ARGS_TWO, "requires one or two parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr) {
        NAPI_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
            return undefinedResult;
        }

        if (napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res) != napi_ok) {
            NAPI_ERR_LOG("Failed to get value string utf8 for type");
            return undefinedResult;
        }
        type = string(buffer);

        if (argc == ARGS_TWO) {
            if (napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function ||
                g_listObj == nullptr) {
                return undefinedResult;
            }

            napi_create_reference(env, argv[PARAM1], refCount, &g_listObj->cbOffRef_);
        }

        obj->UnregisterChange(env, type, *g_listObj);
    }

    return undefinedResult;
}

static void JSReleaseCompleteCallback(napi_env env, napi_status status,
                                      MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->objectInfo != nullptr) {
        context->objectInfo->~MediaLibraryNapi();
        napi_create_int32(env, SUCCESS, &jsContext->data);
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
    } else {
        NAPI_ERR_LOG("JSReleaseCompleteCallback context->objectInfo == nullptr");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSRelease(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    int32_t refCount = 1;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ERR_LOG("NAPI_ASSERT begin %{private}zu", argc);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_ZERO), "requires 1 parameters maximum");
    NAPI_ERR_LOG("NAPI_ASSERT end");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == PARAM1) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[PARAM0], &valueType);
            if (valueType == napi_function) {
                napi_create_reference(env, argv[PARAM0], refCount, &asyncContext->callbackRef);
            }
        }
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSRelease");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSReleaseCompleteCallback),
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

static int32_t GetAlbumCapacity(MediaLibraryAsyncContext *context)
{
    if (context == nullptr) {
        NAPI_ERR_LOG("Async context is null");
        return -1;
    }
    string abilityUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_GETALBUMCAPACITY;
    Uri getAlbumCapacityUri(abilityUri);

    return context->objectInfo->sDataShareHelper_->Insert(getAlbumCapacityUri, context->valuesBucket);
}

static void GetFavSmartAlbumExecute(MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    context->smartAlbumData = make_unique<SmartAlbumAsset>();

    context->smartAlbumData->SetAlbumId(FAVORIT_SMART_ALBUM_ID);
    context->smartAlbumData->SetAlbumName(FAVORIT_SMART_ALBUM_NAME);
    context->valuesBucket.PutBool(MEDIA_DATA_DB_IS_FAV, true);
    context->valuesBucket.PutBool(MEDIA_DATA_DB_IS_TRASH, false);
    context->smartAlbumData->SetAlbumCapacity(GetAlbumCapacity(context));
    context->smartAlbumData->SetAlbumPrivateType(TYPE_FAVORITE);
}

static void GetTrashSmartAlbumExecute(MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    context->smartAlbumData = make_unique<SmartAlbumAsset>();

    context->smartAlbumData->SetAlbumId(TRASH_SMART_ALBUM_ID);
    context->smartAlbumData->SetAlbumName(TRASH_SMART_ALBUM_NAME);
    context->valuesBucket.PutBool(MEDIA_DATA_DB_IS_FAV, false);
    context->valuesBucket.PutBool(MEDIA_DATA_DB_IS_TRASH, true);
    context->smartAlbumData->SetAlbumCapacity(GetAlbumCapacity(context));
    context->smartAlbumData->SetAlbumPrivateType(TYPE_TRASH);
}

static void GetAllSmartAlbumResultDataExecute(MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    DataShare::DataSharePredicates predicates;
    if (context->objectInfo->sDataShareHelper_ == nullptr) {
        context->error = ERR_INVALID_OUTPUT;
    }
    if (context->privateAlbumType == TYPE_FAVORITE) {
        GetFavSmartAlbumExecute(context);
        return;
    }
    if (context->privateAlbumType == TYPE_TRASH) {
        GetTrashSmartAlbumExecute(context);
        return;
    }

    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/"
            + MEDIA_ALBUMOPRN_QUERYALBUM + "/"
            + SMARTABLUMASSETS_VIEW_NAME);
    shared_ptr<DataShare::DataShareResultSet> resultSet = context->objectInfo->sDataShareHelper_->Query(
        uri, columns, predicates);
    if (resultSet != nullptr) {
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            unique_ptr<SmartAlbumAsset> albumData = make_unique<SmartAlbumAsset>();
            if (albumData != nullptr) {
                albumData->SetAlbumId(get<int32_t>(GetValFromColumn(SMARTALBUM_DB_ID, resultSet, TYPE_INT32)));
                albumData->SetAlbumName(get<string>(GetValFromColumn(SMARTALBUM_DB_NAME, resultSet, TYPE_STRING)));
                albumData->SetAlbumCapacity(get<int32_t>(GetValFromColumn(SMARTABLUMASSETS_ALBUMCAPACITY,
                                                                          resultSet, TYPE_INT32)));

                context->privateSmartAlbumNativeArray.push_back(move(albumData));
            }
        }
    }
}

static void GetSmartAlbumResultDataExecute(MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    DataShare::DataSharePredicates predicates;
    if (context->objectInfo->sDataShareHelper_ == nullptr) {
        context->error = ERR_INVALID_OUTPUT;
    }
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    if (!context->order.empty()) {
        predicates.SetOrder(context->order);
    }
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM + "/" + SMARTABLUMASSETS_VIEW_NAME);
    shared_ptr<DataShare::DataShareResultSet> resultSet = context->objectInfo->sDataShareHelper_->Query(
        uri, columns, predicates);
    if (resultSet != nullptr) {
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            unique_ptr<SmartAlbumAsset> albumData = make_unique<SmartAlbumAsset>();
            if (albumData != nullptr) {
                albumData->SetAlbumId(get<int32_t>(GetValFromColumn(SMARTALBUM_DB_ID, resultSet, TYPE_INT32)));
                albumData->SetAlbumName(get<string>(GetValFromColumn(SMARTALBUM_DB_NAME, resultSet, TYPE_STRING)));
                albumData->SetAlbumCapacity(get<int32_t>(GetValFromColumn(SMARTABLUMASSETS_ALBUMCAPACITY,
                                                                          resultSet, TYPE_INT32)));
                albumData->SetAlbumUri(GetFileMediaTypeUri(MEDIA_TYPE_SMARTALBUM,
                    getNetworkId(get<string>(GetValFromColumn(SMARTALBUM_DB_SELF_ID, resultSet, TYPE_STRING))))
                    + "/" + to_string(albumData->GetAlbumId()));

                context->smartAlbumNativeArray.push_back(move(albumData));
            }
        }
    }
}

static void GetPrivateAlbumCallbackComplete(napi_env env, napi_status status,
                                            MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->error);
    if (context->error != ERR_DEFAULT) {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Query for get fileAssets failed");
    } else {
        if (context->smartAlbumData != nullptr) {
            jsContext->status = true;
            napi_value albumArray = nullptr;
            napi_create_array(env, &albumArray);
            napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env, *(context->smartAlbumData),
                context->objectInfo->sDataShareHelper_);
            napi_set_element(env, albumArray, 0, albumNapiObj);
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumArray;
        } else if (!context->privateSmartAlbumNativeArray.empty()) {
            jsContext->status = true;
            napi_value albumArray = nullptr;
            napi_create_array(env, &albumArray);
            for (size_t i = 0; i < context->privateSmartAlbumNativeArray.size(); i++) {
                napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env,
                    *(context->privateSmartAlbumNativeArray[i]),
                    context->objectInfo->sDataShareHelper_);
                napi_set_element(env, albumArray, i, albumNapiObj);
            }
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumArray;
        } else {
            NAPI_ERR_LOG("No fetch file result found!");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Failed to obtain Fetch File Result");
        }
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSGetPrivateAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    const int32_t refCount = 1;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        for (size_t i = PARAM0; i < argc; i++) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[i], &valueType);
            if (i == PARAM0 && valueType == napi_number) {
                napi_get_value_int32(env, argv[i], &asyncContext->privateAlbumType);
            } else if (i == PARAM1 && valueType == napi_function) {
                napi_create_reference(env, argv[i], refCount, &asyncContext->callbackRef);
                break;
            } else {
                NAPI_ASSERT(env, false, "type mismatch");
            }
        }
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetPublicDirectory");
        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                GetAllSmartAlbumResultDataExecute(context);
            },
            reinterpret_cast<CompleteCallback>(GetPrivateAlbumCallbackComplete),
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

napi_value GetJSArgsForCreateSmartAlbum(napi_env env, size_t argc, const napi_value argv[],
                                        MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    size_t res = 0;
    char buffer[PATH_MAX];
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    context->valuesBucket.PutString(SMARTALBUM_DB_NAME, string(buffer));
    napi_get_boolean(env, true, &result);
    return result;
}

static void JSCreateSmartAlbumCompleteCallback(napi_env env, napi_status status,
                                               MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->error == ERR_DEFAULT) {
        if (context->smartAlbumNativeArray.empty()) {
            NAPI_ERR_LOG("No albums found");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "No albums found");
        } else {
            jsContext->status = true;
            napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env, *(context->smartAlbumNativeArray[0]),
                                                                           context->objectInfo->sDataShareHelper_);
            jsContext->data = albumNapiObj;
            napi_get_undefined(env, &jsContext->error);
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "File asset creation failed");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSCreateSmartAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0}, thisVar = nullptr, resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCreateSmartAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteAsset");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void *data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (context->objectInfo->sDataShareHelper_ != nullptr) {
                    string abilityUri = MEDIALIBRARY_DATA_URI;
                    Uri CreateSmartAlbumUri(abilityUri + "/" + MEDIA_SMARTALBUMOPRN + "/" +
                        MEDIA_SMARTALBUMOPRN_CREATEALBUM);
                    int retVal = context->objectInfo->sDataShareHelper_->Insert(CreateSmartAlbumUri,
                        context->valuesBucket);
                    if (retVal > 0) {
                        context->selection = SMARTALBUM_DB_ID + " = ?";
                        context->selectionArgs = {std::to_string(retVal)};
                        context->retVal = retVal;
                        GetSmartAlbumResultDataExecute(context);
                    } else {
                        context->error = retVal;
                    }
                } else {
                    context->error = ERR_INVALID_OUTPUT;
                }
            },
            reinterpret_cast<CompleteCallback>(JSCreateSmartAlbumCompleteCallback),
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

napi_value GetJSArgsForDeleteSmartAlbum(napi_env env, size_t argc, const napi_value argv[],
                                        MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    size_t res = 0;
    char buffer[PATH_MAX];
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    std::string coverUri = string(buffer);
    std::string strRow;
    string::size_type pos = coverUri.find_last_of('/');
    strRow = coverUri.substr(pos + 1);
    context->valuesBucket.PutInt(SMARTALBUM_DB_ID, std::stoi(strRow));
    napi_get_boolean(env, true, &result);
    return result;
}

static void JSDeleteSmartAlbumCompleteCallback(napi_env env, napi_status status,
                                               MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->error == ERR_DEFAULT) {
        napi_create_int32(env, context->retVal, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static void JSDeleteSmartAlbumExecute(MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri DeleteSmartAlbumUri(abilityUri + "/" + MEDIA_SMARTALBUMOPRN + "/" + MEDIA_SMARTALBUMOPRN_DELETEALBUM);
        int retVal = context->objectInfo->sDataShareHelper_->Insert(DeleteSmartAlbumUri,
            context->valuesBucket);
        NAPI_DEBUG_LOG("JSDeleteSmartAlbumCompleteCallback retVal = %{private}d", retVal);
        if (retVal < 0) {
            context->error = retVal;
        } else {
            context->retVal = retVal;
        }
    } else {
        context->error = ERR_INVALID_OUTPUT;
    }
}

napi_value MediaLibraryNapi::JSDeleteSmartAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForDeleteSmartAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteAsset");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                JSDeleteSmartAlbumExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSDeleteSmartAlbumCompleteCallback),
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

static napi_status SetValueUtf8String(const napi_env& env, const char* fieldStr, const char* str, napi_value& result)
{
    napi_value value;
    napi_status status = napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set value create utf8 string error! field: %{private}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set utf8 string named property error! field: %{private}s", fieldStr);
    }
    return status;
}

static napi_status SetValueInt32(const napi_env& env, const char* fieldStr, const int intValue, napi_value& result)
{
    napi_value value;
    napi_status status = napi_create_int32(env, intValue, &value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set value create int32 error! field: %{private}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set int32 named property error! field: %{private}s", fieldStr);
    }
    return status;
}

static napi_status SetValueBool(const napi_env& env, const char* fieldStr, const bool boolvalue, napi_value& result)
{
    napi_value value = nullptr;
    napi_status status = napi_get_boolean(env, boolvalue, &value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set value create boolean error! field: %{private}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set boolean named property error! field: %{private}s", fieldStr);
    }
    return status;
}

static void PeerInfoToJsArray(const napi_env &env, const std::vector<unique_ptr<PeerInfo>> &vecPeerInfo,
    const int32_t idx, napi_value &arrayResult)
{
    if (idx >= (int32_t) vecPeerInfo.size()) {
        return;
    }
    auto info = vecPeerInfo[idx].get();
    if (info == nullptr) {
        return;
    }
    napi_value result = nullptr;
    napi_create_object(env, &result);
    SetValueUtf8String(env, "deviceName", info->deviceName.c_str(), result);
    SetValueUtf8String(env, "networkId", info->networkId.c_str(), result);
    SetValueInt32(env, "deviceTypeId", (int) info->deviceTypeId, result);
    SetValueBool(env, "isOnline", info->isOnline, result);

    napi_status status = napi_set_element(env, arrayResult, idx, result);
    if (status != napi_ok) {
        NAPI_ERR_LOG("PeerInfo To JsArray set element error: %d", status);
    }
}

void JSGetActivePeersCompleteCallback(napi_env env, napi_status status,
    MediaLibraryAsyncContext *context)
{
    napi_value jsPeerInfoArray = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);

    vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    std::string strQueryCondition = DEVICE_DB_DATE_MODIFIED + " = 0";
    predicates.SetWhereClause(strQueryCondition);
    predicates.SetWhereArgs(context->selectionArgs);

    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYACTIVEDEVICE);
    shared_ptr<DataShare::DataShareResultSet> resultSet = context->objectInfo->sDataShareHelper_->Query(
        uri, columns, predicates);

    if (resultSet == nullptr) {
        NAPI_ERR_LOG("JSGetActivePeers resultSet is null");
        delete context;
        return;
    }

    vector<unique_ptr<PeerInfo>> peerInfoArray;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<PeerInfo> peerInfo = make_unique<PeerInfo>();
        if (peerInfo != nullptr) {
            peerInfo->deviceName = get<string>(GetValFromColumn(DEVICE_DB_NAME, resultSet, TYPE_STRING));
            peerInfo->networkId = get<string>(GetValFromColumn(DEVICE_DB_NETWORK_ID, resultSet, TYPE_STRING));
            peerInfo->deviceTypeId = (DistributedHardware::DmDeviceType)
                                     (get<int32_t>(GetValFromColumn(DEVICE_DB_TYPE, resultSet, TYPE_INT32)));
            peerInfo->isOnline = true;
            peerInfoArray.push_back(move(peerInfo));
        }
    }

    if (!peerInfoArray.empty() && (napi_create_array(env, &jsPeerInfoArray) == napi_ok)) {
        for (size_t i = 0; i < peerInfoArray.size(); ++i) {
            PeerInfoToJsArray(env, peerInfoArray, i, jsPeerInfoArray);
        }

        jsContext->data = jsPeerInfoArray;
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        NAPI_DEBUG_LOG("No peer info found!");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain peer info array from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

void JSGetAllPeersCompleteCallback(napi_env env, napi_status status,
    MediaLibraryAsyncContext *context)
{
    napi_value jsPeerInfoArray = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);

    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);

    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYALLDEVICE);
    shared_ptr<DataShare::DataShareResultSet> resultSet = context->objectInfo->sDataShareHelper_->Query(
        uri, columns, predicates);

    if (resultSet == nullptr) {
        NAPI_ERR_LOG("JSGetAllPeers resultSet is null");
        delete context;
        return;
    }

    vector<unique_ptr<PeerInfo>> peerInfoArray;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<PeerInfo> peerInfo = make_unique<PeerInfo>();
        if (peerInfo != nullptr) {
            peerInfo->deviceName = get<string>(GetValFromColumn(DEVICE_DB_NAME, resultSet, TYPE_STRING));
            peerInfo->networkId = get<string>(GetValFromColumn(DEVICE_DB_NETWORK_ID, resultSet, TYPE_STRING));
            peerInfo->deviceTypeId = (DistributedHardware::DmDeviceType)
                                     (get<int32_t>(GetValFromColumn(DEVICE_DB_TYPE, resultSet, TYPE_INT32)));
            peerInfo->isOnline = (get<int32_t>(GetValFromColumn(DEVICE_DB_DATE_MODIFIED, resultSet, TYPE_INT32)) == 0);
            peerInfoArray.push_back(move(peerInfo));
        }
    }

    if (!peerInfoArray.empty() && (napi_create_array(env, &jsPeerInfoArray) == napi_ok)) {
        for (size_t i = 0; i < peerInfoArray.size(); ++i) {
            PeerInfoToJsArray(env, peerInfoArray, i, jsPeerInfoArray);
        }

        jsContext->data = jsPeerInfoArray;
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        NAPI_DEBUG_LOG("No peer info found!");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain peer info array from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSGetActivePeers(napi_env env, napi_callback_info info)
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
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetActivePeers");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSGetActivePeersCompleteCallback),
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

napi_value MediaLibraryNapi::JSGetAllPeers(napi_env env, napi_callback_info info)
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
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAllPeers");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSGetAllPeersCompleteCallback),
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

static int32_t CloseAsset(MediaLibraryAsyncContext *context, string uri)
{
    string abilityUri = MEDIALIBRARY_DATA_URI;
    Uri closeAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);
    context->valuesBucket.Clear();
    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, uri);
    int32_t ret = context->objectInfo->sDataShareHelper_->Insert(closeAssetUri, context->valuesBucket);
    NAPI_DEBUG_LOG("File close asset %{public}d", ret);
    if (ret != DATA_ABILITY_SUCCESS) {
        context->error = ret;
        NAPI_ERR_LOG("File close asset fail, %{public}d", ret);
    }
    return ret;
}

static void JSGetStoreMediaAssetExecute(MediaLibraryAsyncContext *context)
{
    auto helper = context->objectInfo->sDataShareHelper_;
    if (helper == nullptr) {
        NAPI_ERR_LOG("sDataShareHelper_ is not exist");
        context->error = ERR_INVALID_OUTPUT;
        return;
    }
    string realPath;
    if (!PathToRealPath(context->storeMediaSrc, realPath)) {
        NAPI_ERR_LOG("src path is not exist, %{public}d", errno);
        return;
    }
    context->error = ERR_RELATIVE_PATH_NOT_EXIST_OR_INVALID;
    int32_t srcFd = open(realPath.c_str(), O_RDWR);
    if (srcFd == -1) {
        NAPI_ERR_LOG("src path open fail, %{public}d", errno);
        return;
    }
    struct stat statSrc;
    if (fstat(srcFd, &statSrc) == -1) {
        close(srcFd);
        NAPI_DEBUG_LOG("File get stat failed, %{public}d", errno);
        return;
    }
    Uri createFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);
    int index = helper->Insert(createFileUri, context->valuesBucket);
    if (index < 0) {
        close(srcFd);
        NAPI_ERR_LOG("storeMedia fail, file already exist %{public}d", index);
        return;
    }
    getFileAssetById(index, "", context);
    Uri openFileUri(context->fileAsset->GetUri());
    int32_t destFd = helper->OpenFile(openFileUri, MEDIA_FILEMODE_READWRITE);
    if (destFd < 0) {
        context->error = destFd;
        NAPI_DEBUG_LOG("File open asset failed");
        close(srcFd);
        return;
    }
    if (sendfile(destFd, srcFd, nullptr, statSrc.st_size) == -1) {
        close(srcFd);
        close(destFd);
        CloseAsset(context, context->fileAsset->GetUri());
        NAPI_ERR_LOG("copy file fail %{public}d ", errno);
        return;
    }
    close(srcFd);
    close(destFd);
    CloseAsset(context, context->fileAsset->GetUri());
    context->error = ERR_DEFAULT;
}

static void JSGetStoreMediaAssetCompleteCallback(napi_env env, napi_status status,
    MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "Async context is null");
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    if (context->error != ERR_DEFAULT) {
        NAPI_ERR_LOG("JSGetStoreMediaAssetCompleteCallback failed %{public}d ", context->error);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "storeMediaAsset fail");
    } else {
        napi_create_string_utf8(env, context->fileAsset->GetUri().c_str(), NAPI_AUTO_LENGTH, &jsContext->data);
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static int ConvertMediaType(const string &mimeType)
{
    string res;
    // mimeType 'image/gif', 'video/mp4', 'audio/mp3', 'file/pdf'
    size_t slash = mimeType.find('/');
    if (slash != string::npos) {
        res = mimeType.substr(0, slash);
        if (res.empty()) {
            return MediaType::MEDIA_TYPE_FILE;
        }
    }
    if (res == "image") {
        return MediaType::MEDIA_TYPE_IMAGE;
    } else if (res == "video") {
        return MediaType::MEDIA_TYPE_VIDEO;
    } else if (res == "audio") {
        return MediaType::MEDIA_TYPE_AUDIO;
    }
    return MediaType::MEDIA_TYPE_FILE;
}

static bool GetStoreMediaAssetProper(napi_env env, napi_value param, const string &proper, string &res)
{
    napi_value value = MediaLibraryNapiUtils::GetPropertyValueByName(env, param, proper.c_str());
    if (value == nullptr) {
        NAPI_ERR_LOG("GetPropertyValueByName %{public}s fail", proper.c_str());
        return false;
    }
    unique_ptr<char[]> tmp;
    bool succ;
    tie(succ, tmp, ignore) = MediaLibraryNapiUtils::ToUTF8String(env, value);
    if (!succ) {
        NAPI_ERR_LOG("param %{public}s fail", proper.c_str());
        return false;
    }
    res = string(tmp.get());
    return true;
}

static string GetDefaultDirectory(int mediaType)
{
    string relativePath;
    if (mediaType == MediaType::MEDIA_TYPE_IMAGE) {
        relativePath = "Pictures/";
    } else if (mediaType == MediaType::MEDIA_TYPE_VIDEO) {
        relativePath = "Videos/";
    } else if (mediaType == MediaType::MEDIA_TYPE_AUDIO) {
        relativePath = "Audios/";
    } else {
        relativePath = "Documents/";
    }
    return relativePath;
}

static napi_value GetStoreMediaAssetArgs(napi_env env, napi_value param,
    MediaLibraryAsyncContext &asyncContext)
{
    auto context = &asyncContext;
    if (!GetStoreMediaAssetProper(env, param, "src", context->storeMediaSrc)) {
        NAPI_ERR_LOG("param get fail");
        return nullptr;
    }
    string fileName = MediaFileUtils::GetFilename(context->storeMediaSrc);
    if (fileName.empty() || (fileName.at(0) == '.')) {
        NAPI_ERR_LOG("src file name is not proper");
        context->error = ERR_RELATIVE_PATH_NOT_EXIST_OR_INVALID;
        return nullptr;
    };
    context->valuesBucket.PutString(MEDIA_DATA_DB_NAME, fileName);
    string mimeType;
    if (!GetStoreMediaAssetProper(env, param, "mimeType", mimeType)) {
        NAPI_ERR_LOG("param get fail");
        return nullptr;
    }
    auto mediaType = ConvertMediaType(mimeType);
    context->valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    string relativePath;
    if (!GetStoreMediaAssetProper(env, param, "relativePath", relativePath)) {
        NAPI_DEBUG_LOG("optional relativePath param empty");
        relativePath = GetDefaultDirectory(mediaType);
    }
    context->valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    NAPI_DEBUG_LOG("src:%{private}s mime:%{private}s relp:%{private}s filename:%{private}s",
        context->storeMediaSrc.c_str(), mimeType.c_str(), relativePath.c_str(), fileName.c_str());
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value MediaLibraryNapi::JSStoreMediaAsset(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "Failed to get asyncContext");
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if ((status == napi_ok) && (asyncContext->objectInfo != nullptr)) {
        napi_value res = GetStoreMediaAssetArgs(env, argv[PARAM0], *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, res, res, "Failed to obtain arguments");
        if (argc == ARGS_TWO) {
            const int32_t refCount = 1;
            GET_JS_ASYNC_CB_REF(env, argv[PARAM1], refCount, asyncContext->callbackRef);
        }
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        napi_value resource = nullptr;
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSStoreMediaAsset");
        status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                JSGetStoreMediaAssetExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSGetStoreMediaAssetCompleteCallback),
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

static Ability *CreateAsyncCallbackInfo(napi_env env)
{
    if (env == nullptr) {
        NAPI_ERR_LOG("env == nullptr.");
        return nullptr;
    }
    napi_status ret;
    napi_value global = 0;
    const napi_extended_error_info *errorInfo = nullptr;
    ret = napi_get_global(env, &global);
    if (ret != napi_ok) {
        napi_get_last_error_info(env, &errorInfo);
        NAPI_ERR_LOG("get_global=%{public}d err:%{public}s", ret, errorInfo->error_message);
    }
    napi_value abilityObj = 0;
    ret = napi_get_named_property(env, global, "ability", &abilityObj);
    if (ret != napi_ok) {
        napi_get_last_error_info(env, &errorInfo);
        NAPI_ERR_LOG("get_named_property=%{public}d e:%{public}s", ret, errorInfo->error_message);
    }
    Ability *ability = nullptr;
    ret = napi_get_value_external(env, abilityObj, (void **)&ability);
    if (ret != napi_ok) {
        napi_get_last_error_info(env, &errorInfo);
        NAPI_ERR_LOG("get_value_external=%{public}d e:%{public}s", ret, errorInfo->error_message);
    }
    return ability;
}

static napi_value GetImagePreviewArgsUri(napi_env env, napi_value param, MediaLibraryAsyncContext &context)
{
    uint32_t arraySize = 0;
    if (!MediaLibraryNapiUtils::IsArrayForNapiValue(env, param, arraySize)) {
        NAPI_ERR_LOG("GetImagePreviewArgs get args fail, not array");
        return nullptr;
    }
    string uri = "";
    for (uint32_t i = 0; i < arraySize; i++) {
        napi_value jsValue = nullptr;
        if ((napi_get_element(env, param, i, &jsValue)) != napi_ok) {
            NAPI_ERR_LOG("GetImagePreviewArgs get args fail");
            return nullptr;
        }
        unique_ptr<char[]> inputStr;
        bool succ;
        tie(succ, inputStr, ignore) = MediaLibraryNapiUtils::ToUTF8String(env, jsValue);
        if (!succ) {
            NAPI_ERR_LOG("GetImagePreviewArgs get string fail");
            return nullptr;
        }
        uri += string(inputStr.get());
        uri += ",";
    }
    context.uri = uri.substr(0, uri.length() - 1);
    NAPI_DEBUG_LOG("GetImagePreviewArgs res %{private}s", context.uri.c_str());
    napi_value res;
    napi_get_undefined(env, &res);
    return res;
}

static napi_value GetImagePreviewArgsNum(napi_env env, napi_value param, MediaLibraryAsyncContext &context)
{
    context.imagePreviewIndex = 0;
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, param, &valueType);
    if (valueType != napi_number) {
        NAPI_ERR_LOG("not napi value");
        return nullptr;
    }
    if (napi_get_value_int32(env, param, &context.imagePreviewIndex) != napi_ok) {
        NAPI_ERR_LOG("get property value fail");
    }
    NAPI_ERR_LOG("GetImagePreviewArgs num %{public}d", context.imagePreviewIndex);
    napi_value res;
    napi_get_undefined(env, &res);
    return res;
}

static void JSStartImagePreviewExecute(MediaLibraryAsyncContext *context)
{
    if (context->ability_ == nullptr) {
        NAPI_ERR_LOG("ability_ is not exist");
        context->error = ERR_INVALID_OUTPUT;
        return;
    }
    Want want;
    string deviceId = "";
    string bundleName = "com.ohos.photos";
    string abilityName = "com.ohos.photos.MainAbility";
    want.SetElementName(deviceId, bundleName, abilityName);
    want.SetUri(context->uri);
    want.SetAction("ohos.want.action.viewData");
    want.SetParam("index", context->imagePreviewIndex);
    context->error = context->ability_->StartAbility(want);
}

static void JSGetJSStartImagePreviewCompleteCallback(napi_env env, napi_status status,
    MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "get jsContext failed");
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->data);
    if (context->error != 0) {
        jsContext->status = false;
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "startImagePreview currently fail");
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSStartImagePreview(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "Failed to get asyncContext");
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        napi_value res = GetImagePreviewArgsUri(env, argv[PARAM0], *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, res, result, "Failed to obtain arguments uri");
        GetImagePreviewArgsNum(env, argv[PARAM1], *asyncContext);
        asyncContext->ability_ = CreateAsyncCallbackInfo(env);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->ability_, result, "Failed to obtain ability");
        const int32_t refCount = 1;
        if (argc == ARGS_THREE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM2], refCount, asyncContext->callbackRef);
        } else if (argc == ARGS_TWO && MediaLibraryNapiUtils::CheckJSArgsTypeAsFunc(env, argv[PARAM1])) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM1], refCount, asyncContext->callbackRef);
        }
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        napi_value resource = nullptr;
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSStartImagePreview");
        status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                JSStartImagePreviewExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSGetJSStartImagePreviewCompleteCallback),
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
napi_value MediaLibraryNapi::JSGetMediaRemoteStub(napi_env env, napi_callback_info info)
{
    napi_value remoteStub = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, argv[0], isStageMode_);

    if (status != napi_ok){

    } else {
        if (isStageMode_) {
            auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[0]);
            if (context == nullptr) {
                NAPI_ERR_LOG("Failed to get native context instance");
                return nullptr;
            }
            sptr<MediaDataStubImpl> remoteObject = new (std::nothrow) MediaDataStubImpl(env, context);
            if (remoteObject == nullptr) {
                return nullptr;
	    }
	    remoteObject->InitMediaLibraryRdbStore();

            remoteStub = NAPI_ohos_rpc_CreateJsRemoteObject(env, remoteObject);
	}
    }
     return remoteStub;
 }
} // namespace Media
} // namespace OHOS
