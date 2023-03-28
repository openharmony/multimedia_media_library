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
#define MLOG_TAG "MediaLibraryNapi"

#include "media_library_napi.h"

#include <fcntl.h>
#include <sys/sendfile.h>
#include "media_file_utils.h"
#include "hitrace_meter.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_peer_info.h"
#include "medialibrary_tracer.h"
#include "smart_album_napi.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "uv.h"
#include "result_set_utils.h"
#include "string_ex.h"
#include "string_wrapper.h"
#include "userfile_client.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
thread_local unique_ptr<ChangeListenerNapi> g_listObj = nullptr;
const int32_t NUM_2 = 2;
const int32_t NUM_3 = 3;
const string DATE_FUNCTION = "DATE(";

std::mutex MediaLibraryNapi::sUserFileClientMutex_;

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
thread_local napi_ref MediaLibraryNapi::sMediaTypeEnumRef_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sDirectoryEnumRef_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sVirtualAlbumTypeEnumRef_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sFileKeyEnumRef_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sPrivateAlbumEnumRef_ = nullptr;
using CompleteCallback = napi_async_complete_callback;
using Context = MediaLibraryAsyncContext* ;

thread_local napi_ref MediaLibraryNapi::userFileMgrConstructor_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sUserFileMgrFileKeyEnumRef_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sAudioKeyEnumRef_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sImageVideoKeyEnumRef_ = nullptr;
thread_local napi_ref MediaLibraryNapi::sAlbumKeyEnumRef_ = nullptr;

MediaLibraryNapi::MediaLibraryNapi()
    : resultNapiType_(ResultNapiType::TYPE_NAPI_MAX), env_(nullptr) {}

MediaLibraryNapi::~MediaLibraryNapi() = default;

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
        DECLARE_NAPI_FUNCTION("getSmartAlbums", JSGetSmartAlbums),
        DECLARE_NAPI_FUNCTION("getPrivateAlbum", JSGetPrivateAlbum),
        DECLARE_NAPI_FUNCTION("createSmartAlbum", JSCreateSmartAlbum),
        DECLARE_NAPI_FUNCTION("deleteSmartAlbum", JSDeleteSmartAlbum),
        DECLARE_NAPI_FUNCTION("getActivePeers", JSGetActivePeers),
        DECLARE_NAPI_FUNCTION("getAllPeers", JSGetAllPeers),
        DECLARE_NAPI_FUNCTION("storeMediaAsset", JSStoreMediaAsset),
        DECLARE_NAPI_FUNCTION("startImagePreview", JSStartImagePreview),
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

napi_value MediaLibraryNapi::UserFileMgrInit(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        USERFILE_MGR_NAPI_CLASS_NAME,
        &userFileMgrConstructor_,
        MediaLibraryNapiConstructor,
        {
            DECLARE_NAPI_FUNCTION("getPublicDirectory", JSGetPublicDirectory),
            DECLARE_NAPI_FUNCTION("getPhotoAssets", UserFileMgrGetPhotoAssets),
            DECLARE_NAPI_FUNCTION("getAudioAssets", UserFileMgrGetAudioAssets),
            DECLARE_NAPI_FUNCTION("getPhotoAlbums", UserFileMgrGetAlbums),
            DECLARE_NAPI_FUNCTION("createPhotoAsset", UserFileMgrCreateAsset),
            DECLARE_NAPI_FUNCTION("delete", UserFileMgrTrashAsset),
            DECLARE_NAPI_FUNCTION("on", JSOnCallback),
            DECLARE_NAPI_FUNCTION("off", JSOffCallback),
            DECLARE_NAPI_FUNCTION("getPrivateAlbum", UserFileMgrGetPrivateAlbum),
            DECLARE_NAPI_FUNCTION("getActivePeers", JSGetActivePeers),
            DECLARE_NAPI_FUNCTION("getAllPeers", JSGetAllPeers),
            DECLARE_NAPI_FUNCTION("release", JSRelease),
        }
    };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);

    const std::vector<napi_property_descriptor> staticProps = {
        DECLARE_NAPI_STATIC_FUNCTION("getUserFileMgr", GetUserFileMgr),
        DECLARE_NAPI_PROPERTY("FileType", CreateMediaTypeUserFileEnum(env)),
        DECLARE_NAPI_PROPERTY("FileKey", UserFileMgrCreateFileKeyEnum(env)),
        DECLARE_NAPI_PROPERTY("AudioKey", CreateAudioKeyEnum(env)),
        DECLARE_NAPI_PROPERTY("ImageVideoKey", CreateImageVideoKeyEnum(env)),
        DECLARE_NAPI_PROPERTY("AlbumKey", CreateAlbumKeyEnum(env)),
        DECLARE_NAPI_PROPERTY("PrivateAlbumType", CreatePrivateAlbumTypeEnum(env))
    };
    MediaLibraryNapiUtils::NapiAddStaticProps(env, exports, staticProps);
    return exports;
}

// Constructor callback
napi_value MediaLibraryNapi::MediaLibraryNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    MediaLibraryTracer tracer;

    tracer.Start("MediaLibraryNapiConstructor");

    NAPI_CALL(env, napi_get_undefined(env, &result));
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Error while obtaining js environment information, status: %{public}d", status);
        return result;
    }

    unique_ptr<MediaLibraryNapi> obj = make_unique<MediaLibraryNapi>();
    if (obj == nullptr) {
        return result;
    }
    obj->env_ = env;
    // Initialize the ChangeListener object
    if (g_listObj == nullptr) {
        g_listObj = make_unique<ChangeListenerNapi>(env);
    }

    std::unique_lock<std::mutex> helperLock(sUserFileClientMutex_);
    if (!UserFileClient::IsValid()) {
        UserFileClient::Init(env, info);
        if (!UserFileClient::IsValid()) {
            NAPI_ERR_LOG("UserFileClient creation failed");
            napi_get_undefined(env, &(result));
            return result;
        }
    }
    helperLock.unlock();

    status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                       MediaLibraryNapi::MediaLibraryNapiDestructor, nullptr, nullptr);
    if (status == napi_ok) {
        obj.release();
        return thisVar;
    } else {
        NAPI_ERR_LOG("Failed to wrap the native media lib client object with JS, status: %{public}d", status);
    }

    return result;
}

static napi_value CreateNewInstance(napi_env env, napi_callback_info info, napi_ref ref)
{
    constexpr size_t ARG_CONTEXT = 1;
    size_t argc = ARG_CONTEXT;
    napi_value argv[ARG_CONTEXT] = {0};

    napi_value thisVar = nullptr;
    napi_value ctor = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_get_reference_value(env, ref, &ctor));

    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, ctor, argc, argv, &result));
    return result;
}

napi_value MediaLibraryNapi::GetMediaLibraryNewInstance(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("getMediaLibrary");

    napi_value result = nullptr;
    napi_value ctor;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    napi_status status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        status = napi_new_instance(env, ctor, argc, argv, &result);
        if (status == napi_ok) {
            return result;
        } else {
            NAPI_ERR_LOG("New instance could not be obtained status: %{public}d", status);
        }
    } else {
            NAPI_ERR_LOG("status = %{public}d", status);
    }

    napi_get_undefined(env, &result);

    return result;
}

napi_value MediaLibraryNapi::GetUserFileMgr(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("getUserFileManager");

    return CreateNewInstance(env, info, userFileMgrConstructor_);
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

static napi_value CreateNumberEnumProperty(napi_env env, vector<string> properties, napi_ref &ref, int32_t offset = 0)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    for (size_t i = 0; i < properties.size(); i++) {
        NAPI_CALL(env, AddIntegerNamedProperty(env, result, properties[i], i + offset));
    }
    NAPI_CALL(env, napi_create_reference(env, result, NAPI_INIT_REF_COUNT, &ref));
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

static napi_value CreateStringEnumProperty(napi_env env, vector<pair<string, string>> properties, napi_ref &ref)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    for (unsigned int i = 0; i < properties.size(); i++) {
        NAPI_CALL(env, AddStringNamedProperty(env, result, properties[i].first, properties[i].second));
    }
    NAPI_CALL(env, napi_create_reference(env, result, NAPI_INIT_REF_COUNT, &ref));
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
    napi_has_named_property(env, arg, "extendArgs", &present);
    if (present) {
        if ((napi_get_named_property(env, arg, "extendArgs", &property) != napi_ok) ||
            (napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok)) {
            NAPI_ERR_LOG("Could not get the extendArgs string argument!");
            err = true;
            return;
        } else {
            asyncContext->extendArgs = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }
}

static void GetFetchOptionsParam(napi_env env, napi_value arg, const MediaLibraryAsyncContext &context, bool &err)
{
    MediaLibraryAsyncContext *asyncContext = const_cast<MediaLibraryAsyncContext *>(&context);
    CHECK_NULL_PTR_RETURN_VOID(asyncContext, "Async context is null");
    napi_value property = nullptr;
    napi_value stringItem = nullptr;
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
            NAPI_ERR_LOG("fetch options retrieval failed, err: %{public}d", err);
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_value result;
    napi_get_boolean(env, true, &result);
    return result;
}

static void GetPublicDirectoryExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetPublicDirectoryExecute");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    vector<string> selectionArgs;
    vector<string> columns;
    DataSharePredicates predicates;
    NAPI_ERR_LOG("context->dirType is = %{public}d", context->dirType);
    selectionArgs.push_back(to_string(context->dirType));
    predicates.SetWhereClause(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE + " = ?");
    predicates.SetWhereArgs(selectionArgs);
    string queryUri = MEDIALIBRARY_DIRECTORY_URI;
    Uri uri(queryUri);

    shared_ptr<DataShareResultSet> resultSet = UserFileClient::Query(uri, predicates, columns);
    if (resultSet != nullptr) {
        auto count = 0;
        auto ret = resultSet->GetRowCount(count);
        if (ret != NativeRdb::E_OK) {
            NAPI_ERR_LOG("get rdbstore failed");
            context->error = JS_INNER_FAIL;
            return;
        }
        if (count == 0) {
            NAPI_ERR_LOG("Query for get publicDirectory form db failed");
            context->error = JS_INNER_FAIL;
            return;
        }
        NAPI_ERR_LOG("Query for get publicDirectory count = %{private}d", count);
        if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
            context->directoryRelativePath = get<string>(
                ResultSetUtils::GetValFromColumn(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, resultSet, TYPE_STRING));
        }
        return;
    } else {
        context->SaveError(resultSet);
        NAPI_ERR_LOG("Query for get publicDirectory failed");
    }
}

static void GetPublicDirectoryCallbackComplete(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetPublicDirectoryCallbackComplete");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->error == ERR_DEFAULT) {
        napi_create_string_utf8(env, context->directoryRelativePath.c_str(), NAPI_AUTO_LENGTH, &jsContext->data);
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
    } else {
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }

    delete context;
}

napi_value MediaLibraryNapi::JSGetPublicDirectory(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    const int32_t refCount = 1;

    MediaLibraryTracer tracer;
    tracer.Start("JSGetPublicDirectory");

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
        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetPublicDirectory",
            GetPublicDirectoryExecute, GetPublicDirectoryCallbackComplete);
    }

    return result;
}

static void GetFileAssetUpdatePredicates(MediaLibraryAsyncContext *context)
{
    context->predicates.NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_TYPE_ALBUM);
    context->predicates.EqualTo(MEDIA_DATA_DB_DATE_TRASHED, 0);
    MediaLibraryNapiUtils::UpdateMediaTypeSelections(context);
    if (!context->uri.empty()) {
        NAPI_ERR_LOG("context->uri is = %{public}s", context->uri.c_str());
        string fileId;
        MediaLibraryNapiUtils::GetNetworkIdAndFileIdFromUri(context->uri, context->networkId, fileId);
        if (!fileId.empty()) {
            context->predicates.EqualTo(MEDIA_DATA_DB_ID, fileId);
        }
    }
}

static void GetFileAssetUpdateSelections(MediaLibraryAsyncContext *context)
{
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        GetFileAssetUpdatePredicates(context);
        return;
    }

    string trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? ";
    MediaLibraryNapiUtils::AppendFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.emplace_back("0");

    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    MediaLibraryNapiUtils::AppendFetchOptionSelection(context->selection, prefix);
    context->selectionArgs.emplace_back(to_string(MEDIA_TYPE_ALBUM));

    if (!context->uri.empty()) {
        NAPI_ERR_LOG("context->uri is = %{public}s", context->uri.c_str());
        context->networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(context->uri);
        string fileId = MediaLibraryDataManagerUtils::GetIdFromUri(context->uri);
        if (!fileId.empty()) {
            string idPrefix = MEDIA_DATA_DB_ID + " = ? ";
            MediaLibraryNapiUtils::AppendFetchOptionSelection(context->selection, idPrefix);
            context->selectionArgs.emplace_back(fileId);
        }
    }
}

static void GetFileAssetsExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetFileAssetsExecute");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    
    GetFileAssetUpdateSelections(context);

    // fetch columns from fileAsset in medialibrary.d.ts
    static const vector<string> FILE_ASSET_COLUMNS = {
        MEDIA_DATA_DB_ID, MEDIA_DATA_DB_URI, MEDIA_DATA_DB_MIME_TYPE, MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_DATA_DB_NAME,
        MEDIA_DATA_DB_TITLE, MEDIA_DATA_DB_RELATIVE_PATH, MEDIA_DATA_DB_PARENT_ID, MEDIA_DATA_DB_SIZE,
        MEDIA_DATA_DB_DATE_ADDED, MEDIA_DATA_DB_DATE_MODIFIED, MEDIA_DATA_DB_DATE_TAKEN, MEDIA_DATA_DB_ARTIST,
        MEDIA_DATA_DB_WIDTH, MEDIA_DATA_DB_HEIGHT, MEDIA_DATA_DB_ORIENTATION, MEDIA_DATA_DB_DURATION,
        MEDIA_DATA_DB_BUCKET_ID, MEDIA_DATA_DB_BUCKET_NAME, MEDIA_DATA_DB_IS_TRASH, MEDIA_DATA_DB_IS_FAV
    };
    if (context->fetchColumn.size() == 0) {
        context->fetchColumn = FILE_ASSET_COLUMNS;
    }

    if (context->extendArgs.find(DATE_FUNCTION) != string::npos) {
        string group(" GROUP BY (");
        group += context->extendArgs + " )";
        context->selection += group;
        context->fetchColumn.insert(context->fetchColumn.begin(), "count(*)");
    }

    context->predicates.SetWhereClause(context->selection);
    context->predicates.SetWhereArgs(context->selectionArgs);
    context->predicates.SetOrder(context->order);

    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    }
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(queryUri, context->typeMask);
    NAPI_DEBUG_LOG("queryUri is = %{public}s", queryUri.c_str());
    Uri uri(queryUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri,
        context->predicates, context->fetchColumn);
    if (resultSet != nullptr) {
        // Create FetchResult object using the contents of resultSet
        context->fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
        context->fetchFileResult->SetNetworkId(context->networkId);
        if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
            context->fetchFileResult->resultNapiType_ = context->resultNapiType;
        }
        return;
    } else {
        context->SaveError(resultSet);
        NAPI_ERR_LOG("Query for get fileAssets failed");
    }
}

static void GetNapiFileResult(napi_env env, MediaLibraryAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    // Create FetchResult object using the contents of resultSet
    if (context->fetchFileResult == nullptr) {
        NAPI_ERR_LOG("No fetch file result found!");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain Fetch File Result");
        return;
    }
    if (context->fetchFileResult->GetCount() < 0) {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                                                     "find no data by options");
        return;
    }
    napi_value fileResult = FetchFileResultNapi::CreateFetchFileResult(env, move(context->fetchFileResult));
    if (fileResult == nullptr) {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to create js object for Fetch File Result");
    } else {
        jsContext->data = fileResult;
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
    }
}

static void GetFileAssetsAsyncCallbackComplete(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetFileAssetsAsyncCallbackComplete");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);

    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, jsContext->error);
    } else {
        GetNapiFileResult(env, context, jsContext);
    }

    tracer.Finish();
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetFileAssets");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);

    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    asyncContext->mediaTypes.clear();
    asyncContext->resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetFileAssets", GetFileAssetsExecute,
            GetFileAssetsAsyncCallbackComplete);
    }

    return result;
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

static void SetAlbumCoverUri(MediaLibraryAsyncContext *context, unique_ptr<AlbumAsset> &album)
{
    MediaLibraryTracer tracer;
    tracer.Start("SetAlbumCoverUri");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MEDIA_DATA_DB_BUCKET_ID + " = ? ");
    predicates.SetWhereArgs({ std::to_string(album->GetAlbumId()) });
    predicates.SetOrder(MEDIA_DATA_DB_DATE_ADDED + " DESC");
    vector<string> columns;
    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
        NAPI_DEBUG_LOG("querycoverUri is = %{public}s", queryUri.c_str());
    }
    Uri uri(queryUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(
        uri, predicates, columns);
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    fetchFileResult->SetNetworkId(context->networkId);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    CHECK_NULL_PTR_RETURN_VOID(fileAsset, "SetAlbumCoverUr:FileAsset is nullptr");
    string coverUri = fileAsset->GetUri();
    album->SetCoverUri(coverUri);
    NAPI_DEBUG_LOG("coverUri is = %{public}s", album->GetCoverUri().c_str());
}

void SetAlbumData(AlbumAsset* albumData, shared_ptr<DataShare::DataShareResultSet> resultSet,
    const string &networkId)
{
    // Get album id index and value
    albumData->SetAlbumId(get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_BUCKET_ID, resultSet,
        TYPE_INT32)));

    // Get album title index and value
    albumData->SetAlbumName(get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_TITLE, resultSet,
        TYPE_STRING)));

    // Get album asset count index and value
    albumData->SetCount(get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_COUNT, resultSet, TYPE_INT32)));
    albumData->SetAlbumUri(GetFileMediaTypeUri(MEDIA_TYPE_ALBUM, networkId) +
        "/" + to_string(albumData->GetAlbumId()));
    // Get album relativePath index and value
    albumData->SetAlbumRelativePath(get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH,
        resultSet, TYPE_STRING)));
    albumData->SetAlbumDateModified(get<int64_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_DATE_MODIFIED,
        resultSet, TYPE_INT64)));
}

static void GetAlbumResult(MediaLibraryAsyncContext *context, shared_ptr<DataShareResultSet> resultSet)
{
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        context->fetchAlbumResult = make_unique<FetchResult<AlbumAsset>>(move(resultSet));
        context->fetchAlbumResult->SetNetworkId(context->networkId);
        context->fetchAlbumResult->resultNapiType_ = context->resultNapiType;
        context->fetchAlbumResult->typeMask_ = context->typeMask;
        return;
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<AlbumAsset> albumData = make_unique<AlbumAsset>();
        if (albumData != nullptr) {
            SetAlbumData(albumData.get(), resultSet, context->networkId);
            SetAlbumCoverUri(context, albumData);
            albumData->SetAlbumTypeMask(context->typeMask);
            context->albumNativeArray.push_back(move(albumData));
        } else {
            context->SaveError(E_NO_MEMORY);
        }
    }
}

static void GetResultDataExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetResultDataExecute");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    MediaLibraryNapiUtils::UpdateMediaTypeSelections(context);
    context->predicates.SetWhereClause(context->selection);
    context->predicates.SetWhereArgs(context->selectionArgs);
    if (!context->order.empty()) {
        context->predicates.SetOrder(context->order);
    }

    vector<string> columns;
    string queryUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId +
            MEDIALIBRARY_DATA_URI_IDENTIFIER + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;
        NAPI_DEBUG_LOG("queryAlbumUri is = %{public}s", queryUri.c_str());
    }
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(queryUri, context->typeMask);
    Uri uri(queryUri);
    shared_ptr<DataShareResultSet> resultSet = UserFileClient::Query(uri, context->predicates, columns);

    if (resultSet == nullptr) {
        NAPI_ERR_LOG("GetMediaResultData resultSet is nullptr");
        context->SaveError(resultSet);
        return;
    }

    GetAlbumResult(context, resultSet);
}

static void MediaLibAlbumsAsyncResult(napi_env env, MediaLibraryAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    if (context->albumNativeArray.empty()) {
        napi_value albumNoArray = nullptr;
        napi_create_array(env, &albumNoArray);
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
        jsContext->data = albumNoArray;
    } else {
        napi_value albumArray = nullptr;
        napi_create_array_with_length(env, context->albumNativeArray.size(), &albumArray);
        for (size_t i = 0; i < context->albumNativeArray.size(); i++) {
            napi_value albumNapiObj = AlbumNapi::CreateAlbumNapi(env, context->albumNativeArray[i]);
            napi_set_element(env, albumArray, i, albumNapiObj);
        }
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
        jsContext->data = albumArray;
    }
}

static void UserFileMgrAlbumsAsyncResult(napi_env env, MediaLibraryAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    if (context->fetchAlbumResult->GetCount() < 0) {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
            "find no data by options");
    } else {
        napi_value fileResult = FetchFileResultNapi::CreateFetchFileResult(env, move(context->fetchAlbumResult));
        if (fileResult == nullptr) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Failed to create js object for Fetch Album Result");
        } else {
            jsContext->data = fileResult;
            jsContext->status = true;
            napi_get_undefined(env, &jsContext->error);
        }
    }
}

static void AlbumsAsyncResult(napi_env env, MediaLibraryAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    if (context->resultNapiType == ResultNapiType::TYPE_MEDIALIBRARY) {
        MediaLibAlbumsAsyncResult(env, context, jsContext);
    } else {
        UserFileMgrAlbumsAsyncResult(env, context, jsContext);
    }
}

static void AlbumsAsyncCallbackComplete(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("AlbumsAsyncCallbackComplete");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->error);
    if (context->error != ERR_DEFAULT) {
        napi_get_undefined(env, &jsContext->data);
        context->HandleError(env, jsContext->error);
    } else {
        AlbumsAsyncResult(env, context, jsContext);
    }

    tracer.Finish();
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetAlbums");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);

    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetAlbums", GetResultDataExecute,
            AlbumsAsyncCallbackComplete);
    }

    return result;
}

static void getFileAssetById(int32_t id, const string &networkId, MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    vector<string> columns;
    DataShare::DataSharePredicates predicates;

    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({ std::to_string(id) });

    string queryUri = MEDIALIBRARY_DATA_URI;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(queryUri, context->typeMask);
    Uri uri(queryUri);

    auto resultSet = UserFileClient::Query(uri, predicates, columns);
    CHECK_NULL_PTR_RETURN_VOID(resultSet, "Failed to get file asset by id, query resultSet is nullptr");

    // Create FetchResult object using the contents of resultSet
    context->fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    CHECK_NULL_PTR_RETURN_VOID(context->fetchFileResult, "Failed to get file asset by id, fetchFileResult is nullptr");
    context->fetchFileResult->SetNetworkId(networkId);
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        context->fetchFileResult->resultNapiType_ = context->resultNapiType;
    }
    if (context->fetchFileResult->GetCount() < 1) {
        NAPI_ERR_LOG("Failed to query file by id: %{public}d, query count is 0", id);
        return;
    }
    unique_ptr<FileAsset> fileAsset = context->fetchFileResult->GetFirstObject();
    CHECK_NULL_PTR_RETURN_VOID(fileAsset, "getFileAssetById: fileAsset is nullptr");
    context->fileAsset = std::move(fileAsset);
}

static void JSCreateAssetCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCreateAssetCompleteCallback");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
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
            jsFileAsset = FileAssetNapi::CreateFileAsset(env, context->fileAsset);
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
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
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
    bool isValid = false;
    string title = context->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
    if (!isValid) {
        NAPI_ERR_LOG("getting title is invalid");
        return false;
    }
    if (title.empty()) {
        return false;
    }
    return true;
}

static string GetFirstDirName(const string &relativePath)
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

static bool IsDirectory(const string &dirName)
{
    struct stat statInfo {};
    if (stat((ROOT_MEDIA_DIR + dirName).c_str(), &statInfo) == SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return true;
        }
    }

    return false;
}

static bool CheckTypeOfType(const std::string &firstDirName, int32_t fileMediaType)
{
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
    return true;
}
static bool CheckRelativePathPrams(MediaLibraryAsyncContext *context)
{
    if (context == nullptr) {
        NAPI_ERR_LOG("Async context is null");
        return false;
    }
    bool isValid = false;
    string relativePath = context->valuesBucket.Get(MEDIA_DATA_DB_RELATIVE_PATH, isValid);
    if (!isValid) {
        NAPI_DEBUG_LOG("getting relativePath is invalid");
        return false;
    }
    isValid = false;
    int32_t fileMediaType = context->valuesBucket.Get(MEDIA_DATA_DB_MEDIA_TYPE, isValid);
    if (!isValid) {
        NAPI_DEBUG_LOG("getting fileMediaType is invalid");
        return false;
    }
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
            NAPI_DEBUG_LOG("directoryEnumValues%{public}d = %{public}s", i, directoryEnumValues[i].c_str());
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
            NAPI_DEBUG_LOG("type mismatch, valueType: %{public}d", valueType);
            return result;
    }
    }

    context->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileMediaType);
    context->valuesBucket.Put(MEDIA_DATA_DB_NAME, string(titleBuffer));
    context->valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, string(relativePathBuffer));
    NAPI_DEBUG_LOG("GetJSArgsForCreateAsset END");
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

static void JSCreateAssetExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCreateAssetExecute");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    if (!CheckTitlePrams(context)) {
        context->error = JS_E_DISPLAYNAME;
        return;
    }
    if ((context->resultNapiType != ResultNapiType::TYPE_USERFILE_MGR) && (!CheckRelativePathPrams(context))) {
        context->error = JS_E_RELATIVEPATH;
        return;
    }
    string uri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(uri, context->typeMask);
    Uri createFileUri(uri);
    int index = UserFileClient::Insert(createFileUri, context->valuesBucket);
    if (index < 0) {
        context->SaveError(index);
    } else {
        getFileAssetById(index, "", context);
    }
}

napi_value MediaLibraryNapi::JSCreateAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_FOUR;
    napi_value argv[ARGS_FOUR] = {0};
    napi_value thisVar = nullptr;

    MediaLibraryTracer tracer;
    tracer.Start("JSCreateAsset");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_THREE || argc == ARGS_FOUR), "requires 4 parameters maximum");
    napi_get_undefined(env, &result);

    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    asyncContext->resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCreateAsset(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSCreateAsset", JSCreateAssetExecute,
            JSCreateAssetCompleteCallback);
    }

    return result;
}

static void JSDeleteAssetExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteAssetExecute");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    string mediaType;
    string deleteId;
    bool isValid = false;
    string notifyUri = context->valuesBucket.Get(MEDIA_DATA_DB_URI, isValid);
    if (!isValid) {
        context->error = ERR_INVALID_OUTPUT;
        return;
    }
    size_t index = notifyUri.rfind('/');
    if (index != string::npos) {
        deleteId = notifyUri.substr(index + 1);
        notifyUri = notifyUri.substr(0, index);
        size_t indexType = notifyUri.rfind('/');
        if (indexType != string::npos) {
            mediaType = notifyUri.substr(indexType + 1);
        }
    }
    notifyUri = MEDIALIBRARY_DATA_URI + "/" + mediaType;
    NAPI_DEBUG_LOG("JSDeleteAssetExcute notifyUri = %{public}s", notifyUri.c_str());
    string deleteUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET + "/" + deleteId;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(deleteUri, context->typeMask);
    Uri deleteAssetUri(deleteUri);
    int retVal = UserFileClient::Delete(deleteAssetUri, {});
    if (retVal < 0) {
        context->SaveError(retVal);
    } else {
        context->retVal = retVal;
        Uri deleteNotify(notifyUri);
        UserFileClient::NotifyChange(deleteNotify);
    }
}

static void JSDeleteAssetCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteAssetCompleteCallback");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        NAPI_DEBUG_LOG("Delete result = %{public}d", context->retVal);
        napi_create_int32(env, context->retVal, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }

    delete context;
}

static void JSTrashAssetExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSTrashAssetExecute");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    string uri = context->uri;
    if (uri.empty()) {
        context->error = ERR_INVALID_OUTPUT;
        return;
    }
    MediaLibraryNapiUtils::UriRemoveAllFragment(uri);
    string trashId = MediaLibraryDataManagerUtils::GetIdFromUri(uri);

    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, stoi(trashId));
    string trashUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/" +
        MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(trashUri, context->typeMask);
    Uri trashAssetUri(trashUri);
    int retVal = UserFileClient::Insert(trashAssetUri, valuesBucket);
    context->SaveError(retVal);
}

static void JSTrashAssetCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSTrashAssetCompleteCallback");

    MediaLibraryAsyncContext *context = static_cast<MediaLibraryAsyncContext*>(data);
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

    context->valuesBucket.Put(MEDIA_DATA_DB_URI, string(buffer));

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

    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteAsset");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);

    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForDeleteAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSDeleteAsset", JSDeleteAssetExecute,
            JSDeleteAssetCompleteCallback);
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
                    NAPI_ERR_LOG("Create reference fail, status: %{public}d", status);
                    break;
                }
                napi_value retVal = nullptr;
                napi_call_function(env, nullptr, jsCallback, ARGS_TWO, result, &retVal);
                if (status != napi_ok) {
                    NAPI_ERR_LOG("CallJs napi_call_function fail, status: %{public}d", status);
                    break;
                }
            } while (0);
            delete msg;
            delete w;
    });
    if (ret != 0) {
        NAPI_ERR_LOG("Failed to execute libuv work queue, ret: %{public}d", ret);
        delete msg;
        delete work;
    }
}

int32_t MediaLibraryNapi::GetListenerType(const std::string &str) const
{
    auto iter = ListenerTypeMaps.find(str);
    if (iter == ListenerTypeMaps.end()) {
        NAPI_ERR_LOG("Invalid Listener Type %{public}s", str.c_str());
        return INVALID_LISTENER;
    }

    return iter->second;
}

void MediaLibraryNapi::RegisterChange(napi_env env, const std::string &type, ChangeListenerNapi &listObj)
{
    NAPI_DEBUG_LOG("Register change type = %{public}s", type.c_str());

    int32_t typeEnum = GetListenerType(type);
    switch (typeEnum) {
        case AUDIO_LISTENER:
            listObj.audioDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_AUDIO);
            UserFileClient::RegisterObserver(Uri(MEDIALIBRARY_AUDIO_URI), listObj.audioDataObserver_);
            break;
        case VIDEO_LISTENER:
            listObj.videoDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_VIDEO);
            UserFileClient::RegisterObserver(Uri(MEDIALIBRARY_VIDEO_URI), listObj.videoDataObserver_);
            break;
        case IMAGE_LISTENER:
            listObj.imageDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_IMAGE);
            UserFileClient::RegisterObserver(Uri(MEDIALIBRARY_IMAGE_URI), listObj.imageDataObserver_);
            break;
        case FILE_LISTENER:
            listObj.fileDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_FILE);
            UserFileClient::RegisterObserver(Uri(MEDIALIBRARY_FILE_URI), listObj.fileDataObserver_);
            break;
        case SMARTALBUM_LISTENER:
            listObj.smartAlbumDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_SMARTALBUM);
            UserFileClient::RegisterObserver(Uri(MEDIALIBRARY_SMARTALBUM_CHANGE_URI),
                listObj.smartAlbumDataObserver_);
            break;
        case DEVICE_LISTENER:
            listObj.deviceDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_DEVICE);
            UserFileClient::RegisterObserver(Uri(MEDIALIBRARY_DEVICE_URI), listObj.deviceDataObserver_);
            break;
        case REMOTEFILE_LISTENER:
            listObj.remoteFileDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_REMOTEFILE);
            UserFileClient::RegisterObserver(Uri(MEDIALIBRARY_REMOTEFILE_URI), listObj.remoteFileDataObserver_);
            break;
        case ALBUM_LISTENER:
            listObj.albumDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_ALBUM);
            UserFileClient::RegisterObserver(Uri(MEDIALIBRARY_ALBUM_URI), listObj.albumDataObserver_);
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
    char buffer[ARG_BUF_SIZE];
    string type;
    const int32_t refCount = 1;
    MediaLibraryNapi *obj = nullptr;
    napi_status status;

    MediaLibraryTracer tracer;
    tracer.Start("JSOnCallback");

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

        if (napi_get_value_string_utf8(env, argv[PARAM0], buffer, ARG_BUF_SIZE, &res) != napi_ok) {
            NAPI_ERR_LOG("Failed to get value string utf8 for type");
            return undefinedResult;
        }
        type = string(buffer);

        napi_create_reference(env, argv[PARAM1], refCount, &g_listObj->cbOnRef_);

        tracer.Start("RegisterChange");
        obj->RegisterChange(env, type, *g_listObj);
        tracer.Finish();
    }

    return undefinedResult;
}

void MediaLibraryNapi::UnregisterChange(napi_env env, const string &type, ChangeListenerNapi &listObj)
{
    NAPI_DEBUG_LOG("Unregister change type = %{public}s", type.c_str());

    MediaType mediaType;
    int32_t typeEnum = GetListenerType(type);

    switch (typeEnum) {
        case AUDIO_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.audioDataObserver_, "Failed to obtain audio data observer");
            mediaType = MEDIA_TYPE_AUDIO;
            UserFileClient::UnregisterObserver(Uri(MEDIALIBRARY_AUDIO_URI), listObj.audioDataObserver_);
            listObj.audioDataObserver_ = nullptr;
            break;
        case VIDEO_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.videoDataObserver_, "Failed to obtain video data observer");
            mediaType = MEDIA_TYPE_VIDEO;
            UserFileClient::UnregisterObserver(Uri(MEDIALIBRARY_VIDEO_URI), listObj.videoDataObserver_);
            listObj.videoDataObserver_ = nullptr;
            break;
        case IMAGE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.imageDataObserver_, "Failed to obtain image data observer");
            mediaType = MEDIA_TYPE_IMAGE;
            UserFileClient::UnregisterObserver(Uri(MEDIALIBRARY_IMAGE_URI), listObj.imageDataObserver_);
            listObj.imageDataObserver_ = nullptr;
            break;
        case FILE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.fileDataObserver_, "Failed to obtain file data observer");
            mediaType = MEDIA_TYPE_FILE;
            UserFileClient::UnregisterObserver(Uri(MEDIALIBRARY_FILE_URI), listObj.fileDataObserver_);
            listObj.fileDataObserver_ = nullptr;
            break;
        case SMARTALBUM_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.smartAlbumDataObserver_, "Failed to obtain smart album data observer");
            mediaType = MEDIA_TYPE_SMARTALBUM;
            UserFileClient::UnregisterObserver(Uri(MEDIALIBRARY_SMARTALBUM_CHANGE_URI),
                listObj.smartAlbumDataObserver_);
            listObj.smartAlbumDataObserver_ = nullptr;
            break;
        case DEVICE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.deviceDataObserver_, "Failed to obtain device data observer");
            mediaType = MEDIA_TYPE_DEVICE;
            UserFileClient::UnregisterObserver(Uri(MEDIALIBRARY_DEVICE_URI), listObj.deviceDataObserver_);
            listObj.deviceDataObserver_ = nullptr;
            break;
        case REMOTEFILE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.remoteFileDataObserver_, "Failed to obtain remote file data observer");
            mediaType = MEDIA_TYPE_REMOTEFILE;
            UserFileClient::UnregisterObserver(Uri(MEDIALIBRARY_REMOTEFILE_URI), listObj.remoteFileDataObserver_);
            listObj.remoteFileDataObserver_ = nullptr;
            break;
        case ALBUM_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.albumDataObserver_, "Failed to obtain album data observer");
            mediaType = MEDIA_TYPE_ALBUM;
            UserFileClient::UnregisterObserver(Uri(MEDIALIBRARY_ALBUM_URI), listObj.albumDataObserver_);
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
    char buffer[ARG_BUF_SIZE];
    const int32_t refCount = 1;
    string type;
    MediaLibraryNapi *obj = nullptr;
    napi_status status;

    MediaLibraryTracer tracer;
    tracer.Start("JSOffCallback");

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

        if (napi_get_value_string_utf8(env, argv[PARAM0], buffer, ARG_BUF_SIZE, &res) != napi_ok) {
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

        tracer.Start("UnregisterChange");
        obj->UnregisterChange(env, type, *g_listObj);
        tracer.Finish();
    }

    return undefinedResult;
}

static void JSReleaseCompleteCallback(napi_env env, napi_status status,
                                      MediaLibraryAsyncContext *context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSReleaseCompleteCallback");

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
            "UserFileClient is invalid");
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
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

    MediaLibraryTracer tracer;
    tracer.Start("JSRelease");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ERR_LOG("NAPI_ASSERT begin %{public}zu", argc);
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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSRelease", asyncContext);

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

static void SetSmartAlbumCoverUri(MediaLibraryAsyncContext *context, unique_ptr<SmartAlbumAsset> &smartAlbum)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (smartAlbum->GetAlbumCapacity() == 0) {
        return;
    }
    DataShare::DataSharePredicates predicates;
    string trashPrefix;
    if (smartAlbum->GetAlbumId() == TRASH_ALBUM_ID_VALUES) {
        trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " <> ? AND " + SMARTALBUMMAP_DB_ALBUM_ID + " = ? ";
    } else {
        trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? AND " + SMARTALBUMMAP_DB_ALBUM_ID + " = ? ";
    }
    MediaLibraryNapiUtils::AppendFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.emplace_back("0");
    context->selectionArgs.emplace_back(std::to_string(smartAlbum->GetAlbumId()));
    predicates.SetOrder(SMARTALBUMMAP_DB_ID + " DESC");
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    std::vector<std::string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/"
               + MEDIA_ALBUMOPRN_QUERYALBUM + "/"
               + ASSETMAP_VIEW_NAME);

    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri, predicates, columns);
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    CHECK_NULL_PTR_RETURN_VOID(fileAsset, "SetSmartAlbumCoverUri fileAsset is nullptr");
    string coverUri = fileAsset->GetUri();
    smartAlbum->SetCoverUri(coverUri);
    NAPI_DEBUG_LOG("coverUri is = %{private}s", smartAlbum->GetCoverUri().c_str());
}

static void SetSmartAlbumData(SmartAlbumAsset* smartAlbumData, shared_ptr<DataShare::DataShareResultSet> resultSet,
    MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(smartAlbumData, "albumData is null");
    smartAlbumData->SetAlbumId(get<int32_t>(ResultSetUtils::GetValFromColumn(SMARTALBUM_DB_ID, resultSet, TYPE_INT32)));
    smartAlbumData->SetAlbumName(get<string>(ResultSetUtils::GetValFromColumn(SMARTALBUM_DB_NAME, resultSet,
        TYPE_STRING)));
    smartAlbumData->SetAlbumCapacity(get<int32_t>(ResultSetUtils::GetValFromColumn(SMARTALBUM_DB_CAPACITY,
        resultSet, TYPE_INT32)));
    smartAlbumData->SetAlbumUri(GetFileMediaTypeUri(MEDIA_TYPE_SMARTALBUM, context->networkId) +
        "/" + to_string(smartAlbumData->GetAlbumId()));
    smartAlbumData->SetTypeMask(context->typeMask);
}

static void GetAllSmartAlbumResultDataExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetResultDataExecute");

    auto context = static_cast<MediaLibraryAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    NAPI_INFO_LOG("context->privateAlbumType = %{public}d", context->privateAlbumType);

    if (context->privateAlbumType == TYPE_TRASH) {
        context->predicates.SetWhereClause(SMARTALBUM_DB_ID + " = " + to_string(TRASH_ALBUM_ID_VALUES));
        NAPI_INFO_LOG("context->privateAlbumType == TYPE_TRASH");
    }
    if (context->privateAlbumType == TYPE_FAVORITE) {
        context->predicates.SetWhereClause(SMARTALBUM_DB_ID + " = " + to_string(FAVOURITE_ALBUM_ID_VALUES));
        NAPI_INFO_LOG("context->privateAlbumType == TYPE_FAVORITE");
    }

    vector<string> columns;
    string uriStr = MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM + "/" + SMARTALBUM_TABLE;
    if (!context->networkId.empty()) {
        uriStr = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER +
            "/" + MEDIA_ALBUMOPRN_QUERYALBUM + "/" + SMARTALBUM_TABLE;
    }
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(uriStr, context->typeMask);
    Uri uri(uriStr);
    auto resultSet = UserFileClient::Query(uri, context->predicates, columns);
    if (resultSet == nullptr) {
        NAPI_ERR_LOG("resultSet == nullptr");
        return;
    }

    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        context->fetchSmartAlbumResult = make_unique<FetchResult<SmartAlbumAsset>>(move(resultSet));
        context->fetchSmartAlbumResult->SetNetworkId(context->networkId);
        context->fetchSmartAlbumResult->resultNapiType_ = context->resultNapiType;
        context->fetchSmartAlbumResult->typeMask_ = context->typeMask;
        return;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<SmartAlbumAsset> albumData = make_unique<SmartAlbumAsset>();
        SetSmartAlbumData(albumData.get(), resultSet, context);
        SetSmartAlbumCoverUri(context, albumData);

        context->privateSmartAlbumNativeArray.push_back(move(albumData));
    }
}

static void MediaLibSmartAlbumsAsyncResult(napi_env env, MediaLibraryAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    if (context->smartAlbumData != nullptr) {
        NAPI_ERR_LOG("context->smartAlbumData != nullptr");
        jsContext->status = true;
        napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env, context->smartAlbumData);
        napi_get_undefined(env, &jsContext->error);
        jsContext->data = albumNapiObj;
    } else if (!context->privateSmartAlbumNativeArray.empty()) {
        NAPI_ERR_LOG("context->privateSmartAlbumNativeArray.empty()");
        jsContext->status = true;
        napi_value albumArray = nullptr;
        napi_create_array(env, &albumArray);
        for (size_t i = 0; i < context->privateSmartAlbumNativeArray.size(); i++) {
            napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env,
                context->privateSmartAlbumNativeArray[i]);
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

static void UserFileMgrSmartAlbumsAsyncResult(napi_env env, MediaLibraryAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    if (context->fetchSmartAlbumResult->GetCount() < 0) {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
            "find no data by options");
    } else {
        napi_value fileResult = FetchFileResultNapi::CreateFetchFileResult(env, move(context->fetchSmartAlbumResult));
        if (fileResult == nullptr) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Failed to create js object for Fetch SmartAlbum Result");
        } else {
            jsContext->data = fileResult;
            jsContext->status = true;
            napi_get_undefined(env, &jsContext->error);
        }
    }
}

static void SmartAlbumsAsyncResult(napi_env env, MediaLibraryAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    if (context->resultNapiType == ResultNapiType::TYPE_MEDIALIBRARY) {
        MediaLibSmartAlbumsAsyncResult(env, context, jsContext);
    } else {
        UserFileMgrSmartAlbumsAsyncResult(env, context, jsContext);
    }
}

static void GetPrivateAlbumCallbackComplete(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetPrivateAlbumCallbackComplete");

    auto context = static_cast<MediaLibraryAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->error);
    if (context->error != ERR_DEFAULT) {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Query for get fileAssets failed");
    } else {
        SmartAlbumsAsyncResult(env, context, jsContext);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static void SmartAlbumsAsyncCallbackComplete(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<MediaLibraryAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->error);
    if (context->error != ERR_DEFAULT) {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Query for get smartAlbums failed");
    } else {
        if (!context->smartAlbumNativeArray.empty()) {
            jsContext->status = true;
            napi_value albumArray = nullptr;
            napi_create_array(env, &albumArray);
            for (size_t i = 0; i < context->smartAlbumNativeArray.size(); i++) {
                napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env,
                    context->smartAlbumNativeArray[i]);
                napi_set_element(env, albumArray, i, albumNapiObj);
            }
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumArray;
        } else {
            NAPI_ERR_LOG("No SmartAlbums result found!");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Failed to obtain SmartAlbums Result");
        }
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSGetSmartAlbums(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "Async context is null");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetSmartAlbums",
            GetAllSmartAlbumResultDataExecute, SmartAlbumsAsyncCallbackComplete);
    }

    return result;
}

napi_value MediaLibraryNapi::JSGetPrivateAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
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
        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetPrivateAlbum",
            GetAllSmartAlbumResultDataExecute, GetPrivateAlbumCallbackComplete);
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
    context->valuesBucket.Put(SMARTALBUM_DB_NAME, string(buffer));
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
            napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env, context->smartAlbumNativeArray[0]);
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
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCreateSmartAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCreateSmartAlbum", asyncContext);
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void *data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                string abilityUri = MEDIALIBRARY_DATA_URI;
                Uri CreateSmartAlbumUri(abilityUri + "/" + MEDIA_SMARTALBUMOPRN + "/" +
                    MEDIA_SMARTALBUMOPRN_CREATEALBUM);
                int retVal = UserFileClient::Insert(CreateSmartAlbumUri, context->valuesBucket);
                if (retVal > 0) {
                    context->selection = SMARTALBUM_DB_ID + " = ?";
                    context->selectionArgs = {std::to_string(retVal)};
                    context->retVal = retVal;
                } else {
                    context->error = retVal;
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
    context->valuesBucket.Put(SMARTALBUM_DB_ID, std::stoi(strRow));
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
            "UserFileClient is invalid");
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
    bool isValid = false;
    int32_t smartAlbumId = context->valuesBucket.Get(SMARTALBUM_DB_ID, isValid);
    if (!isValid) {
        context->error = ERR_INVALID_OUTPUT;
        return;
    }
    string abilityUri = MEDIALIBRARY_DATA_URI;
    Uri DeleteSmartAlbumUri(abilityUri + "/" + MEDIA_SMARTALBUMOPRN + "/" +
        MEDIA_SMARTALBUMOPRN_DELETEALBUM + '/' + to_string(smartAlbumId));
    DataSharePredicates predicates;
    int retVal = UserFileClient::Delete(DeleteSmartAlbumUri, predicates);
    NAPI_DEBUG_LOG("JSDeleteSmartAlbumCompleteCallback retVal = %{public}d", retVal);
    if (retVal < 0) {
        context->error = retVal;
    } else {
        context->retVal = retVal;
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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteSmartAlbum", asyncContext);
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
        NAPI_ERR_LOG("Set value create utf8 string error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set utf8 string named property error! field: %{public}s", fieldStr);
    }
    return status;
}

static napi_status SetValueInt32(const napi_env& env, const char* fieldStr, const int intValue, napi_value& result)
{
    napi_value value;
    napi_status status = napi_create_int32(env, intValue, &value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set value create int32 error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set int32 named property error! field: %{public}s", fieldStr);
    }
    return status;
}

static napi_status SetValueBool(const napi_env& env, const char* fieldStr, const bool boolvalue, napi_value& result)
{
    napi_value value = nullptr;
    napi_status status = napi_get_boolean(env, boolvalue, &value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set value create boolean error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Set boolean named property error! field: %{public}s", fieldStr);
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
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(
        uri, predicates, columns);

    if (resultSet == nullptr) {
        NAPI_ERR_LOG("JSGetActivePeers resultSet is null");
        delete context;
        return;
    }

    vector<unique_ptr<PeerInfo>> peerInfoArray;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<PeerInfo> peerInfo = make_unique<PeerInfo>();
        if (peerInfo != nullptr) {
            peerInfo->deviceName = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NAME, resultSet,
                TYPE_STRING));
            peerInfo->networkId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NETWORK_ID, resultSet,
                TYPE_STRING));
            peerInfo->deviceTypeId = (DistributedHardware::DmDeviceType)
                (get<int32_t>(ResultSetUtils::GetValFromColumn(DEVICE_DB_TYPE, resultSet, TYPE_INT32)));
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
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(
        uri, predicates, columns);

    if (resultSet == nullptr) {
        NAPI_ERR_LOG("JSGetAllPeers resultSet is null");
        delete context;
        return;
    }

    vector<unique_ptr<PeerInfo>> peerInfoArray;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<PeerInfo> peerInfo = make_unique<PeerInfo>();
        if (peerInfo != nullptr) {
            peerInfo->deviceName = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NAME, resultSet,
                TYPE_STRING));
            peerInfo->networkId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NETWORK_ID, resultSet,
                TYPE_STRING));
            peerInfo->deviceTypeId = (DistributedHardware::DmDeviceType)
                (get<int32_t>(ResultSetUtils::GetValFromColumn(DEVICE_DB_TYPE, resultSet, TYPE_INT32)));
            peerInfo->isOnline = (get<int32_t>(ResultSetUtils::GetValFromColumn(DEVICE_DB_DATE_MODIFIED, resultSet,
                TYPE_INT32)) == 0);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetActivePeers");

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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetActivePeers", asyncContext);
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

    MediaLibraryTracer tracer;
    tracer.Start("JSGetAllPeers");

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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAllPeers", asyncContext);
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
    context->valuesBucket.Put(MEDIA_DATA_DB_URI, uri);
    int32_t ret = UserFileClient::Insert(closeAssetUri, context->valuesBucket);
    NAPI_DEBUG_LOG("File close asset %{public}d", ret);
    if (ret != E_SUCCESS) {
        context->error = ret;
        NAPI_ERR_LOG("File close asset fail, %{public}d", ret);
    }
    return ret;
}

static void JSGetStoreMediaAssetExecute(MediaLibraryAsyncContext *context)
{
    string realPath;
    if (!PathToRealPath(context->storeMediaSrc, realPath)) {
        NAPI_ERR_LOG("src path is not exist, %{public}d", errno);
        context->error = JS_ERR_NO_SUCH_FILE;
        return;
    }
    context->error = JS_E_RELATIVEPATH;
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
    int index = UserFileClient::Insert(createFileUri, context->valuesBucket);
    if (index < 0) {
        close(srcFd);
        NAPI_ERR_LOG("storeMedia fail, file already exist %{public}d", index);
        return;
    }
    getFileAssetById(index, "", context);
    Uri openFileUri(context->fileAsset->GetUri());
    int32_t destFd = UserFileClient::OpenFile(openFileUri, MEDIA_FILEMODE_READWRITE);
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
        context->error = JS_E_RELATIVEPATH;
        return nullptr;
    };
    context->valuesBucket.Put(MEDIA_DATA_DB_NAME, fileName);
    string mimeType;
    if (!GetStoreMediaAssetProper(env, param, "mimeType", mimeType)) {
        NAPI_ERR_LOG("param get fail");
        return nullptr;
    }
    auto mediaType = ConvertMediaType(mimeType);
    context->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    string relativePath;
    if (!GetStoreMediaAssetProper(env, param, "relativePath", relativePath)) {
        NAPI_DEBUG_LOG("optional relativePath param empty");
        relativePath = GetDefaultDirectory(mediaType);
    }
    context->valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    NAPI_DEBUG_LOG("src:%{public}s mime:%{public}s relp:%{private}s filename:%{private}s",
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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSStoreMediaAsset", asyncContext);
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
    NAPI_DEBUG_LOG("GetImagePreviewArgs res %{public}s", context.uri.c_str());
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
    string networkId = "";
    string bundleName = "com.ohos.photos";
    string abilityName = "com.ohos.photos.MainAbility";
    want.SetElementName(networkId, bundleName, abilityName);
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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSStartImagePreview", asyncContext);
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

static napi_value ParseArgsCreateAsset(napi_env env, napi_callback_info info,
    unique_ptr<MediaLibraryAsyncContext> &context)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_THREE;
    NAPI_ASSERT(env, MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs) ==
        napi_ok, "Failed to get object info");

    /* Set mediaTypes to get typeMask */
    vector<uint32_t> mediaTypes;
    mediaTypes.push_back(MEDIA_TYPE_IMAGE);
    mediaTypes.push_back(MEDIA_TYPE_VIDEO);
    MediaLibraryNapiUtils::GenTypeMaskFromArray(mediaTypes, context->typeMask);

    /* Parse the first argument into displayName */
    string displayName;
    NAPI_ASSERT(env, MediaLibraryNapiUtils::GetParamStringPathMax(env, context->argv[ARGS_ZERO], displayName) ==
        napi_ok, "Failed to get displayName");
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);

    /* Parse the second argument into albumUri if exists */
    string albumUri;
    if ((context->argc >= ARGS_TWO) &&
        (MediaLibraryNapiUtils::GetParamStringPathMax(env, context->argv[ARGS_ONE], albumUri) == napi_ok)) {
        context->valuesBucket.Put(MEDIA_DATA_DB_URI, albumUri);
    }

    context->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));
    context->valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        vector<uint32_t> types = { mediaType };
        MediaLibraryNapiUtils::GenTypeMaskFromArray(types, context->typeMask);
    }

    NAPI_ASSERT(env, MediaLibraryNapiUtils::GetParamCallback(env, context) == napi_ok, "Failed to get callback");

    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, true, &result));
    return result;
}

void AddDefaultFetchColumn(unique_ptr<MediaLibraryAsyncContext> &asyncContext)
{
    if (asyncContext->fetchColumn.size() == 0) {
        return;
    }
    asyncContext->fetchColumn.push_back(MEDIA_DATA_DB_ID);
    asyncContext->fetchColumn.push_back(MEDIA_DATA_DB_NAME);
    asyncContext->fetchColumn.push_back(MEDIA_DATA_DB_MEDIA_TYPE);
}

napi_value UserFileMgrGetFileAssets(napi_env env, napi_callback_info info, vector<uint32_t> &mediaTypes)
{
    napi_value ret = nullptr;
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");

    // Parse the first argument into typeMask
    asyncContext->mediaTypes = mediaTypes;
    MediaLibraryNapiUtils::GenTypeMaskFromArray(mediaTypes, asyncContext->typeMask);

    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseAssetFetchOptCallback(env, info, asyncContext), asyncContext,
        JS_ERR_PARAMETER_INVALID);
    AddDefaultFetchColumn(asyncContext);
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UFMJSGetTypeAssets", GetFileAssetsExecute,
        GetFileAssetsAsyncCallbackComplete);
}

napi_value MediaLibraryNapi::UserFileMgrGetPhotoAssets(napi_env env, napi_callback_info info)
{
    vector<uint32_t> mediaTypes;
    mediaTypes.push_back(MEDIA_TYPE_IMAGE);
    mediaTypes.push_back(MEDIA_TYPE_VIDEO);
    return UserFileMgrGetFileAssets(env, info, mediaTypes);
}

napi_value MediaLibraryNapi::UserFileMgrGetAudioAssets(napi_env env, napi_callback_info info)
{
    vector<uint32_t> mediaTypes;
    mediaTypes.push_back(MEDIA_TYPE_AUDIO);
    return UserFileMgrGetFileAssets(env, info, mediaTypes);
}

napi_value MediaLibraryNapi::UserFileMgrGetAlbums(napi_env env, napi_callback_info info)
{
    napi_value ret = nullptr;
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    // Parse the first argument into typeMask
    asyncContext->mediaTypes.push_back(MEDIA_TYPE_IMAGE);
    asyncContext->mediaTypes.push_back(MEDIA_TYPE_VIDEO);
    MediaLibraryNapiUtils::GenTypeMaskFromArray(asyncContext->mediaTypes, asyncContext->typeMask);
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseAlbumFetchOptCallback(env, info, asyncContext), asyncContext,
        JS_ERR_PARAMETER_INVALID);
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrGetAlbums", GetResultDataExecute,
        AlbumsAsyncCallbackComplete);
}

napi_value MediaLibraryNapi::UserFileMgrCreateAsset(napi_env env, napi_callback_info info)
{
    napi_value ret = nullptr;
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    NAPI_ASSERT(env, ParseArgsCreateAsset(env, info, asyncContext), "Failed to parse js args");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrCreateAsset", JSCreateAssetExecute,
        JSCreateAssetCompleteCallback);
}

napi_value MediaLibraryNapi::UserFileMgrTrashAsset(napi_env env, napi_callback_info info)
{
    napi_value ret = nullptr;
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, asyncContext->uri),
        asyncContext, JS_ERR_PARAMETER_INVALID);
    MediaLibraryNapiUtils::GenTypeMaskFromArray({ MediaLibraryNapiUtils::GetMediaTypeFromUri(asyncContext->uri) },
        asyncContext->typeMask);

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrTrashAsset", JSTrashAssetExecute,
        JSTrashAssetCompleteCallback);
}

napi_value MediaLibraryNapi::UserFileMgrGetPrivateAlbum(napi_env env, napi_callback_info info)
{
    napi_value ret = nullptr;
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");

    CHECK_ARGS(env,  MediaLibraryNapiUtils::ParseArgsNumberCallback(env, info, asyncContext,
        asyncContext->privateAlbumType), asyncContext, JS_ERR_PARAMETER_INVALID);
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    // PrivateAlbum only support image and video so far
    asyncContext->mediaTypes.push_back(MEDIA_TYPE_IMAGE);
    asyncContext->mediaTypes.push_back(MEDIA_TYPE_VIDEO);
    MediaLibraryNapiUtils::GenTypeMaskFromArray(asyncContext->mediaTypes, asyncContext->typeMask);

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrGetPrivateAlbum",
        GetAllSmartAlbumResultDataExecute, GetPrivateAlbumCallbackComplete);
}

napi_value MediaLibraryNapi::CreateMediaTypeEnum(napi_env env)
{
    return CreateNumberEnumProperty(env, mediaTypesEnum, sMediaTypeEnumRef_);
}

napi_value MediaLibraryNapi::CreateMediaTypeUserFileEnum(napi_env env)
{
    const int32_t startIdx = 1;
    return CreateNumberEnumProperty(env, mediaTypesUserFileEnum, sMediaTypeEnumRef_, startIdx);
}

napi_value MediaLibraryNapi::CreateDirectoryTypeEnum(napi_env env)
{
    return CreateNumberEnumProperty(env, directoryEnum, sDirectoryEnumRef_);
}

napi_value MediaLibraryNapi::CreateVirtualAlbumTypeEnum(napi_env env)
{
    return CreateNumberEnumProperty(env, virtualAlbumTypeEnum, sVirtualAlbumTypeEnumRef_);
}

napi_value MediaLibraryNapi::CreatePrivateAlbumTypeEnum(napi_env env)
{
    return CreateNumberEnumProperty(env, privateAlbumTypeNameEnum, sPrivateAlbumEnumRef_);
}

napi_value MediaLibraryNapi::CreateFileKeyEnum(napi_env env)
{
    return CreateStringEnumProperty(env, FILE_KEY_ENUM_PROPERTIES, sFileKeyEnumRef_);
}

napi_value MediaLibraryNapi::UserFileMgrCreateFileKeyEnum(napi_env env)
{
    return CreateStringEnumProperty(env, USERFILEMGR_FILEKEY_ENUM_PROPERTIES, sUserFileMgrFileKeyEnumRef_);
}

napi_value MediaLibraryNapi::CreateAudioKeyEnum(napi_env env)
{
    return CreateStringEnumProperty(env, AUDIOKEY_ENUM_PROPERTIES, sAudioKeyEnumRef_);
}

napi_value MediaLibraryNapi::CreateImageVideoKeyEnum(napi_env env)
{
    return CreateStringEnumProperty(env, IMAGEVIDEOKEY_ENUM_PROPERTIES, sImageVideoKeyEnumRef_);
}

napi_value MediaLibraryNapi::CreateAlbumKeyEnum(napi_env env)
{
    return CreateStringEnumProperty(env, ALBUMKEY_ENUM_PROPERTIES, sAlbumKeyEnumRef_);
}
} // namespace Media
} // namespace OHOS
