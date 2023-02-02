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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIALIBRARY_NAPI_UTILS_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIALIBRARY_NAPI_UTILS_H_

#include <tuple>
#include <memory>
#include <vector>
#include <unordered_map>
#include "datashare_result_set.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "hitrace_meter.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "datashare_predicates.h"

#define GET_JS_ARGS(env, info, argc, argv, thisVar)                         \
    do {                                                                    \
        void* data;                                                         \
        napi_get_cb_info(env, info, &(argc), argv, &(thisVar), &(data));    \
    } while (0)

#define GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar)                           \
    do {                                                                                \
        void* data;                                                                     \
        status = napi_get_cb_info(env, info, nullptr, nullptr, &(thisVar), &(data));    \
    } while (0)

#define GET_JS_ASYNC_CB_REF(env, arg, count, cbRef)                                             \
    do {                                                                                        \
        napi_valuetype valueType = napi_undefined;                                              \
        if ((napi_typeof(env, arg, &valueType) == napi_ok) && (valueType == napi_function)) {   \
            napi_create_reference(env, arg, count, &(cbRef));                                   \
        } else {                                                                                \
            NAPI_ERR_LOG("invalid arguments");                                           \
            NAPI_ASSERT(env, false, "type mismatch");                                           \
        }                                                                                       \
    } while (0)

#define ASSERT_NULLPTR_CHECK(env, result)       \
    do {                                        \
        if ((result) == nullptr) {              \
            napi_get_undefined(env, &(result)); \
            return result;                      \
        }                                       \
    } while (0)

#define NAPI_CREATE_PROMISE(env, callbackRef, deferred, result)     \
    do {                                                            \
        if ((callbackRef) == nullptr) {                             \
            napi_create_promise(env, &(deferred), &(result));       \
        }                                                           \
    } while (0)

#define NAPI_CREATE_RESOURCE_NAME(env, resource, resourceName, context)         \
    do {                                                                            \
        napi_create_string_utf8(env, resourceName, NAPI_AUTO_LENGTH, &(resource));  \
        (context)->SetApiName(resourceName);                                        \
    } while (0)

#define CHECK_NULL_PTR_RETURN_UNDEFINED(env, ptr, ret, message)     \
    do {                                                            \
        if ((ptr) == nullptr) {                                     \
            NAPI_ERR_LOG(message);                           \
            napi_get_undefined(env, &(ret));                        \
            return ret;                                             \
        }                                                           \
    } while (0)

#define CHECK_NULL_PTR_RETURN_VOID(ptr, message)   \
    do {                                           \
        if ((ptr) == nullptr) {                    \
            NAPI_ERR_LOG(message);          \
            return;                                \
        }                                          \
    } while (0)
#define CHECK_IF_EQUAL(condition, errMsg)   \
    do {                                    \
        if (!(condition)) {                 \
            NAPI_ERR_LOG(errMsg);    \
            return;                         \
        }                                   \
    } while (0)

#define CHECK_COND_RET(cond, ret, message)                          \
    do {                                                            \
        if (!(cond)) {                                              \
            NAPI_ERR_LOG(message);                                  \
            return ret;                                             \
        }                                                           \
    } while (0)

#define CHECK_STATUS_RET(cond, message)                             \
    do {                                                            \
        napi_status __ret = (cond);                                 \
        if (__ret != napi_ok) {                                     \
            NAPI_ERR_LOG(message);                                  \
            return __ret;                                           \
        }                                                           \
    } while (0)

#define CHECK_ARGS(env, cond, context, err)                         \
    do {                                                            \
        if ((cond) != napi_ok) {                                    \
            NAPI_THROW(env, context, err);                          \
            return nullptr;                                         \
        }                                                           \
    } while (0)

#define NAPI_THROW(env, context, err)                               \
    do {                                                            \
        (context)->ThrowError(env, err);                            \
    } while (0)

namespace OHOS {
namespace Media {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;
const int32_t PARAM3 = 3;

/* Constants for array size */
const int32_t ARGS_ZERO = 0;
const int32_t ARGS_ONE = 1;
const int32_t ARGS_TWO = 2;
const int32_t ARGS_THREE = 3;
const int32_t ARGS_FOUR = 4;
const int32_t ARG_BUF_SIZE = 100;
constexpr uint32_t NAPI_INIT_REF_COUNT = 1;

constexpr size_t NAPI_ARGC_MAX = 4;

// Error codes
const int32_t ERR_DEFAULT = 0;
const int32_t ERR_MEM_ALLOCATION = 2;
const int32_t ERR_INVALID_OUTPUT = 3;

const int32_t TRASH_SMART_ALBUM_ID = 1;
const std::string TRASH_SMART_ALBUM_NAME = "TrashAlbum";
const int32_t FAVORIT_SMART_ALBUM_ID = 2;
const std::string FAVORIT_SMART_ALBUM_NAME = "FavoritAlbum";

enum NapiAssetType {
    TYPE_AUDIO = 0,
    TYPE_VIDEO = 1,
    TYPE_IMAGE = 2,
    TYPE_ALBUM = 3,
};

enum AlbumType {
    TYPE_VIDEO_ALBUM = 0,
    TYPE_IMAGE_ALBUM = 1,
    TYPE_NONE = 2,
};

const std::vector<std::string> privateAlbumTypeNameEnum {
    "TYPE_FAVORITE", "TYPE_TRASH", "TYPE_HIDE", "TYPE_SMART", "TYPE_SEARCH"
};

const std::vector<std::string> mediaTypesEnum {
    "FILE", "IMAGE", "VIDEO", "AUDIO", "MEDIA", "ALBUM_LIST", "ALBUM_LIST_INFO"
};

const std::vector<std::string> mediaTypesUserFileEnum {
    "IMAGE", "VIDEO", "AUDIO"
};

const std::vector<std::string> fileKeyEnum {
    "ID", "RELATIVE_PATH", "DISPLAY_NAME", "PARENT", "MIME_TYPE", "MEDIA_TYPE", "SIZE",
    "DATE_ADDED", "DATE_MODIFIED", "DATE_TAKEN", "TITLE", "ARTIST", "AUDIOALBUM", "DURATION",
    "WIDTH", "HEIGHT", "ORIENTATION", "ALBUM_ID", "ALBUM_NAME"
};

const std::vector<std::string> directoryEnum {
    "DIR_CAMERA", "DIR_VIDEO", "DIR_IMAGE", "DIR_AUDIO", "DIR_DOCUMENTS", "DIR_DOWNLOAD"
};

const std::vector<std::string> virtualAlbumTypeEnum {
    "TYPE_FAVORITE", "TYPE_TRASH"
};

const std::vector<std::string> directoryEnumValues {
    "Camera/",
    "Videos/",
    "Pictures/",
    "Audios/",
    "Documents/",
    "Download/"
};

const std::vector<std::string> fileKeyEnumValues {
    MEDIA_DATA_DB_ID,
    MEDIA_DATA_DB_RELATIVE_PATH,
    MEDIA_DATA_DB_NAME,
    MEDIA_DATA_DB_PARENT_ID,
    MEDIA_DATA_DB_MIME_TYPE,
    MEDIA_DATA_DB_MEDIA_TYPE,
    MEDIA_DATA_DB_SIZE,
    MEDIA_DATA_DB_DATE_ADDED,
    MEDIA_DATA_DB_DATE_MODIFIED,
    MEDIA_DATA_DB_DATE_TAKEN,
    MEDIA_DATA_DB_TITLE,
    MEDIA_DATA_DB_ARTIST,
    MEDIA_DATA_DB_AUDIO_ALBUM,
    MEDIA_DATA_DB_DURATION,
    MEDIA_DATA_DB_WIDTH,
    MEDIA_DATA_DB_HEIGHT,
    MEDIA_DATA_DB_ORIENTATION,
    MEDIA_DATA_DB_BUCKET_ID,
    MEDIA_DATA_DB_BUCKET_NAME
};

const std::vector<std::pair<std::string, std::string>> FILE_KEY_ENUM_PROPERTIES = {
    std::make_pair("ID",                        MEDIA_DATA_DB_ID),
    std::make_pair("RELATIVE_PATH",             MEDIA_DATA_DB_RELATIVE_PATH),
    std::make_pair("DISPLAY_NAME",              MEDIA_DATA_DB_NAME),
    std::make_pair("PARENT",                    MEDIA_DATA_DB_PARENT_ID),
    std::make_pair("MIME_TYPE",                 MEDIA_DATA_DB_MIME_TYPE),
    std::make_pair("MEDIA_TYPE",                MEDIA_DATA_DB_MEDIA_TYPE),
    std::make_pair("SIZE",                      MEDIA_DATA_DB_SIZE),
    std::make_pair("DATE_ADDED",                MEDIA_DATA_DB_DATE_ADDED),
    std::make_pair("DATE_MODIFIED",             MEDIA_DATA_DB_DATE_MODIFIED),
    std::make_pair("DATE_TAKEN",                MEDIA_DATA_DB_DATE_TAKEN),
    std::make_pair("TITLE",                     MEDIA_DATA_DB_TITLE),
    std::make_pair("ARTIST",                    MEDIA_DATA_DB_ARTIST),
    std::make_pair("AUDIOALBUM",                MEDIA_DATA_DB_AUDIO_ALBUM),
    std::make_pair("DURATION",                  MEDIA_DATA_DB_DURATION),
    std::make_pair("WIDTH",                     MEDIA_DATA_DB_WIDTH),
    std::make_pair("HEIGHT",                    MEDIA_DATA_DB_HEIGHT),
    std::make_pair("ORIENTATION",               MEDIA_DATA_DB_ORIENTATION),
    std::make_pair("ALBUM_ID",                  MEDIA_DATA_DB_BUCKET_ID),
    std::make_pair("ALBUM_NAME",                MEDIA_DATA_DB_BUCKET_NAME)
};

const std::vector<std::pair<std::string, std::string>> USERFILEMGR_FILEKEY_ENUM_PROPERTIES = {
    std::make_pair("URI",                       MEDIA_DATA_DB_URI),
    std::make_pair("RELATIVE_PATH",             MEDIA_DATA_DB_RELATIVE_PATH),
    std::make_pair("DISPLAY_NAME",              MEDIA_DATA_DB_NAME),
    std::make_pair("DATE_ADDED",                MEDIA_DATA_DB_DATE_ADDED),
    std::make_pair("DATE_MODIFIED",             MEDIA_DATA_DB_DATE_MODIFIED),
    std::make_pair("TITLE",                     MEDIA_DATA_DB_TITLE)
};

const std::vector<std::pair<std::string, std::string>> AUDIOKEY_ENUM_PROPERTIES = {
    std::make_pair("URI",                       MEDIA_DATA_DB_URI),
    std::make_pair("DISPLAY_NAME",              MEDIA_DATA_DB_NAME),
    std::make_pair("DATE_ADDED",                MEDIA_DATA_DB_DATE_ADDED),
    std::make_pair("DATE_MODIFIED",             MEDIA_DATA_DB_DATE_MODIFIED),
    std::make_pair("TITLE",                     MEDIA_DATA_DB_TITLE),
    std::make_pair("ARTIST",                    MEDIA_DATA_DB_ARTIST),
    std::make_pair("AUDIOALBUM",                MEDIA_DATA_DB_AUDIO_ALBUM),
    std::make_pair("DURATION",                  MEDIA_DATA_DB_DURATION),
    std::make_pair("FAVORITE",                  MEDIA_DATA_DB_IS_FAV)
};

const std::vector<std::pair<std::string, std::string>> IMAGEVIDEOKEY_ENUM_PROPERTIES = {
    std::make_pair("URI",                       MEDIA_DATA_DB_URI),
    std::make_pair("DISPLAY_NAME",              MEDIA_DATA_DB_NAME),
    std::make_pair("DATE_ADDED",                MEDIA_DATA_DB_DATE_ADDED),
    std::make_pair("FILE_TYPE",                 MEDIA_DATA_DB_MEDIA_TYPE),
    std::make_pair("DATE_MODIFIED",             MEDIA_DATA_DB_DATE_MODIFIED),
    std::make_pair("TITLE",                     MEDIA_DATA_DB_TITLE),
    std::make_pair("DURATION",                  MEDIA_DATA_DB_DURATION),
    std::make_pair("WIDTH",                     MEDIA_DATA_DB_WIDTH),
    std::make_pair("HEIGHT",                    MEDIA_DATA_DB_HEIGHT),
    std::make_pair("DATE_TAKEN",                MEDIA_DATA_DB_DATE_TAKEN),
    std::make_pair("ORIENTATION",               MEDIA_DATA_DB_ORIENTATION),
    std::make_pair("FAVORITE",                  MEDIA_DATA_DB_IS_FAV),
    std::make_pair("MEDIA_TYPE",                MEDIA_DATA_DB_MEDIA_TYPE)
};

const std::vector<std::pair<std::string, std::string>> ALBUMKEY_ENUM_PROPERTIES = {
    std::make_pair("URI",                       MEDIA_DATA_DB_URI),
    std::make_pair("ALBUM_NAME",                MEDIA_DATA_DB_BUCKET_NAME),
    std::make_pair("FILE_TYPE",                 MEDIA_DATA_DB_MEDIA_TYPE),
    std::make_pair("DATE_ADDED",                MEDIA_DATA_DB_DATE_ADDED),
    std::make_pair("DATE_MODIFIED",             MEDIA_DATA_DB_DATE_MODIFIED)
};

struct JSAsyncContextOutput {
    napi_value error;
    napi_value data;
    bool status;
};

struct NapiClassInfo {
    std::string name;
    napi_ref *ref;
    napi_value (*constructor)(napi_env, napi_callback_info);
    std::vector<napi_property_descriptor> props;
};

/* Util class used by napi asynchronous methods for making call to js callback function */
class MediaLibraryNapiUtils {
public:
    static napi_value NapiDefineClass(napi_env env, napi_value exports, const NapiClassInfo &info);
    static napi_value NapiAddStaticProps(napi_env env, napi_value exports,
        const std::vector<napi_property_descriptor> &staticProps);

    static napi_status GetUInt32(napi_env env, napi_value arg, uint32_t &value);
    static napi_status GetInt32(napi_env env, napi_value arg, int32_t &value);
    static napi_status GetParamBool(napi_env env, napi_value arg, bool &result);
    static napi_status GetUInt32Array(napi_env env, napi_value arg, std::vector<uint32_t> &param);
    static napi_status GetParamFunction(napi_env env, napi_value arg, napi_ref &callbackRef);
    static napi_status GetParamString(napi_env env, napi_value arg, std::string &str);
    static napi_status GetParamStringPathMax(napi_env env, napi_value arg, std::string &str);
    static napi_status GetProperty(napi_env env, const napi_value arg, const std::string &propName,
        std::string &propValue);
    static napi_status GetArrayProperty(napi_env env, napi_value arg, const std::string &propName,
        std::vector<std::string> &array);
    static void GenTypeMaskFromArray(const std::vector<uint32_t> types, std::string &typeMask);
    static void UriAddFragmentTypeMask(std::string &uri, const std::string &typeMask);
    static void UriRemoveAllFragment(std::string &uri);
    static std::string GetFileIdFromUri(const std::string &uri);
    static MediaType GetMediaTypeFromUri(const std::string &uri);
    template <class AsyncContext>
    static napi_status GetPredicate(napi_env env, const napi_value arg, const std::string &propName,
        AsyncContext &context, bool isAlbum);
    template <class AsyncContext>
    static napi_status ParseAlbumFetchOptCallback(napi_env env, napi_callback_info info, AsyncContext &context);
    template <class AsyncContext>
    static bool HandleSpecialPredicate(AsyncContext &context,
        std::shared_ptr<DataShare::DataShareAbsPredicates> &predicate, bool isAlbum);
    template <class AsyncContext>
    static void UpdateMediaTypeSelections(AsyncContext *context);
    static void GetNetworkIdAndFileIdFromUri(const std::string &uri, std::string &networkId, std::string &fileId);

    template <class AsyncContext>
    static napi_status AsyncContextSetObjectInfo(napi_env env, napi_callback_info info, AsyncContext &asyncContext,
        const size_t minArgs, const size_t maxArgs)
    {
        napi_value thisVar = nullptr;
        asyncContext->argc = maxArgs;
        CHECK_STATUS_RET(napi_get_cb_info(env, info, &asyncContext->argc, &(asyncContext->argv[ARGS_ZERO]), &thisVar,
            nullptr), "Failed to get cb info");
        CHECK_COND_RET(((asyncContext->argc >= minArgs) && (asyncContext->argc <= maxArgs)), napi_invalid_arg,
            "Number of args is invalid");
        if (minArgs > 0) {
            CHECK_COND_RET(asyncContext->argv[ARGS_ZERO] != nullptr, napi_invalid_arg, "Argument list is empty");
        }
        CHECK_STATUS_RET(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo)),
            "Failed to unwrap thisVar");
        CHECK_COND_RET(asyncContext->objectInfo != nullptr, napi_invalid_arg, "Failed to get object info");
        return napi_ok;
    }

    template <class AsyncContext>
    static napi_status GetFetchOption(napi_env env, napi_value arg, AsyncContext &context)
    {
        /* Parse the argument into fetchOption if any */
        bool hasOpt = false;
        CHECK_STATUS_RET(hasFetchOpt(env, arg, hasOpt), "Failed to get fetchopt");
        if (hasOpt) {
            CHECK_STATUS_RET(GetProperty(env, arg, "selections", context->selection), "Failed to parse selections");
            CHECK_STATUS_RET(GetProperty(env, arg, "order", context->order), "Failed to parse order");
            CHECK_STATUS_RET(GetArrayProperty(env, arg, "selectionArgs", context->selectionArgs),
                "Failed to parse selectionArgs");
            CHECK_STATUS_RET(GetProperty(env, arg, "uri", context->uri), "Failed to parse uri");
            CHECK_STATUS_RET(GetProperty(env, arg, "networkId", context->networkId), "Failed to parse networkId");
        }
        return napi_ok;
    }

    template <class AsyncContext>
    static napi_status GetAssetFetchOption(napi_env env, napi_value arg, AsyncContext &context);

    template <class AsyncContext>
    static napi_status GetParamCallback(napi_env env, AsyncContext &context)
    {
        /* Parse the last argument into callbackref if any */
        bool isCallback = false;
        CHECK_STATUS_RET(hasCallback(env, context->argc, context->argv, isCallback), "Failed to check callback");
        if (isCallback) {
            CHECK_STATUS_RET(GetParamFunction(env, context->argv[context->argc - 1], context->callbackRef),
                "Failed to get callback");
        }
        return napi_ok;
    }

    template <class AsyncContext>
    static napi_status ParseAssetFetchOptCallback(napi_env env, napi_callback_info info,
        AsyncContext &context);

    template <class AsyncContext>
    static napi_status ParseArgsTypeFetchOptCallback(napi_env env, napi_callback_info info, AsyncContext &context)
    {
        constexpr size_t minArgs = ARGS_TWO;
        constexpr size_t maxArgs = ARGS_THREE;
        CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
            "Failed to get object info");
        /* Parse the first argument into typeMask */
        CHECK_STATUS_RET(GetUInt32Array(env, context->argv[ARGS_ZERO], context->mediaTypes),
            "Failed to get param array");
        CHECK_COND_RET(context->mediaTypes.size() > 0, napi_invalid_arg, "Require at least one type");
        GenTypeMaskFromArray(context->mediaTypes, context->typeMask);
        CHECK_STATUS_RET(GetFetchOption(env, context->argv[ARGS_ONE], context), "Failed to get fetch option");
        CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
        return napi_ok;
    }

    template <class AsyncContext>
    static napi_status ParseArgsBoolCallBack(napi_env env, napi_callback_info info, AsyncContext &context, bool &param)
    {
        constexpr size_t minArgs = ARGS_ONE;
        constexpr size_t maxArgs = ARGS_TWO;
        CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
            "Failed to get object info");

        /* Parse the first argument into param */
        CHECK_STATUS_RET(GetParamBool(env, context->argv[ARGS_ZERO], param), "Failed to get parameter");
        CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
        return napi_ok;
    }

    template <class AsyncContext>
    static napi_status ParseArgsStringCallback(napi_env env, napi_callback_info info, AsyncContext &context,
        std::string &param)
    {
        constexpr size_t minArgs = ARGS_ONE;
        constexpr size_t maxArgs = ARGS_TWO;
        CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
            "Failed to get object info");

        CHECK_STATUS_RET(GetParamStringPathMax(env, context->argv[ARGS_ZERO], param), "Failed to get string argument");
        CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
        return napi_ok;
    }

    template <class AsyncContext>
    static napi_status ParseArgsNumberCallback(napi_env env, napi_callback_info info, AsyncContext &context,
        int32_t &value)
    {
        constexpr size_t minArgs = ARGS_ONE;
        constexpr size_t maxArgs = ARGS_TWO;
        CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
            "Failed to get object info");

        CHECK_STATUS_RET(GetInt32(env, context->argv[ARGS_ZERO], value), "Failed to get number argument");
        CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
        return napi_ok;
    }

    template <class AsyncContext>
    static napi_status ParseArgsOnlyCallBack(napi_env env, napi_callback_info info, AsyncContext &context)
    {
        constexpr size_t minArgs = ARGS_ZERO;
        constexpr size_t maxArgs = ARGS_ONE;
        CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
            "Failed to get object info");

        CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
        return napi_ok;
    }

    static AssetType GetAssetType(MediaType type)
    {
        AssetType result;

        switch (type) {
            case MEDIA_TYPE_AUDIO:
                result = ASSET_AUDIO;
                break;
            case MEDIA_TYPE_VIDEO:
                result = ASSET_VIDEO;
                break;
            case MEDIA_TYPE_IMAGE:
                result = ASSET_IMAGE;
                break;
            case MEDIA_TYPE_MEDIA:
                result = ASSET_MEDIA;
                break;
            default:
                result = ASSET_NONE;
                break;
        }

        return result;
    }

    static void AppendFetchOptionSelection(std::string &selection, const std::string &newCondition)
    {
        if (!newCondition.empty()) {
            if (!selection.empty()) {
                selection = "(" + selection + ") AND " + newCondition;
            } else {
                selection = newCondition;
            }
        }
    }

    static std::string GetMediaTypeUri(MediaType mediaType)
    {
        switch (mediaType) {
            case MEDIA_TYPE_AUDIO:
                return MEDIALIBRARY_AUDIO_URI;
            case MEDIA_TYPE_VIDEO:
                return MEDIALIBRARY_VIDEO_URI;
            case MEDIA_TYPE_IMAGE:
                return MEDIALIBRARY_IMAGE_URI;
            case MEDIA_TYPE_SMARTALBUM:
                return MEDIALIBRARY_SMARTALBUM_CHANGE_URI;
            case MEDIA_TYPE_DEVICE:
                return MEDIALIBRARY_DEVICE_URI;
            case MEDIA_TYPE_FILE:
            default:
                return MEDIALIBRARY_FILE_URI;
        }
    }

    static int TransErrorCode(const std::string &Name, std::shared_ptr<DataShare::DataShareResultSet> resultSet)
    {
        NAPI_ERR_LOG("interface: %{public}s, server return nullptr", Name.c_str());
        // Query can't return errorcode, so assume nullptr as permission deny
        if (resultSet == nullptr) {
            return JS_ERR_PERMISSION_DENIED;
        }
        return ERR_DEFAULT;
    }

    static int TransErrorCode(const std::string &Name, int error)
    {
        NAPI_ERR_LOG("interface: %{public}s, server errcode:%{public}d ", Name.c_str(), error);
        // Transfer Server error to napi error code
        if (error <= E_COMMON_START && error >= E_COMMON_END) {
            error = JS_INNER_FAIL;
        } else if (trans2JsError.count(error)) {
            error = trans2JsError.at(error);
        }
        return error;
    }

    static void HandleError(napi_env env, int error, napi_value &errorObj, const std::string &Name)
    {
        if (error == ERR_DEFAULT) {
            return;
        }

        std::string errMsg = "operation fail";
        if (jsErrMap.count(error) > 0) {
            errMsg = jsErrMap.at(error);
        }
        CreateNapiErrorObject(env, errorObj, error, errMsg);
        errMsg = Name + " " + errMsg;
        NAPI_ERR_LOG("Error: %{public}s, js errcode:%{public}d ", errMsg.c_str(), error);
    }

    static void CreateNapiErrorObject(napi_env env, napi_value &errorObj,
        const int32_t errCode, const std::string errMsg)
    {
        napi_status statusError;
        napi_value napiErrorCode = nullptr;
        napi_value napiErrorMsg = nullptr;
        statusError = napi_create_string_utf8(env, std::to_string(errCode).c_str(), NAPI_AUTO_LENGTH, &napiErrorCode);
        if (statusError == napi_ok) {
            statusError = napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &napiErrorMsg);
            if (statusError == napi_ok) {
                statusError = napi_create_error(env, napiErrorCode, napiErrorMsg, &errorObj);
                if (statusError == napi_ok) {
                    NAPI_DEBUG_LOG("napi_create_error success");
                }
            }
        }
    }

    static void InvokeJSAsyncMethod(napi_env env, napi_deferred deferred,
        napi_ref callbackRef, napi_async_work work, const JSAsyncContextOutput &asyncContext)
    {
        MediaLibraryTracer tracer;
        tracer.Start("InvokeJSAsyncMethod");

        NAPI_DEBUG_LOG("InvokeJSAsyncMethod IN");
        napi_value retVal;
        napi_value callback = nullptr;

        /* Deferred is used when JS Callback method expects a promise value */
        if (deferred) {
            NAPI_DEBUG_LOG("InvokeJSAsyncMethod promise");
            if (asyncContext.status) {
                napi_resolve_deferred(env, deferred, asyncContext.data);
            } else {
                napi_reject_deferred(env, deferred, asyncContext.error);
            }
        } else {
            NAPI_DEBUG_LOG("InvokeJSAsyncMethod callback");
            napi_value result[ARGS_TWO];
            result[PARAM0] = asyncContext.error;
            result[PARAM1] = asyncContext.data;
            napi_get_reference_value(env, callbackRef, &callback);
            napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
            napi_delete_reference(env, callbackRef);
        }
        napi_delete_async_work(env, work);
        NAPI_DEBUG_LOG("InvokeJSAsyncMethod OUT");
    }

    template <class AsyncContext>
    static napi_value NapiCreateAsyncWork(napi_env env, std::unique_ptr<AsyncContext> &asyncContext,
        const std::string &resourceName,  void (*execute)(napi_env, void *),
        void (*complete)(napi_env, napi_status, void *))
    {
        napi_value result = nullptr;
        napi_value resource = nullptr;
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, resourceName.c_str(), asyncContext);

        NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, execute, complete,
            static_cast<void*>(asyncContext.get()), &asyncContext->work));
        NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
        asyncContext.release();

        return result;
    }

    static std::tuple<bool, std::unique_ptr<char[]>, size_t> ToUTF8String(napi_env env, napi_value value)
    {
        size_t strLen = 0;
        napi_status status = napi_get_value_string_utf8(env, value, nullptr, -1, &strLen);
        if (status != napi_ok) {
            NAPI_ERR_LOG("ToUTF8String get fail, %{public}d", status);
            return { false, nullptr, 0 };
        }

        size_t bufLen = strLen + 1;
        std::unique_ptr<char[]> str = std::make_unique<char[]>(bufLen);
        if (str == nullptr) {
            NAPI_ERR_LOG("ToUTF8String get memory fail");
            return { false, nullptr, 0 };
        }
        status = napi_get_value_string_utf8(env, value, str.get(), bufLen, &strLen);
        return std::make_tuple(status == napi_ok, move(str), strLen);
    }

    static bool IsExistsByPropertyName(napi_env env, napi_value jsObject, const char *propertyName)
    {
        bool result = false;
        if (napi_has_named_property(env, jsObject, propertyName, &result) == napi_ok) {
            return result;
        } else {
            NAPI_ERR_LOG("IsExistsByPropertyName not exist %{public}s", propertyName);
            return false;
        }
    }

    static napi_value GetPropertyValueByName(napi_env env, napi_value jsObject, const char *propertyName)
    {
        napi_value value = nullptr;
        if (IsExistsByPropertyName(env, jsObject, propertyName) == false) {
            NAPI_ERR_LOG("GetPropertyValueByName not exist %{public}s", propertyName);
            return nullptr;
        }
        if (napi_get_named_property(env, jsObject, propertyName, &value) != napi_ok) {
            NAPI_ERR_LOG("GetPropertyValueByName get fail %{public}s", propertyName);
            return nullptr;
        }
        return value;
    }

    static bool CheckJSArgsTypeAsFunc(napi_env env, napi_value arg)
    {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, arg, &valueType);
        return (valueType == napi_function);
    }

    static bool IsArrayForNapiValue(napi_env env, napi_value param, uint32_t &arraySize)
    {
        bool isArray = false;
        arraySize = 0;
        if ((napi_is_array(env, param, &isArray) != napi_ok) || (isArray == false)) {
            return false;
        }
        if (napi_get_array_length(env, param, &arraySize) != napi_ok) {
            return false;
        }
        return true;
    }
private:
    static napi_status hasCallback(napi_env env, const size_t argc, const napi_value argv[],
        bool &isCallback);
    static napi_status hasFetchOpt(napi_env env, const napi_value arg, bool &hasFetchOpt);
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIALIBRARY_NAPI_UTILS_H_
