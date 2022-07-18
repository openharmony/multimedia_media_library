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
#include "datashare_result_set.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "hitrace_meter.h"
#include "medialibrary_napi_log.h"
#include "media_lib_service_const.h"
#include "media_data_ability_const.h"

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

#define NAPI_CREATE_RESOURCE_API_NAME(env, resource, resourceName, context)         \
    do {                                                                            \
        napi_create_string_utf8(env, resourceName, NAPI_AUTO_LENGTH, &(resource));  \
        context->SetApiName(resourceName);                                          \
    } while (0)

#define NAPI_CREATE_RESOURCE_NAME(env, resource, resourceName)                      \
    do {                                                                            \
        napi_create_string_utf8(env, resourceName, NAPI_AUTO_LENGTH, &(resource));  \
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
const int32_t ARGS_FORE = 4;
const int32_t SIZE = 100;
const int32_t REFERENCE_COUNT_ONE = 1;

// Error codes
const int32_t ERR_DEFAULT = 0;
const int32_t ERR_MEM_ALLOCATION = 2;
const int32_t ERR_INVALID_OUTPUT = 3;

const int32_t JS_ERR_PERMISSION_DENIED = 4;
const int32_t ERR_DISPLAY_NAME_INVALID = 5;
const int32_t ERR_RELATIVE_PATH_NOT_EXIST_OR_INVALID = 6;
const int32_t JS_ERR_INNER_FAIL = 7;                // ipc, rdb or file operation fail, etc
const int32_t JS_ERR_PARAMETER_INVALID = 8;         // input parameter invalid
const int32_t JS_ERR_DISPLAYNAME_INVALID = 9;       // input display invalid
const int32_t JS_ERR_NO_SUCH_FILE = 10;             // no such file
const int32_t JS_ERR_FILE_EXIST = 11;               // file has exist
const int32_t JS_ERR_WRONG_FILE_TYPE = 12;          // file type is not allow in the directory

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

const std::vector<std::string> fileKeyEnum {
    "ID", "RELATIVE_PATH", "DISPLAY_NAME", "PARENT", "MIME_TYPE", "MEDIA_TYPE", "SIZE",
    "DATE_ADDED", "DATE_MODIFIED", "DATE_TAKEN", "TITLE", "ARTIST", "AUDIOALBUM", "DURATION",
    "WIDTH", "HEIGHT", "ORIENTATION", "ALBUM_ID", "ALBUM_NAME"
};

const std::vector<std::string> directoryEnum {
    "DIR_CAMERA", "DIR_VIDEO", "DIR_IMAGE", "DIR_AUDIO", "DIR_DOCUMENTS", "DIR_DOWNLOAD"
};

const std::vector<std::string> directoryEnumValues {
    "Camera/",
    "Videos/",
    "Pictures/",
    "Audios/",
    "Documents/",
    "Download/"
};

// trans server errorCode to js Error code
const std::unordered_map<int, int> trans2JsError = {
    {E_PERMISSION_DENIED, JS_ERR_PERMISSION_DENIED},
    {DATA_ABILITY_FAIL, JS_ERR_INNER_FAIL},
    {E_NO_SUCH_FILE, JS_ERR_NO_SUCH_FILE},
    {E_FILE_EXIST, JS_ERR_FILE_EXIST},
    {DATA_ABILITY_FILE_NAME_INVALID, JS_ERR_DISPLAYNAME_INVALID},
    {DATA_ABILITY_CHECK_EXTENSION_FAIL, JS_ERR_WRONG_FILE_TYPE},
    {E_FILE_OPER_FAIL, JS_ERR_INNER_FAIL},
};

const std::unordered_map<int, std::string> jsErrMap = {
    {JS_ERR_PERMISSION_DENIED, "without medialibrary permission"},
    {JS_ERR_INNER_FAIL, "medialibrary inner fail"},
    {JS_ERR_PARAMETER_INVALID, "invalid parameter"},
    {JS_ERR_DISPLAYNAME_INVALID, "display name invalid"},
    {JS_ERR_NO_SUCH_FILE, "no such file"},
    {JS_ERR_FILE_EXIST, "file has existed"},
    {JS_ERR_WRONG_FILE_TYPE, "file type is not allow in the directory"},
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

struct JSAsyncContextOutput {
    napi_value error;
    napi_value data;
    bool status;
};

/* Util class used by napi asynchronous methods for making call to js callback function */
class MediaLibraryNapiUtils {
public:
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
    static void UpdateFetchOptionSelection(std::string &selection, const std::string &prefix)
    {
        if (!prefix.empty()) {
            if (!selection.empty()) {
                selection = prefix + "AND (" + selection + ")";
            } else {
                selection = prefix;
            }
        }
    }
    static std::string GetMediaTypeUri(MediaType mediaType)
    {
        switch (mediaType) {
            case MEDIA_TYPE_AUDIO:
                return MEDIALIBRARY_AUDIO_URI;
                break;
            case MEDIA_TYPE_VIDEO:
                return MEDIALIBRARY_VIDEO_URI;
                break;
            case MEDIA_TYPE_IMAGE:
                return MEDIALIBRARY_IMAGE_URI;
                break;
            case MEDIA_TYPE_SMARTALBUM:
                return MEDIALIBRARY_SMARTALBUM_CHANGE_URI;
                break;
            case MEDIA_TYPE_DEVICE:
                return MEDIALIBRARY_DEVICE_URI;
                break;
            case MEDIA_TYPE_FILE:
            default:
                return MEDIALIBRARY_FILE_URI;
                break;
        }
    }

    static int TransErrorCode(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
    {
        // Query can't return errorcode, so assume nullptr as permission deny
        if (resultSet == nullptr) {
            return JS_ERR_PERMISSION_DENIED;
        }
        return ERR_DEFAULT;
    }

    static int TransErrorCode(int error)
    {
        // Transfer Server error to napi error code
        if (error >= E_COMMON_START && error <= E_COMMON_END) {
            error = JS_ERR_INNER_FAIL;
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
        NAPI_ERR_LOG("Error: %{public}s, code:%{public}d ", errMsg.c_str(), error);
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
        StartTrace(HITRACE_TAG_FILEMANAGEMENT, "InvokeJSAsyncMethod");
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
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
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
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIALIBRARY_NAPI_UTILS_H_
