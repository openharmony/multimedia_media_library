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

#ifndef MEDIALIBRARY_NAPI_UTILS_H
#define MEDIALIBRARY_NAPI_UTILS_H

#include <vector>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
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
            HiLog::Error(LABEL, "invalid arguments");                                           \
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

#define NAPI_CREATE_RESOURCE_NAME(env, resource, resourceName)                      \
    do {                                                                            \
        napi_create_string_utf8(env, resourceName, NAPI_AUTO_LENGTH, &(resource));  \
    } while (0)

#define CHECK_NULL_PTR_RETURN_UNDEFINED(env, ptr, ret, message)     \
    do {                                                            \
        if ((ptr) == nullptr) {                                     \
            HiLog::Error(LABEL, message);                           \
            napi_get_undefined(env, &(ret));                        \
            return ret;                                             \
        }                                                           \
    } while (0)

#define CHECK_NULL_PTR_RETURN_VOID(ptr, message)   \
    do {                                           \
        if ((ptr) == nullptr) {                    \
            HiLog::Error(LABEL, message);          \
            return;                                \
        }                                          \
    } while (0)

#define CHECK_IF_EQUAL(condition, errMsg)   \
    do {                                    \
        if (!(condition)) {                 \
            HiLog::Error(LABEL, errMsg);    \
            return;                         \
        }                                   \
    } while (0)

namespace OHOS {
namespace Media {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;

/* Constants for array size */
const int32_t ARGS_ONE = 1;
const int32_t ARGS_TWO = 2;
const int32_t ARGS_THREE = 3;
const int32_t SIZE = 100;
const int32_t REFERENCE_COUNT_ONE = 1;

// Error codes
const int32_t ERR_MEM_ALLOCATION = 2;
const int32_t ERR_INVALID_OUTPUT = 3;

const std::string ALBUM_ROOT_PATH = "/data/media";

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

const std::vector<std::string> mediaTypesEnum {
    "DEFAULT", "FILE", "MEDIA", "IMAGE", "VIDEO", "AUDIO", "ALBUM_LIST", "ALBUM_LIST_INFO"
};

const std::vector<std::string> fileKeyEnum {
    "ID", "PATH", "RELATIVE_PATH", "MIME_TYPE", "MEDIA_TYPE", "DISPLAY_NAME", "SIZE",
    "DATE_ADDED", "DATE_MODIFIED", "TITLE", "ARTIST", "ALBUM", "ALBUM_ID", "ALBUM_NAME"
};

const std::vector<std::string> fileKeyEnumValues {
    MEDIA_DATA_DB_ID,
    MEDIA_DATA_DB_FILE_PATH,
    MEDIA_DATA_DB_RELATIVE_PATH,
    MEDIA_DATA_DB_MIME_TYPE,
    MEDIA_DATA_DB_MEDIA_TYPE,
    MEDIA_DATA_DB_NAME,
    MEDIA_DATA_DB_SIZE,
    MEDIA_DATA_DB_DATE_ADDED,
    MEDIA_DATA_DB_DATE_MODIFIED,
    MEDIA_DATA_DB_TITLE,
    MEDIA_DATA_DB_ARTIST,
    MEDIA_DATA_DB_ALBUM,
    MEDIA_DATA_DB_ALBUM_ID,
    MEDIA_DATA_DB_ALBUM_NAME
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

    static void CreateNapiErrorObject(napi_env env, napi_value &errorObj,
        const int32_t errCode, const std::string errMsg)
    {
        napi_value napiErrorCode = nullptr;
        napi_value napiErrorMsg = nullptr;

        napi_create_int32(env, errCode, &napiErrorCode);
        napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &napiErrorMsg);
        napi_create_error(env, napiErrorCode, napiErrorMsg, &errorObj);
    }

    static void InvokeJSAsyncMethod(napi_env env, napi_deferred deferred,
        napi_ref callbackRef, napi_async_work work, const JSAsyncContextOutput &asyncContext)
    {
        napi_value retVal;
        napi_value callback = nullptr;

        /* Deferred is used when JS Callback method expects a promise value */
        if (deferred) {
            if (asyncContext.status) {
                napi_resolve_deferred(env, deferred, asyncContext.data);
            } else {
                napi_reject_deferred(env, deferred, asyncContext.error);
            }
        } else {
            napi_value result[ARGS_TWO];
            result[PARAM0] = asyncContext.error;
            result[PARAM1] = asyncContext.data;
            napi_get_reference_value(env, callbackRef, &callback);
            napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
            napi_delete_reference(env, callbackRef);
        }
        napi_delete_async_work(env, work);
    }
};
} // namespace Media
} // namespace OHOS
#endif /* MEDIALIBRARY_NAPI_UTILS_H */
