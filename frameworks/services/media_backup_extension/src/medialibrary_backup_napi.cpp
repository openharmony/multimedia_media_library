/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryBackupNapi"

#include "medialibrary_backup_napi.h"
#include "medialibrary_napi_utils.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_client_errno.h"
#include "js_native_api.h"
#include "backup_restore.h"

namespace OHOS {
namespace Media {
napi_value MediaLibraryBackupNapi::Init(napi_env env, napi_value exports)
{
    NAPI_INFO_LOG("Init, MediaLibraryBackupNapi has been used.");
    napi_property_descriptor media_library_properties[] = {
        DECLARE_NAPI_FUNCTION("startRestore", JSStartRestore),
        DECLARE_NAPI_FUNCTION("moveFiles", JSMoveFiles),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(media_library_properties) /
        sizeof(media_library_properties[0]), media_library_properties));
    return exports;
}

static std::string GetJSStringArgs(napi_env env, const napi_value fileInfoValue, const char *prop)
{
    napi_value resultValue;
    napi_get_named_property(env, fileInfoValue, prop, &resultValue);
    size_t resultLength;
    napi_get_value_string_utf8(env, resultValue, nullptr, 0, &resultLength);
    std::string result(resultLength, '\0');
    napi_get_value_string_utf8(env, resultValue, &result[0], resultLength + 1, &resultLength);
    return result;
}

static int32_t GetJSInt32Args(napi_env env, const napi_value fileInfoValue, const char *prop)
{
    int32_t result;
    napi_value resultValue;
    napi_get_named_property(env, fileInfoValue, prop, &resultValue);
    napi_get_value_int32(env, resultValue, &result);
    return result;
}

static int64_t GetJSInt64Args(napi_env env, const napi_value fileInfoValue, const char *prop)
{
    int64_t result;
    napi_value resultValue;
    napi_get_named_property(env, fileInfoValue, prop, &resultValue);
    napi_get_value_int64(env, resultValue, &result);
    return result;
}

static std::vector<FileInfo> GetJSArgsForStartRestore(napi_env env, size_t argc, const napi_value args[])
{
    uint32_t length;
    napi_get_array_length(env, args[0], &length);
    std::vector<FileInfo> fileInfos(length);
    for (uint32_t i = 0; i < length; i++) {
        FileInfo fileInfo;
        napi_value fileInfoValue;
        napi_get_element(env, args[0], i, &fileInfoValue);

        fileInfos[i].filePath = GetJSStringArgs(env, fileInfoValue, "filePath");
        fileInfos[i].displayName = GetJSStringArgs(env, fileInfoValue, "displayName");
        fileInfos[i]._size = GetJSInt64Args(env, fileInfoValue, "_size");
        fileInfos[i].duration = GetJSInt64Args(env, fileInfoValue, "duration");
        fileInfos[i].recycledTime = GetJSInt64Args(env, fileInfoValue, "recycledTime");
        fileInfos[i].hidden = GetJSInt32Args(env, fileInfoValue, "hidden");
        fileInfos[i].is_hw_favorite = GetJSInt32Args(env, fileInfoValue, "isFavorite");
        fileInfos[i].fileType = GetJSInt32Args(env, fileInfoValue, "fileType");
        fileInfos[i].showDateToken = GetJSInt64Args(env, fileInfoValue, "showDateToken");
    }
    return fileInfos;
}

napi_value MediaLibraryBackupNapi::JSStartRestore(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    std::vector<FileInfo> fileInfos = GetJSArgsForStartRestore(env, argc, argv);
    BackupRestore::GetInstance().StartRestore(fileInfos);
    return result;
}

napi_value MediaLibraryBackupNapi::JSMoveFiles(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[0], &valueType) != napi_ok || valueType != napi_string) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }

    size_t resultLength;
    if (napi_get_value_string_utf8(env, argv[0], nullptr, 0, &resultLength) != napi_ok) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }
    std::string filePath(resultLength, '\0');
    if (napi_get_value_string_utf8(env, argv[0], &filePath[0], resultLength + 1, &resultLength) != napi_ok) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }
    BackupRestore::GetInstance().MoveFiles(filePath);
    return nullptr;
}
} // namespace Media
} // namespace OHOS
