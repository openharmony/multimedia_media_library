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
#include "application_context.h"
#include "backup_restore_service.h"
#include "js_native_api.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils.h"

namespace OHOS {
namespace Media {

using RestoreBlock = struct {
    napi_env env;
    int32_t sceneCode;
    std::string galleryAppName;
    std::string mediaAppName;
    napi_deferred nativeDeferred;
};

napi_value MediaLibraryBackupNapi::Init(napi_env env, napi_value exports)
{
    NAPI_INFO_LOG("Init, MediaLibraryBackupNapi has been used.");
    napi_property_descriptor media_library_properties[] = {
        DECLARE_NAPI_FUNCTION("startRestore", JSStartRestore),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(media_library_properties) /
        sizeof(media_library_properties[0]), media_library_properties));
    return exports;
}

static int32_t GetIntFromParams(napi_env env, const napi_value args[], size_t index)
{
    int32_t result = -1;
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args[index], &valueType) != napi_ok || valueType != napi_number) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }
    napi_get_value_int32(env, args[index], &result);
    return result;
}

static std::string GetStringFromParams(napi_env env, const napi_value args[], size_t index)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args[index], &valueType) != napi_ok || valueType != napi_string) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return "";
    }

    size_t resultLength;
    napi_get_value_string_utf8(env, args[index], nullptr, 0, &resultLength);
    std::string result(resultLength, '\0');
    napi_get_value_string_utf8(env, args[index], &result[0], resultLength + 1, &resultLength);
    return result;
}

static int32_t CheckPermission(void)
{
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        NAPI_ERR_LOG("Failed to get context");
        return E_FAIL;
    }
    std::string bundleName = context->GetBundleName();
    if (bundleName.compare(BUNDLE_NAME) != 0) {
        NAPI_ERR_LOG("bundleName is invalid, %{public}s", bundleName.c_str());
        return E_FAIL;
    }
    return E_OK;
}

napi_value MediaLibraryBackupNapi::JSStartRestore(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    if (CheckPermission() != E_OK) {
        return result;
    }

    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_THREE), "requires 3 parameters");
    napi_get_undefined(env, &result);
    int32_t sceneCode = GetIntFromParams(env, argv, PARAM0);
    std::string galleryAppName = GetStringFromParams(env, argv, PARAM1);
    std::string mediaAppName = GetStringFromParams(env, argv, PARAM2);
    NAPI_INFO_LOG("StartRestore, sceneCode = %{public}d", sceneCode);
    if (sceneCode < 0) {
        NAPI_INFO_LOG("Parameters error, sceneCode = %{public}d", sceneCode);
        return result;
    }
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        NAPI_ERR_LOG("Failed to new uv_work");
        return result;
    }
    napi_deferred nativeDeferred = nullptr;
    napi_create_promise(env, &nativeDeferred, &result);
    RestoreBlock *block = new (std::nothrow) RestoreBlock {
        env, sceneCode, galleryAppName, mediaAppName, nativeDeferred };
    work->data = reinterpret_cast<void *>(block);
    uv_queue_work(
        loop,
        work,
        [](uv_work_t *work) {
            RestoreBlock *block = reinterpret_cast<RestoreBlock *> (work->data);
            BackupRestoreService::GetInstance().StartRestore(block->sceneCode, block->galleryAppName,
                block->mediaAppName);
        },
        [](uv_work_t *work, int _status) {
            RestoreBlock *block = reinterpret_cast<RestoreBlock *> (work->data);
            napi_value resultCode = nullptr;
            napi_create_int32(block->env, 1, &resultCode);
            napi_resolve_deferred(block->env, block->nativeDeferred, resultCode);
            delete block;
            delete work;
        }
    );
    return result;
}
} // namespace Media
} // namespace OHOS
