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
    std::string backupDir;
    napi_deferred nativeDeferred;
};

using RestoreExBlock = struct {
    napi_env env;
    int32_t sceneCode;
    std::string galleryAppName;
    std::string mediaAppName;
    std::string backupDir;
    std::string restoreExInfo;
    napi_deferred nativeDeferred;
};

napi_value MediaLibraryBackupNapi::Init(napi_env env, napi_value exports)
{
    NAPI_INFO_LOG("Init, MediaLibraryBackupNapi has been used.");
    napi_property_descriptor media_library_properties[] = {
        DECLARE_NAPI_FUNCTION("startRestore", JSStartRestore),
        DECLARE_NAPI_FUNCTION("startRestoreEx", JSStartRestoreEx),
        DECLARE_NAPI_FUNCTION("getBackupInfo", JSGetBackupInfo),
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

void MediaLibraryBackupNapi::UvQueueWork(uv_loop_s *loop, uv_work_t *work)
{
    uv_queue_work(loop, work, [](uv_work_t *work) {
        RestoreBlock *block = reinterpret_cast<RestoreBlock *> (work->data);
        if (block == nullptr) {
            delete work;
            return;
        }
        BackupRestoreService::GetInstance().StartRestore(block->sceneCode, block->galleryAppName,
            block->mediaAppName, block->backupDir);
    }, [](uv_work_t *work, int _status) {
        RestoreBlock *block = reinterpret_cast<RestoreBlock *> (work->data);
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(block->env, &scope);
        if (scope == nullptr) {
            delete work;
            return;
        }
        napi_value resultCode = nullptr;
        napi_create_int32(block->env, 1, &resultCode);
        napi_resolve_deferred(block->env, block->nativeDeferred, resultCode);
        napi_close_handle_scope(block->env, scope);
        delete block;
        delete work;
    });
}

napi_value MediaLibraryBackupNapi::JSStartRestore(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    if (CheckPermission() != E_OK) {
        return result;
    }

    size_t argc = ARGS_FOUR;
    napi_value argv[ARGS_FOUR] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_FOUR), "requires 4 parameters");
    napi_get_undefined(env, &result);
    int32_t sceneCode = GetIntFromParams(env, argv, PARAM0);
    std::string galleryAppName = GetStringFromParams(env, argv, PARAM1);
    std::string mediaAppName = GetStringFromParams(env, argv, PARAM2);
    std::string backupDir = GetStringFromParams(env, argv, PARAM3);
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
        env, sceneCode, galleryAppName, mediaAppName, backupDir, nativeDeferred };
    if (block == nullptr) {
        NAPI_ERR_LOG("Failed to new block");
        delete work;
        return result;
    }
    work->data = reinterpret_cast<void *>(block);
    UvQueueWork(loop, work);
    return result;
}

void MediaLibraryBackupNapi::UvQueueWorkEx(uv_loop_s *loop, uv_work_t *work)
{
    uv_queue_work(loop, work, [](uv_work_t *work) {
        RestoreExBlock *block = reinterpret_cast<RestoreExBlock *> (work->data);
        BackupRestoreService::GetInstance().StartRestoreEx(block->sceneCode, block->galleryAppName,
            block->mediaAppName, block->backupDir, block->restoreExInfo);
    }, [](uv_work_t *work, int _status) {
        RestoreExBlock *block = reinterpret_cast<RestoreExBlock *> (work->data);
        if (block == nullptr) {
            delete work;
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(block->env, &scope);
        if (scope == nullptr) {
            delete work;
            return;
        }
        napi_value restoreExResult = nullptr;
        napi_create_string_utf8(block->env, block->restoreExInfo.c_str(), NAPI_AUTO_LENGTH, &restoreExResult);
        napi_resolve_deferred(block->env, block->nativeDeferred, restoreExResult);
        napi_close_handle_scope(block->env, scope);
        delete block;
        delete work;
    });
}

napi_value MediaLibraryBackupNapi::JSStartRestoreEx(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    if (CheckPermission() != E_OK) {
        return result;
    }

    size_t argc = ARGS_FOUR;
    napi_value argv[ARGS_FOUR] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_FOUR), "requires 4 parameters");
    napi_get_undefined(env, &result);
    int32_t sceneCode = GetIntFromParams(env, argv, PARAM0);
    std::string galleryAppName = GetStringFromParams(env, argv, PARAM1);
    std::string mediaAppName = GetStringFromParams(env, argv, PARAM2);
    std::string backupDir = GetStringFromParams(env, argv, PARAM3);
    std::string restoreExInfo;
    NAPI_INFO_LOG("StartRestoreEx, sceneCode = %{public}d", sceneCode);
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
    RestoreExBlock *block = new (std::nothrow) RestoreExBlock {
        env, sceneCode, galleryAppName, mediaAppName, backupDir, restoreExInfo, nativeDeferred };
    if (block == nullptr) {
        NAPI_ERR_LOG("Failed to new block");
        delete work;
        return result;
    }
    work->data = reinterpret_cast<void *>(block);
    UvQueueWorkEx(loop, work);
    return result;
}

napi_value MediaLibraryBackupNapi::JSGetBackupInfo(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    if (CheckPermission() != E_OK) {
        return result;
    }

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE), "requires 1 parameters");
    napi_get_undefined(env, &result);
    int32_t sceneCode = GetIntFromParams(env, argv, PARAM0);
    NAPI_INFO_LOG("GetBackupInfo, sceneCode = %{public}d", sceneCode);
    if (sceneCode < 0) {
        NAPI_INFO_LOG("Parameters error, sceneCode = %{public}d", sceneCode);
        return result;
    }
    std::string backupInfo;
    BackupRestoreService::GetInstance().GetBackupInfo(sceneCode, backupInfo);
    CHECK_ARGS(env, napi_create_string_utf8(env, backupInfo.c_str(), NAPI_AUTO_LENGTH, &result), JS_INNER_FAIL);
    return result;
}
} // namespace Media
} // namespace OHOS
