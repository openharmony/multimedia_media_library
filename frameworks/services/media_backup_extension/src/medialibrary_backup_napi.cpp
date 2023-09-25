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
#include "js_native_api.h"
#include "application_context.h"
#include "medialibrary_napi_utils.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_client_errno.h"
#include "backup_restore_service.h"

namespace OHOS {
namespace Media {
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

static int32_t GetJSArgsForStartRestore(napi_env env, size_t argc, const napi_value args[])
{
    int32_t result = -1;
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }
    napi_get_value_int32(env, args[0], &result);
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

    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    int32_t sceneCode = GetJSArgsForStartRestore(env, argc, argv);
    NAPI_INFO_LOG("StartRestore, sceneCode = %{public}d", sceneCode);
    if (sceneCode < 0) {
        NAPI_INFO_LOG("Parameters error, sceneCode = %{public}d", sceneCode);
        return result;
    }
    BackupRestoreService::GetInstance().StartRestore(sceneCode);
    return result;
}
} // namespace Media
} // namespace OHOS
