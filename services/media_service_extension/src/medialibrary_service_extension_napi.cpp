/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaBgTask_MediaLibraryServiceExtensionNapi"

#include "medialibrary_service_extension_napi.h"

#include <napi/native_api.h>
#include <napi_base_context.h>

#include "application_context.h"
#include "js_native_api.h"
#include "medialibrary_bg_task_manager.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils.h"
#include "napi_error.h"

namespace OHOS {
namespace Media {
napi_value MediaLibraryServiceExtensionNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor media_library_properties[] = {
        DECLARE_NAPI_FUNCTION("doTaskOps", JSDoTaskOps),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(media_library_properties) /
        sizeof(media_library_properties[0]), media_library_properties));
    return exports;
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

napi_value MediaLibraryServiceExtensionNapi::JSDoTaskOps(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("JSStartMmlTaskOps begin.");
    napi_value result = nullptr;

    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_THREE), "requires 3 parameters");
    napi_get_undefined(env, &result);

    std::string operation = GetStringFromParams(env, argv, PARAM0);
    std::string taskName = GetStringFromParams(env, argv, PARAM1);
    std::string taskExtra = GetStringFromParams(env, argv, PARAM2);
    if (operation.empty() || taskName.empty()) {
        NAPI_ERR_LOG("operation or taskName is empty.");
        return result;
    }

    int32_t ret = CommitTaskOps(operation, taskName, taskExtra);
    napi_create_int32(env, ret, &result);
    return result;
}

int32_t MediaLibraryServiceExtensionNapi::CommitTaskOps(const std::string &operation, const std::string &taskName,
    const std::string &taskExtra)
{
    if (operation.empty() || taskName.empty()) {
        NAPI_ERR_LOG("operation or taskName is empty.");
        return E_ERR;
    }
 
    return MediaLibraryBgTaskManager::GetInstance().CommitTaskOps(operation, taskName, taskExtra);
}
} // namespace Media
} // namespace OHOS
