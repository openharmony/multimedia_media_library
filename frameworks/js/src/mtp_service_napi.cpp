/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifdef MEDIALIBRARY_MTP_ENABLE
#define MLOG_TAG "MtpServiceNapi"

#include "mtp_service_napi.h"

#include "mtp_service.h"

namespace OHOS {
namespace Media {
thread_local napi_ref MtpServiceNapi::sConstructor_ = nullptr;

napi_value MtpServiceNapi::Init(napi_env env, napi_value exports)
{
    napi_value ctorObj;
    napi_property_descriptor media_library_properties[] = {};
    napi_status status = napi_define_class(env, MTP_SERVICE_NAPI_CLASS_NAME.c_str(),
        NAPI_AUTO_LENGTH, MtpServiceNapiConstructor, nullptr,
        sizeof(media_library_properties) / sizeof(napi_property_descriptor),
        media_library_properties, &ctorObj);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi define class error %{public}d", status);
        return nullptr;
    }

    int32_t refCount = 1;
    status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi create reference error %{public}d", status);
        return nullptr;
    }

    status = napi_set_named_property(env, exports, MTP_SERVICE_NAPI_CLASS_NAME.c_str(), ctorObj);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi set named property error %{public}d", status);
        return nullptr;
    }

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("startMtpService", StartMtpService),
        DECLARE_NAPI_STATIC_FUNCTION("stopMtpService", StopMtpService),
    };
    status = napi_define_properties(env, exports, sizeof(static_prop) / sizeof(napi_property_descriptor), static_prop);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi define properties error %{public}d", status);
        return nullptr;
    }

    return exports;
}

napi_value MtpServiceNapi::MtpServiceNapiConstructor(napi_env env, napi_callback_info info)
{
    return nullptr;
}

void MtpServiceNapi::MtpServiceNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
}

napi_value MtpServiceNapi::StartMtpService(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("StartMtpService IN");

    napi_value result = nullptr;
    std::shared_ptr<OHOS::Media::MtpService> mtpService = OHOS::Media::MtpService::GetInstance();
    if (mtpService != nullptr) {
        mtpService->StartService();
        NAPI_DEBUG_LOG("StartMtpService success");
    } else {
        NAPI_ERR_LOG("StartMtpService fail");
    }
    napi_get_undefined(env, &result);
    NAPI_DEBUG_LOG("StartMtpService OUT");
    return result;
}

napi_value MtpServiceNapi::StopMtpService(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("StopMtpService IN");

    napi_value result = nullptr;
        std::shared_ptr<OHOS::Media::MtpService> mtpService = OHOS::Media::MtpService::GetInstance();
    if (mtpService != nullptr) {
        mtpService->StopService();
        NAPI_DEBUG_LOG("StopMtpService success");
    } else {
        NAPI_ERR_LOG("StopMtpService fail");
    }

    napi_get_undefined(env, &result);
    NAPI_DEBUG_LOG("StopMtpService OUT");
    return result;
}

/*
 * Function registering all props and functions of ohos.medialibrary module
 */
static napi_value Export(napi_env env, napi_value exports)
{
    MtpServiceNapi::Init(env, exports);
    return exports;
}

/*
 * module define
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Export,
    .nm_modname = "multimedia.MtpService",
    .nm_priv = reinterpret_cast<void *>(0),
    .reserved = {0}
};

/*
 * module register
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}
} // namespace Media
} // namespace OHOS
#endif