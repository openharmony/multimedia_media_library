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

#ifndef MPT_SERVICE_H_
#define MPT_SERVICE_H_
#ifdef MEDIALIBRARY_MTP_ENABLE

#include "napi_base_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "medialibrary_napi_log.h"

namespace OHOS {
namespace Media {
const std::string MTP_SERVICE_NAPI_CLASS_NAME = "MtpService";
class MtpServiceNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);

    MtpServiceNapi();
    ~MtpServiceNapi();

private:
    static void MtpServiceNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint);
    static napi_value MtpServiceNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value StartMtpService(napi_env env, napi_callback_info info);
    static napi_value StopMtpService(napi_env env, napi_callback_info info);

    napi_env env_;
    static thread_local napi_ref sConstructor_;
};
} // namespace Media
} // namespace OHOS

#endif // MPT_SERVICE_H_
#endif