/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_ENHANCEMENT_TASK_STATE_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_ENHANCEMENT_TASK_STATE_NAPI_H

#include <memory>

#include "cloud_enhancement_napi.h"
#include "media_asset_data_handler.h"
#include "media_asset_manager_napi.h"
#include "media_library_napi.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {

class CloudEnhancementTaskStateNapi {
public:
    CloudEnhancementTaskStateNapi() = default;
    ~CloudEnhancementTaskStateNapi() = default;
    static napi_value NewCloudEnhancementTaskStateNapi(napi_env env, CloudEnhancementAsyncContext* context);
    EXPORT static napi_value Init(napi_env env, napi_value exports);

private:
    EXPORT static napi_value Constructor(napi_env env, napi_callback_info info);
    EXPORT static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    EXPORT static napi_value JSGetTaskStage(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetTransferredFileSize(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetTotalFileSize(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetExpectedDuration(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetStatusCode(napi_env env, napi_callback_info info);

    CloudEnhancementTaskStage GetCloudEnhancementTaskStage() const;
    void SetCloudEnhancementTaskStage(CloudEnhancementTaskStage cloudEnhancementTaskStage);

    int32_t GetTransferredFileSize() const;
    void SetTransferredFileSize(int32_t transferredFileSize);

    int32_t GetTotalFileSize() const;
    void SetTotalFileSize(int32_t totalFileSize);

    int32_t GetExpectedDuration() const;
    void SetExpectedDuration(int32_t expectedDuration);

    int32_t GetStatusCode() const;
    void SetStatusCode(int32_t statusCode);

    static thread_local napi_ref constructor_;
    CloudEnhancementTaskStage cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_EXCEPTION;
    static const int32_t UNDEFINED = -1;
    int32_t transferredFileSize_ {UNDEFINED};
    int32_t totalFileSize_ {UNDEFINED};
    int32_t expectedDuration_ {UNDEFINED};
    int32_t statusCode_ {UNDEFINED};
};

} // Media
} // OHOS
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_ENHANCEMENT_TASK_STATE_NAPI_H
