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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_STATUS_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_STATUS_NAPI_H

#include <memory>

#include "cloud_media_asset_manager_napi.h"
#include "media_asset_data_handler.h"
#include "media_asset_manager_napi.h"
#include "media_library_napi.h"
#include "cloud_media_asset_types.h"

namespace OHOS {
namespace Media {
class CloudMediaAssetStatusNapi {
public:
    EXPORT CloudMediaAssetStatusNapi() = default;
    EXPORT ~CloudMediaAssetStatusNapi() = default;
    static napi_value NewCloudMediaAssetStatusNapi(napi_env env, CloudMediaAssetAsyncContext* context);
    EXPORT static napi_value Init(napi_env env, napi_value exports);

private:
    EXPORT static napi_value Constructor(napi_env env, napi_callback_info info);
    EXPORT static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    EXPORT static napi_value JSGetTaskStatus(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetErrorCode(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetTaskInfo(napi_env env, napi_callback_info info);

    CloudMediaAssetTaskStatus GetCloudMediaAssetTaskStatus() const;
    void SetCloudMediaAssetTaskStatus(CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus);

    CloudMediaTaskPauseCause GetCloudMediaTaskPauseCause() const;
    void SetCloudMediaTaskPauseCause(CloudMediaTaskPauseCause cloudMediaTaskPauseCause);

    std::string GetTaskInfo() const;
    void SetTaskInfo(const std::string &taskInfo);

    static thread_local napi_ref constructor_;
    CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    CloudMediaTaskPauseCause cloudMediaTaskPauseCause_ = CloudMediaTaskPauseCause::NO_PAUSE;
    std::string taskInfo_ = "";
};
} // Media
} // OHOS
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_STATUS_NAPI_H