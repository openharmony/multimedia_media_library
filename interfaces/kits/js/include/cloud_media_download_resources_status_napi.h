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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_DOWNLOAD_RESOURCES_STATUS_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_DOWNLOAD_RESOURCES_STATUS_NAPI_H

#include <memory>

#include "cloud_media_asset_manager_napi.h"
#include "media_asset_data_handler.h"
#include "media_asset_manager_napi.h"
#include "media_library_napi.h"
#include "cloud_media_asset_types.h"

namespace OHOS {
namespace Media {
class CloudMediaDownloadResourcesStatusNapi {
public:
    EXPORT CloudMediaDownloadResourcesStatusNapi() = default;
    EXPORT ~CloudMediaDownloadResourcesStatusNapi() = default;
    static napi_value NewCloudMediaDownloadResourcesStatusNapi(napi_env env, CloudMediaAssetAsyncContext* context);
    EXPORT static napi_value Init(napi_env env, napi_value exports);

private:
    EXPORT static napi_value Constructor(napi_env env, napi_callback_info info);
    EXPORT static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    EXPORT static napi_value JSGetTaskInfos(napi_env env, napi_callback_info info);

    std::vector<std::string> GetTaskInfos() const;
    void SetTaskInfos(const std::vector<std::string>  &taskInfos);

    static thread_local napi_ref constructor_;
    std::vector<std::string> taskInfos_;
};
} // Media
} // OHOS
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_DOWNLOAD_RESOURCES_STATUS_NAPI_H