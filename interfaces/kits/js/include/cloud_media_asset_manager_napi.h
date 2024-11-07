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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_MANAGER_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_MANAGER_NAPI_H

#include <vector>

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "file_asset_napi.h"
#include "photo_proxy.h"
#include "values_bucket.h"
#include "napi_base_context.h"
#include "napi_error.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "fetch_file_result_napi.h"
#include "cloud_media_asset_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class CloudMediaAssetManagerNapi {
public:
    EXPORT CloudMediaAssetManagerNapi() = default;
    EXPORT ~CloudMediaAssetManagerNapi() = default;
    EXPORT static napi_value Init(napi_env env, napi_value exports);

    static bool InitUserFileClient(napi_env env, napi_callback_info info);
private:
    EXPORT static napi_value Constructor(napi_env env, napi_callback_info info);
    EXPORT static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    EXPORT static napi_value JSGetCloudMediaAssetManagerInstance(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSStartDownloadCloudMedia(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSPauseDownloadCloudMedia(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSCancelDownloadCloudMedia(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSRetainCloudMediaAsset(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetCloudMediaAssetStatus(napi_env env, napi_callback_info info);

    static thread_local napi_ref constructor_;
};

struct CloudMediaAssetAsyncContext : public NapiError {
    size_t argc;
    napi_value argv[NAPI_ARGC_MAX];
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;

    CloudMediaAssetManagerNapi* objectInfo;
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    int32_t cloudMediaDownloadType;
    int32_t cloudMediaRetainType;
    CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus_;
    CloudMediaTaskPauseCause cloudMediaTaskPauseCause_;
    string taskInfo_;
};
}
}
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_MANAGER_NAPI_H