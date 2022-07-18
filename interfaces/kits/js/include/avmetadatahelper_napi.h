/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_AVMETADATAHELPER_NAPI_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_AVMETADATAHELPER_NAPI_H_

#include "avmetadatahelper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "medialibrary_napi_utils.h"

namespace OHOS {
namespace Media {
class AVMetadataHelperNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);
    static napi_value CreateAVMetadataHelper(napi_env env, napi_callback_info info);
    static napi_value SetSource(napi_env env, napi_callback_info info);
    static napi_value ResolveMetadata(napi_env env, napi_callback_info info);
    static napi_value FetchVideoScaledPixelMapByTime(napi_env env, napi_callback_info info);
    static napi_value FetchVideoPixelMapByTime(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

    AVMetadataHelperNapi();
    ~AVMetadataHelperNapi();

    static thread_local napi_ref constructor_;
    napi_env env_ = nullptr;

    std::shared_ptr<OHOS::Media::AVMetadataHelper> nativeAVMetadataHelper_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_AVMETADATAHELPER_NAPI_H_
