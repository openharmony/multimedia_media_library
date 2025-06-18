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

#ifndef OHOS_MEDIA_MEDIALIBRARY_SERVICE_EXTENSION_NAPI_H
#define OHOS_MEDIA_MEDIALIBRARY_SERVICE_EXTENSION_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_remote_object.h"
#include "uv.h"

#include <vector>

namespace OHOS {
namespace Media {
class MediaLibraryServiceExtensionNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);

    MediaLibraryServiceExtensionNapi() = default;
    ~MediaLibraryServiceExtensionNapi() = default;

private:
    static napi_value JSDoTaskOps(napi_env env, napi_callback_info info);
    static int32_t CommitTaskOps(const std::string &operation, const std::string &taskName,
        const std::string &taskExtra);
};
} // namespace Media
} // namespace OHOS
#endif  // OHOS_MEDIA_MEDIALIBRARY_SERVICE_EXTENSION_NAPI_H
