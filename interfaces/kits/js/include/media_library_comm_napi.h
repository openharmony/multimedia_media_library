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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_LIBRARY_COMM_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_LIBRARY_COMM_NAPI_H

#include <string>

#include "napi/native_api.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaLibraryCommNapi {
public:
    MediaLibraryCommNapi();
    ~MediaLibraryCommNapi();

    EXPORT static napi_value CreatePhotoAssetNapi(
        napi_env env, const std::string &uri, int32_t cameraShotType, const std::string &burstKey = "");
};
} // namespace Media
} // namespace OHOS
#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_LIBRARY_COMM_NAPI_H