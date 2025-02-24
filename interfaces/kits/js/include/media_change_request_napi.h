/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_CHANGE_REQUEST_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_CHANGE_REQUEST_NAPI_H

#include "medialibrary_napi_utils.h"
#include "napi_error.h"

namespace OHOS {
namespace Media {
class MediaChangeRequestNapi {
public:
    MediaChangeRequestNapi() = default;
    virtual ~MediaChangeRequestNapi() = default;

    static bool InitUserFileClient(napi_env env, napi_callback_info info, const int32_t userId = -1);
    virtual napi_value ApplyChanges(napi_env env, napi_callback_info info) = 0;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_CHANGE_REQUEST_NAPI_H