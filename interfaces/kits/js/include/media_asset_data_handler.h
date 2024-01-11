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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_DATA_HANDLER_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_DATA_HANDLER_NAPI_H

#include "medialibrary_napi_utils.h"

namespace OHOS {
namespace Media {
enum class ReturnDataType {
    TYPE_IMAGE_SOURCE = 0,
    TYPE_ARRAY_BUFFER,
};

enum class DeliveryMode {
    FAST = 0,
    HIGH_QUALITY,
    BALANCED_MODE,
};

enum class SourceMode {
    ORIGINAL_MODE = 0,
    EDITED_MODE,
};

class NapiMediaAssetDataHandler {
public:
    NapiMediaAssetDataHandler(napi_env env, napi_value jsMediaAssetDataHandler, ReturnDataType dataType);
    ~NapiMediaAssetDataHandler() = default;
    ReturnDataType GetHandlerType();
    void JsOnDataPreared(napi_value exports);

private:
    ReturnDataType dataType_;
    napi_value ondataPreparedFunc_ = nullptr;
    napi_value thisVar_ = nullptr;
    napi_env env_ = nullptr;
};

} // Media
} // OHOS
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_DATA_HANDLER_NAPI_H
