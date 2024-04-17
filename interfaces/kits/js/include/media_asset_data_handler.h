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
    TYPE_MOVING_PHOTO,
    TYPE_TARGET_PATH,
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

enum class NotifyMode : int32_t {
    FAST_NOTIFY = 0,
    WAIT_FOR_HIGH_QUALITY,
};

constexpr const char* ON_DATA_PREPARED_FUNC = "onDataPrepared";

class NapiMediaAssetDataHandler {
public:
    NapiMediaAssetDataHandler(napi_env env, napi_value dataHandler, ReturnDataType dataType, const std::string &uri,
        const std::string &destUri, SourceMode sourceMode);
    ~NapiMediaAssetDataHandler();
    napi_env GetEnv();
    ReturnDataType GetReturnDataType();
    std::string GetRequestUri();
    std::string GetDestUri();
    SourceMode GetSourceMode();
    void SetNotifyMode(NotifyMode trigger);
    NotifyMode GetNotifyMode();
    void JsOnDataPrepared(napi_value exports, napi_value extraInfo = nullptr);

private:
    napi_env env_ = nullptr;
    napi_ref dataHandlerRef_ = nullptr;
    ReturnDataType dataType_;
    std::string requestUri_;
    std::string destUri_;
    SourceMode sourceMode_;
    NotifyMode notifyMode_;
};
} // Media
} // OHOS
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_DATA_HANDLER_NAPI_H
