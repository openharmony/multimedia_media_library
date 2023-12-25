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

#include "media_asset_data_handler.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_utils.h"
#include "napi_error.h"

namespace OHOS {
namespace Media {
static const std::string MEDIA_ASSET_DATA_HANDLER_CLASS = "MediaAssetDataHandler";

NapiMediaAssetDataHandler::NapiMediaAssetDataHandler(napi_env env,
    napi_value jsMediaAssetDataHandler, ReturnDataType dataType)
{
    thisVar_ = jsMediaAssetDataHandler;
    dataType_ = dataType;
    env_ = env;
    napi_status status = napi_get_named_property(env_, jsMediaAssetDataHandler, "onDataPrepared", &ondataPreparedFunc_);
    if (status != napi_ok) {
        NAPI_ERR_LOG("NapiMediaAssetDataHandler get onDataPrepared function failed");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "handler is invalid");
    }
}

ReturnDataType NapiMediaAssetDataHandler::GetHandlerType()
{
    return dataType_;
}

void NapiMediaAssetDataHandler::JsOnDataPreared(napi_value arg)
{
    napi_value argv[] = {arg};
    napi_value result = nullptr;
    if (ondataPreparedFunc_ == nullptr) {
        NAPI_ERR_LOG("NapiMediaAssetDataHandler JsOnDataPreared js function is null");
        NapiError::ThrowError(env_, JS_INNER_FAIL, "handler is invalid");
        return;
    }
    napi_status status = napi_call_function(env_, thisVar_, ondataPreparedFunc_, 1, argv, &result);
    if (status != napi_ok) {
        NAPI_ERR_LOG("call js function failed");
        NapiError::ThrowError(env_, JS_INNER_FAIL, "calling onDataPrepared failed");
    }
}
    
} // namespace Media
} // namespace Media
