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

NapiMediaAssetDataHandler::NapiMediaAssetDataHandler(napi_env env, napi_value dataHandler, ReturnDataType dataType,
    const std::string &uri, const std::string &destUri, SourceMode sourceMode)
{
    dataType_ = dataType;
    env_ = env;
    requestUri_ = uri;
    destUri_ = destUri;
    sourceMode_ = sourceMode;
    napi_status status = napi_create_reference(env_, dataHandler, PARAM1, &dataHandlerRef_);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi_create_reference failed");
        NapiError::ThrowError(env_, OHOS_INVALID_PARAM_CODE, "napi_create_reference fail");
    }
}

NapiMediaAssetDataHandler::~NapiMediaAssetDataHandler()
{
    if (dataHandlerRef_ != nullptr) {
        napi_delete_reference(env_, dataHandlerRef_);
    }
}

ReturnDataType NapiMediaAssetDataHandler::GetReturnDataType()
{
    return dataType_;
}

napi_env NapiMediaAssetDataHandler::GetEnv()
{
    return env_;
}

std::string NapiMediaAssetDataHandler::GetRequestUri()
{
    return requestUri_;
}

std::string NapiMediaAssetDataHandler::GetDestUri()
{
    return destUri_;
}

SourceMode NapiMediaAssetDataHandler::GetSourceMode()
{
    return sourceMode_;
}

void NapiMediaAssetDataHandler::SetNotifyMode(NotifyMode notifyMode)
{
    notifyMode_ = notifyMode;
}

NotifyMode NapiMediaAssetDataHandler::GetNotifyMode()
{
    return notifyMode_;
}

void NapiMediaAssetDataHandler::JsOnDataPrepared(napi_value arg, napi_value extraInfo)
{
    if (dataHandlerRef_ == nullptr) {
        NAPI_ERR_LOG("JsOnDataPrepared js function is null");
        return;
    }

    napi_value callback;
    napi_status status = napi_get_reference_value(env_, dataHandlerRef_, &callback);
    if (status != napi_ok) {
        NAPI_ERR_LOG("JsOnDataPrepared napi_get_reference_value fail, napi status: %{public}d",
            static_cast<int>(status));
        return;
    }

    napi_value jsOnDataPrepared;
    status = napi_get_named_property(env_, callback, ON_DATA_PREPARED_FUNC, &jsOnDataPrepared);
    if (status != napi_ok) {
        NAPI_ERR_LOG("JsOnDataPrepared napi_get_named_property fail, napi status: %{public}d",
            static_cast<int>(status));
        return;
    }

    constexpr size_t maxArgs = 2;
    napi_value argv[maxArgs];
    size_t argc = 0;
    if (extraInfo != nullptr) {
        argv[PARAM0] = arg;
        argv[PARAM1] = extraInfo;
        argc = ARGS_TWO;
    } else {
        argv[PARAM0] = arg;
        argc = ARGS_ONE;
    }
    napi_value promise;
    status = napi_call_function(env_, nullptr, jsOnDataPrepared, argc, argv, &promise);
    if (status != napi_ok) {
        NAPI_ERR_LOG("call js function failed %{public}d", static_cast<int32_t>(status));
        NapiError::ThrowError(env_, JS_INNER_FAIL, "calling onDataPrepared failed");
    }
}
} // namespace Media
} // namespace OHOS
