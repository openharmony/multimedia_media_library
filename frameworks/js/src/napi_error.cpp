/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "napi_error.h"

#include "medialibrary_client_errno.h"
#include "medialibrary_napi_utils.h"
using namespace std;

namespace OHOS {
namespace Media {
void NapiError::SetApiName(const std::string &Name)
{
    apiName = Name;
}

void NapiError::SaveError(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    error = MediaLibraryNapiUtils::TransErrorCode(apiName, resultSet);
}

void NapiError::SaveError(int32_t ret)
{
    if (ret < 0) {
        error = MediaLibraryNapiUtils::TransErrorCode(apiName, ret);
    }
}

void NapiError::HandleError(napi_env env, napi_value &errorObj)
{
    // deal with context->error
    MediaLibraryNapiUtils::HandleError(env, error, errorObj, apiName);
}

void NapiError::ThrowError(napi_env env, int32_t err)
{
    string errMessage = "operation not support";
    string errCode = std::to_string(err);
    if (jsErrMap.count(err) > 0) {
        errMessage = jsErrMap.at(err);
    }
    NAPI_ERR_LOG("ThrowError errCode:%{public}d errMessage:%{public}s", err, errMessage.c_str());
    napi_throw_error(env, errCode.c_str(), errMessage.c_str());
}
} // namespace Media
} // namespace OHOS