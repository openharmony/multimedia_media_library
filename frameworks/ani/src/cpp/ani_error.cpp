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

#include "ani_error.h"

#include "medialibrary_client_errno.h"
#include "medialibrary_ani_utils.h"
using namespace std;

namespace OHOS {
namespace Media {
void AniError::SetApiName(const std::string &Name)
{
    apiName = Name;
}

void AniError::SaveError(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    error = MediaLibraryAniUtils::TransErrorCode(apiName, resultSet);
}

void AniError::SaveError(int32_t ret)
{
    if (ret < 0) {
        error = MediaLibraryAniUtils::TransErrorCode(apiName, ret);
    }
}

void AniError::HandleError(ani_env *env, ani_error &errorObj)
{
    // deal with context->error
    MediaLibraryAniUtils::HandleError(env, error, errorObj, apiName);
}

void AniError::ThrowError(ani_env *env, int32_t err, const std::string &errMsg)
{
    string message = errMsg;
    if (message.empty()) {
        message = "operation not support";
        if (jsErrMap.count(err) > 0) {
            message = jsErrMap.at(err);
        }
    }

    ANI_ERR_LOG("ThrowError errCode:%{public}d errMsg:%{public}s", err, message.c_str());
    ani_error aniError;
    MediaLibraryAniUtils::CreateAniErrorObject(env, aniError, err, errMsg);
    env->ThrowError(aniError);
}

void AniError::ThrowError(ani_env *env, int32_t err, const char *funcName, int32_t line, const std::string &errMsg)
{
    string message = errMsg;
    if (message.empty()) {
        message = "operation not support";
        if (jsErrMap.count(err) > 0) {
            message = jsErrMap.at(err);
        }
    }

    ANI_ERR_LOG("{%{public}s:%d} ThrowError errCode:%{public}d errMsg:%{public}s", funcName, line,
        err, message.c_str());
    ani_error aniError;
    MediaLibraryAniUtils::CreateAniErrorObject(env, aniError, err, errMsg);
    env->ThrowError(aniError);
}

} // namespace Media
} // namespace OHOS