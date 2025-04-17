/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "media_change_request_impl.h"

#include "photo_accesshelper_impl.h"
#include "userfile_client.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Media {
bool MediaChangeRequestImpl::InitUserFileClient(int64_t contextId)
{
    if (UserFileClient::IsValid()) {
        return true;
    }

    std::unique_lock<std::mutex> helperLock(PhotoAccessHelperImpl::sUserFileClientMutex_);
    if (!UserFileClient::IsValid()) {
        auto context = FFIData::GetData<AbilityRuntime::CJAbilityContext>(contextId);
        if (context == nullptr) {
            LOGE("Get context instance failed.");
            return false;
        }
        sptr<IRemoteObject> token = context->GetToken();
        UserFileClient::Init(token);
    }
    helperLock.unlock();
    return UserFileClient::IsValid();
}
} // namespace Media
} // namespace OHOS