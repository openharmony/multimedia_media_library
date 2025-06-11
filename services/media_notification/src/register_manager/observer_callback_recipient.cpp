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

#include "observer_callback_recipient.h"
#include "media_datashare_stub_impl.h"
#include "medialibrary_errno.h"
#include "media_log.h"

namespace OHOS::Media {
using namespace Notification;
void ObserverCallbackRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    MEDIA_INFO_LOG("enter OnRemoteDied");
    auto observerManger = MediaObserverManager::GetObserverManager();
    int32_t ret = observerManger->RemoveObserver(object);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("failed to RemoveObserver, ret is %{public}d", (int)ret);
    }
    return;
}
} // OHOS::Media