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

#ifndef OHOS_MEDIA_I_OBSERVER_MANAGER_INTERFACE_H
#define OHOS_MEDIA_I_OBSERVER_MANAGER_INTERFACE_H

#include "data_ability_observer_stub.h"
#include "observer_info.h"
#include "media_change_info.h"

namespace OHOS {
namespace Media {
namespace Notification {
#define EXPORT __attribute__ ((visibility ("default")))

class IObserverManager {
public:
    EXPORT IObserverManager() = default;
    EXPORT virtual ~IObserverManager() = default;
    EXPORT virtual int32_t AddObserver(const NotifyUriType &uri, const sptr<AAFwk::IDataAbilityObserver>
        &dataObserver, bool isReconnect) = 0;
    EXPORT virtual int32_t RemoveObserver(const wptr<IRemoteObject> &object) = 0;
    EXPORT virtual std::vector<ObserverInfo> FindObserver(const NotifyUriType &uri) = 0;
    EXPORT virtual int32_t RemoveObserverWithUri(const NotifyUriType &uri,
        const sptr<AAFwk::IDataAbilityObserver> &dataObserver) = 0;
};

} // Notification
} // Media
} // OHOS

#endif //OHOS_MEDIA_I_OBSERVER_MANAGER_INTERFACE_H
