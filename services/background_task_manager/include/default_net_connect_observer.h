/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEFAULT_NET_CONNECT_OBSERVER_H
#define OHOS_DEFAULT_NET_CONNECT_OBSERVER_H

#include "net_all_capabilities.h"
#include "net_conn_callback_stub.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))

enum class DefaultNetConnStatus : int32_t {
    NO_NETWORK = 0,
    WIFI_CONNECTED,
    CELLULAR_CONNECTED,
};

class EXPORT DefaultNetConnectObserver : public NetManagerStandard::NetConnCallbackStub {
public:
    DefaultNetConnectObserver() {}
    int32_t NetCapabilitiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
        const sptr<NetManagerStandard::NetAllCapabilities> &netAllCap) override;
    int32_t NetLost(sptr<NetManagerStandard::NetHandle> &netHandle) override;

private:
    void SetNetConnStatus(const DefaultNetConnStatus status);

private:
    DefaultNetConnStatus netStatus_ = DefaultNetConnStatus::NO_NETWORK;
};
} // namespace OHOS::Media
#endif  // OHOS_DEFAULT_NET_CONNECT_OBSERVER_H