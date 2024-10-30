/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_STANDBY_SERVICE_SUBSCRIBER_H
#define MEDIALIBRARY_STANDBY_SERVICE_SUBSCRIBER_H
#ifdef DEVICE_STANDBY_ENABLE

#include "standby_service_client.h"
#include "standby_service_subscriber_stub.h"

namespace OHOS {
namespace Media {
const uint32_t NORMAL = 0;
const uint32_t MINOR = 1;
const uint32_t WARNING = 2;
const uint32_t SERIOUS = 3;
const uint32_t EXTREME = 4;
const uint32_t FATAL = 5;

class MediaLibraryStandbyServiceSubscriber : public DevStandbyMgr::StandbyServiceSubscriberStub {
public:
    void OnPowerOverused(const std::string& module, uint32_t level) override;
};
} // namespace Media
} // namespace OHOS
#endif
#endif // MEDIALIBRARY_STANDBY_SERVICE_SUBSCRIBER_H