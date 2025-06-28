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

#ifndef  INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_PEER_INFO_H_
#define  INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_PEER_INFO_H_

#include <cstdint>
#ifdef  DM_DEVICE_INFO_ENABLE
#include "dm_device_info.h"
#endif

namespace OHOS {
namespace Media {
typedef struct PeerInfo {
    std::string deviceName;
    std::string networkId;
    DistributedHardware::DmDeviceType deviceTypeId;
    bool isOnline;
} PeerInfo;
} // namespace Media
} // namespace OHOS
#endif //  INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_PEER_INFO_H_
