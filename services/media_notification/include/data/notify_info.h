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

#ifndef OHOS_MEDIA_NOTIFY_INFO_H
#define OHOS_MEDIA_NOTIFY_INFO_H

#include "observer_info.h"
#include "media_change_info.h"

namespace OHOS {
namespace Media {
namespace Notification {

struct NotifyInfo {
    std::vector<ObserverInfo> observerInfos;
    std::unordered_map<Notification::NotifyUriType, std::vector<Notification::MediaChangeInfo>> changeInfosMap;
};
} // namespace Notification
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_NOTIFY_INFO_INNER_H