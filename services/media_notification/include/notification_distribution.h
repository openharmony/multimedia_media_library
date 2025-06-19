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
 
#ifndef OHOS_MEDIA_NOTIFICATION_DISTRIBUTION_H
#define OHOS_MEDIA_NOTIFICATION_DISTRIBUTION_H
 
#include <vector>
#include <unordered_map>
#include <functional>
#include <variant>
 
#include "notify_info.h"
#include "media_change_info.h"
 
namespace OHOS {
namespace Media {
namespace Notification {
#define EXPORT __attribute__ ((visibility ("default")))
class NotificationDistribution {
public:
    EXPORT NotificationDistribution();
    EXPORT ~NotificationDistribution();
    EXPORT static int32_t DistributeNotifyInfo(const std::vector<NotifyInfo>& notifyInfos);
private:
    static MediaChangeInfo FilterNotifyInfoByPermission(const MediaChangeInfo& changeInfo, NotifyUriType notifyUriType);
    static int32_t SendNotificationWithRecheckChangeInfo(const MediaChangeInfo& changeInfo,
        const ObserverInfo& observerInfo);
    static int32_t ProcessMediaChangeInfos(const std::vector<Notification::MediaChangeInfo>& mediaChangeInfos,
        Notification::NotifyUriType notifyUriType, const ObserverInfo& observerInfo);
    static int32_t ProcessNotifyInfo(const NotifyInfo& notifyInfo);
};
} // namespace Notification
} // namespace Media
} // namespace OHOS
 
#endif  // OHOS_MEDIA_NOTIFICATION_DISTRIBUTION_H