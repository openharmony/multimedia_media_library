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


#include "notification_distribution.h"

#include "media_log.h"
#include "notify_info.h"
#include "media_observer_manager.h"
#include "notify_register_permission.h"
#include "media_column.h"
#include "photo_album_column.h"
#include "media_change_info.h"
#include "medialibrary_errno.h"
#include "observer_info.h"
#include "notification_merging.h"
#include "media_notification_utils.h"

#include <map>
#include <unordered_set>
#include <securec.h>

using namespace std;

namespace OHOS {
namespace Media {
namespace Notification {
NotificationDistribution::NotificationDistribution() {}

NotificationDistribution::~NotificationDistribution() {}

MediaChangeInfo NotificationDistribution::FilterNotifyInfoByPermission(
    const MediaChangeInfo& changeInfo, NotifyUriType notifyUriType)
{
    const NotifyUriType changeUri = changeInfo.notifyUri;

    if ((notifyUriType == NotifyUriType::PHOTO_URI || notifyUriType == NotifyUriType::PHOTO_ALBUM_URI) &&
        changeUri == notifyUriType) {
        return changeInfo;
    }

    if (notifyUriType == NotifyUriType::HIDDEN_PHOTO_URI ||
        notifyUriType == NotifyUriType::HIDDEN_ALBUM_URI) {
        return changeInfo;
    }

    if ((notifyUriType == NotifyUriType::TRASH_PHOTO_URI ||
         notifyUriType == NotifyUriType::TRASH_ALBUM_URI) &&
        (changeUri == NotifyUriType::PHOTO_URI ||
         changeUri == NotifyUriType::TRASH_PHOTO_URI ||
         changeUri == NotifyUriType::PHOTO_ALBUM_URI ||
         changeUri == NotifyUriType::TRASH_ALBUM_URI)) {
        return changeInfo;
    }

    return MediaChangeInfo{};
}

int32_t NotificationDistribution::SendNotificationWithRecheckChangeInfo(
    const MediaChangeInfo& changeInfo, const ObserverInfo& observerInfo)
{
    MediaChangeInfo recheckChangeInfo = changeInfo;
    recheckChangeInfo.changeInfos.clear();
    recheckChangeInfo.isForRecheck = true;
    recheckChangeInfo.isSystem = observerInfo.isSystem;
    if (changeInfo.notifyType == NotifyType::NOTIFY_ASSET_ADD ||
        changeInfo.notifyType == NotifyType::NOTIFY_ASSET_UPDATE ||
        changeInfo.notifyType == NotifyType::NOTIFY_ASSET_REMOVE) {
        recheckChangeInfo.notifyType = NotifyType::NOTIFY_ASSET_ADD;
    } else {
        recheckChangeInfo.notifyType = NotifyType::NOTIFY_ALBUM_ADD;
    }
    shared_ptr<MediaChangeInfo> sharedChangeInfo = make_shared<MediaChangeInfo>(recheckChangeInfo);
    return NotificationUtils::SendNotification(observerInfo.observer, sharedChangeInfo);
}

int32_t NotificationDistribution::ProcessMediaChangeInfos(
    const std::vector<Notification::MediaChangeInfo>& mediaChangeInfos,
    Notification::NotifyUriType notifyUriType,
    const ObserverInfo& observerInfo)
{
    for (const auto& mediaChangeInfo : mediaChangeInfos) {
        // 如果存在一个isForRecheck为true，只需要发送一个add通知
        if (mediaChangeInfo.isForRecheck) {
            return SendNotificationWithRecheckChangeInfo(mediaChangeInfo, observerInfo);
        }
    }
    for (const auto& mediaChangeInfo : mediaChangeInfos) {
        MEDIA_INFO_LOG("mediaChangeInfo:%{public}s", mediaChangeInfo.ToString().c_str());
        if (mediaChangeInfo.changeInfos.empty()) {
            MEDIA_INFO_LOG("mediaChangeInfo changeInfos is null");
            continue;
        }
        MediaChangeInfo filteredInfo = FilterNotifyInfoByPermission(mediaChangeInfo, notifyUriType);
        if (filteredInfo.changeInfos.empty()) {
            MEDIA_INFO_LOG("After filtering mediaChangeInfo changeInfos is null");
            continue;
        }
        filteredInfo.isSystem = observerInfo.isSystem;
        shared_ptr<MediaChangeInfo> sharedChangeInfo = make_shared<MediaChangeInfo>(filteredInfo);
        int32_t ret = NotificationUtils::SendNotification(observerInfo.observer, sharedChangeInfo);
        CHECK_AND_RETURN_RET_LOG(ret != E_OK, ret, "CallbackProcessing fail err:%{public}d", ret);
        MEDIA_INFO_LOG("CallbackProcessing ret:%{public}d", ret);
    }
    return E_OK;
}

int32_t NotificationDistribution::ProcessNotifyInfo(const NotifyInfo& notifyInfo)
{
    for (const auto& observerInfo : notifyInfo.observerInfos) {
        for (const auto& [notifyUriType, mediaChangeInfos] : notifyInfo.changeInfosMap) {
            if (!mediaChangeInfos.empty()) {
                ProcessMediaChangeInfos(mediaChangeInfos, notifyUriType, observerInfo);
            }
        }
    }
    return E_OK;
}

int32_t NotificationDistribution::DistributeNotifyInfo(const std::vector<NotifyInfo>& notifyInfos)
{
    CHECK_AND_RETURN_RET_LOG(!notifyInfos.empty(), E_OK, "notifyInfos is null");

    MEDIA_INFO_LOG("enter distributeNotifyInfo, notifyInfos size:%{public}d", static_cast<int32_t>(notifyInfos.size()));

    for (const auto& notifyInfo : notifyInfos) {
        if (notifyInfo.observerInfos.empty() || notifyInfo.changeInfosMap.empty()) {
            MEDIA_INFO_LOG("notifyInfo has empty observerInfos or changeInfosMap");
            continue;
        }

        ProcessNotifyInfo(notifyInfo);
    }
    return E_OK;
}

} // Notification
} // Media
} // OHOS