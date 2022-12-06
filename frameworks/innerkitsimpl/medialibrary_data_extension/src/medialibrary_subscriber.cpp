/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Subscribe"

#include "medialibrary_subscriber.h"

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "want.h"

#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_scanner_manager.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace Media {
const std::vector<std::string> MedialibrarySubscriber::events_ = {
    EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED,
    EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON
};

MedialibrarySubscriber::MedialibrarySubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : EventFwk::CommonEventSubscriber(subscriberInfo)
{
    isScreenOff_ = false;
    isPowerConnected_ = false;
}

bool MedialibrarySubscriber::Subscribe(void)
{
    EventFwk::MatchingSkills matchingSkills;
    for (auto event : events_) {
        matchingSkills.AddEvent(event);
    }
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    std::shared_ptr<MedialibrarySubscriber> subscriber = std::make_shared<MedialibrarySubscriber>(subscribeInfo);
    return EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber);
}

void MedialibrarySubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const AAFwk::Want& want = eventData.GetWant();
    std::string action = want.GetAction();
    MEDIA_INFO_LOG("OnReceiveEvent action:%{public}s.", action.c_str());

    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) == 0) {
        isScreenOff_ = true;
        DoBackgroundOperation();
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED) == 0) {
        isPowerConnected_ = true;
        DoBackgroundOperation();
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) == 0) {
        isScreenOff_ = false;
        StopBackgroundOperation();
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED) == 0) {
        isPowerConnected_ = false;
        StopBackgroundOperation();
    }
}

void MedialibrarySubscriber::DoBackgroundOperation()
{
    if (isScreenOff_ && isPowerConnected_) {
        std::shared_ptr<MediaLibraryDataManager> dataManager = MediaLibraryDataManager::GetInstance();
        if (dataManager == nullptr) {
            return;
        }
        auto result = dataManager->GenerateThumbnails();
        if (result != E_OK) {
            MEDIA_ERR_LOG("GenerateThumbnails faild");
        }

        result = dataManager->DoAging();
        if (result != E_OK) {
            MEDIA_ERR_LOG("DoAging faild");
        }
    } else {
        MEDIA_DEBUG_LOG("DoBackgroundOperation success isScreenOff_ %{public}d, isPowerConnected_ %{public}d",
            isScreenOff_, isPowerConnected_);
    }
}

void MedialibrarySubscriber::StopBackgroundOperation()
{
    MediaLibraryDataManager::GetInstance()->InterruptBgworker();
}
}  // namespace Media
}  // namespace OHOS
