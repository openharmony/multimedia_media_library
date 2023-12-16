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

#include <memory>
#include "appexecfwk_errors.h"
#include "background_task_mgr_helper.h"
#include "bundle_info.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "want.h"
#include "post_event_utils.h"

#include "medialibrary_bundle_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "medialibrary_inotify.h"
#include "application_context.h"
#include "ability_manager_client.h"
#include "resource_type.h"
using namespace OHOS::AAFwk;

namespace OHOS {
namespace Media {
const std::vector<std::string> MedialibrarySubscriber::events_ = {
    EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED,
    EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
    EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED
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
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) == 0) {
        string packageName = want.GetElement().GetBundleName();
        RevertPendingByPackage(packageName);
        MediaLibraryBundleManager::GetInstance()->Clear();
    }
}

int64_t MedialibrarySubscriber::GetNowTime()
{
    struct timespec t;
    constexpr int64_t SEC_TO_MSEC = 1e3;
    constexpr int64_t MSEC_TO_NSEC = 1e6;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * SEC_TO_MSEC + t.tv_nsec / MSEC_TO_NSEC;
}

void MedialibrarySubscriber::Init()
{
    lockTime_ = GetNowTime();
    agingCount_ = 0;
    scanCount_ = 0;
}

void MedialibrarySubscriber::DoBackgroundOperation()
{
    if (isScreenOff_ && isPowerConnected_) {
        BackgroundTaskMgr::EfficiencyResourceInfo resourceInfo = BackgroundTaskMgr::EfficiencyResourceInfo(
            BackgroundTaskMgr::ResourceType::CPU, true, 0, "apply", true, true);
        BackgroundTaskMgr::BackgroundTaskMgrHelper::ApplyEfficiencyResources(resourceInfo);
        Init();
        std::shared_ptr<MediaLibraryDataManager> dataManager = MediaLibraryDataManager::GetInstance();
        if (dataManager == nullptr) {
            return;
        }
        auto err = dataManager->GetAgingDataSize(lockTime_, agingCount_);
        if (err < 0) {
            MEDIA_ERR_LOG("GetAgingDataSize faild, err:%{public}d", err);
        }

        auto result = dataManager->GenerateThumbnails();
        if (result != E_OK) {
            MEDIA_ERR_LOG("GenerateThumbnails faild");
        }

        result = dataManager->DoAging();
        if (result != E_OK) {
            MEDIA_ERR_LOG("DoAging faild");
        }

        shared_ptr<int> trashCountPtr = make_shared<int>();
        result = dataManager->DoTrashAging(trashCountPtr);
        if (result != E_OK) {
            MEDIA_ERR_LOG("DoTrashAging faild");
        }

        VariantMap map = {{KEY_COUNT, *trashCountPtr}};
        PostEventUtils::GetInstance().PostStatProcess(StatType::AGING_STAT, map);

        auto watch = MediaLibraryInotify::GetInstance();
        if (watch != nullptr) {
            watch->DoAging();
        }
        auto scannerManager = MediaScannerManager::GetInstance();
        if (scannerManager == nullptr) {
            return;
        }
        scannerManager->ScanError();

        MEDIA_DEBUG_LOG("DoBackgroundOperation success isScreenOff_ %{public}d, isPowerConnected_ %{public}d",
            isScreenOff_, isPowerConnected_);
        
        result = dataManager->DoStopLongTimeTask();
        if (result != E_OK) {
            MEDIA_ERR_LOG("DoStopLongTimeTask faild");
        }
    }
}

void MedialibrarySubscriber::WriteThumbnailStat()
{
    std::shared_ptr<MediaLibraryDataManager> dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        return;
    }
    int agingCount = 0;
    int32_t err = dataManager->GetAgingDataSize(lockTime_, agingCount);
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get aging data size,err:%{public}d", err);
        return;
    }
    int agingSize = agingCount_ - agingCount;
    int generateSize = 0;
    err = dataManager->QueryNewThumbnailCount(lockTime_, generateSize);
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to query thumbnail count,err:%{public}d", err);
    }

    VariantMap map = {{KEY_GNUMS, generateSize}, {KEY_ANUMS, agingSize}};
    PostEventUtils::GetInstance().PostStatProcess(StatType::THUMBNAIL_STAT, map);
}


void MedialibrarySubscriber::StopBackgroundOperation()
{
    MediaLibraryDataManager::GetInstance()->InterruptBgworker();
    WriteThumbnailStat();
    BackgroundTaskMgr::BackgroundTaskMgrHelper::ResetAllEfficiencyResources();
}

void MedialibrarySubscriber::DoStartMtpService()
{
    AAFwk::Want want;
    want.SetElementName("com.ohos.medialibrary.medialibrarydata", "MtpService");
    auto abilityContext = AbilityRuntime::Context::GetApplicationContext();
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, abilityContext->GetToken(),
        OHOS::AAFwk::DEFAULT_INVAL_VALUE);
    MEDIA_INFO_LOG("MedialibrarySubscriber::DoStartMtpService. End calling StartAbility. ret=%{public}d", err);
}

void MedialibrarySubscriber::RevertPendingByPackage(const std::string &bundleName)
{
    MediaLibraryDataManager::GetInstance()->RevertPendingByPackage(bundleName);
}
}  // namespace Media
}  // namespace OHOS
