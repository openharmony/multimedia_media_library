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
#ifndef MEDIALIBRARY_SUBSCRIBER_H
#define MEDIALIBRARY_SUBSCRIBER_H

#include <thread>

#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "matching_skills.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
enum class StatusEventType {
    CHARGING,
    DISCHARGING,
    SCREEN_OFF,
    SCREEN_ON,
    BATTERY_CHANGED,
    THERMAL_LEVEL_CHANGED
};

class EXPORT MedialibrarySubscriber : public EventFwk::CommonEventSubscriber {
public:
    EXPORT MedialibrarySubscriber() = default;
    EXPORT explicit MedialibrarySubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    EXPORT static bool Subscribe(void);
    EXPORT virtual ~MedialibrarySubscriber();

    EXPORT virtual void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;
    EXPORT static bool IsCellularNetConnected();
    EXPORT static bool IsWifiConnected();
    EXPORT static bool IsCurrentStatusOn();

private:
    static const std::vector<std::string> events_;
    bool isScreenOff_ {false};
    bool isCharging_ {false};
    bool isPowerSufficient_{false};
    bool isDeviceTemperatureProper_{false};
    static bool isWifiConnected_;
    static bool currentStatus_;
    bool timerStatus_{false};
    static bool isCellularNetConnected_;
    std::mutex mutex_;
    int32_t agingCount_ {0};
    int32_t deviceTemperatureLevel_ {0};
    int32_t newTemperatureLevel_ {0};
    int64_t lockTime_ {0};

    std::mutex delayTaskLock_;
    std::condition_variable delayTaskCv_;
    bool isTaskWaiting_{false};
    std::thread backgroundOperationThread_;

    EXPORT void DoBackgroundOperation();
    EXPORT void StopBackgroundOperation();
    EXPORT void StartAnalysisService();
    void WalCheckPointAsync();

#ifdef MEDIALIBRARY_MTP_ENABLE
    void DoStartMtpService();
#endif
    void RevertPendingByPackage(const std::string &bundleName);
    int64_t GetNowTime();
    void Init();
    void UpdateBackgroundOperationStatus(const AAFwk::Want &want, const StatusEventType statusEventType);
    void UpdateCloudMediaAssetDownloadStatus(const AAFwk::Want &want, const StatusEventType statusEventType);
    void UpdateCurrentStatus();
    void CheckHalfDayMissions();
    void UpdateBackgroundTimer();
    void DoThumbnailOperation();
    bool IsDelayTaskTimeOut();
    void EndBackgroundOperationThread();
    void UpdateCloudMediaAssetDownloadTaskStatus();
};
}  // namespace Media
}  // namespace OHOS

#endif // MEDIALIBRARY_SUBSCRIBER_H
