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

#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "matching_skills.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MedialibrarySubscriber : public EventFwk::CommonEventSubscriber {
public:
    EXPORT MedialibrarySubscriber() = default;
    EXPORT explicit MedialibrarySubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    EXPORT static bool Subscribe(void);
    EXPORT virtual ~MedialibrarySubscriber() = default;

    EXPORT virtual void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;

private:
    static const std::vector<std::string> events_;
    bool isScreenOff_ {false};
    bool isCharging_ {false};
    int32_t agingCount_;
    int64_t lockTime_;
    EXPORT void DoBackgroundOperation();
    EXPORT void StopBackgroundOperation();

#ifdef MEDIALIBRARY_MTP_ENABLE
    void DoStartMtpService();
#endif
    void RevertPendingByPackage(const std::string &bundleName);
    int64_t GetNowTime();
    void Init();
};
}  // namespace Media
}  // namespace OHOS

#endif // MEDIALIBRARY_SUBSCRIBER_H
