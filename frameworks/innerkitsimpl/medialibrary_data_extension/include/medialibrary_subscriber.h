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
class MedialibrarySubscriber : public EventFwk::CommonEventSubscriber {
public:
    MedialibrarySubscriber() = default;
    explicit MedialibrarySubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    static bool Subscribe(void);
    virtual ~MedialibrarySubscriber() = default;

    virtual void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;

private:
    static const std::vector<std::string> events_;
    bool isScreenOff_;
    bool isPowerConnected_;

    void DoBackgroundOperation();
    void StopBackgroundOperation();
};
}  // namespace Media
}  // namespace OHOS

#endif // MEDIALIBRARY_SUBSCRIBER_H
