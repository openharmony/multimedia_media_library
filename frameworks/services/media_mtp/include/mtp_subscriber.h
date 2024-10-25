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
#ifndef OHOS_MTP_SUBSCRIBER_H
#define OHOS_MTP_SUBSCRIBER_H

#include "common_event_subscriber.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MtpSubscriber : public EventFwk::CommonEventSubscriber {
public:
    EXPORT virtual ~MtpSubscriber() = default;
    EXPORT explicit MtpSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);

    EXPORT static bool Subscribe(void);
    EXPORT void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MTP_SUBSCRIBER_H
