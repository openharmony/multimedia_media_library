/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "media_event_receiver.h"
#include "media_log.h"
#include "inner/task_event_receiver.h"
namespace OHOS {
namespace Media {
namespace {
}
MediaEventReceiver::MediaEventReceiver()
{
    MEDIA_DEBUG_LOG("MediaEventReceiver created|");
}

MediaEventReceiver::~MediaEventReceiver()
{
    MEDIA_DEBUG_LOG("MediaEventReceiver released|");
}

void MediaEventReceiver::Init(void)
{
    MEDIA_DEBUG_LOG("MediaEventReceiver::Init enter|");

    auto &receiver = TaskEventReceiver::GetInstance();
    receiver.Init();

    MEDIA_DEBUG_LOG("MediaEventReceiver::Init leave|");
}

void MediaEventReceiver::OnEvent(const std::string &event)
{
    MEDIA_DEBUG_LOG("MediaEventReceiver::OnEvent enter|");

    auto &receiver = TaskEventReceiver::GetInstance();
    receiver.Init();
    receiver.OnEvent(event);

    MEDIA_DEBUG_LOG("MediaEventReceiver::OnEvent leave|");
}
} // namespace Media
} // namespace OHOS