/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MultistagesCapture::Notify"

#include "multistages_capture_notify.h"

#include "low_quality_memory_num_notify_info.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify_new.h"
#include "notification_distribution.h"
#include "user_define_notify_info.h"

namespace OHOS {
namespace Media::Notification {
int32_t MultistagesCaptureNotify::SyncNotifyLowQualityMemoryCount(int32_t count)
{
    MEDIA_INFO_LOG("count: %{public}d.", count);
    auto notifyBody = std::make_shared<LowQualityMemoryNumNotifyInfo>();
    CHECK_AND_RETURN_RET_LOG(notifyBody != nullptr, E_ERR, "notifyBody is nullptr");
    notifyBody->count_ = count;

    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::LOW_QUALITY_MEMORY);
    notifyInfo.SetUserDefineNotifyBody(notifyBody);

    NotificationDistribution::DistributeUserDefineNotifyInfo({ notifyInfo });
    return E_OK;
}

} // namespace Media::Notification
} // namespace OHOS