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
#define MLOG_TAG "DfxTimer"

#include "dfx_timer.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "dfx_manager.h"
#include "medialibrary_bundle_manager.h"

namespace OHOS {
namespace Media {
DfxTimer::DfxTimer(int32_t type, int32_t object, int64_t timeOut, bool isReport)
{
    type_ = type;
    object_ = object;
    start_ = MediaFileUtils::UTCTimeMilliSeconds();
    timeOut_ = timeOut;
    isReport_ = isReport;
    isEnd_ = false;
}

DfxTimer::~DfxTimer()
{
    if (isEnd_) {
        return;
    }
    timeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start_;
    if (timeCost_ > timeOut_) {
        if (isReport_) {
            std::string bundleName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
            MEDIA_WARN_LOG("timeout! bundleName: %{public}s, type: %{public}d, object: %{public}d, cost %{public}d",
                bundleName.c_str(), type_, object_, (int) (timeCost_));
            if (timeCost_ > TO_MILLION) {
                DfxManager::GetInstance()->HandleTimeOutOperation(bundleName, type_, object_, (int) (timeCost_));
            }
        } else {
            MEDIA_WARN_LOG("timeout! type: %{public}d, object: %{public}d, cost %{public}lld ms", type_,
                object_, (long long) (timeCost_));
        }
    }
    if (isReport_) {
        DfxManager::GetInstance()->HandleCommonBehavior(MediaLibraryBundleManager::GetInstance()->GetClientBundleName(),
            type_);
    }
}

void DfxTimer::End()
{
    timeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start_;
    if (timeCost_ > timeOut_) {
        MEDIA_WARN_LOG("timeout! type: %{public}d, object: %{public}d, cost %{public}d ms", type_, object_,
            (int) (timeCost_));
    }
    isEnd_ = true;
}

} // namespace Media
} // namespace OHOS