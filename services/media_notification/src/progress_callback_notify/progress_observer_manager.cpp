/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <cstring>
#include <string>
#include <sstream>
#include "progress_observer_manager.h"
#include "media_progress_change_info.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include <securec.h>

namespace OHOS {
namespace Media {
namespace Notification {
const size_t MAX_PARCEL_SIZE = 200 * 1024 * 0.95;
ProgressObserverManager &ProgressObserverManager::GetInstance()
{
    static ProgressObserverManager instance;
    return instance;
}

int32_t ProgressObserverManager::AddObserver(const int32_t &requestId,
    const sptr<AAFwk::IDataAbilityObserver> &observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(observers_.count(requestId) == 0, E_ERR, "requestId has been registered");
    observers_[requestId] = observer;
    MEDIA_INFO_LOG("ObserverManager::AddObserver, requestId: %{public}d", (int)requestId);
    return E_OK;
}

int32_t ProgressObserverManager::RemoveObserver(const int32_t &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(observers_.count(requestId) != 0, E_ERR, "requestId has not been registered");
    observers_.erase(requestId);
    MEDIA_INFO_LOG("ObserverManager::RemoveObserver, requestId: %{public}d", (int)requestId);
    return E_OK;
}

sptr<AAFwk::IDataAbilityObserver> ProgressObserverManager::GetObserver(const int32_t &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = observers_.find(requestId);
    if (it != observers_.end()) {
        return it->second;
    }
    return nullptr;
}

bool ProgressObserverManager::NotifyProgress(const std::shared_ptr<MediaProgressChangeInfo> &progressInfo)
{
    auto observer = GetObserver(progressInfo->requestId);

    Parcel parcel;
    bool ret = progressInfo->Marshalling(parcel);
    CHECK_AND_RETURN_RET_LOG(ret, false, "fail to marshlling");
    CHECK_AND_RETURN_RET_LOG(parcel.GetDataSize() < MAX_PARCEL_SIZE, false,
        "The size of the parcel exceeds the limit.");
    uintptr_t buf = parcel.GetData();
    auto *uBuf = new (std::nothrow) uint8_t[parcel.GetDataSize()];
    if (uBuf == nullptr) {
        MEDIA_ERR_LOG("parcel->GetDataSize is null");
        return false;
    }
    int res = memcpy_s(uBuf, parcel.GetDataSize(), reinterpret_cast<uint8_t *>(buf), parcel.GetDataSize());
    if (res != 0) {
        MEDIA_ERR_LOG("Parcel data copy failed, err = %{public}d", res);
        if (uBuf != nullptr) {
            delete[] uBuf;
            uBuf = nullptr;
        }
        return false;
    }
    AAFwk::ChangeInfo serverChangeInfo;
    serverChangeInfo.data_ = uBuf;
    serverChangeInfo.size_ = parcel.GetDataSize();

    if (observer != nullptr) {
        observer->OnChangeExt(serverChangeInfo);
    } else {
        MEDIA_WARN_LOG("ObserverManager::NotifyProgress, observer not found, requestId: %{public}d",
            (int)progressInfo->requestId);
    }
    return true;
}

} // namespace Notification
} // namespace Media
} // namespace OHOS