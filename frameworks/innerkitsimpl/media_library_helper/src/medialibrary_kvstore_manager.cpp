/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "medialibrary_kvstore_manager.h"

#include <atomic>
#include <shared_mutex>

#include "medialibrary_errno.h"
#include "media_log.h"

namespace OHOS::Media {
std::mutex MediaLibraryKvStoreManager::mutex_;
Utils::Timer MediaLibraryKvStoreManager::timer_("close_kvStore");
std::atomic<uint32_t> MediaLibraryKvStoreManager::insertImageCount_ = 0;
uint32_t MediaLibraryKvStoreManager::timerId_ = 0;

MediaLibraryKvStoreManager::~MediaLibraryKvStoreManager()
{
    timer_.Unregister(timerId_);
    timer_.Shutdown();
    timerId_ = 0;
}

int32_t MediaLibraryKvStoreManager::InitKvStore(const KvStoreRoleType &roleType, const KvStoreValueType &valueType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    KvStoreSharedPtr ptr;
    if (kvStoreMap_.Find(valueType, ptr)) {
        return E_OK;
    }

    std::string baseDir = "";
    if (roleType == KvStoreRoleType::OWNER) {
        baseDir = KV_STORE_OWNER_DIR;
    } else if (roleType == KvStoreRoleType::VISITOR) {
        baseDir = KV_STORE_VISITOR_DIR;
    } else {
        MEDIA_ERR_LOG("invalid role type");
        return E_ERR;
    }

    ptr = std::make_shared<MediaLibraryKvStore>();
    int32_t status = ptr->Init(roleType, valueType, baseDir);
    if (status != E_OK) {
        MEDIA_ERR_LOG("init kvStore failed, status %{public}d", status);
        return status;
    }
    kvStoreMap_.Insert(valueType, ptr);
    return E_OK;
}

std::shared_ptr<MediaLibraryKvStore> MediaLibraryKvStoreManager::GetKvStore(
    const KvStoreRoleType &roleType, const KvStoreValueType &valueType)
{
    RegisterTimer(roleType, valueType);
    KvStoreSharedPtr ptr;
    if (kvStoreMap_.Find(valueType, ptr)) {
        return ptr;
    }

    InitKvStore(roleType, valueType);
    kvStoreMap_.Find(valueType, ptr);
    return ptr;
}

void MediaLibraryKvStoreManager::CloseAllKvStore()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (kvStoreMap_.IsEmpty()) {
        return;
    }

    std::set<KvStoreValueType> valueTypes;
    kvStoreMap_.Iterate([&valueTypes](KvStoreValueType valueType, KvStoreSharedPtr &ptr) {
        if (ptr != nullptr && ptr->Close()) {
            valueTypes.insert(valueType);
        }
    });
    for (auto type : valueTypes) {
        kvStoreMap_.Erase(type);
    }
    valueTypes.clear();
}

bool MediaLibraryKvStoreManager::CloseKvStore(const KvStoreValueType &valueType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    KvStoreSharedPtr ptr;
    if (!kvStoreMap_.Find(valueType, ptr)) {
        return false;
    }

    if (ptr != nullptr && ptr->Close()) {
        kvStoreMap_.Erase(valueType);
        MEDIA_INFO_LOG("CloseKvStore success, valueType %{public}d", valueType);
        return true;
    }
    return false;
}

void MediaLibraryKvStoreManager::RegisterTimer(const KvStoreRoleType &roleType, const KvStoreValueType &valueType)
{
    if (roleType != KvStoreRoleType::OWNER) {
        return;
    }

    Utils::Timer::TimerCallback timerCallback = [this]() {
        MEDIA_INFO_LOG("KvStore timerCallback, CloseAllKvStore");
        insertImageCount_ = 0;
        CloseAllKvStore();
    };

    std::lock_guard<std::mutex> lock(mutex_);
    if (timerId_ == 0) {
        MEDIA_INFO_LOG("KvStore timer Setup");
        timer_.Setup();
    }
    
    if (insertImageCount_ == 0 || insertImageCount_ >= KVSTORE_INSERT_COUNT) {
        timer_.Unregister(timerId_);
        insertImageCount_ = 0;
        timerId_ = timer_.Register(timerCallback, CLOSE_KVSTORE_TIME_INTERVAL, true);
        MEDIA_INFO_LOG("KvStore timer Restart");
    }
    insertImageCount_++;
}
} // namespace OHOS::Media