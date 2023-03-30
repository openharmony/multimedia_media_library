/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "mtp_storage_manager.h"
#include <mutex>
#include <sys/statvfs.h>

#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "system_ability_definition.h"

using namespace std;

namespace OHOS {
namespace Media {

std::shared_ptr<MtpStorageManager> MtpStorageManager::instance_ = nullptr;
std::mutex MtpStorageManager::mutex_;

MtpStorageManager::MtpStorageManager(void)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remote = samgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    proxy_ = iface_cast<StorageManager::IStorageManager>(remote);
}

MtpStorageManager::~MtpStorageManager(void)
{
}

std::shared_ptr<MtpStorageManager> MtpStorageManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::shared_ptr<MtpStorageManager>(new MtpStorageManager());
        }
    }
    return instance_;
}

int64_t MtpStorageManager::GetTotalSize()
{
    struct statvfs diskInfo;
    int ret = statvfs("/data", &diskInfo);
    if (ret != 0) {
        MEDIA_ERR_LOG("GetTotalSize failed, errno: %{public}d", errno);
        return MTP_FAIL;
    }
    int64_t totalSize =
        static_cast<long long>(diskInfo.f_bsize) * static_cast<long long>(diskInfo.f_blocks);
    return totalSize;
}

int64_t MtpStorageManager::GetFreeSize()
{
    struct statvfs diskInfo;
    int ret = statvfs("/data", &diskInfo);
    if (ret != 0) {
        MEDIA_ERR_LOG("GetFreeSize failed, errno: %{public}d", errno);
        return MTP_FAIL;
    }
    int64_t freeSize =
        static_cast<long long>(diskInfo.f_bsize) * static_cast<long long>(diskInfo.f_bfree);
    return freeSize;
}

void MtpStorageManager::AddStorage(shared_ptr<Storage> &storage)
{
    storages.push_back(storage);
}

void MtpStorageManager::RemoveStorage(std::shared_ptr<Storage> &storage)
{
    auto iter = std::find(storages.begin(), storages.end(), storage);
    if (iter != storages.end()) {
        storages.erase(iter);
    }
}

shared_ptr<Storage> MtpStorageManager::GetStorage(uint32_t id)
{
    for (auto storage : storages) {
        if (storage->GetStorageID() == id) {
            return storage;
        }
    }
    return nullptr;
}

bool MtpStorageManager::HasStorage(uint32_t id)
{
    bool result = false;

    if (id == MTP_STORAGE_ID_ALL || id == MTP_STORAGE_ID_ALL2) {
        result = (storages.size() > 0);
    } else {
        result = (GetStorage(id) != nullptr);
    }

    return result;
}

std::vector<std::shared_ptr<Storage>> MtpStorageManager::GetStorages()
{
    return storages;
}
}  // namespace Media
}  // namespace OHOS
