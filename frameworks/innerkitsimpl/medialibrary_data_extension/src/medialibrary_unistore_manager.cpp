/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "medialibrary_unistore_manager.h"

namespace OHOS {
namespace Media {
MediaLibraryUnistoreManager& MediaLibraryUnistoreManager::GetInstance()
{
    static MediaLibraryUnistoreManager instance;
    return instance;
}

int32_t MediaLibraryUnistoreManager::Init(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    if (rdbStorePtr_) {
        return E_OK;
    }

    rdbStorePtr_ = std::make_shared<MediaLibraryRdbStore>(context);
    if (!rdbStorePtr_) {
        MEDIA_ERR_LOG("create rdbStore failed");
        return E_ERR;
    }
    return rdbStorePtr_->Init();
}

int32_t MediaLibraryUnistoreManager::Init(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context,
    const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback)
{
    if (rdbStorePtr_) {
        return E_OK;
    }

    rdbStorePtr_ = std::make_shared<MediaLibraryRdbStore>(context);
    if (!rdbStorePtr_) {
        MEDIA_ERR_LOG("create rdbStore failed");
        return E_ERR;
    }
    return rdbStorePtr_->Init(config, version, openCallback);
}

void MediaLibraryUnistoreManager::Stop()
{
    if (rdbStorePtr_) {
        rdbStorePtr_->Stop();
    }
    rdbStorePtr_ = nullptr;
}

std::shared_ptr<MediaLibraryRdbStore> MediaLibraryUnistoreManager::GetRdbStore() const
{
    if (rdbStorePtr_ != nullptr && rdbStorePtr_->CheckRdbStore()) {
        return rdbStorePtr_;
    }
    MEDIA_ERR_LOG("MediaLibraryRdbStore or rdbStore is nullptr");
    return nullptr;
}
} // namespace Media
} // namespace OHOS
