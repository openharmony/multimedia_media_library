/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_UNISTORE_MANAGER_H
#define OHOS_MEDIALIBRARY_UNISTORE_MANAGER_H

#include <map>

#include "medialibrary_kvstore_operations.h"
#include "medialibrary_rdbstore_operations.h"
#include "medialibrary_unistore.h"

namespace OHOS {
namespace Media {

enum class MediaLibraryUnistoreType {
    RDB,
};

class MediaLibraryUnistoreManager {
public:
    static MediaLibraryUnistoreManager &GetInstance()
    {
        static MediaLibraryUnistoreManager instance;
        return instance;
    }
    void Init(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context)
    {
        unistoreMap_.clear();
        // unistoreMap_[MediaLibraryUnistoreType::KV] = std::make_shared<MediaLibraryKvStoreOperations>();
        unistoreMap_[MediaLibraryUnistoreType::RDB] = std::make_shared<MediaLibraryRdbStoreOperations>(context);

        for (auto &it : unistoreMap_) {
            it.second->Init();
        }
        kvStorePtr_ = std::make_shared<MediaLibraryKvStoreOperations>();
        kvStorePtr_->Init();
    }
    void Stop()
    {
        for (auto &it : unistoreMap_) {
            it.second->Stop();
        }
        unistoreMap_.clear();

        if (!kvStorePtr_) {
            kvStorePtr_->Stop();
            kvStorePtr_ = nullptr;
        }
    }
    std::shared_ptr<MediaLibraryUnistore> GetUnistore(MediaLibraryUnistoreType type)
    {
        if (unistoreMap_.find(type) != unistoreMap_.end()) {
            return unistoreMap_[type];
        }
        return nullptr;
    }
    std::shared_ptr<MediaLibraryKvStoreOperations> GetKvStore() { return kvStorePtr_; }

private:
    MediaLibraryUnistoreManager() = default;
    virtual ~MediaLibraryUnistoreManager() = default;

    std::map<MediaLibraryUnistoreType, std::shared_ptr<MediaLibraryUnistore>> unistoreMap_;
    std::shared_ptr<MediaLibraryKvStoreOperations> kvStorePtr_{nullptr};
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_UNISTORE_MANAGER_H
