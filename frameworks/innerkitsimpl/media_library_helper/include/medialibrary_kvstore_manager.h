/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_KVSTORE_MANAGER_H
#define OHOS_MEDIALIBRARY_KVSTORE_MANAGER_H

#include <safe_map.h>

#include "medialibrary_kvstore.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
using KvStoreSharedPtr = std::shared_ptr<MediaLibraryKvStore>;

class MediaLibraryKvStoreManager {
public:
    EXPORT static MediaLibraryKvStoreManager &GetInstance()
    {
        static MediaLibraryKvStoreManager instance;
        return instance;
    }

    EXPORT int32_t InitKvStore(const KvStoreRoleType &roleType, const KvStoreValueType &valueType);
    EXPORT std::shared_ptr<MediaLibraryKvStore> GetKvStore(
        const KvStoreRoleType &roleType, const KvStoreValueType &valueType);
    EXPORT bool CloseKvStore(const KvStoreValueType &valueType);
    EXPORT void CloseAllKvStore();

private:
    MediaLibraryKvStoreManager() = default;
    ~MediaLibraryKvStoreManager() = default;

    SafeMap<KvStoreValueType, KvStoreSharedPtr> kvStoreMap_;
    static std::mutex mutex_;
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_KVSTORE_MANAGER_H