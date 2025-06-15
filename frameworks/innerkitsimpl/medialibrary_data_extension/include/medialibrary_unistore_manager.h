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

#include <memory>

#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaLibraryUnistoreManager {
public:
    EXPORT static MediaLibraryUnistoreManager &GetInstance();
    EXPORT int32_t Init(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context);
    EXPORT int32_t Init(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context,
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback);
    EXPORT void Stop();
    EXPORT std::shared_ptr<MediaLibraryRdbStore> GetRdbStore() const;

private:
    MediaLibraryUnistoreManager() = default;
    virtual ~MediaLibraryUnistoreManager() = default;

    std::shared_ptr<MediaLibraryRdbStore> rdbStorePtr_;
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_UNISTORE_MANAGER_H
