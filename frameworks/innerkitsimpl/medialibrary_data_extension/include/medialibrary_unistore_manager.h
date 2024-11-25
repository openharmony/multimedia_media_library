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
    EXPORT static MediaLibraryUnistoreManager &GetInstance()
    {
        static MediaLibraryUnistoreManager instance;
        return instance;
    }

    EXPORT int32_t Init(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context)
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

    EXPORT int32_t Init(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context,
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

    EXPORT void Stop()
    {
        if (rdbStorePtr_) {
            rdbStorePtr_->Stop();
        }
        rdbStorePtr_ = nullptr;
    }

    EXPORT std::shared_ptr<MediaLibraryRdbStore> GetRdbStore() const
    {
        if (rdbStorePtr_ != nullptr && rdbStorePtr_->CheckRdbStore()) {
            return rdbStorePtr_;
        }
        MEDIA_ERR_LOG("MediaLibraryRdbStore or rdbStore is nullptr");
        return nullptr;
    }

private:
    MediaLibraryUnistoreManager() = default;
    virtual ~MediaLibraryUnistoreManager() = default;

    std::shared_ptr<MediaLibraryRdbStore> rdbStorePtr_;
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_UNISTORE_MANAGER_H
