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

#ifndef MEDIALIBRARY_BACKUP_TEST_DATABASE_MOCK_H
#define MEDIALIBRARY_BACKUP_TEST_DATABASE_MOCK_H

#include <string>

#define private public
#define protected public
#include "medialibrary_rdbstore.h"
#include "base_restore.h"
#undef private
#undef protected

#include "application_context.h"
#include "ability_context_impl.h"
#include "media_log.h"
#include "gallery_source.h"
#include "external_source.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "medialibrary_data_manager.h"
#include "upgrade_restore.h"
#include "medialibrary_unistore_manager.h"
#include "db_upgrade_utils.h"

namespace OHOS::Media {
class DatabaseMock {
private:
    enum { ERROR_1 = -1, ERROR_2 = -2, ERROR_3 = -3 };

private:
    class ContextImplMock : public OHOS::AbilityRuntime::ContextImpl {
    private:
        const std::string baseDir_;

    public:
        ContextImplMock() = default;
        ~ContextImplMock() = default;
        ContextImplMock(const std::string &baseDir) : baseDir_(baseDir)
        {}
        std::string GetDatabaseDir()
        {
            return this->baseDir_;
        }
    };

public:
    int32_t MediaLibraryDbMock(const std::string &baseDir)
    {
        const std::string path = baseDir + "/rdb/media_library.db";
        // mock the context
        auto stageContext = std::make_shared<ContextImplMock>(baseDir);
        auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
        abilityContextImpl->SetStageContext(stageContext);
        // mock the rdbStore
        // initiate the media_libarary.db.
        int32_t sceneCode;
        int32_t errorCode =
            MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl, nullptr, sceneCode);
        if (errorCode != E_OK) {
            return ERROR_1;
        }
        std::shared_ptr<MediaLibraryRdbStore> mediaLibraryRdbStorePtr =
            MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        if (mediaLibraryRdbStorePtr->config_.GetPath() != path) {
            return ERROR_2;
        }
        std::shared_ptr<NativeRdb::RdbStore> rdbStorePtr = mediaLibraryRdbStorePtr->GetRaw();
        if (rdbStorePtr == nullptr) {
            return ERROR_3;
        }
        DataTransfer::DbUpgradeUtils().DropAllTriggers(*rdbStorePtr, "PhotoAlbum");
        return E_OK;
    }
};
}  // namespace OHOS::Media
#endif  // MEDIALIBRARY_BACKUP_TEST_DATABASE_MOCK_H