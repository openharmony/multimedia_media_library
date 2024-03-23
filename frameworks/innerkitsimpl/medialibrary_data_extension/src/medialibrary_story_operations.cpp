/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "StoryOperation"

#include "medialibrary_story_operations.h"

#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t MediaLibraryStoryOperations::InsertOperation(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Story insert operation, rdbStore is null.");
        return E_HAS_DB_ERROR;
    }
    int64_t outRowId = -1;
    int32_t errCode = rdbStore->Insert(cmd, outRowId);
    if (errCode != NativeRdb::E_OK || outRowId < 0) {
        MEDIA_ERR_LOG("Story Insert into db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(outRowId);
}

int32_t MediaLibraryStoryOperations::UpdateOperation(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Story update operation, rdbStore is null.");
        return E_HAS_DB_ERROR;
    }
    int32_t updateRows = -1;
    int32_t errCode = rdbStore->Update(cmd, updateRows);
    if (errCode != NativeRdb::E_OK || updateRows < 0) {
        MEDIA_ERR_LOG("Story Update db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(updateRows);
}

int32_t MediaLibraryStoryOperations::DeleteOperation(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Story delete operation, rdbStore is null.");
        return E_HAS_DB_ERROR;
    }
    int32_t deleteRows = -1;
    int32_t errCode = rdbStore->Delete(cmd, deleteRows);
    if (errCode != NativeRdb::E_OK || deleteRows < 0) {
        MEDIA_ERR_LOG("Story Delete db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(deleteRows);
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryStoryOperations::QueryOperation(MediaLibraryCommand &cmd,
    const std::vector<std::string> &columns)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Story query operation, rdbStore is null.");
        return nullptr;
    }
    return rdbStore->Query(cmd, columns);
}
} // namespace Media
} // namespace OHOS
