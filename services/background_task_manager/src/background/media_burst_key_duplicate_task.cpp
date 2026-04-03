/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under * Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with * License.
 * You may obtain a copy of * License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under * License is distributed on an "AS IS" BASIS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See * License for * specific language governing permissions and
 * limitations under * License.
 */

#define MLOG_TAG "Media_Background"

#include "media_burst_key_duplicate_task.h"

#include <string>

#include "media_log.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "photo_burst_operation.h"
#include "result_set_utils.h"

using namespace OHOS::NativeRdb;

namespace OHOS::Media::Background {
    
constexpr int32_t BATCH_SIZE = 200;

bool MediaBurstKeyDuplicateTask::Accept()
{
    return MedialibrarySubscriber::IsCurrentStatusOn();
}

void MediaBurstKeyDuplicateTask::Execute()
{
    HandleDuplicateBurstKey();
}

void MediaBurstKeyDuplicateTask::HandleDuplicateBurstKey()
{
    BurstKeyDuplicateList duplicateBurstKeyList = FindDuplicateBurstKey();
    MEDIA_INFO_LOG("duplicateBurstKeyList: %{public}zu", duplicateBurstKeyList.size());

    for (auto &info : duplicateBurstKeyList) {
        CHECK_AND_BREAK_INFO_LOG(Accept(), "HandleDuplicateBurstKey check condition failed, stopping");
        CHECK_AND_CONTINUE(!info.burstKey.empty());

        int32_t ret = UpdateBurstKey(info.ownerAlbumId, info.burstKey);
        CHECK_AND_PRINT_LOG(ret == E_OK, "HandleDuplicateBurstKey failed, ret=%{public}d", ret);
    }
}

BurstKeyDuplicateList MediaBurstKeyDuplicateTask::FindDuplicateBurstKey()
{
    BurstKeyDuplicateList result;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, result, "rdbStore is nullptr");

    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_BURST_KEY_DUPLICATE_QUERY);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        BurstKeyDuplicateInfo info;
        info.ownerAlbumId = GetInt32Val("owner_album_id", resultSet);
        info.burstKey = GetStringVal("burst_key", resultSet);
        result.emplace_back(info);
    }
    resultSet->Close();
    return result;
}

int32_t MediaBurstKeyDuplicateTask::UpdateBurstKey(int32_t ownerAlbumId, const std::string &burstKey)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, NativeRdb::E_ERROR, "rdbStore is nullptr");

    std::string newBurstKey = PhotoBurstOperation::GenerateUuid();
    std::vector<ValueObject> bindArgs = {newBurstKey, ownerAlbumId, burstKey};
    std::string executeSql = SQL_PHOTOS_TABLE_BURST_KEY_UPDATE;
    int32_t ret = rdbStore->ExecuteSql(executeSql, bindArgs);
    MEDIA_INFO_LOG("updateBurstkey, oldKey: %{public}s, newKey: %{public}s, ownerAlbumId: %{public}d, ret: %{public}d",
        burstKey.c_str(), newBurstKey.c_str(), ownerAlbumId, ret);
    return ret;
}

}  // namespace OHOS::Media::Background
