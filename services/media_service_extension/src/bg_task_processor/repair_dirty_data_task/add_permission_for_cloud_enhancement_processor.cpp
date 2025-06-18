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

#define MLOG_TAG "MediaBgTask_AddPermissionForCloudEnhancementProcessor"

#include "add_permission_for_cloud_enhancement_processor.h"

#include "enhancement_database_operations.h"
#include "enhancement_manager.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
namespace OHOS {
namespace Media {
static const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
static const std::string PERMISSION_ADDED_FILE_ID = "permission_added_file_id";

int32_t AddPermissionForCloudEnhancementProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    // add permission for cloud enhancement photo
    ffrt::submit([this]() {
#ifdef MEDIALIBRARY_FEATURE_CLOUD_ENHANCEMENT
        AddPermissionForCloudEnhancement();
#endif
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t AddPermissionForCloudEnhancementProcessor::Stop(const std::string &taskExtra)
{
    taskStop_ = true;
    return E_OK;
}

static void GetMaxFileId(int32_t& maxFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "get rdb store failed");
    string queryMaxSql = "SELECT Max(file_id) FROM " + PhotoColumn::PHOTOS_TABLE;
    auto resultSet = rdbStore->QuerySql(queryMaxSql);
    bool cond = (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK);
    CHECK_AND_RETURN_LOG(!cond, "Failed to get max file_id!");
    resultSet->GetInt(0, maxFileId);
    resultSet->Close();
    return;
}

void AddPermissionForCloudEnhancementProcessor::AddPermissionForCloudEnhancement()
{
    MEDIA_INFO_LOG("start to add permission for cloud enhancement photo!");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    int32_t curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    MEDIA_INFO_LOG("start file id: %{public}d", curFileId);
    vector<string> columns = { MediaColumn::MEDIA_ID, PhotoColumn::PHOTO_ASSOCIATE_FILE_ID };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.GreaterThan(MediaColumn::MEDIA_ID, curFileId);
    predicates.And();
    predicates.EqualTo(PhotoColumn::PHOTO_STRONG_ASSOCIATION,
        to_string(static_cast<int32_t>(StrongAssociationType::CLOUD_ENHANCEMENT)));
    auto resultSet = MediaLibraryRdbStore::StepQueryWithoutCheck(predicates, columns);
    errCode = (resultSet == nullptr) ? E_ERR : E_OK;
    CHECK_AND_EXECUTE(resultSet == nullptr, errCode = (resultSet->GoToFirstRow() != E_OK) ? E_ERR : E_OK);
    if (errCode == E_ERR) {
        int32_t maxFileId = 0;
        GetMaxFileId(maxFileId);
        prefs->PutInt(PERMISSION_ADDED_FILE_ID, maxFileId);
        prefs->FlushSync();
        MEDIA_INFO_LOG("no cloud enhancement photo need to add permission, current max id:%{public}d",
            maxFileId);
        return;
    }

    do {
        int32_t sourceId = GetInt32Val(PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, resultSet);
        int32_t targetId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        EnhancementDatabaseOperations::InsertCloudEnhancementPerm(sourceId, targetId);
        prefs->PutInt(PERMISSION_ADDED_FILE_ID, targetId);
        prefs->FlushSync();
    } while (resultSet->GoToNextRow() == E_OK && !taskStop_);
    MEDIA_INFO_LOG("end add permission for cloud enhancement photo, taskStop: %{public}d.", taskStop_);
}
} // namespace Media
} // namespace OHOS
