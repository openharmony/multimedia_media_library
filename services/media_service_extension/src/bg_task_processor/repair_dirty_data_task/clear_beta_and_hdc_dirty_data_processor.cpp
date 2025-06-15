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

#define MLOG_TAG "MediaBgTask_ClearBetaAndHdcDirtyDataProcessor"

#include "clear_beta_and_hdc_dirty_data_processor.h"

#include "abs_rdb_predicates.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "parameter.h"
#include "parameters.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "value_object.h"

#include <string>
#include <vector>

using namespace std;
using namespace OHOS::NativeRdb;
namespace OHOS {
namespace Media {
const int32_t UPDATE_BATCH_SIZE = 200;
const int32_t DELETE_BATCH_SIZE = 1000;
const int32_t UPDATE_DIRTY_CLOUD_CLONE_V1 = 1;
const int32_t UPDATE_DIRTY_CLOUD_CLONE_V2 = 2;
const int32_t ERROR_OLD_FILE_ID_OFFSET = -1000000;

static const std::string NO_UPDATE_DIRTY = "no_update_dirty";
static const std::string NO_UPDATE_DIRTY_CLOUD_CLONE_V2 = "no_update_dirty_cloud_clone_v2";
static const std::string NO_DELETE_DIRTY_HDC_DATA = "no_delete_dirty_hdc_data";

const std::string KEY_HIVIEW_VERSION_TYPE = "const.logsystem.versiontype";
const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
static const std::string COLUMN_OLD_FILE_ID = "old_file_id";
static const std::string CLOUD_PREFIX_PATH = "/storage/cloud/files";
static const std::string THUMB_PREFIX_PATH = "/storage/cloud/files/.thumbs";

static const std::string REMOVE_KEY = "taskRun";
static const std::string REMOVE_VALUE = "false";

int32_t ClearBetaAndHdcDirtyDataProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        ClearDirtyData();

        // remove task
        int32_t errCode;
        std::shared_ptr<NativePreferences::Preferences> prefs =
            NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
        CHECK_AND_RETURN_LOG(prefs, "Get preferences error: %{public}d", errCode);
        if (prefs->GetInt(NO_UPDATE_DIRTY, 0) == 1 && prefs->GetInt(NO_UPDATE_DIRTY_CLOUD_CLONE_V2, 0) == 1 &&
            prefs->GetInt(NO_DELETE_DIRTY_HDC_DATA, 0) == 1) {
            std::string modifyInfo;
            WriteModifyInfo(REMOVE_KEY, REMOVE_VALUE, modifyInfo);
            if (modifyInfo.empty()) {
                MEDIA_WARN_LOG("failed to remove ClearBetaAndHdcDirtyDataProcessor.");
                return;
            }
            ModifyTask(taskName_, modifyInfo);
        }
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t ClearBetaAndHdcDirtyDataProcessor::Stop(const std::string &taskExtra)
{
    taskStop_ = true;
    return E_OK;
}

void ClearBetaAndHdcDirtyDataProcessor::ClearDirtyData()
{
    int32_t errCode;
    std::shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "Get preferences error: %{public}d", errCode);
    UpdateDirtyForBeta(prefs);
    ClearDirtyHdcData(prefs);
    return;
}

static bool IsBetaVersion()
{
    static const string versionType = system::GetParameter(KEY_HIVIEW_VERSION_TYPE, "unknown");
    static bool isBetaVersion = versionType.find("beta") != std::string::npos;
    return isBetaVersion;
}

void ClearBetaAndHdcDirtyDataProcessor::UpdateDirtyForBeta(const shared_ptr<NativePreferences::Preferences>& prefs)
{
    CHECK_AND_RETURN_LOG((IsBetaVersion() && prefs != nullptr), "not need UpdateDirtyForBeta");
    if (prefs->GetInt(NO_UPDATE_DIRTY, 0) != 1) {
        int32_t ret = UpdateDirtyForCloudClone(UPDATE_DIRTY_CLOUD_CLONE_V1);
        CHECK_AND_PRINT_LOG(ret == E_OK, "DoUpdateDirtyForCloudClone failed");
    }
    if (prefs->GetInt(NO_UPDATE_DIRTY_CLOUD_CLONE_V2, 0) != 1) {
        int32_t ret = UpdateDirtyForCloudClone(UPDATE_DIRTY_CLOUD_CLONE_V2);
        CHECK_AND_PRINT_LOG(ret == E_OK, "DoUpdateDirtyForCloudClone failed");
    }
}

int32_t ClearBetaAndHdcDirtyDataProcessor::UpdateDirtyForCloudClone(int32_t version)
{
    switch (version) {
        case UPDATE_DIRTY_CLOUD_CLONE_V1: {
            return UpdateDirtyForCloudClone();
        }
        case UPDATE_DIRTY_CLOUD_CLONE_V2: {
            return UpdateDirtyForCloudCloneV2();
        }
        default: {
            break;
        }
    }
    return E_OK;
}

static int32_t DoUpdateDirtyForCloudCloneOperation(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    const std::vector<std::string> &fileIds, bool updateToZero)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_FAIL, "rdbStore is nullptr");
    if (fileIds.empty()) {
        MEDIA_INFO_LOG("No cloud data need to update dirty for clone found.");
        return E_OK;
    }
    ValuesBucket updatePostBucket;
    if (updateToZero) {
        updatePostBucket.Put(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
    } else {
        updatePostBucket.Put(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_FDIRTY));
    }
    AbsRdbPredicates updatePredicates = AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    updatePredicates.In(MediaColumn::MEDIA_ID, fileIds);
    int32_t changeRows = -1;
    int32_t ret = rdbStore->Update(changeRows, updatePostBucket, updatePredicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && changeRows > 0), E_FAIL,
        "Failed to UpdateDirtyForCloudClone, ret: %{public}d, updateRows: %{public}d", ret, changeRows);
    return ret;
}

static void DealUpdateForDirty(const shared_ptr<NativeRdb::ResultSet> &resultSet, bool fileExist,
    std::vector<std::string> &dirtyToZeroFileIds, std::vector<std::string> &dirtyToThreeFileIds)
{
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    int32_t position = GetInt32Val(PhotoColumn::PHOTO_POSITION, resultSet);
    int32_t effectMode = GetInt32Val(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, resultSet);
    int64_t editTime = GetInt64Val(PhotoColumn::PHOTO_EDIT_TIME, resultSet);
    
    // position = 2：update dirty 0
    // position = 3: if edit, update dirty 3; else update dirty 0
    if (position == static_cast<int32_t>(PhotoPositionType::CLOUD)) {
        if (fileExist) {
            MEDIA_WARN_LOG("File exists while position is 2, file_id: %{public}d", fileId);
            return;
        } else {
            dirtyToZeroFileIds.push_back(to_string(fileId));
        }
    } else if (position == static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD)) {
        if (!fileExist) {
            MEDIA_WARN_LOG("File not exists while position is 3, file_id: %{public}d", fileId);
            return;
        } else {
            if (editTime > 0 || effectMode > 0) {
                dirtyToThreeFileIds.push_back(to_string(fileId));
            } else {
                dirtyToZeroFileIds.push_back(to_string(fileId));
            }
        }
    }
}

int32_t ClearBetaAndHdcDirtyDataProcessor::UpdateDirtyForCloudClone()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_FAIL, "rdbStore is nullptr");

    MEDIA_INFO_LOG("MediaLibraryDataManager::UpdateDirtyForCloudClone");
    const std::string QUERY_DIRTY_FOR_CLOUD_CLONE_INFO =
        "SELECT p.file_id, p.data, p.position, p.edit_time, p.moving_photo_effect_mode "
        "FROM Photos p "
        "JOIN tab_old_photos t ON p.file_id = t.file_id "
        "WHERE (p.position = 2 OR p.position = 3) AND p.dirty = 1 "
        "LIMIT " + std::to_string(UPDATE_BATCH_SIZE);

    bool nextUpdate = true;
    while (nextUpdate && !taskStop_) {
        shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(QUERY_DIRTY_FOR_CLOUD_CLONE_INFO);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_FAIL, "Failed to query resultSet");
        int32_t count = -1;
        int32_t err = resultSet->GetRowCount(count);
        MEDIA_INFO_LOG("the resultSet size is %{public}d", count);
        if (count < UPDATE_BATCH_SIZE) {
            nextUpdate = false;
        }
        // get file id need to update
        vector<std::string> dirtyToZeroFileIds;
        vector<std::string> dirtyToThreeFileIds;
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            std::string dataPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
            dataPath.replace(0, PhotoColumn::FILES_CLOUD_DIR.length(), PhotoColumn::FILES_LOCAL_DIR);
            if (dataPath == "") {
                MEDIA_INFO_LOG("The data path is empty, data path: %{public}s", dataPath.c_str());
                continue;
            }
            bool fileExist = MediaFileUtils::IsFileExists(dataPath);
            DealUpdateForDirty(resultSet, fileExist, dirtyToZeroFileIds, dirtyToThreeFileIds);
        }
        resultSet->Close();
        CHECK_AND_PRINT_LOG(DoUpdateDirtyForCloudCloneOperation(rdbStore, dirtyToZeroFileIds, true) == E_OK,
            "Failed to DoUpdateDirtyForCloudCloneOperation for dirtyToZeroFileIds");
        CHECK_AND_PRINT_LOG(DoUpdateDirtyForCloudCloneOperation(rdbStore, dirtyToThreeFileIds, false) == E_OK,
            "Failed to DoUpdateDirtyForCloudCloneOperation for dirtyToThreeFileIds");
    }
    if (!nextUpdate) {
        int32_t errCode;
        shared_ptr<NativePreferences::Preferences> prefs =
            NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
        CHECK_AND_RETURN_RET_LOG(prefs, E_FAIL, "Get preferences error: %{public}d", errCode);
        prefs->PutInt(NO_UPDATE_DIRTY, 1);
    }
    return E_OK;
}

static int32_t DoUpdateDirtyForCloudCloneOperationV2(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    const std::vector<std::string> &fileIds)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_FAIL, "rdbStore is nullptr");
    if (fileIds.empty()) {
        MEDIA_INFO_LOG("No cloud data need to update dirty for clone found.");
        return E_OK;
    }
    ValuesBucket updatePostBucket;
    updatePostBucket.Put(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL));
    AbsRdbPredicates updatePredicates = AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    updatePredicates.In(MediaColumn::MEDIA_ID, fileIds);
    int32_t changeRows = -1;
    int32_t ret = rdbStore->Update(changeRows, updatePostBucket, updatePredicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && changeRows > 0), E_FAIL,
        "Failed to UpdateDirtyForCloudClone, ret: %{public}d, updateRows: %{public}d", ret, changeRows);
    
    string updateSql = "UPDATE " + PhotoColumn::TAB_OLD_PHOTOS_TABLE + " SET " +
        COLUMN_OLD_FILE_ID + " = (" + std::to_string(ERROR_OLD_FILE_ID_OFFSET) + " - " + MediaColumn::MEDIA_ID + ") "+
        "WHERE " +  MediaColumn::MEDIA_ID + " IN (";
    vector<ValueObject> bindArgs;
    for (auto fileId : fileIds) {
        bindArgs.push_back(fileId);
        updateSql.append("?,");
    }
    updateSql = updateSql.substr(0, updateSql.length() -1);
    updateSql.append(")");
    ret = rdbStore->ExecuteSql(updateSql, bindArgs);
    return ret;
}

int32_t ClearBetaAndHdcDirtyDataProcessor::UpdateDirtyForCloudCloneV2()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_FAIL, "rdbStore is nullptr");

    MEDIA_INFO_LOG("MediaLibraryDataManager::UpdateDirtyForCloudCloneV2");
    const std::string QUERY_DIRTY_FOR_CLOUD_CLONE_INFO_V2 =
        "SELECT p.file_id, p.data, p.position, p.cloud_id "
        "FROM Photos p "
        "JOIN tab_old_photos t ON p.file_id = t.file_id "
        "WHERE p.position = 2 AND COALESCE(cloud_id,'') = '' AND t.old_file_id = -1 "
        "LIMIT " + std::to_string(UPDATE_BATCH_SIZE);
    bool nextUpdate = true;
    while (nextUpdate && !taskStop_) {
        shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(QUERY_DIRTY_FOR_CLOUD_CLONE_INFO_V2);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_FAIL, "Failed to query resultSet");
        int32_t count = -1;
        int32_t err = resultSet->GetRowCount(count);
        MEDIA_INFO_LOG("the resultSet size is %{public}d", count);
        if (count < UPDATE_BATCH_SIZE) {
            nextUpdate = false;
        }
        // get file id need to update
        vector<std::string> dirtyFileIds;
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            std::string dataPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
            dataPath.replace(0, PhotoColumn::FILES_CLOUD_DIR.length(), PhotoColumn::FILES_LOCAL_DIR);
            if (dataPath == "" || !MediaFileUtils::IsFileExists(dataPath)) {
                MEDIA_INFO_LOG("The data path is empty, data path: %{public}s",
                    MediaFileUtils::DesensitizePath(dataPath).c_str());
                continue;
            }
            int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
            dirtyFileIds.push_back(to_string(fileId));
        }
        resultSet->Close();
        CHECK_AND_PRINT_LOG(DoUpdateDirtyForCloudCloneOperationV2(rdbStore, dirtyFileIds) == E_OK,
            "Failed to DoUpdateDirtyForCloudCloneOperationV2 for dirtyFileIds");
    }
    if (!nextUpdate) {
        int32_t errCode;
        shared_ptr<NativePreferences::Preferences> prefs =
            NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
        CHECK_AND_RETURN_RET_LOG(prefs, E_FAIL, "Get preferences error: %{public}d", errCode);
        prefs->PutInt(NO_UPDATE_DIRTY_CLOUD_CLONE_V2, 1);
    }
    return E_OK;
}

static int32_t UpdateDirtyHdcDataStatus()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_RET_LOG(prefs, E_FAIL, "Get preferences error: %{public}d", errCode);
    prefs->PutInt(NO_DELETE_DIRTY_HDC_DATA, 1);
    return E_OK;
}

void DeleteDirtyFileAndDir(const std::vector<std::string>& deleteFilePaths)
{
    for (auto path : deleteFilePaths) {
        bool deleteFileRet = MediaFileUtils::DeleteFileOrFolder(path, true);
        std::string thumbsFolder =
            MediaFileUtils::GetReplacedPathByPrefix(CLOUD_PREFIX_PATH, THUMB_PREFIX_PATH, path);
        bool deleteThumbsRet = MediaFileUtils::DeleteFileOrFolder(thumbsFolder, false);
        if (!deleteFileRet || !deleteThumbsRet) {
            MEDIA_ERR_LOG("Clean file failed, path: %{public}s, deleteFileRet: %{public}d, "
                "deleteThumbsRet: %{public}d, errno: %{public}d",
                MediaFileUtils::DesensitizePath(path).c_str(),
                static_cast<int32_t>(deleteFileRet), static_cast<int32_t>(deleteThumbsRet), errno);
        }
    }
}

void ClearBetaAndHdcDirtyDataProcessor::ClearDirtyHdcData(const shared_ptr<NativePreferences::Preferences>& prefs)
{
    if (prefs != nullptr && (prefs->GetInt(NO_DELETE_DIRTY_HDC_DATA, 0) != 1)) {
        int32_t result = ClearDirtyHdcData();
        CHECK_AND_PRINT_LOG(result == E_OK, "ClearDirtyHdcData faild, result = %{public}d", result);
    }
    return;
}

static int32_t DoDeleteHdcDataOperation(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    const std::vector<std::string> &fileIds)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_FAIL, "rdbStore is nullptr");
    if (fileIds.empty()) {
        MEDIA_INFO_LOG("Not need to delete dirty data.");
        return E_OK;
    }
    AbsRdbPredicates deletePredicates = AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    deletePredicates.In(MediaColumn::MEDIA_ID, fileIds);
    int32_t deletedRows = -1;
    int32_t ret = rdbStore->Delete(deletedRows, deletePredicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && deletedRows > 0), E_FAIL,
        "Failed to DoDeleteHdcDataOperation, ret: %{public}d, deletedRows: %{public}d", ret, deletedRows);
    return ret;
}

int32_t ClearBetaAndHdcDirtyDataProcessor::ClearDirtyHdcData()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_FAIL, "rdbStore is nullptr");

    MEDIA_INFO_LOG("MediaLibraryDataManager::ClearDirtyHdcData");
    const std::string QUERY_DIRTY_HDC_INFO =
        "SELECT p.file_id, p.data, p.position, p.cloud_id, p.display_name FROM Photos p "
        "JOIN tab_old_photos t ON p.file_id = t.file_id "
        "WHERE p.position = 2  AND COALESCE(cloud_id,'') = '' "
        "LIMIT " + std::to_string(DELETE_BATCH_SIZE);
    bool nextDelete = true;
    while (nextDelete && !taskStop_) {
        shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(QUERY_DIRTY_HDC_INFO);
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_FAIL, "Failed to query resultSet");
        int32_t count = -1;
        int32_t err = resultSet->GetRowCount(count);
        MEDIA_INFO_LOG("the resultSet size is %{public}d", count);
        if (count < DELETE_BATCH_SIZE) {
            nextDelete = false;
        }

        vector<std::string> dirtyFileIds;
        vector<std::string> deleteUris;
        vector<std::string> deleteFilePaths;
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            std::string dataPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
            dataPath.replace(0, PhotoColumn::FILES_CLOUD_DIR.length(), PhotoColumn::FILES_LOCAL_DIR);
            if (dataPath == "" || MediaFileUtils::IsFileExists(dataPath)) {
                MEDIA_INFO_LOG("The data path is empty or file exist, data path: %{public}s",
                    MediaFileUtils::DesensitizePath(dataPath).c_str());
                continue;
            }
            int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
            dirtyFileIds.push_back(to_string(fileId));
            string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
            string filePath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
            string uri = MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileId),
                MediaFileUtils::GetExtraUri(displayName, filePath));
            deleteUris.push_back(uri);
            deleteFilePaths.push_back(filePath);
        }
        resultSet->Close();
        DeleteDirtyFileAndDir(deleteFilePaths);
        CHECK_AND_RETURN_RET_LOG(DoDeleteHdcDataOperation(rdbStore, dirtyFileIds) == E_OK,
            E_FAIL, "Failed to DoDeleteHdcDataOperation for dirtyFileIds");
        MediaLibraryRdbUtils::UpdateAllAlbums(rdbStore, deleteUris);
    }

    if (!nextDelete) {
        return UpdateDirtyHdcDataStatus();
    }
    return E_OK;
}
} // namespace Media
} // namespace OHOS
