/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include "bg_task_processor_test.h"
 
#include "media_log.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_type_const.h"
#include "media_old_photos_column.h"
#include "media_file_utils.h"
#include "photo_file_utils.h"
#include "values_bucket.h"
#include "rdb_utils.h"
#include "rdb_predicates.h"
#include "parameters.h"
#include "result_set_utils.h"
 
#define private public
#include "clear_beta_and_hdc_dirty_data_processor.h"
#undef private
 
using namespace std;
using namespace OHOS;
using namespace testing::ext;
 
namespace OHOS {
namespace Media {
const int32_t UPDATE_DIRTY_CLOUD_CLONE_V0 = 0;
const int32_t UPDATE_DIRTY_CLOUD_CLONE_V1 = 1;
const int32_t UPDATE_DIRTY_CLOUD_CLONE_V2 = 2;
const std::string KEY_HIVIEW_VERSION_TYPE = "const.logsystem.versiontype";
const std::string NO_UPDATE_DIRTY = "no_update_dirty";
const std::string NO_UPDATE_DIRTY_CLOUD_CLONE_V2 = "no_update_dirty_cloud_clone_v2";
const std::string PHOTO_CLOUD_PATH = "/storage/cloud/files/Photo/16/IMG_1749113958_000.jpg";
const std::string PHOTO_LOCAL_PATH = "/storage/media/local/files/Photo/16/IMG_1749113958_000.jpg";
const std::string PHOTO_CLOUD_DIR = "/storage/cloud/files/Photo/16/";
const std::string PHOTO_LOCAL_DIR = "/storage/media/local/files/Photo/16/";
 
const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
 
int32_t InsertDirtyAsset(int32_t position, int32_t editTime, int32_t count,
    std::string filePath, int32_t &fileId)
{
    MEDIA_INFO_LOG("start");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    NativeRdb::ValuesBucket value;
    value.Put(PhotoColumn::PHOTO_POSITION, position);
    value.Put(PhotoColumn::PHOTO_EDIT_TIME, editTime);
    value.Put(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, 0);
    value.Put(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));
    value.Put(MediaColumn::MEDIA_FILE_PATH, filePath);
    value.PutNull(PhotoColumn::PHOTO_CLOUD_ID);
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < count; ++i) {
        insertValues.push_back(value);
    }
    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoColumn::PHOTOS_TABLE, insertValues);
    EXPECT_EQ(ret, E_OK);
    fileId = static_cast<int32_t>(outRowId);
    MEDIA_INFO_LOG("InsertDirtyAsset end, fileId: %{public}d", fileId);
    return E_OK;
}

int32_t InsertOldAsset(int32_t count, int32_t &fileId)
{
    MEDIA_INFO_LOG("start");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    NativeRdb::ValuesBucket value;
    value.Put(TabOldPhotosColumn::MEDIA_OLD_ID, -1);
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < count; ++i) {
        insertValues.push_back(value);
    }
    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoColumn::TAB_OLD_PHOTOS_TABLE, insertValues);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertOldAsset end, fileId: %{public}d, update fileId to: %{public}d",
        static_cast<int32_t>(outRowId), fileId);
    NativeRdb::RdbPredicates predicates(PhotoColumn::TAB_OLD_PHOTOS_TABLE);
    predicates.EqualTo(TabOldPhotosColumn::MEDIA_ID, static_cast<int32_t>(outRowId));
    NativeRdb::ValuesBucket updateValue;
    updateValue.Put(TabOldPhotosColumn::MEDIA_ID, fileId);
    int32_t changedRows = -1;
    ret = rdbStore->Update(changedRows, updateValue, predicates);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && changedRows > 0), E_ERR,
        "Failed to UpdateOldAsset, ret: %{public}d, updateRows: %{public}d",
        ret, changedRows);
    MEDIA_INFO_LOG("UpdateOldAsset successfully. ret: %{public}d, updateRows: %{public}d",
        ret, changedRows);
    return E_OK;
}

 
int32_t QueryDirty(int32_t fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return E_ERR;
    }
 
    vector<string> columns = { PhotoColumn::PHOTO_DIRTY, MediaColumn::MEDIA_ID };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID, to_string(fileId));
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_ERR;
    }
    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file dirty");
        return E_ERR;
    }
    int32_t dirty = GetInt32Val(PhotoColumn::PHOTO_DIRTY, resultSet);
    resultSet->Close();
    return dirty;
}

int32_t QueryPosition(int32_t fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return E_ERR;
    }
 
    vector<string> columns = { PhotoColumn::PHOTO_POSITION, MediaColumn::MEDIA_ID };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID, to_string(fileId));
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_ERR;
    }
    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file is_temp");
        return E_ERR;
    }
    int32_t position = GetInt32Val(PhotoColumn::PHOTO_POSITION, resultSet);
    resultSet->Close();
    MEDIA_INFO_LOG("query fileId: %{public}d, position: %{public}d", fileId, position);
    return position;
}
 
HWTEST_F(MediaLibraryBgTaskProcessorTest, ClearDirtyData_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("ClearDirtyData_test_001 start");
    auto processor = make_shared<ClearBetaAndHdcDirtyDataProcessor>();
    ASSERT_NE(processor, nullptr);
    processor->ClearDirtyData();
    MEDIA_INFO_LOG("ClearDirtyData_test_001 end");
}
 
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateDirtyForBeta_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateDirtyForBeta_test_001 start");
    OHOS::system::SetParameter(KEY_HIVIEW_VERSION_TYPE, "beta");
    std::string versionType = system::GetParameter(KEY_HIVIEW_VERSION_TYPE, "unknown");
    bool isBetaVersion = versionType.find("beta") != std::string::npos;
    EXPECT_EQ(isBetaVersion, true);
    int32_t errCode;
    std::shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    prefs->PutInt(NO_UPDATE_DIRTY, 0);
    EXPECT_NE(prefs->GetInt(NO_UPDATE_DIRTY, 0), 1);
    prefs->PutInt(NO_UPDATE_DIRTY_CLOUD_CLONE_V2, 0);
    EXPECT_NE(prefs->GetInt(NO_UPDATE_DIRTY_CLOUD_CLONE_V2, 0), 1);
    prefs->FlushSync();
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    processor.UpdateDirtyForBeta(prefs);
    MEDIA_INFO_LOG("UpdateDirtyForBeta_test_001 end");
}
 
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateDirtyForCloudClone_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateDirtyForCloudClone_test_001 start");
    // 预置local文件存在
    MediaFileUtils::CreateDirectory(PHOTO_LOCAL_DIR);
    MediaFileUtils::CreateFile(PHOTO_LOCAL_PATH);
    // 预置数据库 postition = 2 and dirty = 1
    int32_t fileId = -1;
    int32_t position = 2;
    int32_t editTime = 0;
    int32_t ret = InsertDirtyAsset(position, editTime, 1, PHOTO_CLOUD_PATH, fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertOldAsset(1, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预期不更新，dirty为1
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    ret = processor.UpdateDirtyForCloudClone();
    EXPECT_EQ(ret, E_OK);
    int32_t dirty = QueryDirty(fileId);
    EXPECT_EQ(dirty, 1);
    MEDIA_INFO_LOG("UpdateDirtyForCloudClone_test_001 end");
}
 
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateDirtyForCloudClone_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateDirtyForCloudClone_test_002 start");
    // 预置local文件存在
    bool isLocalDir = MediaFileUtils::CreateDirectory(PHOTO_LOCAL_DIR);
    bool isLocalFile = MediaFileUtils::CreateFile(PHOTO_LOCAL_PATH);
    // 预置数据库 position = 3 and dirty = 1 editTime = 0 and effectMode = 0
    int32_t fileId = -1;
    int32_t position = 3;
    int32_t editTime = 0;
    int32_t ret = InsertDirtyAsset(position, editTime, 1, PHOTO_CLOUD_PATH, fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertOldAsset(1, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预期 dirty = 0
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    ret = processor.UpdateDirtyForCloudClone();
    EXPECT_EQ(ret, E_OK);
    int32_t dirty = QueryDirty(fileId);
    EXPECT_EQ(dirty, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
    MEDIA_INFO_LOG("UpdateDirtyForCloudClone_test_002 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateDirtyForCloudClone_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateDirtyForCloudClone_test_003 start");
    // 预置local文件存在
    bool isLocalDir = MediaFileUtils::CreateDirectory(PHOTO_LOCAL_DIR);
    bool isLocalFile = MediaFileUtils::CreateFile(PHOTO_LOCAL_PATH);
    // 预置数据库 position = 3 and dirty = 1 editTime > 0 and effectMode = 0
    int32_t fileId = -1;
    int32_t position = 3;
    int32_t editTime = 1749113958;
    int32_t ret = InsertDirtyAsset(position, editTime, 1, PHOTO_CLOUD_PATH, fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertOldAsset(1, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预期 dirty = 3
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    ret = processor.UpdateDirtyForCloudClone();
    EXPECT_EQ(ret, E_OK);
    int32_t dirty = QueryDirty(fileId);
    EXPECT_EQ(dirty, static_cast<int32_t>(DirtyType::TYPE_FDIRTY));
    MEDIA_INFO_LOG("UpdateDirtyForCloudClone_test_003 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateDirtyForCloudClone_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateDirtyForCloudClone_test_004 start");
    // 预置local文件不存在
    bool isLocalDir = MediaFileUtils::CreateDirectory(PHOTO_LOCAL_DIR);
    bool isLocalFileDelete = MediaFileUtils::DeleteFile(PHOTO_LOCAL_PATH);
    // 预置数据库 position = 3 and dirty = 1 editTime = 0 and effectMode = 0
    int32_t fileId = -1;
    int32_t position = 3;
    int32_t editTime = 0;
    int32_t ret = InsertDirtyAsset(position, editTime, 1, PHOTO_CLOUD_PATH, fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertOldAsset(1, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预期 dirty = 1
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    ret = processor.UpdateDirtyForCloudClone();
    EXPECT_EQ(ret, E_OK);
    int32_t dirty = QueryDirty(fileId);
    EXPECT_EQ(dirty, static_cast<int32_t>(DirtyType::TYPE_NEW));
    MEDIA_INFO_LOG("UpdateDirtyForCloudClone_test_004 end");
}
 
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateDirtyForCloudCloneV2_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateDirtyForCloudCloneV2_test_001 start");
    // 预置local文件不存在
    bool isLocalDir = MediaFileUtils::CreateDirectory(PHOTO_LOCAL_DIR);
    bool isLocalFileDelete = MediaFileUtils::DeleteFile(PHOTO_LOCAL_PATH);
    // 预置数据库 position = 2 and old_file_id = -1
    int32_t fileId = -1;
    int32_t position = 2;
    int32_t editTime = 0;
    int32_t ret = InsertDirtyAsset(position, editTime, 10, PHOTO_CLOUD_PATH, fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertOldAsset(10, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预期position = 2
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    ret = processor.UpdateDirtyForCloudCloneV2();
    EXPECT_EQ(ret, E_OK);
    position = QueryPosition(fileId);
    EXPECT_EQ(position, 2);
    MEDIA_INFO_LOG("UpdateDirtyForCloudCloneV2_test_001 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateDirtyForCloudCloneV2_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateDirtyForCloudCloneV2_test_002 start");
    // 预置local文件存在
    MediaFileUtils::CreateDirectory(PHOTO_LOCAL_DIR);
    MediaFileUtils::CreateFile(PHOTO_LOCAL_PATH);
    // 预置数据库 position = 2 and old_file_id = -1
    int32_t fileId = -1;
    int32_t position = 2;
    int32_t editTime = 0;
    int32_t ret = InsertDirtyAsset(position, editTime, 10, PHOTO_CLOUD_PATH, fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertOldAsset(10, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预期position = 1
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    ret = processor.UpdateDirtyForCloudCloneV2();
    EXPECT_EQ(ret, E_OK);
    position = QueryPosition(fileId);
    EXPECT_EQ(position, 1);
    MEDIA_INFO_LOG("UpdateDirtyForCloudCloneV2_test_002 end");
}
 
HWTEST_F(MediaLibraryBgTaskProcessorTest, ClearDirtyHdcData_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("ClearDirtyHdcData_test_001 start");
    // 预置local文件不存在
    bool isLocalDir = MediaFileUtils::CreateDirectory(PHOTO_LOCAL_DIR);
    bool isLocalFileDelete = MediaFileUtils::DeleteFile(PHOTO_LOCAL_PATH);
    // 预置cloud文件存在
    bool isCloudDir = MediaFileUtils::CreateDirectory(PHOTO_CLOUD_DIR);
    bool isCloudFile = MediaFileUtils::CreateFile(PHOTO_CLOUD_PATH);
    EXPECT_EQ(MediaFileUtils::IsFileExists(PHOTO_CLOUD_PATH), true);
    // postition = 2
    int32_t fileId = -1;
    int32_t position = 2;
    int32_t editTime = 0;
    int32_t ret = InsertDirtyAsset(position, editTime, 1, PHOTO_CLOUD_PATH, fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertOldAsset(1, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预期cloud文件不存在
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    ret = processor.ClearDirtyHdcData();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(MediaFileUtils::IsFileExists(PHOTO_CLOUD_PATH), false);
    MEDIA_INFO_LOG("ClearDirtyHdcData_test_001 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, ClearDirtyHdcData_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("ClearDirtyHdcData_test_002 start");
    // 预置local文件存在
    bool isLocalDir = MediaFileUtils::CreateDirectory(PHOTO_LOCAL_DIR);
    bool isLocalFile = MediaFileUtils::CreateFile(PHOTO_LOCAL_PATH);
    EXPECT_EQ(MediaFileUtils::IsFileExists(PHOTO_LOCAL_PATH), true);
    // 预置cloud文件存在
    bool isCloudDir = MediaFileUtils::CreateDirectory(PHOTO_CLOUD_DIR);
    bool isCloudFile = MediaFileUtils::CreateFile(PHOTO_CLOUD_PATH);
    EXPECT_EQ(MediaFileUtils::IsFileExists(PHOTO_CLOUD_PATH), true);
    // postition = 2
    int32_t fileId = -1;
    int32_t position = 2;
    int32_t editTime = 0;
    int32_t ret = InsertDirtyAsset(position, editTime, 1, PHOTO_CLOUD_PATH, fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertOldAsset(1, fileId);
    EXPECT_EQ(ret, E_OK);
    // 预期local文件和cloud文件存在
    auto processor = ClearBetaAndHdcDirtyDataProcessor();
    ret = processor.ClearDirtyHdcData();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(MediaFileUtils::IsFileExists(PHOTO_LOCAL_PATH), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(PHOTO_CLOUD_PATH), true);
    MEDIA_INFO_LOG("ClearDirtyHdcData_test_002 end");
}
 
} // namespace Media
} // namespace OHOS
