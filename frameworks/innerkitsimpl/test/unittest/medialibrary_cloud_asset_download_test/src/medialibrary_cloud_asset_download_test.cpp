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

#define MLOG_TAG "CloudAssetDownloadUnitTest"

#include "medialibrary_cloud_asset_download_test.h"

#include <chrono>
#include <thread>

#include "image_source.h"
#include "media_exif.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_errno.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "userfilemgr_uri.h"
#include "values_bucket.h"

#define private public
#define protected public
#include "file_utils.h"
#include "cloud_media_asset_manager.h"
#include "cloud_media_asset_download_operation.h"
#include "cloud_media_asset_callback.h"
#include "cloud_media_asset_observer.h"
#include "cloud_media_asset_types.h"
#undef private
#undef protected
#include "cloud_media_asset_uri.h"
#include "data_secondary_directory_uri.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static std::atomic<int> number(0);
static const int32_t EXIT_TASK = 1;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void CleanTestTables()
{
    vector<string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
        MEDIALIBRARY_TABLE
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

void SetTables()
{
    vector<string> createTableSqlList = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        CREATE_MEDIA_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

void ClearAndRestart()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    system("rm -rf /storage/cloud/files/.thumbs");
    system("rm -rf /storage/cloud/files/.editData");
    for (const auto &dir : TEST_ROOT_DIRS) {
        string ROOT_PATH = "/storage/cloud/100/files/";
        bool ret = MediaFileUtils::CreateDirectory(ROOT_PATH + dir + "/");
        CHECK_AND_PRINT_LOG(ret, "make %{public}s dir failed, ret=%{public}d", dir.c_str(), ret);
    }
    CleanTestTables();
    SetTables();
}

int GetNumber()
{
    return ++number;
}

std::string GetTitle(int64_t &timestamp)
{
    return "IMG_" + to_string(timestamp) + "_" + to_string(GetNumber());
}

int64_t GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    return seconds.count() + GetNumber();
}

int32_t InsertCloudAssetINDb(int64_t &fileId, std::string &data)
{
    int64_t timestamp = GetTimestamp();
    string title = GetTitle(timestamp);
    string displayName = title + ".jpg";
    data = "/storage/cloud/files/photo/1/" + title + ".jpg";
    ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, data);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE));
    valuesBucket.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD));
    valuesBucket.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));
    int32_t ret = g_rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertCloudAsset fileId is %{public}s", to_string(fileId).c_str());
    return ret;
}

int32_t InsertCloudAndLocalAssetINDb(int64_t &fileId, std::string &data)
{
    int64_t timestamp = GetTimestamp();
    string title = GetTitle(timestamp);
    string displayName = title + ".jpg";
    data = "/storage/cloud/files/photo/1/" + title + ".jpg";
    ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, data);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE));
    valuesBucket.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
    int32_t ret = g_rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertCloudAndLocalAsset fileId is %{public}s", to_string(fileId).c_str());
    return ret;
}

int32_t SetPosition(const int64_t fileId)
{
    ValuesBucket valuesBucket;
    AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    valuesBucket.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL));
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    int32_t rows = 0;
    int32_t ret = g_rdbStore->Update(rows, valuesBucket, predicates);
    return ret;
}

void MediaLibraryCloudAssetDownloadTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    SetTables();
}

void MediaLibraryCloudAssetDownloadTest::TearDownTestCase(void)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    ClearAndRestart();
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    this_thread::sleep_for(chrono::seconds(1));
    MEDIA_INFO_LOG("Clean is finish");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

// SetUp:Execute before each test case
void MediaLibraryCloudAssetDownloadTest::SetUp()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryCloudAssetDownloadTest failed, can not get rdbstore");
        exit(1);
    }
    ClearAndRestart();
}

void MediaLibraryCloudAssetDownloadTest::TearDown(void) {}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_001 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t ret = instance.RecoverDownloadCloudAsset(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    EXPECT_EQ(ret, E_ERR);
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    ret = instance.RecoverDownloadCloudAsset(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    ret = instance.RecoverDownloadCloudAsset(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    operation->pauseCause_ = CloudMediaTaskPauseCause::USER_PAUSED;
    ret = instance.RecoverDownloadCloudAsset(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_001 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_002 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    int32_t ret = instance.PauseDownloadCloudAsset(CloudMediaTaskPauseCause::USER_PAUSED);
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    operation->pauseCause_ = CloudMediaTaskPauseCause::USER_PAUSED;
    ret = instance.PauseDownloadCloudAsset(CloudMediaTaskPauseCause::USER_PAUSED);
    EXPECT_EQ(ret, E_OK);
    operation = nullptr;
    ret = instance.PauseDownloadCloudAsset(CloudMediaTaskPauseCause::USER_PAUSED);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_002 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_003 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    int32_t ret = instance.CancelDownloadCloudAsset();
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    ret = instance.CancelDownloadCloudAsset();
    EXPECT_EQ(ret, E_OK);
    operation = nullptr;
    ret = instance.CancelDownloadCloudAsset();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_003 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_004 Start");
    std::vector<std::string> idVec;
    int64_t fileId1 = 0;
    std::string data1 = "";
    int32_t ret = InsertCloudAssetINDb(fileId1, data1);
    EXPECT_EQ(ret, E_OK);
    idVec.push_back(std::to_string(fileId1));

    int64_t fileId2 = 0;
    std::string data2 = "";
    ret = InsertCloudAssetINDb(fileId2, data2);
    EXPECT_EQ(ret, E_OK);
    idVec.push_back(std::to_string(fileId2));

    int64_t fileId3 = 0;
    std::string data3 = "";
    ret = InsertCloudAssetINDb(fileId3, data3);
    EXPECT_EQ(ret, E_OK);
    idVec.push_back(std::to_string(fileId3));
    
    ret = CloudMediaAssetManager::GetInstance().DeleteBatchCloudFile(idVec);
    EXPECT_EQ(ret, E_OK);
    idVec.clear();
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_004 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_005 Start");
    Uri uriStartForce(CMAM_CLOUD_MEDIA_ASSET_TASK_START_FORCE);
    MediaLibraryCommand cmdStartForce(uriStartForce);
    int32_t ret = CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmdStartForce);
    EXPECT_EQ(ret, E_ERR);
    Uri uriStartGentle(CMAM_CLOUD_MEDIA_ASSET_TASK_START_GENTLE);
    MediaLibraryCommand cmdStartGentle(uriStartGentle);
    ret = CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmdStartGentle);
    EXPECT_EQ(ret, E_OK);
    Uri uriPause(CMAM_CLOUD_MEDIA_ASSET_TASK_PAUSE);
    MediaLibraryCommand cmdPause(uriPause);
    ret = CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmdPause);
    EXPECT_EQ(ret, E_OK);
    Uri uriCancel(CMAM_CLOUD_MEDIA_ASSET_TASK_CANCEL);
    MediaLibraryCommand cmdCancel(uriCancel);
    ret = CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmdCancel);
    EXPECT_EQ(ret, E_OK);
    Uri uriRetain(CMAM_CLOUD_MEDIA_ASSET_TASK_RETAIN_FORCE);
    MediaLibraryCommand cmdRetain(uriRetain);
    ret = CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmdRetain);
    EXPECT_EQ(ret, E_ERR);
    Uri uriOther(MEDIALIBRARY_AUDIO_URI);
    MediaLibraryCommand cmdOther(uriOther);
    ret = CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmdOther);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_005 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_006 Start");
    Uri uriType(CMAM_CLOUD_MEDIA_ASSET_TASK_STATUS_QUERY);
    MediaLibraryCommand cmdType(uriType);
    std::string ret = CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetGetTypeOperations(cmdType);
    EXPECT_EQ(ret, "2,0,0,0,0,0");
    Uri uriOther(MEDIALIBRARY_AUDIO_URI);
    MediaLibraryCommand cmdOther(uriOther);
    ret = CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetGetTypeOperations(cmdOther);
    EXPECT_EQ(ret, "");
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_006 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_007 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t ret = instance.CheckDownloadTypeOfTask(CloudMediaDownloadType::DOWNLOAD_FORCE);
    EXPECT_EQ(ret, E_OK);
    ret = instance.CheckDownloadTypeOfTask(CloudMediaDownloadType::DOWNLOAD_GENTLE);
    EXPECT_EQ(ret, E_OK);
    CloudMediaDownloadType type = static_cast<CloudMediaDownloadType>(-1);
    ret = instance.CheckDownloadTypeOfTask(type);
    EXPECT_EQ(ret, E_ERR);
    type = static_cast<CloudMediaDownloadType>(10);
    ret = instance.CheckDownloadTypeOfTask(type);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_007 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_008 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    CloudMediaDownloadType type = static_cast<CloudMediaDownloadType>(-1);
    int32_t ret = instance.StartDownloadCloudAsset(type);
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    ret = instance.StartDownloadCloudAsset(CloudMediaDownloadType::DOWNLOAD_GENTLE);
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    ret = instance.StartDownloadCloudAsset(CloudMediaDownloadType::DOWNLOAD_GENTLE);
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    operation->downloadType_ = CloudMediaDownloadType::DOWNLOAD_GENTLE;
    ret = instance.StartDownloadCloudAsset(CloudMediaDownloadType::DOWNLOAD_GENTLE);
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    operation->downloadType_ = CloudMediaDownloadType::DOWNLOAD_GENTLE;
    ret = instance.StartDownloadCloudAsset(CloudMediaDownloadType::DOWNLOAD_FORCE);
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    operation->downloadType_ = CloudMediaDownloadType::DOWNLOAD_FORCE;
    ret = instance.StartDownloadCloudAsset(CloudMediaDownloadType::DOWNLOAD_GENTLE);
    EXPECT_EQ(ret, E_ERR);
    CloudMediaAssetTaskStatus status = static_cast<CloudMediaAssetTaskStatus>(-1);
    operation->taskStatus_ = status;
    ret = instance.StartDownloadCloudAsset(CloudMediaDownloadType::DOWNLOAD_GENTLE);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_008 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_009 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t ret = instance.CheckDownloadTypeOfTask(CloudMediaDownloadType::DOWNLOAD_FORCE);
    EXPECT_EQ(ret, E_OK);
    ret = instance.CheckDownloadTypeOfTask(CloudMediaDownloadType::DOWNLOAD_GENTLE);
    EXPECT_EQ(ret, E_OK);
    CloudMediaDownloadType type = static_cast<CloudMediaDownloadType>(-1);
    ret = instance.CheckDownloadTypeOfTask(type);
    EXPECT_EQ(ret, E_ERR);
    type = static_cast<CloudMediaDownloadType>(10);
    ret = instance.CheckDownloadTypeOfTask(type);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_009 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_010 Start");
    std::vector<std::string> idVec = { "id1", "id2" };
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t ret = instance.DeleteBatchCloudFile(idVec);
    EXPECT_EQ(ret, E_ERR);
    std::vector<std::string> fileIds;
    std::vector<std::string> paths;
    std::vector<std::string> dateTakens;
    ret = instance.ReadyDataForDelete(fileIds, paths, dateTakens);
    EXPECT_EQ(ret, E_OK);
    ret = instance.ForceRetainDownloadCloudMedia();
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_010 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_011, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_011 Start");
    std::string result = "2,0,0,0,0,0";
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ =  CloudMediaAssetTaskStatus::IDLE;
    std::string ret = instance.GetCloudMediaAssetTaskStatus();
    EXPECT_EQ(ret, result);
    operation = nullptr;
    ret = instance.GetCloudMediaAssetTaskStatus();
    EXPECT_EQ(ret, result);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_011 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_012, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_012 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ =  CloudMediaAssetTaskStatus::DOWNLOADING;
    bool ret = instance.SetIsThumbnailUpdate();
    EXPECT_EQ(ret, true);
    operation->taskStatus_ =  CloudMediaAssetTaskStatus::IDLE;
    ret = instance.SetIsThumbnailUpdate();
    EXPECT_EQ(ret, false);
    operation = nullptr;
    ret = instance.SetIsThumbnailUpdate();
    EXPECT_EQ(ret, false);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_012 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_013, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_013 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ =  CloudMediaAssetTaskStatus::DOWNLOADING;
    int32_t ret = instance.GetTaskStatus();
    EXPECT_EQ(ret, 0);
    operation->downloadType_ = CloudMediaDownloadType::DOWNLOAD_GENTLE;
    ret = instance.GetDownloadType();
    EXPECT_EQ(ret, 1);
    operation = nullptr;
    ret = instance.GetTaskStatus();
    EXPECT_EQ(ret, 0);
    ret = instance.GetDownloadType();
    EXPECT_EQ(ret, 1);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_013 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_014, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_014 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ =  CloudMediaAssetTaskStatus::IDLE;
    bool ret = instance.SetBgDownloadPermission(true);
    EXPECT_EQ(ret, false);
    operation->taskStatus_ =  CloudMediaAssetTaskStatus::DOWNLOADING;
    ret = instance.SetBgDownloadPermission(true);
    EXPECT_EQ(ret, true);
    operation = nullptr;
    ret = instance.SetBgDownloadPermission(true);
    EXPECT_EQ(ret, true);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_014 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_manager_test_015, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_015 Start");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t ret = instance.UpdateCloudMediaAssets();
    EXPECT_EQ(ret, E_ERR);

    int64_t fileId1 = 0;
    std::string data1 = "";
    ret = InsertCloudAssetINDb(fileId1, data1);
    EXPECT_EQ(ret, E_OK);

    int64_t fileId2 = 0;
    std::string data2 = "";
    ret = InsertCloudAssetINDb(fileId2, data2);
    EXPECT_EQ(ret, E_OK);

    ret = instance.UpdateCloudMediaAssets();
    EXPECT_EQ(ret, E_OK);
    ret = instance.DeleteEmptyCloudAlbums();
    EXPECT_EQ(ret, E_OK);
    ret = instance.UpdateLocalAlbums();
    EXPECT_EQ(ret, E_OK);
    
    ret = instance.UpdateBothLocalAndCloudAssets();
    EXPECT_EQ(ret, E_OK);
    int64_t fileId3 = 0;
    std::string data3 = "";
    ret = InsertCloudAndLocalAssetINDb(fileId3, data3);
    EXPECT_EQ(ret, E_OK);
    ret = instance.UpdateBothLocalAndCloudAssets();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("cloud_asset_download_manager_test_015 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_operation_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_001 Start");
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->isThumbnailUpdate_ = false;
    int32_t ret = operation->InitDownloadTaskInfo();
    EXPECT_EQ(ret, E_OK);
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    instance.SetIsThumbnailUpdate();
    ret = operation->InitDownloadTaskInfo();
    EXPECT_EQ(ret, E_ERR);
    int64_t fileId1 = 0;
    std::string data1 = "";
    ret = InsertCloudAssetINDb(fileId1, data1);
    EXPECT_EQ(ret, E_OK);
    ret = operation->InitDownloadTaskInfo();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_001 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_operation_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_002 Start");
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    CloudMediaAssetDownloadOperation::DownloadFileData datas;
    int32_t ret = operation->SubmitBatchDownload(datas, true);
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    operation->downloadId_ = 1;
    ret = operation->SubmitBatchDownload(datas, true);
    EXPECT_EQ(ret, E_ERR);
    operation->downloadId_ = -1;
    ret = operation->SubmitBatchDownload(datas, true);
    EXPECT_EQ(ret, E_OK);
    ret = operation->SubmitBatchDownload(datas, false);
    EXPECT_EQ(ret, EXIT_TASK);
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_002 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_operation_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_003 Start");
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    int32_t ret = operation->DoForceTaskExecute();
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    ret = operation->DoForceTaskExecute();
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    ret = operation->DoForceTaskExecute();
    EXPECT_EQ(ret, EXIT_TASK);
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_003 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_operation_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_004 Start");
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    int32_t ret = operation->StartDownloadTask(static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_FORCE));
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    ret = operation->StartDownloadTask(static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_GENTLE));
    EXPECT_EQ(ret, E_OK);
    ret = operation->StartDownloadTask(static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_FORCE));
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;

    ret = operation->DoRecoverExecute();
    EXPECT_EQ(ret, E_ERR);

    operation->dataForDownload_.fileDownloadMap["test001.jpg"] = 1024;
    ret = operation->DoRecoverExecute();
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_004 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_operation_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_005 Start");
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    int32_t ret = operation->ManualActiveRecoverTask(static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_FORCE));
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    ret = operation->ManualActiveRecoverTask(static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_GENTLE));
    EXPECT_EQ(ret, E_OK);
    operation->dataForDownload_.fileDownloadMap["test001.jpg"] = 1024;
    ret = operation->ManualActiveRecoverTask(static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_FORCE));
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_005 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_operation_test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_006 Start");
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    int32_t ret = operation->PassiveStatusRecoverTask(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    operation->pauseCause_ = CloudMediaTaskPauseCause::USER_PAUSED;
    ret = operation->PassiveStatusRecoverTask(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    EXPECT_EQ(ret, E_ERR);
    operation->pauseCause_ = CloudMediaTaskPauseCause::WIFI_UNAVAILABLE;
    operation->downloadType_ = CloudMediaDownloadType::DOWNLOAD_GENTLE;
    operation->isBgDownloadPermission_ = false;
    ret = operation->PassiveStatusRecoverTask(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    operation->dataForDownload_.fileDownloadMap["test001.jpg"] = 1024;
    operation->pauseCause_ = CloudMediaTaskPauseCause::WIFI_UNAVAILABLE;
    operation->downloadType_ = CloudMediaDownloadType::DOWNLOAD_FORCE;
    ret = operation->PassiveStatusRecoverTask(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    operation->pauseCause_ = CloudMediaTaskPauseCause::WIFI_UNAVAILABLE;
    ret = operation->PassiveStatusRecoverTask(CloudMediaTaskRecoverCause::FOREGROUND_TEMPERATURE_PROPER);
    EXPECT_EQ(ret, E_ERR);
    operation->pauseCause_ = CloudMediaTaskPauseCause::BACKGROUND_TASK_UNAVAILABLE;
    ret = operation->PassiveStatusRecoverTask(CloudMediaTaskRecoverCause::FOREGROUND_TEMPERATURE_PROPER);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_006 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_operation_test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_007 Start");
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    operation->pauseCause_ = CloudMediaTaskPauseCause::WIFI_UNAVAILABLE;
    int32_t ret = operation->PauseDownloadTask(CloudMediaTaskPauseCause::NETWORK_FLOW_LIMIT);
    EXPECT_EQ(ret, E_OK);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::PAUSED;
    operation->pauseCause_ = CloudMediaTaskPauseCause::USER_PAUSED;
    ret = operation->PauseDownloadTask(CloudMediaTaskPauseCause::NETWORK_FLOW_LIMIT);
    EXPECT_EQ(ret, E_ERR);
    operation->taskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    ret = operation->PauseDownloadTask(CloudMediaTaskPauseCause::NETWORK_FLOW_LIMIT);
    EXPECT_EQ(ret, E_ERR);
    ret = operation->CancelDownloadTask();
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_007 End");
}

HWTEST_F(MediaLibraryCloudAssetDownloadTest, cloud_asset_download_operation_test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_008 Start");
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->dataForDownload_.fileDownloadMap["test001.jpg"] = 1024;
    operation->downloadType_ = CloudMediaDownloadType::DOWNLOAD_GENTLE;
    operation->isBgDownloadPermission_ = true;
    int32_t ret = operation->PassiveStatusRecover();
    EXPECT_EQ(ret, E_ERR);
    operation->isBgDownloadPermission_ = false;
    ret = operation->PassiveStatusRecover();
    EXPECT_EQ(ret, E_OK);
    operation->downloadType_ = CloudMediaDownloadType::DOWNLOAD_FORCE;
    operation->isBgDownloadPermission_ = true;
    ret = operation->PassiveStatusRecover();
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("cloud_asset_download_operation_test_008 End");
}
}
}