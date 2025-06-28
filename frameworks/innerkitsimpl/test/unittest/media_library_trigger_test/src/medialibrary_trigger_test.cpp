
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

#define MLOG_TAG "MediaLibraryTriggerTest"

#include "medialibrary_unittest_utils.h"
#include "medialibrary_trigger_test_utils.h"
#include "medialibrary_trigger_test.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#define private public
#include "medialibrary_trigger.h"
#undef private


using namespace testing::ext;
using namespace OHOS::Media::AccurateRefresh;

namespace OHOS {
namespace Media {

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;
static std::shared_ptr<TransactionOperations> g_trans = nullptr;
static const int32_t SLEEP_FIVE_SECONDS = 5;
static const std::string DEFAULT_PACKAGE_NAME = "packageName";
static const std::string DEFAULT_OWNER_PACKAGE_NAME = "ownerPackage";
static const std::string DEFAULT_LPATH = "lPath";
static const std::string DEFAULT_KEY = "packageKey";
static const int INVALID_ALBUM_CNT = -1;
static const int EXIT_ALBUM_CNT = 1;
static const int NON_EXIST_ALBUM_CNT = 0;
static const int INVALID_ALBUM_WO_BUNDLE_NAME_CNT = -1;
static const int EXIT_ALBUM_WO_BUNDLE_NAME_CNT = 1;
static const int NON_EXIT_ALBUM_WO_BUNDLE_NAME_CNT = 0;
static const int DEFAULT_OWNER_ALBUM_ID = 1;
static const int INVALID_OWNER_ALBUM_ID = 0;
static const int DEFAULT_FILEID = 1;

void MediaLibraryTriggerTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    g_trans = std::make_shared<TransactionOperations>(__func__);
    if (g_trans == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdb trans");
        exit(1);
    }
    MediaLibraryTriggerTestUtils::SetRdbStore(g_rdbStore);
    MediaLibraryTriggerTestUtils::SetTables();
}

void MediaLibraryTriggerTest::TearDownTestCase(void)
{
    MediaLibraryTriggerTestUtils::ClearTables();
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MediaLibraryTriggerTestUtils::SetRdbStore(nullptr);
    g_rdbStore = nullptr;
    g_trans = nullptr;
    MEDIA_INFO_LOG("MediaLibraryTriggerTest TearDownTestCase finished");
}

void MediaLibraryTriggerTest::SetUp()
{
    MediaLibraryTriggerTestUtils::PrepareData();
}

void MediaLibraryTriggerTest::TearDown()
{
    MediaLibraryTriggerTestUtils::RemoveData();
}

HWTEST_F(MediaLibraryTriggerTest, TriggerHelper_NameUtil_000, TestSize.Level2)
{
    std::string triggerHelperName = "triggerHelper";
    TriggerHelper triggerHelper;
    triggerHelper.SetName(triggerHelperName);
    EXPECT_EQ(triggerHelper.GetName(), triggerHelperName);
}

HWTEST_F(MediaLibraryTriggerTest, TriggerHelper_ColumnName_000, TestSize.Level2)
{
    TriggerHelper triggerHelper;
    std::unordered_set<std::string> column1{"column1", "column2"};
    std::unordered_set<std::string> column2{"column1", "column3"};
    std::vector<std::string> expectedVec{"column1", "column2", "column3"};
    std::unordered_set<std::string> expectedSet{"column1", "column2", "column3"};
    triggerHelper.AddFocusedColumnName(column1);
    triggerHelper.AddFocusedColumnName(column2);
    EXPECT_TRUE(MediaLibraryTriggerTestUtils::HaveCommonData(expectedVec,
        triggerHelper.GetFocusedColumnNamesVec()));
    EXPECT_TRUE(expectedSet == triggerHelper.GetFocusedColumnNames());
}

HWTEST_F(MediaLibraryTriggerTest, MediaLibraryTrigger_Init_000, TestSize.Level2)
{
    std::vector<std::shared_ptr<MediaLibraryTriggerBase>> triggerVec;
    triggerVec.push_back(std::make_shared<InsertSourcePhotoCreateSourceAlbumTrigger>());
    triggerVec.push_back(std::make_shared<InsertPhotoUpdateAlbumBundleNameTrigger>());
    auto inValidTriggerVec = triggerVec;
    inValidTriggerVec.push_back(nullptr);

    int expectedTriggerSize = 0;
    std::string expectedTableName = "";
    MediaLibraryTrigger trigger;
    EXPECT_FALSE(trigger.Init(inValidTriggerVec, PhotoAlbumColumns::TABLE));
    EXPECT_EQ(trigger.triggers_.size(), expectedTriggerSize);
    EXPECT_EQ(trigger.table_, expectedTableName);

    expectedTriggerSize = 2;
    expectedTableName = PhotoAlbumColumns::TABLE;
    EXPECT_TRUE(trigger.Init(triggerVec, PhotoAlbumColumns::TABLE));
    EXPECT_EQ(trigger.triggers_.size(), expectedTriggerSize);
    EXPECT_EQ(trigger.table_, expectedTableName);
}

HWTEST_F(MediaLibraryTriggerTest, MediaLibraryTrigger_Processs_000, TestSize.Level2)
{
    PhotoAssetChangeData changeData;
    std::vector<PhotoAssetChangeData> changeDataVec{changeData};
    std::shared_ptr<MockTrigger> mockTrigger = std::make_shared<MockTrigger>();
    
    MediaLibraryTrigger trigger;
    // 1. trans nullptr
    EXPECT_EQ(trigger.Process(nullptr, changeDataVec), NativeRdb::E_ERROR);
    // 2. 0 trigger
    EXPECT_EQ(trigger.Process(g_trans, changeDataVec), NativeRdb::E_OK);
    // 3. 0 changeDataVec
    EXPECT_TRUE(trigger.Init({mockTrigger}, PhotoAlbumColumns::TABLE));
    EXPECT_EQ(trigger.Process(g_trans, {}), NativeRdb::E_OK);
    // 4. IsTriggerFireForRow fail
    EXPECT_CALL(*mockTrigger, IsTriggerFireForRow(g_trans, ::testing::_))
        .Times(1).WillOnce(::testing::Return(false));
    EXPECT_CALL(*mockTrigger, Process(g_trans, ::testing::_)).Times(0);
    EXPECT_EQ(trigger.Process(g_trans, changeDataVec), NativeRdb::E_ERROR);
    // 5. IsTriggerFireForRow succeed & Process fail
    ::testing::Mock::VerifyAndClearExpectations(&(*mockTrigger));
    EXPECT_CALL(*mockTrigger, IsTriggerFireForRow(g_trans, ::testing::_))
        .Times(1).WillOnce(::testing::Return(true));
    EXPECT_CALL(*mockTrigger, Process(g_trans, ::testing::_))
        .Times(1).WillOnce(::testing::Return(NativeRdb::E_ERROR));
    EXPECT_EQ(trigger.Process(g_trans, changeDataVec), NativeRdb::E_ERROR);
    // 6. IsTriggerFireForRow succeed & Process succeed
    ::testing::Mock::VerifyAndClearExpectations(&(*mockTrigger));
    EXPECT_CALL(*mockTrigger, IsTriggerFireForRow(g_trans, ::testing::_))
        .Times(1).WillOnce(::testing::Return(true));
    EXPECT_CALL(*mockTrigger, Process(g_trans, ::testing::_))
        .Times(1).WillOnce(::testing::Return(NativeRdb::E_OK));
    EXPECT_EQ(trigger.Process(g_trans, changeDataVec), NativeRdb::E_OK);
}

HWTEST_F(MediaLibraryTriggerTest, MediaLibraryTrigger_IsTriggerFireForRow_000, TestSize.Level2)
{
    PhotoAssetChangeData changeData;
    std::shared_ptr<MockTrigger> mockTrigger = std::make_shared<MockTrigger>();

    MediaLibraryTrigger trigger;
    EXPECT_TRUE(trigger.Init({mockTrigger}, PhotoAlbumColumns::TABLE));

    // 1. nullptr trans
    EXPECT_FALSE(trigger.IsTriggerFireForRow(nullptr, changeData));
    // 2. IsTriggerFireForRow fail
    EXPECT_CALL(*mockTrigger, IsTriggerFireForRow(g_trans, ::testing::_))
        .Times(1).WillOnce(::testing::Return(false));
    EXPECT_FALSE(trigger.IsTriggerFireForRow(g_trans, changeData));
    ::testing::Mock::VerifyAndClearExpectations(&(*mockTrigger));
    // 3. IsTriggerFireForRow succeed
    EXPECT_CALL(*mockTrigger, IsTriggerFireForRow(g_trans, ::testing::_))
        .Times(1).WillOnce(::testing::Return(true));
    EXPECT_TRUE(trigger.IsTriggerFireForRow(g_trans, changeData));
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_PackageInfo_000, TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo packageInfo;
    EXPECT_FALSE(packageInfo.IsValid());
    packageInfo.lPath = DEFAULT_LPATH;
    EXPECT_FALSE(packageInfo.IsValid());
    packageInfo.packageName = DEFAULT_PACKAGE_NAME;
    EXPECT_FALSE(packageInfo.IsValid());
    packageInfo.ownerPackage = DEFAULT_OWNER_PACKAGE_NAME;
    EXPECT_FALSE(packageInfo.IsValid());
    packageInfo.albumCnt = NON_EXIST_ALBUM_CNT;
    EXPECT_TRUE(packageInfo.IsValid());
    std::string expectedStr = "packageName:packageName, ownerPackageName:ownerPackage, lPath:lPath, albumCnt:0";
    EXPECT_EQ(packageInfo.ToString(), expectedStr);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_QueryAlbumIdByLPath_000, TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    bool ret = false;
    std::function<int()> transFunc = [&]() -> int {
        ret = trigger.QueryAlbumIdByLPath(g_trans);
        return NativeRdb::E_OK;
    };
    std::string key = DEFAULT_KEY;
    // 1. trans nullptr
    EXPECT_FALSE(trigger.QueryAlbumIdByLPath(nullptr));
    // 2. invalid lPath
    InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo packageInfo = {
        .lPath = DEFAULT_LPATH,
        .packageName = DEFAULT_PACKAGE_NAME,
        .ownerPackage = DEFAULT_OWNER_PACKAGE_NAME,
        .albumCnt = NON_EXIST_ALBUM_CNT
    };
    trigger.packageInfoMap_[key] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_FALSE(ret);
    // 3. valid lpath
    packageInfo.lPath = MediaLibraryTriggerTestUtils::SOURCE_ALBUM_INFO.lpath_;
    trigger.packageInfoMap_[key] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_CheckValid_000, TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo packageInfo = {
        .lPath = DEFAULT_LPATH,
        .packageName = DEFAULT_PACKAGE_NAME,
        .ownerPackage = DEFAULT_OWNER_PACKAGE_NAME,
        .albumCnt = NON_EXIST_ALBUM_CNT
    };
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_TRUE(trigger.CheckValid());

    packageInfo.lPath = "";
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_FALSE(trigger.CheckValid());
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_UpdatePhotoOwnerAlbumId_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.UpdatePhotoOwnerAlbumId(g_trans);
        return NativeRdb::E_OK;
    };
    // 1. trans nullptr
    EXPECT_FALSE(trigger.UpdatePhotoOwnerAlbumId(nullptr));
    // 2. QueryAlbumIdByLPath fail
    InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo packageInfo = {
        .lPath = DEFAULT_LPATH,
        .packageName = DEFAULT_PACKAGE_NAME,
        .ownerPackage = DEFAULT_OWNER_PACKAGE_NAME,
        .albumCnt = NON_EXIST_ALBUM_CNT
    };
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_FALSE(ret);
    // 3. invalid albumId
    std::string key = "packageKey1";
    packageInfo.lPath = MediaLibraryTriggerTestUtils::SOURCE_ALBUM_INFO.lpath_;
    trigger.packageInfoMap_[key] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_FALSE(ret);
    
    trigger.packageInfoMap_.erase(DEFAULT_KEY);
    trigger.lPathAlbumIdMap_.clear();
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_DeleteFromPhotoAlbum_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.DeleteFromPhotoAlbum(g_trans);
        return NativeRdb::E_OK;
    };
    // 1. trans nullptr
    EXPECT_FALSE(trigger.DeleteFromPhotoAlbum(nullptr));
    // 2. empty candidateLPaths
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);

    InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo packageInfo = {
        .lPath = "",
        .packageName = DEFAULT_PACKAGE_NAME,
        .ownerPackage = DEFAULT_OWNER_PACKAGE_NAME,
        .albumCnt = INVALID_ALBUM_CNT
    };
    // 3. albumCnt invalid
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_FALSE(ret);
    // 4. lPath invalid
    packageInfo.albumCnt =EXIT_ALBUM_CNT;
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_FALSE(ret);
    // 5. albumCnt > 0
    packageInfo.lPath = DEFAULT_LPATH;
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);

    packageInfo.albumCnt = NON_EXIST_ALBUM_CNT;
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_InsertIntoPhotoAlbum_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.InsertIntoPhotoAlbum(g_trans);
        return NativeRdb::E_OK;
    };
    // 1. trans nullptr
    EXPECT_FALSE(trigger.InsertIntoPhotoAlbum(nullptr));
    // 2. empty insert values
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);

    InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo packageInfo = {
        .lPath = "",
        .packageName = DEFAULT_PACKAGE_NAME,
        .ownerPackage = DEFAULT_OWNER_PACKAGE_NAME,
        .albumCnt = INVALID_ALBUM_CNT
    };
    // 3. albumCnt invalid
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_FALSE(ret);
    // 4. lPath invalid
    packageInfo.albumCnt =EXIT_ALBUM_CNT;
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_FALSE(ret);
    // 5. albumCnt > 0
    packageInfo.lPath = DEFAULT_LPATH;
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);

    packageInfo.albumCnt = NON_EXIST_ALBUM_CNT;
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_GetLPathFromAlbumPlugin_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    std::string packageName = DEFAULT_PACKAGE_NAME;
    std::string ownerPackage = DEFAULT_OWNER_PACKAGE_NAME;
    std::string key = "packageName#ownerPackage";
    std::string expectedLPath = "/Pictures/packageName";
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.GetLPathFromAlbumPlugin(g_trans, packageName, ownerPackage);
        return NativeRdb::E_OK;
    };
    // 1. trans nullptr
    EXPECT_FALSE(trigger.GetLPathFromAlbumPlugin(nullptr, packageName, ownerPackage));
    // 2. lPath already quried
    trigger.packageInfoMap_[key].lPath = DEFAULT_LPATH;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    
    trigger.packageInfoMap_[key].lPath = "";
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    EXPECT_EQ(trigger.packageInfoMap_[key].lPath, expectedLPath);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_GetSourceAlbumCntByLPath_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    std::string packageName = DEFAULT_PACKAGE_NAME;
    std::string ownerPackage = DEFAULT_OWNER_PACKAGE_NAME;
    std::string key = "packageName#ownerPackage";
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.GetSourceAlbumCntByLPath(g_trans, packageName, ownerPackage);
        return NativeRdb::E_OK;
    };
    // 1. trans nullptr
    EXPECT_FALSE(trigger.GetSourceAlbumCntByLPath(nullptr, packageName, ownerPackage));
    // 2. albumCnt already found
    trigger.packageInfoMap_[key].albumCnt = NON_EXIST_ALBUM_CNT;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    trigger.packageInfoMap_[key].albumCnt = INVALID_ALBUM_CNT;
    // 3. lPath invalid
    trigger.packageInfoMap_[key].lPath = "";
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_FALSE(ret);
    
    trigger.packageInfoMap_[key].lPath = DEFAULT_LPATH;
    int expectedAlbumCnt = NON_EXIST_ALBUM_CNT;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    EXPECT_EQ(trigger.packageInfoMap_[key].albumCnt, expectedAlbumCnt);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_Notify_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo packageInfo;
    // 1. invalid albumCnt
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_FALSE(trigger.Notify());
    packageInfo.albumCnt =EXIT_ALBUM_CNT;
    // 2. invalid lPath
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_FALSE(trigger.Notify());
    packageInfo.lPath = DEFAULT_LPATH;
    // 3. invalid albumId
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_FALSE(trigger.Notify());
    trigger.lPathAlbumIdMap_[packageInfo.lPath] = 11;
    // 4. albumCnt > 0
    EXPECT_TRUE(trigger.Notify());
    // 5. albnumCnt == 0
    packageInfo.albumCnt = NON_EXIST_ALBUM_CNT;
    trigger.packageInfoMap_[DEFAULT_KEY] = packageInfo;
    EXPECT_TRUE(trigger.Notify());
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_CollectPackageInfo_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    std::string packageName = DEFAULT_PACKAGE_NAME;
    std::string ownerPackage = DEFAULT_OWNER_PACKAGE_NAME;
    std::string key = "packageName#ownerPackage";
    std::string expectedLPath = "/Pictures/packageName";
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.CollectPackageInfo(g_trans, packageName, ownerPackage);
        return NativeRdb::E_OK;
    };
    // 1. trans nullptr
    EXPECT_FALSE(trigger.CollectPackageInfo(nullptr, packageName, ownerPackage));
    
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    EXPECT_EQ(trigger.packageInfoMap_[key].lPath, expectedLPath);
    EXPECT_EQ(trigger.packageInfoMap_[key].albumCnt, NON_EXIST_ALBUM_CNT);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_IsTriggerFireForRow_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    PhotoAssetChangeData changeData;
    changeData.infoAfterChange_.packageName_ = "";
    changeData.infoAfterChange_.ownerPackage_ = DEFAULT_OWNER_PACKAGE_NAME;
    changeData.infoAfterChange_.ownerAlbumId_ = DEFAULT_OWNER_ALBUM_ID;
    changeData.infoAfterChange_.fileId_ = DEFAULT_FILEID;
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.IsTriggerFireForRow(g_trans, changeData);
        return NativeRdb::E_OK;
    };
    std::string key = "packageName#ownerPackage";
    std::string expectedLPath = "/Pictures/packageName";
    int expectedAlbumCnt = NON_EXIST_ALBUM_CNT;
    // 1. trans nullptr
    EXPECT_FALSE(trigger.IsTriggerFireForRow(nullptr, changeData));
    // 2. packageName invalid
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(trigger.triggeredFileIds_.empty());
    changeData.infoAfterChange_.packageName_ = DEFAULT_PACKAGE_NAME;
    // 3. ownerAlbumId invalid
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(trigger.triggeredFileIds_.empty());
    changeData.infoAfterChange_.ownerAlbumId_ = INVALID_OWNER_ALBUM_ID;
    
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    auto packageInfo = trigger.packageInfoMap_[key];
    EXPECT_EQ(packageInfo.lPath, expectedLPath);
    EXPECT_EQ(packageInfo.albumCnt, expectedAlbumCnt);
}

HWTEST_F(MediaLibraryTriggerTest, InsertSourcePhotoCreateSourceAlbumTrigger_Process_000,
    TestSize.Level2)
{
    InsertSourcePhotoCreateSourceAlbumTrigger trigger;
    std::vector<PhotoAssetChangeData> changeDataVec;
    int32_t ret = -1;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.Process(g_trans, changeDataVec);
        return NativeRdb::E_OK;
    };
    // 1. trans nullptr
    EXPECT_EQ(trigger.Process(nullptr, changeDataVec), NativeRdb::E_ERROR);
    // 2. 0 triggered fileIds
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    trigger.triggeredFileIds_.push_back("1");
    // 3. 0 changeData
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    PhotoAssetChangeData changeData;
    changeDataVec.push_back(changeData);
    // 4. checkValid faild
    std::string key = DEFAULT_KEY;
    InsertSourcePhotoCreateSourceAlbumTrigger::PackageInfo packageInfo = {
        .lPath = "",
        .packageName = DEFAULT_PACKAGE_NAME,
        .ownerPackage = DEFAULT_OWNER_PACKAGE_NAME,
        .albumCnt = NON_EXIST_ALBUM_CNT
    };
    trigger.packageInfoMap_[key] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    packageInfo.lPath = DEFAULT_LPATH;
    trigger.packageInfoMap_[key] = packageInfo;
    
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

HWTEST_F(MediaLibraryTriggerTest, InsertPhotoUpdateAlbumBundleNameTrigger_PackageInfo_000, TestSize.Level2)
{
    InsertPhotoUpdateAlbumBundleNameTrigger::PackageInfo packageInfo;
    EXPECT_FALSE(packageInfo.IsValid());
    packageInfo.packageName = DEFAULT_PACKAGE_NAME;
    EXPECT_FALSE(packageInfo.IsValid());
    packageInfo.ownerPackage = DEFAULT_OWNER_PACKAGE_NAME;
    EXPECT_FALSE(packageInfo.IsValid());
    packageInfo.albumWithoutBundleNameCnt = EXIT_ALBUM_WO_BUNDLE_NAME_CNT;
    EXPECT_TRUE(packageInfo.IsValid());
}

HWTEST_F(MediaLibraryTriggerTest, InsertPhotoUpdateAlbumBundleNameTrigger_Process_000, TestSize.Level2)
{
    InsertPhotoUpdateAlbumBundleNameTrigger trigger;
    std::vector<PhotoAssetChangeData> changeDataVec;
    int32_t ret = -1;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.Process(g_trans, changeDataVec);
        return NativeRdb::E_OK;
    };
    InsertPhotoUpdateAlbumBundleNameTrigger::PackageInfo packageInfo = {
        .packageName = DEFAULT_PACKAGE_NAME,
        .ownerPackage = DEFAULT_OWNER_PACKAGE_NAME,
        .albumWithoutBundleNameCnt = INVALID_ALBUM_WO_BUNDLE_NAME_CNT
    };
    std::string key = DEFAULT_KEY;

    // 1. trans nullptr
    EXPECT_EQ(trigger.Process(nullptr, changeDataVec), NativeRdb::E_ERROR);
    // 2. 0 triggered package
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    // 3. invalid packageInfo
    trigger.packageInfoMap_[key] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    packageInfo.albumWithoutBundleNameCnt = NON_EXIT_ALBUM_WO_BUNDLE_NAME_CNT;
    trigger.packageInfoMap_[key] = packageInfo;
    // 4. packageInfo albumWithoutBundleNameCnt 0
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    packageInfo.albumWithoutBundleNameCnt = EXIT_ALBUM_WO_BUNDLE_NAME_CNT;
    trigger.packageInfoMap_[key] = packageInfo;

    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

HWTEST_F(MediaLibraryTriggerTest, InsertPhotoUpdateAlbumBundleNameTrigger_isAlbumWoBundleName_000, TestSize.Level2)
{
    InsertPhotoUpdateAlbumBundleNameTrigger trigger;
    std::string packageName = DEFAULT_PACKAGE_NAME;
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.isAlbumWoBundleName(g_trans, packageName);
        return NativeRdb::E_OK;
    };
    // 1. trans nullptr
    EXPECT_FALSE(trigger.isAlbumWoBundleName(nullptr, packageName));
    // 2. packageInfo valid
    InsertPhotoUpdateAlbumBundleNameTrigger::PackageInfo packageInfo = {
        .packageName = packageName,
        .ownerPackage = DEFAULT_OWNER_PACKAGE_NAME,
        .albumWithoutBundleNameCnt = NON_EXIT_ALBUM_WO_BUNDLE_NAME_CNT
    };
    trigger.packageInfoMap_[packageName] = packageInfo;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    packageInfo.albumWithoutBundleNameCnt = INVALID_ALBUM_WO_BUNDLE_NAME_CNT;
    trigger.packageInfoMap_[packageName] = packageInfo;
    // 3. packageInfo inValid
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaLibraryTriggerTest, InsertPhotoUpdateAlbumBundleNameTrigger_IsTriggerFireForRow_000,
    TestSize.Level2)
{
    InsertPhotoUpdateAlbumBundleNameTrigger trigger;
    PhotoAssetChangeData changeData;
    changeData.infoAfterChange_.packageName_ = "";
    changeData.infoAfterChange_.ownerPackage_ = "";
    bool ret = false;
    std::function<int(void)> transFunc = [&]() -> int {
        ret = trigger.IsTriggerFireForRow(g_trans, changeData);
        return NativeRdb::E_OK;
    };
    std::string packageName = DEFAULT_PACKAGE_NAME;
    std::string ownerPackage = DEFAULT_OWNER_PACKAGE_NAME;

    // 1. trans nullptr
    EXPECT_FALSE(trigger.IsTriggerFireForRow(nullptr, changeData));
    // 2. packageName invalid
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(trigger.packageInfoMap_.empty());
    changeData.infoAfterChange_.packageName_ = packageName;
    // 3. ownerPackage invalid
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(trigger.packageInfoMap_.empty());
    changeData.infoAfterChange_.ownerPackage_ = ownerPackage;

    int expectedAlbumWoBundleCnt = NON_EXIT_ALBUM_WO_BUNDLE_NAME_CNT;
    EXPECT_EQ(g_trans->RetryTrans(transFunc), NativeRdb::E_OK);
    EXPECT_TRUE(ret);
    auto packageInfo = trigger.packageInfoMap_[packageName];
    EXPECT_EQ(packageInfo.packageName, packageName);
    EXPECT_EQ(packageInfo.ownerPackage, ownerPackage);
    EXPECT_EQ(packageInfo.albumWithoutBundleNameCnt, expectedAlbumWoBundleCnt);
}
} // namespace Media
} // namespace OHOS