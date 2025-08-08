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

#define MLOG_TAG "MediaCloudSync"

#include "media_cloud_sync_service_dao_test.h"

#include "media_log.h"
#include "result_set_utils.h"
#include "media_file_utils.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_photo_operations.h"
#include "fetch_result.h"

#define private public
#include "cloud_media_album_dao.h"
#undef private
#include "cloud_media_common_dao.h"
#include "cloud_media_data_dao.h"
#include "cloud_media_photos_dao.h"
#include "media_cloud_sync_test_utils.h"

#include <iostream>

namespace OHOS::Media::CloudSync {
using namespace testing::ext;
using namespace OHOS::NativeRdb;

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

void CloudMediaSyncServiceDaoTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        GTEST_LOG_(ERROR) << "Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore";
        exit(1);
    }
    SetTestTables(g_rdbStore);
}

void CloudMediaSyncServiceDaoTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    ClearAndRestart(g_rdbStore);
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
}

// SetUp:Execute before each test case
void CloudMediaSyncServiceDaoTest::SetUp()
{
    if (g_rdbStore == nullptr) {
        GTEST_LOG_(ERROR) << "Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore";
        exit(1);
    }
    ClearAndRestart(g_rdbStore);
}

void CloudMediaSyncServiceDaoTest::TearDown() {}

HWTEST_F(CloudMediaSyncServiceDaoTest, CloudMediaAlbumDao_HandleLPathAndAlbumType_Test_001, TestSize.Level1)
{
    CloudMediaAlbumDao albumDao;
    PhotoAlbumDto record;
    int32_t ret = albumDao.HandleLPathAndAlbumType(record);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaSyncServiceDaoTest, CloudMediaAlbumDao_HandleLPathAndAlbumType_Test_002, TestSize.Level1)
{
    PhotoAlbumDto record1 = {
        .albumId = 15,
        .albumType = 0,
        .albumSubType = 2,
        .albumName = "test1",
        .lPath = "test2",
        .bundleName = "test3",
        .priority = 0,
        .cloudId = "10",
        .newCloudId = "20",
        .localLanguage = "test4",
        .albumDateCreated = 50,
        .albumDateAdded = 100,
        .albumDateModified = 150,
        .isDelete = false,
        .isSuccess = true,
    };
    CloudMediaAlbumDao albumDao;
    auto albumRefreshHandle = make_shared<AccurateRefresh::AlbumAccurateRefresh>();
    int32_t ret1 = albumDao.InsertAlbums(record1, albumRefreshHandle);
    std::cout << "ret1: " << ret1 << std::endl;

    PhotoAlbumDto record2;
    int32_t ret2 = albumDao.HandleLPathAndAlbumType(record2);
    std::cout << "ret2: " << ret2 << std::endl;
}

HWTEST_F(CloudMediaSyncServiceDaoTest, CloudMediaAlbumDao_ReplaceCoverUriCondition_Test_001, TestSize.Level1)
{
    CloudMediaAlbumDao albumDao;
    PhotoAlbumDto record;
    std::string coverUri = "file://media/Photo/93/VID_1754566736_008/SVID_20250807_193716_1.jpg";
    std::string lPath = "/Pictures/Screenrecords";
    bool ret = albumDao.ReplaceCoverUriCondition(coverUri, lPath);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CloudMediaSyncServiceDaoTest, CloudMediaAlbumDao_ReplaceCoverUriCondition_Test_002, TestSize.Level1)
{
    CloudMediaAlbumDao albumDao;
    PhotoAlbumDto record;
    std::string coverUri = "file://media/Photo/93/VID_1754566736_008/SVID_20250807_193716_1.mp4";
    std::string lPath = "/Pictures/Screenshots";
    bool ret = albumDao.ReplaceCoverUriCondition(coverUri, lPath);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CloudMediaSyncServiceDaoTest, CloudMediaAlbumDao_ReplaceCoverUriCondition_Test_003, TestSize.Level1)
{
    CloudMediaAlbumDao albumDao;
    PhotoAlbumDto record;
    std::string coverUri = "file://media/Photo/93/VID_1754566736_008/SVID_20250807_193716_1.mp4";
    std::string lPath = "/Pictures/Screenrecords";
    bool ret = albumDao.ReplaceCoverUriCondition(coverUri, lPath);
    EXPECT_EQ(ret, true);
}

HWTEST_F(CloudMediaSyncServiceDaoTest, CloudMediaAlbumDao_ReplaceCoverUriCondition_Test_004, TestSize.Level1)
{
    CloudMediaAlbumDao albumDao;
    PhotoAlbumDto record;
    std::string coverUri = "file://media/Photo/93/VID_1754566736_008/SVID_20250807_193716_1.jpg";
    std::string lPath = "/Pictures/Screenshots";
    bool ret = albumDao.ReplaceCoverUriCondition(coverUri, lPath);
    EXPECT_EQ(ret, true);
}
}