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

#define MLOG_TAG "PhotoAlbumDaoTest"

#define private public
#define protected public
#include "database_mock.h"
#undef private
#undef protected

#include "photo_album_dao_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>
#include <sys/stat.h>
#include <cstdlib>

#include "rdb_store.h"
#include "media_log.h"
#include "database_utils.h"
#include "album_plugin_config.h"

using namespace testing::ext;

namespace OHOS::Media {

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void PhotoAlbumDaoTest::Init()
{
    /**
    MODE: UPGRADE_RESTORE_ID
    media_library.db Path = /data/test/backup/db/medialibrary/ce/databases/media_library.db
    */
    // mock media_library.db
    DatabaseMock().MediaLibraryDbMock(BASE_DIR_MEDIALIBRARY);
    MEDIA_INFO_LOG("medialib_backup_test StartRestore - end.");
}

void PhotoAlbumDaoTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    PhotoAlbumDaoTest::Init();
}

void PhotoAlbumDaoTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase");
}

// SetUp:Execute before each test case
void PhotoAlbumDaoTest::SetUp()
{
    auto medialibraryRdbPtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    this->photoAlbumDao_.SetMediaLibraryRdb(medialibraryRdbPtr);
}

void PhotoAlbumDaoTest::TearDown(void)
{}

HWTEST_F(PhotoAlbumDaoTest, check_database_exists, TestSize.Level0)
{
    MEDIA_INFO_LOG("check_database_exists start");
    auto rdbStorePtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    EXPECT_FALSE(rdbStorePtr == nullptr);
    MEDIA_INFO_LOG("check_database_exists end");
}

HWTEST_F(PhotoAlbumDaoTest, GetPhotoAlbum_Success, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetPhotoAlbum_Success start");
    auto medialibraryRdbPtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    EXPECT_FALSE(medialibraryRdbPtr == nullptr);
    PhotoAlbumDao photoAlbumDao;
    photoAlbumDao.SetMediaLibraryRdb(medialibraryRdbPtr);
    std::string lPath = "/Pictures/其它";
    PhotoAlbumDao::PhotoAlbumRowData screenRecorderAlbum = photoAlbumDao.GetPhotoAlbum(lPath);
    EXPECT_EQ(screenRecorderAlbum.lPath, lPath);
    MEDIA_INFO_LOG("GetPhotoAlbum_Success end");
}

HWTEST_F(PhotoAlbumDaoTest, album_op_success, TestSize.Level0)
{
    MEDIA_INFO_LOG("album_op_success start");
    auto medialibraryRdbPtr = DatabaseUtils().GetRdbStore(DB_PATH_MEDIALIBRARY);
    EXPECT_FALSE(medialibraryRdbPtr == nullptr);
    PhotoAlbumDao photoAlbumDao;
    photoAlbumDao.SetMediaLibraryRdb(medialibraryRdbPtr);
    std::string lPath = AlbumPlugin::LPATH_SCREEN_RECORDS;
    PhotoAlbumDao::PhotoAlbumRowData screenRecorderAlbum = photoAlbumDao.GetPhotoAlbum(lPath);
    EXPECT_TRUE(screenRecorderAlbum.lPath.empty());
    screenRecorderAlbum = photoAlbumDao.BuildAlbumInfoOfRecorders();
    EXPECT_EQ(screenRecorderAlbum.lPath, AlbumPlugin::LPATH_SCREEN_RECORDS);
    screenRecorderAlbum = photoAlbumDao.GetOrCreatePhotoAlbum(screenRecorderAlbum);
    EXPECT_EQ(screenRecorderAlbum.albumName, AlbumPlugin::ALBUM_NAME_SCREEN_RECORDS);
    EXPECT_EQ(screenRecorderAlbum.lPath, AlbumPlugin::LPATH_SCREEN_RECORDS);
    MEDIA_INFO_LOG("album_op_success end");
}

HWTEST_F(PhotoAlbumDaoTest, GetPhotoAlbum_find_crash_01, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetPhotoAlbum_find_crash_01 start");
    int32_t maxAlbumCount = 1 * 100;
    for (int32_t offset = 0; offset < maxAlbumCount; offset++) {
        std::string lPath = "/Pictures/example_" + std::to_string(offset);
        this->RunPhotoAlbumCache(lPath);
        PhotoAlbumDao::PhotoAlbumRowData albumRowData = this->photoAlbumDao_.GetPhotoAlbum(lPath);
        EXPECT_EQ(albumRowData.lPath, lPath);
    }
    MEDIA_INFO_LOG("GetPhotoAlbum_find_crash_01 end");
}

HWTEST_F(PhotoAlbumDaoTest, BuildAlbumInfoOfRecorders_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("BuildAlbumInfoOfRecorders_Test start");
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = this->photoAlbumDao_.BuildAlbumInfoOfRecorders();
    EXPECT_EQ(albumRowData.albumName, AlbumPlugin::ALBUM_NAME_SCREEN_RECORDS);
    EXPECT_EQ(albumRowData.bundleName, AlbumPlugin::BUNDLE_NAME_SCREEN_RECORDS);
    EXPECT_EQ(albumRowData.lPath, AlbumPlugin::LPATH_SCREEN_RECORDS);
    EXPECT_EQ(albumRowData.priority, 1);
    MEDIA_INFO_LOG("BuildAlbumInfoOfRecorders_Test end");
}

HWTEST_F(PhotoAlbumDaoTest, ParseSourcePathToLPath_Test01, TestSize.Level0)
{
    MEDIA_INFO_LOG("ParseSourcePathToLPath_Test01 start");
    const std::string sourcePath = "/storage/emulated/0/DCIM/Camera/IMG_111.jpg";
    std::string result = this->photoAlbumDao_.ParseSourcePathToLPath(sourcePath);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result, "/DCIM/Camera");
    MEDIA_INFO_LOG("ParseSourcePathToLPath_Test01 end");
}

HWTEST_F(PhotoAlbumDaoTest, ParseSourcePathToLPath_Test02, TestSize.Level0)
{
    MEDIA_INFO_LOG("ParseSourcePathToLPath_Test02 start");
    const std::string sourcePath = "";
    std::string result = this->photoAlbumDao_.ParseSourcePathToLPath(sourcePath);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result, "/Pictures/其它");
    MEDIA_INFO_LOG("ParseSourcePathToLPath_Test02 end");
}

HWTEST_F(PhotoAlbumDaoTest, BuildAlbumInfoByLPath_Test01, TestSize.Level0)
{
    MEDIA_INFO_LOG("BuildAlbumInfoByLPath_Test01 start");
    const std::string lPath = "/Pictures/Test";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = this->photoAlbumDao_.BuildAlbumInfoByLPath(lPath);
    EXPECT_FALSE(albumRowData.lPath.empty());
    EXPECT_EQ(albumRowData.lPath, "/Pictures/Test");
    MEDIA_INFO_LOG("BuildAlbumInfoByLPath_Test01 end");
}

HWTEST_F(PhotoAlbumDaoTest, BuildAlbumInfoByLPath_Test02, TestSize.Level0)
{
    MEDIA_INFO_LOG("BuildAlbumInfoByLPath_Test02 start");
    const std::string lPath = "/Pictures/Users";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = this->photoAlbumDao_.BuildAlbumInfoByLPath(lPath);
    EXPECT_FALSE(albumRowData.lPath.empty());
    EXPECT_EQ(albumRowData.lPath, "/Pictures/Users");
    MEDIA_INFO_LOG("BuildAlbumInfoByLPath_Test02 end");
}

HWTEST_F(PhotoAlbumDaoTest, BuildAlbumInfoByLPath_Test03, TestSize.Level0)
{
    MEDIA_INFO_LOG("BuildAlbumInfoByLPath_Test03 start");
    const std::string lPath = "";
    PhotoAlbumDao::PhotoAlbumRowData albumRowData = this->photoAlbumDao_.BuildAlbumInfoByLPath(lPath);
    EXPECT_FALSE(albumRowData.lPath.empty());
    EXPECT_EQ(albumRowData.lPath, "/Pictures/其它");
    MEDIA_INFO_LOG("BuildAlbumInfoByLPath_Test03 end");
}
}  // namespace OHOS::Media