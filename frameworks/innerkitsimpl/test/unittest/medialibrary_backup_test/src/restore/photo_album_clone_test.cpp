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

#define MLOG_TAG "PhotoAlbumCloneTest"

#include "photo_album_clone_test.h"

#include <string>

#define private public
#define protected public
#include "database_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "photo_album_clone.h"
#undef private
#undef protected
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace testing::ext;

namespace OHOS::Media {
const int32_t TEST_FILE_ID = 1;
const int32_t TEST_ALBUM_ID = 10;
const int64_t TEST_FILE_SIZE = 1024;
const std::string TEST_ALBUM_NAME = "Camera";
const std::string TEST_ALBUM_LPATH = "/DCIM/Camera";
const std::string TEST_DATA = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
const std::string TEST_DISPLAY_NAME = "test.jpg";

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

void PhotoAlbumCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    MEDIA_INFO_LOG("Start Init");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
}

void PhotoAlbumCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    PhotoAlbumCloneTestUtils::ClearAllData();
}

void PhotoAlbumCloneTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
    PhotoAlbumCloneTestUtils::ClearAllData();
}

void PhotoAlbumCloneTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoAlbumCloneTest, GetPhotoAlbumCountInOriginalDb_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test start");
    auto count = PhotoAlbumClone().GetPhotoAlbumCountInOriginalDb();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test end");
}

HWTEST_F(PhotoAlbumCloneTest, GetPhotoAlbumInOriginalDb_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetPhotoAlbumInOriginalDb_Test start");
    int32_t offset = 0;
    int32_t count = 200;
    auto resultSet = PhotoAlbumClone().GetPhotoAlbumInOriginalDb(offset, count);
    EXPECT_EQ(resultSet, nullptr);
    MEDIA_INFO_LOG("GetPhotoAlbumInOriginalDb_Test end");
}

HWTEST_F(PhotoAlbumCloneTest, GetPhotoAlbumCountInOriginalDb_Test_001, TestSize.Level0)
{
    // normal album, local photo, cloud restore not satisfied
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test_001 start");
    PhotoAlbumCloneTestUtils::InsertAlbum(static_cast<int32_t>(DirtyType::TYPE_NEW));
    PhotoAlbumCloneTestUtils::InsertPhoto(static_cast<int32_t>(PhotoPositionType::LOCAL));
    PhotoAlbumClone photoAlbumClone;
    photoAlbumClone.OnStart(g_rdbStore->GetRaw(), nullptr, false);

    int32_t count = photoAlbumClone.GetPhotoAlbumCountInOriginalDb();
    EXPECT_GT(count, 0);
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test_001 end");
}

HWTEST_F(PhotoAlbumCloneTest, GetPhotoAlbumCountInOriginalDb_Test_002, TestSize.Level0)
{
    // normal album, cloud photo, cloud restore not satisfied
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test_002 start");
    PhotoAlbumCloneTestUtils::InsertAlbum(static_cast<int32_t>(DirtyType::TYPE_NEW));
    PhotoAlbumCloneTestUtils::InsertPhoto(static_cast<int32_t>(PhotoPositionType::CLOUD));
    PhotoAlbumClone photoAlbumClone;
    photoAlbumClone.OnStart(g_rdbStore->GetRaw(), nullptr, false);

    int32_t count = photoAlbumClone.GetPhotoAlbumCountInOriginalDb();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test_002 end");
}

HWTEST_F(PhotoAlbumCloneTest, GetPhotoAlbumCountInOriginalDb_Test_003, TestSize.Level0)
{
    // normal album, cloud photo, cloud restore satisfied
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test_003 start");
    PhotoAlbumCloneTestUtils::InsertAlbum(static_cast<int32_t>(DirtyType::TYPE_DELETED));
    PhotoAlbumCloneTestUtils::InsertPhoto(static_cast<int32_t>(PhotoPositionType::CLOUD));
    PhotoAlbumClone photoAlbumClone;
    photoAlbumClone.OnStart(g_rdbStore->GetRaw(), nullptr, true);

    int32_t count = photoAlbumClone.GetPhotoAlbumCountInOriginalDb();
    EXPECT_GT(count, 0);
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test_003 end");
}

HWTEST_F(PhotoAlbumCloneTest, GetPhotoAlbumCountInOriginalDb_Test_004, TestSize.Level0)
{
    // deleted album, cloud photo, cloud restore satisfied
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test_004 start");
    PhotoAlbumCloneTestUtils::InsertAlbum(static_cast<int32_t>(DirtyType::TYPE_DELETED));
    PhotoAlbumCloneTestUtils::InsertPhoto(static_cast<int32_t>(PhotoPositionType::CLOUD));
    PhotoAlbumClone photoAlbumClone;
    photoAlbumClone.OnStart(g_rdbStore->GetRaw(), nullptr, true);

    int32_t count = photoAlbumClone.GetPhotoAlbumCountInOriginalDb();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test_004 end");
}

void PhotoAlbumCloneTestUtils::ClearAllData()
{
    ClearPhotosData();
    ClearPhotoAlbumData();
}

void PhotoAlbumCloneTestUtils::ClearPhotosData()
{
    const std::string CLEAR_PHOTOS_SQL = "DELETE FROM Photos";
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), CLEAR_PHOTOS_SQL);
}

void PhotoAlbumCloneTestUtils::ClearPhotoAlbumData()
{
    const std::string CLEAR_PHOTO_ALBUM_SQL = "DELETE FROM PhotoAlbum WHERE album_type <> ?";
    const std::vector<NativeRdb::ValueObject> BIND_ARGS = { static_cast<int32_t>(PhotoAlbumType::SYSTEM) };
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), CLEAR_PHOTO_ALBUM_SQL, BIND_ARGS);
}

void PhotoAlbumCloneTestUtils::InsertPhoto(int32_t position)
{
    const std::string INSERT_SQL = "INSERT INTO Photos (file_id, data, size, display_name, owner_album_id, position) "
        " VALUES (?, ?, ?, ?, ?, ?)";
    const std::vector<NativeRdb::ValueObject> BIND_ARGS = { TEST_FILE_ID, TEST_DATA, TEST_FILE_SIZE, TEST_DISPLAY_NAME,
        TEST_ALBUM_ID, position };
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), INSERT_SQL, BIND_ARGS);
}

void PhotoAlbumCloneTestUtils::InsertAlbum(int32_t dirty)
{
    const std::string INSERT_SQL = "INSERT INTO PhotoAlbum (album_id, album_name, lpath, album_type, album_subtype, "
        " dirty) VALUES (?, ?, ?, ?, ?, ?)";
    const std::vector<NativeRdb::ValueObject> BIND_ARGS = { TEST_ALBUM_ID, TEST_ALBUM_NAME, TEST_ALBUM_LPATH,
        static_cast<int32_t>(PhotoAlbumType::USER), static_cast<int32_t>(PhotoAlbumSubType::USER_GENERIC), dirty};
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), INSERT_SQL, BIND_ARGS);
}
}  // namespace OHOS::Media