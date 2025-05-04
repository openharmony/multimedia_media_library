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

#define MLOG_TAG "CloudBackupRestoreTest"

#include "cloud_backup_restore_test.h"

#include <string>

#define private public
#define protected public
#include "cloud_backup_restore.h"
#include "database_utils.h"
#include "gallery_source.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "media_log.h"
#undef protected
#undef private

using namespace testing::ext;

namespace OHOS::Media {
const std::string TEST_BACKUP_PATH = "/data/test/backup/db";
const std::string TEST_BACKUP_GALLERY_PATH = "/data/test/backup/db/gallery.db";
const std::string TEST_UPGRADE_FILE_DIR = "/data/test/backup/file";
const std::string GALLERY_APP_NAME = "gallery";
const std::string MEDIA_APP_NAME = "external";
const std::string TEST_NEW_DATA = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

void InitGallerySource(GallerySource &gallerySource, const std::string &dbPath)
{
    MEDIA_INFO_LOG("Start init gallerySource");
    gallerySource.Init(dbPath);
    ASSERT_NE(gallerySource.galleryStorePtr_, nullptr);
}

void ClearCloneSource(GallerySource &gallerySource, const std::string &dbPath)
{
    gallerySource.galleryStorePtr_ = nullptr;
    NativeRdb::RdbHelper::DeleteRdbStore(dbPath);
}

void CloudBackupRestoreTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("SetUpTestCase");
    MEDIA_INFO_LOG("Start Init media_library.db");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
    CloudBackupRestoreTestUtils::ClearAllData();
}

void CloudBackupRestoreTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("TearDownTestCase");
    CloudBackupRestoreTestUtils::ClearAllData();
}

// SetUp:Execute before each test case
void CloudBackupRestoreTest::SetUp() {}

void CloudBackupRestoreTest::TearDown() {}

HWTEST_F(CloudBackupRestoreTest, cloud_backup_restore_init_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start cloud_backup_restore_init_001");
    GallerySource gallerySource;
    InitGallerySource(gallerySource, TEST_BACKUP_GALLERY_PATH);
    std::unique_ptr<CloudBackupRestore> restore =
        std::make_unique<CloudBackupRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, CLOUD_BACKUP_RESTORE_ID);
    restore->mediaLibraryRdb_ = g_rdbStore->GetRaw();

    int32_t errCode = restore->Init(TEST_BACKUP_PATH, TEST_UPGRADE_FILE_DIR, true);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(restore->filePath_, TEST_BACKUP_PATH);
    EXPECT_NE(restore->photoAlbumRestore_.mediaLibraryRdb_, nullptr);

    ClearCloneSource(gallerySource, TEST_BACKUP_GALLERY_PATH);
    MEDIA_INFO_LOG("End cloud_backup_restore_init_001");
}

HWTEST_F(CloudBackupRestoreTest, cloud_backup_restore_query_file_infos_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start cloud_backup_restore_query_file_infos_001");
    GallerySource gallerySource;
    InitGallerySource(gallerySource, TEST_BACKUP_GALLERY_PATH);
    std::unique_ptr<CloudBackupRestore> restore =
        std::make_unique<CloudBackupRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, CLOUD_BACKUP_RESTORE_ID);
    restore->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restore->Init(TEST_BACKUP_PATH, TEST_UPGRADE_FILE_DIR, true);

    std::vector<FileInfo> fileInfos = restore->QueryFileInfos(0);
    EXPECT_GT(fileInfos.size(), 0);
    FileInfo fileInfo = fileInfos[0];
    EXPECT_EQ(fileInfo.localMediaId, fileInfo.fileIdOld);

    ClearCloneSource(gallerySource, TEST_BACKUP_GALLERY_PATH);
    MEDIA_INFO_LOG("End cloud_backup_restore_query_file_infos_001");
}

HWTEST_F(CloudBackupRestoreTest, cloud_backup_restore_query_file_infos_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start cloud_backup_restore_query_file_infos_002");
    GallerySource gallerySource;
    InitGallerySource(gallerySource, TEST_BACKUP_GALLERY_PATH);
    std::unique_ptr<CloudBackupRestore> restore =
        std::make_unique<CloudBackupRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, CLOUD_BACKUP_RESTORE_ID);
    restore->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    restore->Init(TEST_BACKUP_PATH, TEST_UPGRADE_FILE_DIR, true);

    std::vector<FileInfo> fileInfos = restore->QueryFileInfos(0);
    EXPECT_GT(fileInfos.size(), 0);
    EXPECT_GT(CloudBackupRestoreTestUtils::GetNullStorageIdCount(), 0);

    ClearCloneSource(gallerySource, TEST_BACKUP_GALLERY_PATH);
    MEDIA_INFO_LOG("End cloud_backup_restore_query_file_infos_002");
}

HWTEST_F(CloudBackupRestoreTest, cloud_backup_restore_get_insert_value_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start cloud_backup_restore_get_insert_value_001");
    std::unique_ptr<CloudBackupRestore> restore =
        std::make_unique<CloudBackupRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, CLOUD_BACKUP_RESTORE_ID);
    FileInfo fileInfo;
    NativeRdb::ValuesBucket value = restore->GetInsertValue(fileInfo, TEST_NEW_DATA, SourceType::GALLERY);

    ValueObject valueObject;
    EXPECT_EQ(value.GetObject(PhotoColumn::PHOTO_ORIENTATION, valueObject), 0); // orientation not added to value

    std::string filePath;
    EXPECT_NE(value.GetObject(MediaColumn::MEDIA_FILE_PATH, valueObject), 0); // data not added to value
    valueObject.GetString(filePath);
    EXPECT_EQ(filePath, TEST_NEW_DATA);

    MEDIA_INFO_LOG("End cloud_backup_restore_get_insert_value_001");
}

HWTEST_F(CloudBackupRestoreTest, cloud_backup_restore_set_value_from_metadata_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start cloud_backup_restore_set_value_from_metadata_001");
    std::unique_ptr<CloudBackupRestore> restore =
        std::make_unique<CloudBackupRestore>(GALLERY_APP_NAME, MEDIA_APP_NAME, CLOUD_BACKUP_RESTORE_ID);
    FileInfo fileInfo;
    NativeRdb::ValuesBucket value;
    restore->SetValueFromMetaData(fileInfo, values);

    ValueObject valueObject;
    EXPECT_NE(value.GetObject(PhotoColumn::PHOTO_ORIENTATION, valueObject), 0); // orientation added to value
    EXPECT_NE(value.GetObject(MediaColumn::MEDIA_SIZE, valueObject), 0); // size added to value
    EXPECT_NE(value.GetObject(MediaColumn::MEDIA_DATE_TAKEN, valueObject), 0); // date_taken added to value
    EXPECT_NE(value.GetObject(MediaColumn::MEDIA_DATE_MODIFIED, valueObject), 0); // date_modified added to value
    EXPECT_NE(value.GetObject(MediaColumn::MEDIA_DATE_ADDED, valueObject), 0); // date_added added to value

    MEDIA_INFO_LOG("End cloud_backup_restore_set_value_from_metadata_001");
}

void CloudBackupRestoreTestUtils::ClearAllData()
{
    ClearPhotosData();
}

void CloudBackupRestoreTestUtils::ClearPhotosData()
{
    const std::string CLEAR_PHOTOS_SQL = "DELETE FROM Photos";
    DatabaseUtils::ExecuteSql(g_rdbStore->GetRaw(), CLEAR_PHOTOS_SQL);
}

int32_t CloudBackupRestoreTestUtils::GetNullStorageIdCount(const std::vector<FileInfo> &infos)
{
    int32_t count = 0;
    for (const auto &info : infos) {
        count += static_cast<int32_t>(info.title == "null_storage_id");
    }
    return count;
}
}  // namespace OHOS::Media