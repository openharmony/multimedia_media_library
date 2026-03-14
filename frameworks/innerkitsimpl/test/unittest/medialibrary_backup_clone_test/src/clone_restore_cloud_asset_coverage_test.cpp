/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "CloneRestoreCloudAssetCoverageTest"

#include "clone_restore_cloud_asset_coverage_test.h"

#include "backup_const.h"
#include "clone_restore.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_errno.h"

using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
const std::string TEST_DB_PATH = "/data/test/backup/clone_restore_cloud_asset_coverage.db";
constexpr int64_t TEST_MEDIA_SIZE = 4 * 1024;

class CloneCoverageOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        std::string sql = "CREATE TABLE IF NOT EXISTS Photos ("
            "file_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "data TEXT, clean_flag INT DEFAULT 0, position INT DEFAULT 1, "
            "display_name TEXT, size BIGINT DEFAULT 0, orientation INT DEFAULT 0, "
            "owner_album_id INT DEFAULT 0, cloud_id TEXT, source_path TEXT, "
            "date_trashed BIGINT DEFAULT 0, hidden INT DEFAULT 0);";
        return store.ExecuteSql(sql);
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

std::shared_ptr<RdbStore> g_db = nullptr;

FileInfo BuildFileInfo(int32_t srcPosition, const std::string &cloudId)
{
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = srcPosition;
    fileInfo.uniqueId = cloudId;
    fileInfo.displayName = "ut.jpg";
    fileInfo.fileSize = TEST_MEDIA_SIZE;
    fileInfo.orientation = 0;
    fileInfo.ownerAlbumId = 1;
    fileInfo.packageName = "pkg";
    fileInfo.bundleName = "bundle";
    fileInfo.sourcePath = "/storage/emulated/0/Pictures/ut.jpg";
    fileInfo.lPath = "/Pictures";
    fileInfo.filePath = "/data/test/backup/source/ut.jpg";
    fileInfo.relativePath = "/Photo/1/ut.jpg";
    fileInfo.needMove = true;
    return fileInfo;
}

int32_t InsertPhotoRow(const std::shared_ptr<RdbStore> &db, const std::string &cloudId, int32_t cleanFlag,
    int32_t position, const std::string &path)
{
    ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, path);
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, cleanFlag);
    values.PutInt(PhotoColumn::PHOTO_POSITION, position);
    values.PutString(MediaColumn::MEDIA_NAME, "ut.jpg");
    values.PutLong(MediaColumn::MEDIA_SIZE, TEST_MEDIA_SIZE);
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, 0);
    values.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, 1);
    values.PutString(PhotoColumn::PHOTO_CLOUD_ID, cloudId);
    values.PutString(PhotoColumn::PHOTO_SOURCE_PATH, "/storage/emulated/0/Pictures/ut.jpg");
    values.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    values.PutInt(MediaColumn::MEDIA_HIDDEN, 0);
    int64_t rowNum = -1;
    int ret = db->Insert(rowNum, PhotoColumn::PHOTOS_TABLE, values);
    if (ret != E_OK) {
        return -1;
    }
    return static_cast<int32_t>(rowNum);
}

void ClearPhotos(const std::shared_ptr<RdbStore> &db)
{
    if (db == nullptr) {
        return;
    }
    (void)db->ExecuteSql("DELETE FROM Photos;");
}

void PreparePhotosClone(CloneRestore &restore, const std::shared_ptr<RdbStore> &db)
{
    restore.mediaLibraryRdb_ = db;
    (void)restore.photosClone_.OnStart(db, db);
}
} // namespace

void CloneRestoreCloudAssetCoverageTest::SetUpTestCase()
{
    RdbStoreConfig config(TEST_DB_PATH);
    CloneCoverageOpenCallback callback;
    int32_t errCode = E_OK;
    RdbHelper::DeleteRdbStore(TEST_DB_PATH);
    g_db = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    ASSERT_NE(g_db, nullptr);
}

void CloneRestoreCloudAssetCoverageTest::TearDownTestCase()
{
    g_db = nullptr;
    RdbHelper::DeleteRdbStore(TEST_DB_PATH);
}

void CloneRestoreCloudAssetCoverageTest::SetUp()
{
    ClearPhotos(g_db);
}

void CloneRestoreCloudAssetCoverageTest::TearDown()
{
    ClearPhotos(g_db);
}

// 验证 GetCloudInsertValue 会写入云端插入所需的基础字段。
HWTEST_F(CloneRestoreCloudAssetCoverageTest, CloudInsertValue_BasicColumns_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info = BuildFileInfo(static_cast<int32_t>(PhotoPositionType::CLOUD), "cid-base-001");
    NativeRdb::ValuesBucket values = restore.GetCloudInsertValue(info, "/storage/cloud/files/Photo/1/a.jpg", 0);
    EXPECT_TRUE(values.HasColumn(MediaColumn::MEDIA_FILE_PATH));
    EXPECT_TRUE(values.HasColumn(MediaColumn::MEDIA_SIZE));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_POSITION));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_CLOUD_ID));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_SYNC_STATUS));
}

// 验证 GetCloudInsertValue 在包名和 bundleName 为空时仍能生成关键字段。
HWTEST_F(CloneRestoreCloudAssetCoverageTest, CloudInsertValue_EmptyPkgBundle_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info = BuildFileInfo(static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD), "cid-empty-001");
    info.packageName = "";
    info.bundleName = "";
    NativeRdb::ValuesBucket values = restore.GetCloudInsertValue(info, "/storage/cloud/files/Photo/1/b.jpg", 0);
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_POSITION));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_CLOUD_ID));
}

// 验证 GetCloudInsertValue 在完整包信息场景下可正常生成云端插入字段。
HWTEST_F(CloneRestoreCloudAssetCoverageTest, CloudInsertValue_Batch_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info = BuildFileInfo(1, "cid-batch-001");
    info.packageName = "pkg";
    info.bundleName = "bundle";
    NativeRdb::ValuesBucket values = restore.GetCloudInsertValue(info,
        "/storage/cloud/files/Photo/1/batch_001.jpg", 0);
    EXPECT_TRUE(values.HasColumn(MediaColumn::MEDIA_FILE_PATH));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_POSITION));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_CLOUD_ID));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_SYNC_STATUS));
}

// 验证 GetCloudInsertValue 在包信息全部为空时仍保留核心云端字段。
HWTEST_F(CloneRestoreCloudAssetCoverageTest, CloudInsertValue_Batch_005, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info = BuildFileInfo(2, "cid-batch-005");
    info.packageName = "";
    info.bundleName = "";
    NativeRdb::ValuesBucket values = restore.GetCloudInsertValue(info,
        "/storage/cloud/files/Photo/1/batch_005.jpg", 0);
    EXPECT_TRUE(values.HasColumn(MediaColumn::MEDIA_FILE_PATH));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_POSITION));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_CLOUD_ID));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_SYNC_STATUS));
}

// 验证 GetCloudInsertValue 在仅缺少 bundleName 时仍可生成完整插入结果。
HWTEST_F(CloneRestoreCloudAssetCoverageTest, CloudInsertValue_Batch_007, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info = BuildFileInfo(1, "cid-batch-007");
    info.packageName = "pkg";
    info.bundleName = "";
    NativeRdb::ValuesBucket values = restore.GetCloudInsertValue(info,
        "/storage/cloud/files/Photo/1/batch_007.jpg", 0);
    EXPECT_TRUE(values.HasColumn(MediaColumn::MEDIA_FILE_PATH));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_POSITION));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_CLOUD_ID));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_SYNC_STATUS));
}

} // namespace Media
} // namespace OHOS
