/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define MLOG_TAG "CloneRestoreCloudAssetCoverageTest"

#include "clone_restore_cloud_asset_coverage_test.h"

#define private public
#define protected public
#include "backup_const.h"
#include "clone_restore.h"
#include "media_column.h"
#undef private
#undef protected

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
    fileInfo.cloudId = cloudId;
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

HWTEST_F(CloneRestoreCloudAssetCoverageTest, IsSameFileForClone_CloudDuplicateNeedMove_001, TestSize.Level1)
{
    CloneRestore restore;
    PreparePhotosClone(restore, g_db);
    int32_t id = InsertPhotoRow(g_db, "cid-need-move-001", 0, static_cast<int32_t>(PhotoPositionType::CLOUD),
        "/storage/cloud/files/Photo/1/exist_001.jpg");
    ASSERT_GT(id, 0);
    FileInfo info = BuildFileInfo(static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD), "cid-need-move-001");
    bool same = restore.IsSameFileForClone(PhotoColumn::PHOTOS_TABLE, info);
    EXPECT_FALSE(same);
    EXPECT_FALSE(info.isNew);
    EXPECT_TRUE(info.needMove);
    EXPECT_EQ(info.fileIdNew, id);
}

HWTEST_F(CloneRestoreCloudAssetCoverageTest, IsSameFileForClone_CloudCleanRecordNeedUpdate_001, TestSize.Level1)
{
    CloneRestore restore;
    PreparePhotosClone(restore, g_db);
    int32_t id = InsertPhotoRow(g_db, "cid-clean-001", 1, static_cast<int32_t>(PhotoPositionType::CLOUD),
        "/storage/cloud/files/Photo/1/exist_002.jpg");
    ASSERT_GT(id, 0);
    FileInfo info = BuildFileInfo(static_cast<int32_t>(PhotoPositionType::LOCAL), "cid-clean-001");
    bool same = restore.IsSameFileForClone(PhotoColumn::PHOTOS_TABLE, info);
    EXPECT_FALSE(same);
    EXPECT_TRUE(info.needUpdate);
}

HWTEST_F(CloneRestoreCloudAssetCoverageTest, IsSameFileForClone_NormalDuplicate_001, TestSize.Level1)
{
    CloneRestore restore;
    PreparePhotosClone(restore, g_db);
    int32_t id = InsertPhotoRow(g_db, "cid-normal-001", 0, static_cast<int32_t>(PhotoPositionType::LOCAL),
        "/storage/cloud/files/Photo/1/exist_003.jpg");
    ASSERT_GT(id, 0);
    FileInfo info = BuildFileInfo(static_cast<int32_t>(PhotoPositionType::LOCAL), "cid-normal-001");
    bool same = restore.IsSameFileForClone(PhotoColumn::PHOTOS_TABLE, info);
    EXPECT_TRUE(same);
    EXPECT_FALSE(info.needMove);
}

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
