/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define MLOG_TAG "BaseRestoreBranchCoverageTest"

#include "base_restore_branch_coverage_test.h"

#include <fstream>

#define private public
#define protected public
#include "base_restore.h"
#include "media_file_utils.h"
#include "photos_dao.h"
#include "result_set.h"
#include "values_bucket.h"
#undef private
#undef protected

#include "medialibrary_errno.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
const std::string TEST_DIR = "/data/test/backup/base_restore_branch_coverage";

class TestBaseRestore final : public BaseRestore {
public:
    int32_t Init(const std::string &backupRestorePath, const std::string &upgradePath, bool isUpgrade) override
    {
        return E_OK;
    }

    NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType) override
    {
        NativeRdb::ValuesBucket values;
        values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
        return values;
    }

    bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
        std::string dbName = "") override
    {
        return false;
    }

    bool ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) override
    {
        return false;
    }

    void AnalyzeSource() override {}
    void RestorePhoto() override {}
    void RestoreAudio() override {}
    void HandleRestData() override {}
};

FileInfo BuildBaseInfo()
{
    FileInfo info;
    info.fileIdOld = 1;
    info.filePath = TEST_DIR + "/src.jpg";
    info.cloudPath = TEST_DIR + "/dst.jpg";
    info.needMove = true;
    info.isNew = true;
    info.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    return info;
}

void PrepareDir()
{
    if (!MediaFileUtils::IsDirectory(TEST_DIR)) {
        (void)MediaFileUtils::CreateDirectory(TEST_DIR);
    }
}

void WriteFile(const std::string &path, const std::string &content)
{
    std::ofstream ofs(path, std::ios::trunc | std::ios::binary);
    ofs << content;
}
} // namespace

void BaseRestoreBranchCoverageTest::SetUpTestCase()
{
    PrepareDir();
}

void BaseRestoreBranchCoverageTest::TearDownTestCase()
{
    (void)MediaFileUtils::DeleteDir(TEST_DIR);
}

void BaseRestoreBranchCoverageTest::SetUp()
{
    PrepareDir();
}

void BaseRestoreBranchCoverageTest::TearDown()
{
    (void)MediaFileUtils::DeleteDir(TEST_DIR);
    PrepareDir();
}

HWTEST_F(BaseRestoreBranchCoverageTest, ExtraCheckForCloneSameFile_CleanCloud_001, TestSize.Level1)
{
    TestBaseRestore restore;
    FileInfo info = BuildBaseInfo();
    PhotosDao::PhotosRowData rowData;
    rowData.fileId = 100;
    rowData.data = "/storage/cloud/files/Photo/1/clean_001.jpg";
    rowData.cleanFlag = 1;
    rowData.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    bool ret = restore.ExtraCheckForCloneSameFile(info, rowData);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(info.needUpdate);
    EXPECT_FALSE(info.isNew);
    EXPECT_EQ(info.fileIdNew, 100);
}

HWTEST_F(BaseRestoreBranchCoverageTest, ExtraCheckForCloneSameFile_NormalDuplicate_001, TestSize.Level1)
{
    TestBaseRestore restore;
    FileInfo info = BuildBaseInfo();
    PhotosDao::PhotosRowData rowData;
    rowData.fileId = 101;
    rowData.data = "/storage/cloud/files/Photo/1/dup_001.jpg";
    rowData.cleanFlag = 0;
    rowData.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool ret = restore.ExtraCheckForCloneSameFile(info, rowData);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(info.needMove);
    EXPECT_FALSE(info.isNew);
    EXPECT_EQ(info.fileIdNew, 101);
}

HWTEST_F(BaseRestoreBranchCoverageTest, CheckAndDelete_RemoveExistingColumn_001, TestSize.Level1)
{
    TestBaseRestore restore;
    NativeRdb::ValuesBucket values;
    values.PutString(PhotoColumn::PHOTO_USER_COMMENT, "abc");
    ASSERT_TRUE(values.HasColumn(PhotoColumn::PHOTO_USER_COMMENT));
    restore.CheckAndDelete(values, PhotoColumn::PHOTO_USER_COMMENT);
    EXPECT_FALSE(values.HasColumn(PhotoColumn::PHOTO_USER_COMMENT));
}

HWTEST_F(BaseRestoreBranchCoverageTest, CheckAndDelete_NonExistingColumn_001, TestSize.Level1)
{
    TestBaseRestore restore;
    NativeRdb::ValuesBucket values;
    restore.CheckAndDelete(values, PhotoColumn::PHOTO_USER_COMMENT);
    EXPECT_FALSE(values.HasColumn(PhotoColumn::PHOTO_USER_COMMENT));
}

HWTEST_F(BaseRestoreBranchCoverageTest, InsertDateTime_InvalidDetailTime_001, TestSize.Level1)
{
    TestBaseRestore restore;
    NativeRdb::ValuesBucket values;
    FileInfo info;
    info.dateTaken = 1715000000000;
    info.detailTime = "invalid";
    restore.InsertDateTime(values, info);
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_DETAIL_TIME));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_DATE_YEAR));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_DATE_MONTH));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_DATE_DAY));
}

HWTEST_F(BaseRestoreBranchCoverageTest, InsertDateTime_ValidDetailTime_001, TestSize.Level1)
{
    TestBaseRestore restore;
    NativeRdb::ValuesBucket values;
    FileInfo info;
    info.dateTaken = 1715000000000;
    info.detailTime = "2024:05:06 01:02:03";
    restore.InsertDateTime(values, info);
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_DETAIL_TIME));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_DATE_YEAR));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_DATE_MONTH));
    EXPECT_TRUE(values.HasColumn(PhotoColumn::PHOTO_DATE_DAY));
}

HWTEST_F(BaseRestoreBranchCoverageTest, MoveFile_CopyFallback_001, TestSize.Level1)
{
    TestBaseRestore restore;
    std::string src = TEST_DIR + "/src_fallback.txt";
    std::string dst = TEST_DIR + "/sub/dst_fallback.txt";
    (void)MediaFileUtils::CreateDirectory(TEST_DIR + "/sub");
    WriteFile(src, "hello-fallback");
    int32_t ret = restore.MoveFile(src, dst);
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(MediaFileUtils::IsFileExists(dst));
}

HWTEST_F(BaseRestoreBranchCoverageTest, MoveFile_SourceNotExist_001, TestSize.Level1)
{
    TestBaseRestore restore;
    std::string src = TEST_DIR + "/not_exist.txt";
    std::string dst = TEST_DIR + "/dst_not_exist.txt";
    int32_t ret = restore.MoveFile(src, dst);
    EXPECT_NE(ret, E_OK);
}

#define GEN_EXTRA_CHECK_TEST(ID, FILEID, CLEAN, POSITION, EXPECT_RET, EXPECT_NEED_UPDATE, EXPECT_NEED_MOVE) \
HWTEST_F(BaseRestoreBranchCoverageTest, ExtraCheckForCloneSameFile_Batch_##ID, TestSize.Level1) \
{ \
    TestBaseRestore restore; \
    FileInfo info = BuildBaseInfo(); \
    PhotosDao::PhotosRowData rowData; \
    rowData.fileId = FILEID; \
    rowData.data = "/storage/cloud/files/Photo/1/batch_" #ID ".jpg"; \
    rowData.cleanFlag = CLEAN; \
    rowData.position = POSITION; \
    bool ret = restore.ExtraCheckForCloneSameFile(info, rowData); \
    EXPECT_EQ(ret, EXPECT_RET); \
    EXPECT_EQ(info.needUpdate, EXPECT_NEED_UPDATE); \
    EXPECT_EQ(info.needMove, EXPECT_NEED_MOVE); \
    EXPECT_FALSE(info.isNew); \
    EXPECT_EQ(info.fileIdNew, FILEID); \
}

GEN_EXTRA_CHECK_TEST(001, 1001, 0, 1, true,  false, false)
GEN_EXTRA_CHECK_TEST(004, 1004, 1, 1, true,  false, false)
GEN_EXTRA_CHECK_TEST(005, 1005, 1, 2, false, true,  true)

#undef GEN_EXTRA_CHECK_TEST

} // namespace Media
} // namespace OHOS
