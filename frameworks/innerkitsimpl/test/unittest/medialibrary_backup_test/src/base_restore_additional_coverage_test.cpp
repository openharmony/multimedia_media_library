/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define MLOG_TAG "BaseRestoreAdditionalCoverageTest"

#include "base_restore_additional_coverage_test.h"

#define private public
#define protected public
#include "base_restore.h"
#undef private
#undef protected

#include "medialibrary_errno.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
class TestBaseRestoreAdditional final : public BaseRestore {
public:
    int32_t Init(const std::string &backupRestorePath, const std::string &upgradePath, bool isUpgrade) override
    {
        return E_OK;
    }

    NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType) override
    {
        return {};
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
} // namespace

void BaseRestoreAdditionalCoverageTest::SetUpTestCase() {}

void BaseRestoreAdditionalCoverageTest::TearDownTestCase() {}

void BaseRestoreAdditionalCoverageTest::SetUp() {}

void BaseRestoreAdditionalCoverageTest::TearDown() {}

HWTEST_F(BaseRestoreAdditionalCoverageTest, ConvertPathToRealPath_InvalidInput_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    std::string newPath;
    std::string relativePath;
    bool ret = restore.ConvertPathToRealPath("a/b/c", "/dst", newPath, relativePath);
    EXPECT_FALSE(ret);
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, ConvertPathToRealPath_DualDirReplace_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    restore.dualDirName_ = "B";
    std::string newPath;
    std::string relativePath;
    bool ret = restore.ConvertPathToRealPath("/a/b/c/B/file.jpg", "/dst", newPath, relativePath);
    EXPECT_TRUE(ret);
    EXPECT_EQ(relativePath, "/A/file.jpg");
    EXPECT_NE(newPath.find("/A/file.jpg"), std::string::npos);
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, HasExThumbnail_LocalMediaIdInvalid_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    FileInfo info;
    info.localMediaId = -1;
    info.fileType = MediaType::MEDIA_TYPE_VIDEO;
    info.orientation = 90;
    info.exifRotate = 0;
    EXPECT_TRUE(restore.HasExThumbnail(info));
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, HasExThumbnail_LocalMediaIdValidNonImage_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    FileInfo info;
    info.localMediaId = 1;
    info.fileType = MediaType::MEDIA_TYPE_VIDEO;
    info.orientation = 90;
    info.exifRotate = 0;
    EXPECT_FALSE(restore.HasExThumbnail(info));
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, UpdateProcessedNumber_StopSetsProcessedToTotal_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    std::atomic<uint64_t> processedNumber = 1;
    std::atomic<uint64_t> totalNumber = 5;
    restore.UpdateProcessedNumber(STOP, processedNumber, totalNumber);
    EXPECT_EQ(processedNumber.load(), 5);
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, UpdateProcessedNumber_StartIncrementsBeforeTotal_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    std::atomic<uint64_t> processedNumber = 1;
    std::atomic<uint64_t> totalNumber = 5;
    processedNumber = 1;
    restore.UpdateProcessedNumber(START, processedNumber, totalNumber);
    EXPECT_EQ(processedNumber.load(), 2);
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, UpdateProcessedNumber_StartDoesNotExceedTotal_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    std::atomic<uint64_t> processedNumber = 5;
    std::atomic<uint64_t> totalNumber = 5;
    processedNumber = 5;
    restore.UpdateProcessedNumber(START, processedNumber, totalNumber);
    EXPECT_EQ(processedNumber.load(), 5);
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, IsCloudRestoreSatisfied_InvalidAccount_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    restore.isAccountValid_ = false;
    restore.isSyncSwitchOn_ = true;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, IsCloudRestoreSatisfied_SyncSwitchOff_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    restore.isAccountValid_ = true;
    restore.isSyncSwitchOn_ = false;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, IsCloudRestoreSatisfied_AllConditionsMet_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    restore.isAccountValid_ = true;
    restore.isSyncSwitchOn_ = true;
    EXPECT_TRUE(restore.IsCloudRestoreSatisfied());
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, GetBackupErrorInfoJson_Success_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    restore.SetErrorCode(RestoreError::SUCCESS);
    auto successJson = restore.GetBackupErrorInfoJson();
    EXPECT_EQ(successJson[STAT_KEY_TYPE], STAT_VALUE_ERROR_INFO);
    EXPECT_EQ(successJson[STAT_KEY_ERROR_CODE], std::to_string(STAT_DEFAULT_ERROR_CODE_SUCCESS));
}

HWTEST_F(BaseRestoreAdditionalCoverageTest, GetBackupErrorInfoJson_Failed_001, TestSize.Level1)
{
    TestBaseRestoreAdditional restore;
    restore.SetErrorCode(RestoreError::INIT_FAILED);
    auto failedJson = restore.GetBackupErrorInfoJson();
    EXPECT_EQ(failedJson[STAT_KEY_ERROR_CODE], std::to_string(STAT_DEFAULT_ERROR_CODE_FAILED));
}
} // namespace Media
} // namespace OHOS
