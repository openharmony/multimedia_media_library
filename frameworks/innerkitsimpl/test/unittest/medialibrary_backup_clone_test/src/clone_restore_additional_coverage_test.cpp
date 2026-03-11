/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define MLOG_TAG "CloneRestoreAdditionalCoverageTest"

#include "clone_restore_additional_coverage_test.h"

#define private public
#define protected public
#include "clone_restore.h"
#undef private
#undef protected

#include "medialibrary_errno.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
void CloneRestoreAdditionalCoverageTest::SetUpTestCase() {}

void CloneRestoreAdditionalCoverageTest::TearDownTestCase() {}

void CloneRestoreAdditionalCoverageTest::SetUp() {}

void CloneRestoreAdditionalCoverageTest::TearDown() {}

HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbReady_Branches_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    CloudPhotoFileExistFlag allExist;
    allExist.isThmExist = true;
    allExist.isDayAstcExist = true;
    allExist.isYearAstcExist = true;
    EXPECT_EQ(restore.CheckThumbReady(fileInfo, allExist), RESTORE_THUMBNAIL_READY_FAIL);

    CloudPhotoFileExistFlag missAstc;
    missAstc.isThmExist = true;
    missAstc.isDayAstcExist = false;
    missAstc.isYearAstcExist = true;
    EXPECT_EQ(restore.CheckThumbReady(fileInfo, missAstc), RESTORE_THUMBNAIL_READY_ALL_SUCCESS);
}

HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_NoExThumbnailBranches_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    fileInfo.orientation = 0;
    fileInfo.exifRotate = 0;

    CloudPhotoFileExistFlag flag;
    flag.isThmExist = true;
    flag.isLcdExist = true;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_ALL);

    flag.isThmExist = true;
    flag.isLcdExist = false;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_LCD);

    flag.isThmExist = false;
    flag.isLcdExist = true;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_THUMB);

    flag.isThmExist = false;
    flag.isLcdExist = false;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_ALL);
}

HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_ExThumbnailBranches_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    fileInfo.orientation = 90;
    fileInfo.exifRotate = 0;

    CloudPhotoFileExistFlag flag;
    flag.isExThmExist = true;
    flag.isExLcdExist = true;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_ALL);

    flag.isExThmExist = true;
    flag.isExLcdExist = false;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_LCD);

    flag.isExThmExist = false;
    flag.isExLcdExist = true;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_THUMB);

    flag.isExThmExist = false;
    flag.isExLcdExist = false;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_ALL);
}

HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckLcdVisitTime_Branches_001, TestSize.Level1)
{
    CloneRestore restore;
    CloudPhotoFileExistFlag flag;
    flag.isLcdExist = false;
    EXPECT_EQ(restore.CheckLcdVisitTime(flag), RESTORE_LCD_VISIT_TIME_SUCCESS);
    flag.isLcdExist = true;
    EXPECT_EQ(restore.CheckLcdVisitTime(flag), RESTORE_LCD_VISIT_TIME_NO_LCD);
}

HWTEST_F(CloneRestoreAdditionalCoverageTest, IsInvalidLocalFile_Branches_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId = "cid-001";
    EXPECT_TRUE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, fileInfo));

    EXPECT_FALSE(restore.IsInvalidLocalFile(E_FAIL, fileInfo));
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    EXPECT_FALSE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, fileInfo));
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId.clear();
    EXPECT_FALSE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, fileInfo));
}

HWTEST_F(CloneRestoreAdditionalCoverageTest, AddAndRemoveInvalidLocalFiles_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileIdOld = 100;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId = "cid-100";
    fileInfo.cloudPath = "/storage/cloud/files/Photo/1/a.jpg";
    fileInfo.needMove = true;

    restore.AddInvalidLocalFiles(fileInfo);
    EXPECT_EQ(restore.invalidLocalFiles_.size(), 1);
    EXPECT_TRUE(fileInfo.cloudPath.empty());
    EXPECT_FALSE(fileInfo.needMove);

    restore.AddInvalidLocalFiles(fileInfo);
    EXPECT_EQ(restore.invalidLocalFiles_.size(), 1);

    FileInfo removeInfo;
    removeInfo.fileIdOld = 100;
    restore.RemoveInvalidLocalFiles(removeInfo);
    EXPECT_TRUE(restore.invalidLocalFiles_.empty());

    restore.RemoveInvalidLocalFiles(removeInfo);
    EXPECT_TRUE(restore.invalidLocalFiles_.empty());
}
} // namespace Media
} // namespace OHOS
