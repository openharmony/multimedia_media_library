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

#define MLOG_TAG "CloneRestoreAdditionalCoverageTest"

#include "clone_restore_additional_coverage_test.h"
#include "clone_restore.h"
#include "medialibrary_errno.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
void CloneRestoreAdditionalCoverageTest::SetUpTestCase() {}

void CloneRestoreAdditionalCoverageTest::TearDownTestCase() {}

void CloneRestoreAdditionalCoverageTest::SetUp() {}

void CloneRestoreAdditionalCoverageTest::TearDown() {}

// 验证本地图片在普通缩略图和 LCD 都存在时返回完整状态。
HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_NoExThumbnail_AllExist_001, TestSize.Level1)
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
}

// 验证本地图片缺少 LCD 时返回缺少 LCD 的状态码。
HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_NoExThumbnail_MissingLcd_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    fileInfo.orientation = 0;
    fileInfo.exifRotate = 0;
    CloudPhotoFileExistFlag flag;
    flag.isThmExist = true;
    flag.isLcdExist = false;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_LCD);
}

// 验证本地图片缺少普通缩略图时返回缺少缩略图的状态码。
HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_NoExThumbnail_MissingThumb_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    fileInfo.orientation = 0;
    fileInfo.exifRotate = 0;
    CloudPhotoFileExistFlag flag;
    flag.isThmExist = false;
    flag.isLcdExist = true;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_THUMB);
}

// 验证本地图片普通缩略图和 LCD 都缺失时返回全缺失状态。
HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_NoExThumbnail_AllMissing_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    fileInfo.orientation = 0;
    fileInfo.exifRotate = 0;
    CloudPhotoFileExistFlag flag;
    flag.isThmExist = false;
    flag.isLcdExist = false;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_ALL);
}

// 验证云端图片扩展缩略图和扩展 LCD 都存在时返回完整状态。
HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_ExThumbnail_AllExist_001, TestSize.Level1)
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
}

// 验证云端图片缺少扩展 LCD 时返回缺少 LCD 的状态码。
HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_ExThumbnail_MissingLcd_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    fileInfo.orientation = 90;
    fileInfo.exifRotate = 0;
    CloudPhotoFileExistFlag flag;
    flag.isExThmExist = true;
    flag.isExLcdExist = false;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_LCD);
}

// 验证云端图片缺少扩展缩略图时返回缺少缩略图的状态码。
HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_ExThumbnail_MissingThumb_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    fileInfo.orientation = 90;
    fileInfo.exifRotate = 0;
    CloudPhotoFileExistFlag flag;
    flag.isExThmExist = false;
    flag.isExLcdExist = true;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_THUMB);
}

// 验证云端图片扩展缩略图和扩展 LCD 都缺失时返回全缺失状态。
HWTEST_F(CloneRestoreAdditionalCoverageTest, CheckThumbStatus_ExThumbnail_AllMissing_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    fileInfo.orientation = 90;
    fileInfo.exifRotate = 0;
    CloudPhotoFileExistFlag flag;
    flag.isExThmExist = false;
    flag.isExLcdExist = false;
    EXPECT_EQ(restore.CheckThumbStatus(fileInfo, flag), RESTORE_THUMBNAIL_STATUS_NOT_ALL);
}

// 验证 IsInvalidLocalFile 对端云资产且文件不存在时判定为无效本地文件。
HWTEST_F(CloneRestoreAdditionalCoverageTest, IsInvalidLocalFile_NoSuchFileWithCloudIdentity_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId = "cid-001";
    EXPECT_TRUE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, fileInfo));
}

// 验证 IsInvalidLocalFile 对非文件不存在错误不会误判为无效本地文件。
HWTEST_F(CloneRestoreAdditionalCoverageTest, IsInvalidLocalFile_NonNoSuchFileError_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId = "cid-001";
    EXPECT_FALSE(restore.IsInvalidLocalFile(E_FAIL, fileInfo));
}

// 验证 IsInvalidLocalFile 对仅本地资产不会按端云异常路径处理。
HWTEST_F(CloneRestoreAdditionalCoverageTest, IsInvalidLocalFile_LocalOnlyAsset_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    fileInfo.uniqueId = "cid-001";
    EXPECT_FALSE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, fileInfo));
}

// 验证 IsInvalidLocalFile 在 uniqueId 为空时不会判定为无效端云文件。
HWTEST_F(CloneRestoreAdditionalCoverageTest, IsInvalidLocalFile_EmptyUniqueId_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId.clear();
    EXPECT_FALSE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, fileInfo));
}

// 验证 AddInvalidLocalFiles 首次加入记录时会清理 cloudPath 和 needMove 状态。
HWTEST_F(CloneRestoreAdditionalCoverageTest, AddInvalidLocalFiles_FirstInsertClearsMoveState_001, TestSize.Level1)
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
}

// 验证 AddInvalidLocalFiles 对同一 fileId 重复加入时不会重复存储。
HWTEST_F(CloneRestoreAdditionalCoverageTest, AddInvalidLocalFiles_DuplicateInsertIgnored_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileIdOld = 100;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId = "cid-100";
    fileInfo.cloudPath = "/storage/cloud/files/Photo/1/a.jpg";
    fileInfo.needMove = true;
    restore.AddInvalidLocalFiles(fileInfo);
    restore.AddInvalidLocalFiles(fileInfo);
    EXPECT_EQ(restore.invalidLocalFiles_.size(), 1);
}

// 验证 RemoveInvalidLocalFiles 能删除已记录的无效本地文件信息。
HWTEST_F(CloneRestoreAdditionalCoverageTest, RemoveInvalidLocalFiles_ExistingRecord_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo fileInfo;
    fileInfo.fileIdOld = 100;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId = "cid-100";
    restore.AddInvalidLocalFiles(fileInfo);
    FileInfo removeInfo;
    removeInfo.fileIdOld = 100;
    restore.RemoveInvalidLocalFiles(removeInfo);
    EXPECT_TRUE(restore.invalidLocalFiles_.empty());
}

// 验证 RemoveInvalidLocalFiles 对不存在的记录执行删除时保持容器为空。
HWTEST_F(CloneRestoreAdditionalCoverageTest, RemoveInvalidLocalFiles_MissingRecord_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo removeInfo;
    removeInfo.fileIdOld = 100;
    restore.RemoveInvalidLocalFiles(removeInfo);
    EXPECT_TRUE(restore.invalidLocalFiles_.empty());
}
} // namespace Media
} // namespace OHOS
