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

#define MLOG_TAG "CloneRestoreStateBranchTest"

#include "clone_restore_state_branch_test.h"

#define private public
#define protected public
#include "clone_restore.h"
#undef private
#undef protected

#include "rdb_helper.h"

using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
const std::string ORI_DB_PATH = "/data/test/backup/clone_restore_state_branch.db";
std::shared_ptr<RdbStore> g_db = nullptr;

class StateBranchOpenCallback final : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return store.ExecuteSql(
            "CREATE TABLE IF NOT EXISTS orientation_test ("
            "file_id INTEGER PRIMARY KEY, "
            "orientation INT DEFAULT 0, "
            "exif_rotate INT DEFAULT 0);");
    }

    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

void ClearOrientationTable()
{
    if (g_db != nullptr) {
        (void)g_db->ExecuteSql("DELETE FROM orientation_test;");
    }
}
} // namespace

void CloneRestoreStateBranchTest::SetUpTestCase(void)
{
    RdbStoreConfig config(ORI_DB_PATH);
    StateBranchOpenCallback callback;
    int32_t errCode = E_OK;
    (void)RdbHelper::DeleteRdbStore(ORI_DB_PATH);
    g_db = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    ASSERT_NE(g_db, nullptr);
}

void CloneRestoreStateBranchTest::TearDownTestCase(void)
{
    g_db = nullptr;
    (void)RdbHelper::DeleteRdbStore(ORI_DB_PATH);
}

void CloneRestoreStateBranchTest::SetUp()
{
    ClearOrientationTable();
}

void CloneRestoreStateBranchTest::TearDown()
{
    ClearOrientationTable();
}

HWTEST_F(CloneRestoreStateBranchTest, CheckSrcDstSwitchStatusMatch_InvalidConfig_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.srcCloneRestoreConfigInfo_.isValid = false;
    restore.dstCloneRestoreConfigInfo_.isValid = true;
    restore.CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restore.isSrcDstSwitchStatusMatch_);
}

HWTEST_F(CloneRestoreStateBranchTest, CheckSrcDstSwitchStatusMatch_SrcClose_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.srcCloneRestoreConfigInfo_.isValid = true;
    restore.dstCloneRestoreConfigInfo_.isValid = true;
    restore.srcCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOSE;
    restore.dstCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOUD;
    restore.CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restore.isSrcDstSwitchStatusMatch_);
}

HWTEST_F(CloneRestoreStateBranchTest, CheckSrcDstSwitchStatusMatch_DstClose_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.srcCloneRestoreConfigInfo_.isValid = true;
    restore.dstCloneRestoreConfigInfo_.isValid = true;
    restore.srcCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOUD;
    restore.dstCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOSE;
    restore.CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restore.isSrcDstSwitchStatusMatch_);
}

HWTEST_F(CloneRestoreStateBranchTest, CheckSrcDstSwitchStatusMatch_NotEqual_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.srcCloneRestoreConfigInfo_.isValid = true;
    restore.dstCloneRestoreConfigInfo_.isValid = true;
    restore.srcCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOUD;
    restore.srcCloneRestoreConfigInfo_.deviceId = "a";
    restore.dstCloneRestoreConfigInfo_.switchStatus = SwitchStatus::HDC;
    restore.dstCloneRestoreConfigInfo_.deviceId = "b";
    restore.CheckSrcDstSwitchStatusMatch();
    EXPECT_FALSE(restore.isSrcDstSwitchStatusMatch_);
}

HWTEST_F(CloneRestoreStateBranchTest, CheckSrcDstSwitchStatusMatch_Equal_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.srcCloneRestoreConfigInfo_.isValid = true;
    restore.dstCloneRestoreConfigInfo_.isValid = true;
    restore.srcCloneRestoreConfigInfo_.switchStatus = SwitchStatus::HDC;
    restore.srcCloneRestoreConfigInfo_.deviceId = "device-id";
    restore.dstCloneRestoreConfigInfo_.switchStatus = SwitchStatus::HDC;
    restore.dstCloneRestoreConfigInfo_.deviceId = "device-id";
    restore.CheckSrcDstSwitchStatusMatch();
    EXPECT_TRUE(restore.isSrcDstSwitchStatusMatch_);
}

HWTEST_F(CloneRestoreStateBranchTest, ParseDstDeviceBackupInfo_EmptyRestoreInfo_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.restoreInfo_ = "";
    restore.dstDeviceBackupInfo_.hdcEnabled = true;
    restore.ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restore.dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(CloneRestoreStateBranchTest, ParseDstDeviceBackupInfo_InvalidJson_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.restoreInfo_ = "{invalid_json}";
    restore.ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restore.dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(CloneRestoreStateBranchTest, ParseDstDeviceBackupInfo_NoCompatibilityInfo_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.restoreInfo_ = R"([{"type":"x","detail":"y"}])";
    restore.ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restore.dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(CloneRestoreStateBranchTest, ParseDstDeviceBackupInfo_InvalidCompatibilityJson_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.restoreInfo_ = R"([{"type":"compatibility_info","detail":"not_json"}])";
    restore.ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restore.dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(CloneRestoreStateBranchTest, ParseDstDeviceBackupInfo_MissingHdcKey_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.restoreInfo_ = R"([{"type":"compatibility_info","detail":"{\"other\":true}"}])";
    restore.ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restore.dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(CloneRestoreStateBranchTest, ParseDstDeviceBackupInfo_NonBooleanHdcKey_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.restoreInfo_ = R"([{"type":"compatibility_info","detail":"{\"backupHdcEnable\":\"yes\"}"}])";
    restore.ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restore.dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(CloneRestoreStateBranchTest, ParseDstDeviceBackupInfo_HdcEnabledTrue_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.restoreInfo_ = R"([{"type":"compatibility_info","detail":"{\"backupHdcEnable\":true}"}])";
    restore.ParseDstDeviceBackupInfo();
    EXPECT_TRUE(restore.dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(CloneRestoreStateBranchTest, ParseDstDeviceBackupInfo_HdcEnabledFalse_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.restoreInfo_ = R"([{"type":"compatibility_info","detail":"{\"backupHdcEnable\":false}"}])";
    restore.ParseDstDeviceBackupInfo();
    EXPECT_FALSE(restore.dstDeviceBackupInfo_.hdcEnabled);
}

HWTEST_F(CloneRestoreStateBranchTest, IsCloudRestoreSatisfied_AndBranch_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.isAccountValid_ = false;
    restore.isSrcDstSwitchStatusMatch_ = true;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
    restore.isAccountValid_ = true;
    restore.isSrcDstSwitchStatusMatch_ = false;
    EXPECT_FALSE(restore.IsCloudRestoreSatisfied());
    restore.isSrcDstSwitchStatusMatch_ = true;
    EXPECT_TRUE(restore.IsCloudRestoreSatisfied());
}

HWTEST_F(CloneRestoreStateBranchTest, CorrectTimestamp_AlreadyMilliseconds_001, TestSize.Level1)
{
    CloneRestore restore;
    int64_t input = 1700000000000LL;
    EXPECT_EQ(restore.CorrectTimestamp(input), input);
}

HWTEST_F(CloneRestoreStateBranchTest, CorrectTimestamp_SecondsConvertToMilliseconds_001, TestSize.Level1)
{
    CloneRestore restore;
    int64_t input = 1700000000LL;
    EXPECT_EQ(restore.CorrectTimestamp(input), input * 1000);
}

HWTEST_F(CloneRestoreStateBranchTest, CorrectTimestamp_KeepOriginalSmallValue_001, TestSize.Level1)
{
    CloneRestore restore;
    int64_t input = 123LL;
    EXPECT_EQ(restore.CorrectTimestamp(input), input);
}

HWTEST_F(CloneRestoreStateBranchTest, HasExThumbnail_CloudImageTrue_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info;
    info.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    info.fileType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    info.orientation = 90;
    info.exifRotate = 0;
    EXPECT_TRUE(restore.HasExThumbnail(info));
}

HWTEST_F(CloneRestoreStateBranchTest, IsInvalidLocalFile_AllConditionsTrue_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info;
    info.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    info.uniqueId = "cid";
    EXPECT_TRUE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, info));
}

HWTEST_F(CloneRestoreStateBranchTest, IsInvalidLocalFile_ErrCodeMismatch_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info;
    info.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    info.uniqueId = "cid";
    EXPECT_FALSE(restore.IsInvalidLocalFile(E_FAIL, info));
}

HWTEST_F(CloneRestoreStateBranchTest, IsInvalidLocalFile_PositionMismatch_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info;
    info.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    info.uniqueId = "cid";
    EXPECT_FALSE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, info));
}

HWTEST_F(CloneRestoreStateBranchTest, IsInvalidLocalFile_EmptyCloudId_001, TestSize.Level1)
{
    CloneRestore restore;
    FileInfo info;
    info.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    info.uniqueId = "";
    EXPECT_FALSE(restore.IsInvalidLocalFile(E_NO_SUCH_FILE, info));
}

HWTEST_F(CloneRestoreStateBranchTest, GetOrientationAndExifRotateValue_WithExifColumn_001, TestSize.Level1)
{
    CloneRestore restore;
    restore.existNewAddColumnSet_.insert(PhotoColumn::PHOTO_EXIF_ROTATE);
    ASSERT_EQ(g_db->ExecuteSql("INSERT INTO orientation_test (file_id, orientation, exif_rotate) VALUES (1, 6, 90);"),
        E_OK);
    auto resultSet = g_db->QuerySql("SELECT orientation, exif_rotate FROM orientation_test WHERE file_id = 1;");
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    FileInfo info;
    info.fileType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    restore.GetOrientationAndExifRotateValue(resultSet, info);
    EXPECT_EQ(info.orientation, 6);
    EXPECT_EQ(info.exifRotate, 90);
    resultSet->Close();
}

HWTEST_F(CloneRestoreStateBranchTest, GetOrientationAndExifRotateValue_OrientationZero_001, TestSize.Level1)
{
    CloneRestore restore;
    ASSERT_EQ(g_db->ExecuteSql("INSERT INTO orientation_test (file_id, orientation, exif_rotate) VALUES (2, 0, 90);"),
        E_OK);
    auto resultSet = g_db->QuerySql("SELECT orientation, exif_rotate FROM orientation_test WHERE file_id = 2;");
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    FileInfo info;
    info.fileType = static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    restore.GetOrientationAndExifRotateValue(resultSet, info);
    EXPECT_EQ(info.orientation, 0);
    EXPECT_EQ(info.exifRotate, 0);
    resultSet->Close();
}

HWTEST_F(CloneRestoreStateBranchTest, GetOrientationAndExifRotateValue_NonImage_001, TestSize.Level1)
{
    CloneRestore restore;
    ASSERT_EQ(g_db->ExecuteSql("INSERT INTO orientation_test (file_id, orientation, exif_rotate) VALUES (3, 6, 90);"),
        E_OK);
    auto resultSet = g_db->QuerySql("SELECT orientation, exif_rotate FROM orientation_test WHERE file_id = 3;");
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    FileInfo info;
    info.fileType = static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO);
    restore.GetOrientationAndExifRotateValue(resultSet, info);
    EXPECT_EQ(info.orientation, 6);
    EXPECT_EQ(info.exifRotate, 0);
    resultSet->Close();
}
} // namespace Media
} // namespace OHOS
