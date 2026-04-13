/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MediaPermissionHandlerTest"

#include "media_permission_test.h"

#include "media_log.h"
#include "media_tool_permission_handler.h"
#include "grant_permission_handler.h"
#include "read_write_permission_handler.h"
#include "db_permission_handler.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_uripermission_operations.h"
#include "permission_utils.h"
#include "parameters.h"
#include "medialibrary_operation.h"
#include "medialibrary_rdbstore.h"
#include "rdb_utils.h"
#include "context.h"
#include "ability_context_impl.h"
#include "get_self_permissions.h"
#include "medialibrary_unittest_utils.h"
#include "userfilemgr_uri.h"
#include "media_cloud_permission_check.h"
#include "media_column.h"
#include "datashare_predicates.h"
#include "media_permission_header_req.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

void MediaPermissionTest::SetUpTestCase(void) {}

void MediaPermissionTest::TearDownTestCase(void) {}

void MediaPermissionTest::SetUp(void) {}

void MediaPermissionTest::TearDown(void) {}

// MediaTool鉴权成功
HWTEST_F(MediaPermissionTest, MediaPermissionTest_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaPermissionTest_001 begin");
    Uri uri("uri_permission");
    MediaLibraryCommand cmd(uri);
    cmd.SetOprnObject(OperationObject::TOOL_PHOTO);
    PermParam permParam = {
        .isWrite = true,
    };
    permissionHandler_ = std::make_shared<MediaToolPermissionHandler>();
    int err = permissionHandler_->CheckPermission(cmd, permParam);
    EXPECT_EQ(err, 0);
    MEDIA_INFO_LOG("MediaPermissionTest_001 end");
}

// MediaTool鉴权失败
HWTEST_F(MediaPermissionTest, MediaPermissionTest_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaPermissionTest_002 begin");
    Uri uri("uri_permission");
    MediaLibraryCommand cmd(uri);
    PermParam permParam = {
        .isWrite = true,
    };
    permissionHandler_ = std::make_shared<MediaToolPermissionHandler>();
    int err = permissionHandler_->CheckPermission(cmd, permParam);
    EXPECT_LT(err, 0);
    MEDIA_INFO_LOG("MediaPermissionTest_002 end");
}

// readWrite鉴权成功
HWTEST_F(MediaPermissionTest, MediaPermissionTest_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaPermissionTest_003 begin");
    Uri uri(CONST_URI_CLOSE_FILE); // HandleNoPermCheck 使得鉴权通过
    MediaLibraryCommand cmd(uri);
    PermParam permParam = {
        .isWrite = true,
    };
    permissionHandler_ = std::make_shared<ReadWritePermissionHandler>();
    int err = permissionHandler_->CheckPermission(cmd, permParam);
    EXPECT_EQ(err, 0);
    MEDIA_INFO_LOG("MediaPermissionTest_003 end");
}


// readWrite鉴权失败
HWTEST_F(MediaPermissionTest, MediaPermissionTest_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaPermissionTest_004 begin");
    Uri uri("uri_permission");
    MediaLibraryCommand cmd(uri);
    PermParam permParam = {
        .isWrite = true,
    };
    permissionHandler_ = std::make_shared<ReadWritePermissionHandler>();
    int err = permissionHandler_->CheckPermission(cmd, permParam);
    EXPECT_EQ(err, 0);
    MEDIA_INFO_LOG("MediaPermissionTest_004 end");
}

// grant鉴权失败
HWTEST_F(MediaPermissionTest, MediaPermissionTest_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaPermissionTest_005 begin");
    Uri uri("uri_permission");
    MediaLibraryCommand cmd(uri);
    cmd.SetOprnObject(OperationObject::UNKNOWN_OBJECT);
    PermParam permParam = {
        .isWrite = true,
    };
    permissionHandler_ = std::make_shared<GrantPermissionHandler>();
    int err = permissionHandler_->CheckPermission(cmd, permParam);
    // unknown object will return E_PERMISSION_DENIED
    EXPECT_EQ(err, E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionTest_005 end");
}

// grant鉴权失败
HWTEST_F(MediaPermissionTest, MediaPermissionTest_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaPermissionTest_006 begin");
    Uri uri("uri_permission");
    MediaLibraryCommand cmd(uri);
    cmd.SetOprnObject(OperationObject::FILESYSTEM_PHOTO);
    PermParam permParam = {
        .isWrite = true,
    };
    permissionHandler_ = std::make_shared<GrantPermissionHandler>();
    int err = permissionHandler_->CheckPermission(cmd, permParam);
    EXPECT_LT(err, 0);
    MEDIA_INFO_LOG("MediaPermissionTest_006 end");
}

//Media_Tool_Permission_Handler_Test
HWTEST_F(MediaPermissionTest, Media_Tool_Permission_Handler_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Media_Tool_Permission_Handler_Test_001 begin");
    Uri uri("test_tool");
    MediaLibraryCommand cmd(uri);
    PermParam permParam = {
        .isWrite = true,
    };
    int32_t ret = -1;
    permissionHandler_ = std::make_shared<MediaToolPermissionHandler>();
    ret = permissionHandler_->ExecuteCheckPermission(cmd, permParam);
    EXPECT_NE(ret, 0);
    MEDIA_INFO_LOG("Media_Tool_Permission_Handler_Test_001 end");
}

//Media_Tool_Permission_Handler_Test
HWTEST_F(MediaPermissionTest, Media_Tool_Permission_Handler_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Media_Tool_Permission_Handler_Test_002 begin");
    Uri uri("test_tool");
    MediaLibraryCommand cmd(uri);
    PermParam permParam = {
        .isWrite = false,
    };
    int32_t ret = -1;
    permissionHandler_ = std::make_shared<MediaToolPermissionHandler>();
    ret = permissionHandler_->ExecuteCheckPermission(cmd, permParam);
    EXPECT_NE(ret, 0);
    MEDIA_INFO_LOG("Media_Tool_Permission_Handler_Test_002 end");
}

//Read_Write_Permission_Handler_Test
HWTEST_F(MediaPermissionTest, Read_Write_Permission_Handler_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Read_Write_Permission_Handler_Test_001 begin");
    Uri uri("test_read_write");
    MediaLibraryCommand cmd(uri);
    PermParam permParam = {
        .isWrite = true,
    };
    int32_t ret = -1;
    permissionHandler_ = std::make_shared<ReadWritePermissionHandler>();
    ret = permissionHandler_->ExecuteCheckPermission(cmd, permParam);
    EXPECT_NE(ret, -1);
    MEDIA_INFO_LOG("Read_Write_Permission_Handler_Test_001 end");
}

//Read_Write_Permission_Handler_Test
HWTEST_F(MediaPermissionTest, Read_Write_Permission_Handler_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Read_Write_Permission_Handler_Test_002 begin");
    Uri uri("test_read_write");
    MediaLibraryCommand cmd(uri);
    PermParam permParam = {
        .isWrite = false,
    };
    int32_t ret = -1;
    permissionHandler_ = std::make_shared<ReadWritePermissionHandler>();
    ret = permissionHandler_->ExecuteCheckPermission(cmd, permParam);
    EXPECT_NE(ret, -1);
    MEDIA_INFO_LOG("Read_Write_Permission_Handler_Test_002 end");
}

//Grant_Permission_Handler_Test
HWTEST_F(MediaPermissionTest, Grant_Permission_Handler_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Grant_Permission_Handler_Test_001 begin");
    Uri uri("test_grant");
    MediaLibraryCommand cmd(uri);
    cmd.SetOprnObject(OperationObject::FILESYSTEM_DIR);
    PermParam permParam = {
        .isWrite = true,
    };
    int32_t ret = -1;
    permissionHandler_ = std::make_shared<GrantPermissionHandler>();
    ret = permissionHandler_->ExecuteCheckPermission(cmd, permParam);
    EXPECT_NE(ret, -1);
    MEDIA_INFO_LOG("Grant_Permission_Handler_Test_001 end");
}

//Grant_Permission_Handler_Test
HWTEST_F(MediaPermissionTest, Grant_Permission_Handler_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Grant_Permission_Handler_Test_002 begin");
    Uri uri("test_grant");
    MediaLibraryCommand cmd(uri);
    cmd.SetOprnObject(OperationObject::FILESYSTEM_DIR);
    PermParam permParam = {
        .isWrite = false,
    };
    int32_t ret = -1;
    permissionHandler_ = std::make_shared<GrantPermissionHandler>();
    ret = permissionHandler_->ExecuteCheckPermission(cmd, permParam);
    EXPECT_NE(ret, -1);
    MEDIA_INFO_LOG("Grant_Permission_Handler_Test_002 end");
}

//Db_Permission_Handler_Test
HWTEST_F(MediaPermissionTest, Db_Permission_Handler_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Db_Permission_Handler_Test_001 begin");
    Uri uri("test_grant");
    MediaLibraryCommand cmd(uri);
    cmd.SetOprnObject(OperationObject::FILESYSTEM_DIR);
    PermParam permParam = {
        .isWrite = true,
    };
    int32_t ret = -1;
    permissionHandler_ = std::make_shared<DbPermissionHandler>();
    ret = permissionHandler_->ExecuteCheckPermission(cmd, permParam);
    EXPECT_NE(ret, -1);
    MEDIA_INFO_LOG("Db_Permission_Handler_Test_001 end");
}

//Db_Permission_Handler_Test
HWTEST_F(MediaPermissionTest, Db_Permission_Handler_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Db_Permission_Handler_Test_002 begin");
    Uri uri("test_grant");
    MediaLibraryCommand cmd(uri);
    cmd.SetOprnObject(OperationObject::FILESYSTEM_DIR);
    PermParam permParam = {
        .isWrite = false,
    };
    int32_t ret = -1;
    permissionHandler_ = std::make_shared<DbPermissionHandler>();
    ret = permissionHandler_->ExecuteCheckPermission(cmd, permParam);
    EXPECT_NE(ret, -1);
    MEDIA_INFO_LOG("Db_Permission_Handler_Test_002 end");
}

void CloudPermissionTest::SetUpTestCase(void)
{}

void CloudPermissionTest::TearDownTestCase(void)
{}

void CloudPermissionTest::SetUp(void)
{}

void CloudPermissionTest::TearDown(void)
{}

void CloudPermissionTest::SetPermissionWithReadImageVideo(uint64_t &tokenId)
{
    std::vector<std::string> permission = {
        "ohos.permission.READ_IMAGEVIDEO",
    };
    PermissionUtilsUnitTest::SetAccessTokenPermission("cloud_permission_test_read", permission, tokenId);
}

void CloudPermissionTest::SetPermissionWithReadCloudImageVideo(uint64_t &tokenId)
{
    std::vector<std::string> permission = {
        "ohos.permission.READ_IMAGEVIDEO",
        "ohos.permission.READ_CLOUD_IMAGEVIDEO",
    };
    PermissionUtilsUnitTest::SetAccessTokenPermission("cloud_permission_test_cloud", permission, tokenId);
}

void CloudPermissionTest::SetPermissionWithBoth(uint64_t &tokenId)
{
    std::vector<std::string> permission = {
        "ohos.permission.READ_IMAGEVIDEO",
        "ohos.permission.READ_CLOUD_IMAGEVIDEO",
    };
    PermissionUtilsUnitTest::SetAccessTokenPermission("cloud_permission_test_both", permission, tokenId);
}

void CloudPermissionTest::SetPermissionWithoutAny(uint64_t &tokenId)
{
    std::vector<std::string> permission = {};
    PermissionUtilsUnitTest::SetAccessTokenPermission("cloud_permission_test_none", permission, tokenId);
}

void CloudPermissionTest::ResetPermission(uint64_t tokenId)
{
    (void)tokenId;
}

HWTEST_F(CloudPermissionTest, CheckCloudPermission_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CheckCloudPermission_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);
    bool result = PermissionUtils::CheckCloudPermission();
    EXPECT_TRUE(result);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("CheckCloudPermission_001 end");
}

HWTEST_F(CloudPermissionTest, CheckCloudPermission_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("CheckCloudPermission_002 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadCloudImageVideo(tokenId);
    bool result = PermissionUtils::CheckCloudPermission();
    EXPECT_FALSE(result);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("CheckCloudPermission_002 end");
}

HWTEST_F(CloudPermissionTest, CheckCloudPermission_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("CheckCloudPermission_003 begin");
    uint64_t tokenId = 0;
    SetPermissionWithBoth(tokenId);
    bool result = PermissionUtils::CheckCloudPermission();
    EXPECT_FALSE(result);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("CheckCloudPermission_003 end");
}

HWTEST_F(CloudPermissionTest, AddCloudAssetFilter_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddCloudAssetFilter_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);
    DataShare::DataSharePredicates predicates;
    CloudReadPermissionCheck::AddCloudAssetFilter(predicates);
    std::string whereClause = predicates.GetWhereClause();
    EXPECT_TRUE(whereClause.find(PhotoColumn::PHOTO_POSITION) != std::string::npos);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("AddCloudAssetFilter_001 end");
}

HWTEST_F(CloudPermissionTest, AddCloudAssetFilter_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddCloudAssetFilter_002 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadCloudImageVideo(tokenId);
    DataShare::DataSharePredicates predicates;
    CloudReadPermissionCheck::AddCloudAssetFilter(predicates);
    std::string whereClause = predicates.GetWhereClause();
    EXPECT_TRUE(whereClause.empty() || whereClause.find(PhotoColumn::PHOTO_POSITION) == std::string::npos);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("AddCloudAssetFilter_002 end");
}

HWTEST_F(CloudPermissionTest, AddCloudAssetFilter_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddCloudAssetFilter_003 begin");
    uint64_t tokenId = 0;
    SetPermissionWithBoth(tokenId);
    DataShare::DataSharePredicates predicates;
    CloudReadPermissionCheck::AddCloudAssetFilter(predicates);
    std::string whereClause = predicates.GetWhereClause();
    EXPECT_TRUE(whereClause.empty() || whereClause.find(PhotoColumn::PHOTO_POSITION) == std::string::npos);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("AddCloudAssetFilter_003 end");
}

HWTEST_F(CloudPermissionTest, CheckPureCloudAssets_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CheckPureCloudAssets_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);
    std::string localFileId = "1";
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(localFileId);
    EXPECT_EQ(result, E_SUCCESS);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("CheckPureCloudAssets_001 end");
}

HWTEST_F(CloudPermissionTest, CheckPureCloudAssets_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("CheckPureCloudAssets_002 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadCloudImageVideo(tokenId);
    std::string cloudFileId = "2";
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(cloudFileId);
    EXPECT_EQ(result, E_SUCCESS);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("CheckPureCloudAssets_002 end");
}

HWTEST_F(CloudPermissionTest, CheckPureCloudAssets_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("CheckPureCloudAssets_003 begin");
    uint64_t tokenId = 0;
    SetPermissionWithBoth(tokenId);
    std::string cloudFileId = "2";
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(cloudFileId);
    EXPECT_EQ(result, E_SUCCESS);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("CheckPureCloudAssets_003 end");
}

HWTEST_F(CloudPermissionTest, CloudReadPermissionCheck_CheckPermission_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CloudReadPermissionCheck_CheckPermission_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadCloudImageVideo(tokenId);
    CloudReadPermissionCheck checker;
    PermissionHeaderReq data;
    int32_t result = checker.CheckPermission(0, data);
    EXPECT_EQ(result, E_SUCCESS);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("CloudReadPermissionCheck_CheckPermission_001 end");
}

HWTEST_F(CloudPermissionTest, CloudReadPermissionCheck_CheckPermission_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("CloudReadPermissionCheck_CheckPermission_002 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);
    CloudReadPermissionCheck checker;
    PermissionHeaderReq data;
    int32_t result = checker.CheckPermission(0, data);
    EXPECT_EQ(result, E_PERMISSION_DENIED);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("CloudReadPermissionCheck_CheckPermission_002 end");
}

HWTEST_F(CloudPermissionTest, CloudWritePermissionCheck_CheckPermission_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CloudWritePermissionCheck_CheckPermission_001 begin");
    CloudWritePermissionCheck checker;
    PermissionHeaderReq data;
    int32_t result = checker.CheckPermission(0, data);
    EXPECT_EQ(result, E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("CloudWritePermissionCheck_CheckPermission_001 end");
}

HWTEST_F(CloudPermissionTest, PhotoPositionType_EnumValue_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PhotoPositionType_EnumValue_001 begin");
    EXPECT_EQ(static_cast<int32_t>(PhotoPositionType::INVALID), -1);
    EXPECT_EQ(static_cast<int32_t>(PhotoPositionType::LOCAL), 1);
    EXPECT_EQ(static_cast<int32_t>(PhotoPositionType::CLOUD), 2);
    EXPECT_EQ(static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD), 3);
    MEDIA_INFO_LOG("PhotoPositionType_EnumValue_001 end");
}

HWTEST_F(CloudPermissionTest, VerifyScene1_LocalOnlyPermission_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("VerifyScene1_LocalOnlyPermission_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);
    bool needFilter = PermissionUtils::CheckCloudPermission();
    EXPECT_TRUE(needFilter);
    DataShare::DataSharePredicates predicates;
    CloudReadPermissionCheck::AddCloudAssetFilter(predicates);
    std::string whereClause = predicates.GetWhereClause();
    EXPECT_TRUE(whereClause.find(PhotoColumn::PHOTO_POSITION) != std::string::npos);
    EXPECT_TRUE(whereClause.find("1") != std::string::npos);
    EXPECT_TRUE(whereClause.find("3") != std::string::npos);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("VerifyScene1_LocalOnlyPermission_001 end");
}

HWTEST_F(CloudPermissionTest, VerifyScene2_BothPermission_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("VerifyScene2_BothPermission_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithBoth(tokenId);
    bool needFilter = PermissionUtils::CheckCloudPermission();
    EXPECT_FALSE(needFilter);
    DataShare::DataSharePredicates predicates;
    CloudReadPermissionCheck::AddCloudAssetFilter(predicates);
    std::string whereClause = predicates.GetWhereClause();
    EXPECT_TRUE(whereClause.empty() || whereClause.find(PhotoColumn::PHOTO_POSITION) == std::string::npos);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("VerifyScene2_BothPermission_001 end");
}

HWTEST_F(CloudPermissionTest, VerifyScene3_NoPermission_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("VerifyScene3_NoPermission_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithoutAny(tokenId);
    bool needFilter = PermissionUtils::CheckCloudPermission();
    EXPECT_TRUE(needFilter);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("VerifyScene3_NoPermission_001 end");
}

HWTEST_F(CloudPermissionTest, VerifyScene4_LocalWithPicker_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("VerifyScene4_LocalWithPicker_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);
    bool needFilter = PermissionUtils::CheckCloudPermission();
    EXPECT_TRUE(needFilter);
    ResetPermission(tokenId);
    MEDIA_INFO_LOG("VerifyScene4_LocalWithPicker_001 end");
}

HWTEST_F(CloudPermissionTest, OpenFile_LocalAsset_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("OpenFile_LocalAsset_Test_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);

    std::string localFileId = "test_local_file";
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(localFileId);
    EXPECT_EQ(result, E_SUCCESS);

    ResetPermission(tokenId);
    MEDIA_INFO_LOG("OpenFile_LocalAsset_Test_001 end");
}

HWTEST_F(CloudPermissionTest, OpenFile_CloudAsset_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("OpenFile_CloudAsset_Test_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadCloudImageVideo(tokenId);

    std::string cloudFileId = "test_cloud_file";
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(cloudFileId);
    EXPECT_EQ(result, E_SUCCESS);

    ResetPermission(tokenId);
    MEDIA_INFO_LOG("OpenFile_CloudAsset_Test_001 end");
}

HWTEST_F(CloudPermissionTest, OpenFile_NoCloudPermission_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("OpenFile_NoCloudPermission_Test_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);

    bool hasCloudPermission = !PermissionUtils::CheckCloudPermission();
    EXPECT_TRUE(hasCloudPermission);

    ResetPermission(tokenId);
    MEDIA_INFO_LOG("OpenFile_NoCloudPermission_Test_001 end");
}

HWTEST_F(CloudPermissionTest, OpenFile_BothPermission_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("OpenFile_BothPermission_Test_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithBoth(tokenId);

    bool hasCloudPermission = !PermissionUtils::CheckCloudPermission();
    EXPECT_FALSE(hasCloudPermission);

    std::string cloudFileId = "test_cloud_file_both";
    int32_t result = CloudReadPermissionCheck::CheckPureCloudAssets(cloudFileId);
    EXPECT_EQ(result, E_SUCCESS);

    ResetPermission(tokenId);
    MEDIA_INFO_LOG("OpenFile_BothPermission_Test_001 end");
}

HWTEST_F(CloudPermissionTest, OpenFile_PickerAuthorization_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("OpenFile_PickerAuthorization_Test_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithReadImageVideo(tokenId);

    bool needFilter = PermissionUtils::CheckCloudPermission();
    EXPECT_TRUE(needFilter);

    ResetPermission(tokenId);
    MEDIA_INFO_LOG("OpenFile_PickerAuthorization_Test_001 end");
}

HWTEST_F(CloudPermissionTest, OpenFile_NoPermission_WithPicker_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("OpenFile_NoPermission_WithPicker_Test_001 begin");
    uint64_t tokenId = 0;
    SetPermissionWithoutAny(tokenId);

    bool needFilter = PermissionUtils::CheckCloudPermission();
    EXPECT_TRUE(needFilter);

    ResetPermission(tokenId);
    MEDIA_INFO_LOG("OpenFile_NoPermission_WithPicker_Test_001 end");
}
} // namespace Media
} // namespace OHOS
