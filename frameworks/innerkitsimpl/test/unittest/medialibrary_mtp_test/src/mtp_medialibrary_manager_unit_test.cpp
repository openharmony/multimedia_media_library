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

#include <thread>
#include "mtp_medialibrary_manager_unit_test.h"
#include "mtp_medialibrary_manager.h"
#include "userfile_manager_types.h"
#include "userfilemgr_uri.h"
#include "mtp_constants.h"
#include "medialibrary_errno.h"
#include "iservice_registry.h"
#include "media_file_utils.h"
#include "get_self_permissions.h"
#include "mtp_ptp_const.h"
#include "media_mtp_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static constexpr int STORAGE_MANAGER_UID_TEST = 5003;
constexpr int32_t MILLI_TO_SECOND = 1000;

const std::shared_ptr<MtpMedialibraryManager> mtpMedialibraryManager_ = MtpMedialibraryManager::GetInstance();

void MtpMediaLibraryManagerUnitTest::SetUpTestCase(void)
{
    vector<string> perms;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MtpDataUtilsUnitTest", perms, tokenId);
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return;
    }
}

void MtpMediaLibraryManagerUnitTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

// SetUp:Execute before each test case
void MtpMediaLibraryManagerUnitTest::SetUp() {}
void MtpMediaLibraryManagerUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Clear GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_001, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    int32_t parentId = 0;
    vector<int> outHandles;
    int32_t res = mtpMedialibraryManager_->GetHandles(parentId, outHandles);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Clear GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_002, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    int32_t parentId = 0;
    vector<int> outHandles;
    int32_t res = mtpMedialibraryManager_->GetHandles(parentId, outHandles);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Clear GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_003, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    int32_t parentId = 1;
    vector<int> outHandles;
    int32_t res = mtpMedialibraryManager_->GetHandles(parentId, outHandles);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumCloud
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_004, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    int32_t res = mtpMedialibraryManager_->GetAlbumCloud();

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumCloud
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_005, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    int32_t res = mtpMedialibraryManager_->GetAlbumCloud();

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumCloudDisplay
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_006, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    vector<string> ownerAlbumIds;
    int32_t res = mtpMedialibraryManager_->GetAlbumCloudDisplay(ownerAlbumIds);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumCloudDisplay
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_007, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    vector<string> ownerAlbumIds;
    int32_t res = mtpMedialibraryManager_->GetAlbumCloudDisplay(ownerAlbumIds);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumCloudDisplay
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_008, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    vector<string> ownerAlbumIds;
    ownerAlbumIds.push_back("1");
    ownerAlbumIds.push_back("2");
    int32_t res = mtpMedialibraryManager_->GetAlbumCloudDisplay(ownerAlbumIds);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_009, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = nullptr;
    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    bool isHandle = false;
    auto res = mtpMedialibraryManager_->GetAlbumInfo(context, isHandle);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_010, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    bool isHandle = false;
    auto res = mtpMedialibraryManager_->GetAlbumInfo(context, isHandle);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_011, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    bool isHandle = false;
    auto res = mtpMedialibraryManager_->GetAlbumInfo(context, isHandle);

    mtpMedialibraryManager_->Clear();
    EXPECT_NE(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_012, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    bool isHandle = true;
    auto res = mtpMedialibraryManager_->GetAlbumInfo(context, isHandle);

    mtpMedialibraryManager_->Clear();
    EXPECT_NE(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetOwnerAlbumIdList
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_013, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    auto res = mtpMedialibraryManager_->GetOwnerAlbumIdList();

    mtpMedialibraryManager_->Clear();
    EXPECT_NE(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_014, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = nullptr;
    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    bool isHandle = false;
    auto res = mtpMedialibraryManager_->GetPhotosInfo(context, isHandle);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_015, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    bool isHandle = false;
    auto res = mtpMedialibraryManager_->GetPhotosInfo(context, isHandle);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_016, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    bool isHandle = false;
    auto res = mtpMedialibraryManager_->GetPhotosInfo(context, isHandle);

    mtpMedialibraryManager_->Clear();
    EXPECT_NE(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_017, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    bool isHandle = true;
    auto res = mtpMedialibraryManager_->GetPhotosInfo(context, isHandle);

    mtpMedialibraryManager_->Clear();
    EXPECT_NE(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetBurstKeyFromPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_018, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    vector<string> res = mtpMedialibraryManager_->GetBurstKeyFromPhotosInfo();

    mtpMedialibraryManager_->Clear();
    EXPECT_TRUE(res.empty());
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetBurstKeyFromPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_019, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    vector<string> res = mtpMedialibraryManager_->GetBurstKeyFromPhotosInfo();

    mtpMedialibraryManager_->Clear();
    EXPECT_TRUE(res.empty());
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HaveMovingPhotesHandle
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_020, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<DataShare::DataShareResultSet> resultSet = nullptr;
    shared_ptr<UInt32List> outHandles = nullptr;
    uint32_t parent = 0;
    int32_t res = mtpMedialibraryManager_->HaveMovingPhotesHandle(resultSet, outHandles, parent);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, E_HAS_DB_ERROR);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HaveMovingPhotesHandle
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_021, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    ASSERT_NE(resultSet, nullptr);
    shared_ptr<UInt32List> outHandles = nullptr;
    uint32_t parent = 0;
    int32_t res = mtpMedialibraryManager_->HaveMovingPhotesHandle(resultSet, outHandles, parent);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, E_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_022, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = nullptr;
    shared_ptr<UInt32List> outHandles = nullptr;
    int32_t res = mtpMedialibraryManager_->GetHandles(context, outHandles);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_023, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    shared_ptr<UInt32List> outHandles = nullptr;
    int32_t res = mtpMedialibraryManager_->GetHandles(context, outHandles);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_024, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    shared_ptr<UInt32List> outHandles = std::make_shared<UInt32List>();
    int32_t res = mtpMedialibraryManager_->GetHandles(context, outHandles);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_025, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->format = 1;

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    shared_ptr<UInt32List> outHandles = nullptr;
    int32_t res = mtpMedialibraryManager_->GetHandles(context, outHandles);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHmdfsPath
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_026, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::string path = "/abc";
    std::string res = mtpMedialibraryManager_->GetHmdfsPath(path);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, path);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHmdfsPath
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_027, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::string path = "/files/doc";
    std::string res = mtpMedialibraryManager_->GetHmdfsPath(path);
    std::string dir = "/mnt/hmdfs/100/account/device_view/local/files/doc";

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, dir);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_028, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->parent = 1;

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    shared_ptr<UInt32List> outHandles = nullptr;
    int32_t res = mtpMedialibraryManager_->GetHandles(context, outHandles);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAllHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_029, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = nullptr;
    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    std::shared_ptr<UInt32List> out = nullptr;
    int32_t res = mtpMedialibraryManager_->GetAllHandles(context, out);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAllHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_030, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    std::shared_ptr<UInt32List> out = std::make_shared<UInt32List>();
    int32_t res = mtpMedialibraryManager_->GetAllHandles(context, out);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, E_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_031, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    int32_t res = mtpMedialibraryManager_->GetObjectInfo(context, outObjectInfo);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_032, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->handle = 100000000;

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    int32_t res = mtpMedialibraryManager_->GetObjectInfo(context, outObjectInfo);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_033, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->parent = 1;

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    int32_t res = mtpMedialibraryManager_->GetObjectInfo(context, outObjectInfo);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_034, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->parent = 1;
    context->handle = 100000000;

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    int32_t res = mtpMedialibraryManager_->GetObjectInfo(context, outObjectInfo);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetObject
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_035, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    ASSERT_NE(resultSet, nullptr);

    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    int32_t res = mtpMedialibraryManager_->SetObject(resultSet, context, outObjectInfo);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetObject
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_036, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->handle = 200000000;

    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    ASSERT_NE(resultSet, nullptr);

    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    int32_t res = mtpMedialibraryManager_->SetObject(resultSet, context, outObjectInfo);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetObjectInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_037, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    unique_ptr<FileAsset> fileAsset = std::make_unique<FileAsset>();
    ASSERT_NE(fileAsset, nullptr);

    uint32_t handle = 1;
    shared_ptr<ObjectInfo> outObjectInfo = std::make_shared<ObjectInfo>(handle);
    ASSERT_NE(outObjectInfo, nullptr);
    int32_t res = mtpMedialibraryManager_->SetObjectInfo(fileAsset, outObjectInfo);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetObjectInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_038, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    unique_ptr<FileAsset> fileAsset = std::make_unique<FileAsset>();
    ASSERT_NE(fileAsset, nullptr);
    MediaType mediaType = MEDIA_TYPE_ALBUM;
    fileAsset->SetMediaType(mediaType);
    int64_t utcTime = MediaFileUtils::UTCTimeMilliSeconds();
    fileAsset->SetDateModified(utcTime);
    uint32_t handle = 1;
    shared_ptr<ObjectInfo> outObjectInfo = std::make_shared<ObjectInfo>(handle);
    ASSERT_NE(outObjectInfo, nullptr);
    int32_t res = mtpMedialibraryManager_->SetObjectInfo(fileAsset, outObjectInfo);
    ASSERT_EQ(outObjectInfo->dateModified, utcTime / MILLI_TO_SECOND);
    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetObjectInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_039, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    unique_ptr<FileAsset> fileAsset = std::make_unique<FileAsset>();
    ASSERT_NE(fileAsset, nullptr);
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    fileAsset->SetMediaType(mediaType);
    int64_t utcTime = MediaFileUtils::UTCTimeMilliSeconds();
    fileAsset->SetDateModified(utcTime);
    uint32_t handle = 1;
    shared_ptr<ObjectInfo> outObjectInfo = std::make_shared<ObjectInfo>(handle);
    ASSERT_NE(outObjectInfo, nullptr);
    int32_t res = mtpMedialibraryManager_->SetObjectInfo(fileAsset, outObjectInfo);
    ASSERT_EQ(outObjectInfo->dateModified, utcTime / MILLI_TO_SECOND);
    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetObjectInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_040, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    unique_ptr<FileAsset> fileAsset = std::make_unique<FileAsset>();
    ASSERT_NE(fileAsset, nullptr);
    MediaType mediaType = MEDIA_TYPE_VIDEO;
    fileAsset->SetMediaType(mediaType);

    uint32_t handle = 1;
    shared_ptr<ObjectInfo> outObjectInfo = std::make_shared<ObjectInfo>(handle);
    ASSERT_NE(outObjectInfo, nullptr);
    int32_t res = mtpMedialibraryManager_->SetObjectInfo(fileAsset, outObjectInfo);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFd
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_041, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    int32_t outFd = 0;
    std::string mode = "";
    int32_t res = mtpMedialibraryManager_->GetFd(context, outFd, mode);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFdByOpenFile
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_042, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    int32_t outFd = 0;
    int32_t res = mtpMedialibraryManager_->GetFdByOpenFile(context, outFd);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumb
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_043, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    shared_ptr<UInt8List> outThumb = nullptr;
    int32_t res = mtpMedialibraryManager_->GetThumb(context, outThumb);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumb
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_044, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->handle = 100000000;

    shared_ptr<UInt8List> outThumb = nullptr;
    int32_t res = mtpMedialibraryManager_->GetThumb(context, outThumb);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumbnailFromPath
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_045, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    string path = "/files/local";
    shared_ptr<UInt8List> outThumb = std::make_shared<UInt8List>();
    ASSERT_NE(outThumb, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    int32_t res = mtpMedialibraryManager_->GetThumbnailFromPath(path, outThumb);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, E_ERR);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumbUri
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_046, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    int32_t id = 0;
    std::string thumbSizeValue = "";
    std::string dataPath = "/abc";
    std::string res = mtpMedialibraryManager_->GetThumbUri(id, thumbSizeValue, dataPath);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, "");
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumbUri
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_047, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    int32_t id = 0;
    std::string thumbSizeValue = "local";
    std::string dataPath = "1.jpg";
    std::string res = mtpMedialibraryManager_->GetThumbUri(id, thumbSizeValue, dataPath);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, "");
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumbUri
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_048, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    int32_t id = 0;
    std::string thumbSizeValue = "/local/1.jpg";
    std::string dataPath = "./local";
    std::string res = mtpMedialibraryManager_->GetThumbUri(id, thumbSizeValue, dataPath);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, "");
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumbUri
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_049, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    int32_t id = 0;
    std::string thumbSizeValue = "/local";
    std::string dataPath = "/1.jpg";
    std::string res = mtpMedialibraryManager_->GetThumbUri(id, thumbSizeValue, dataPath);

    mtpMedialibraryManager_->Clear();
    EXPECT_NE(res, "");
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumbUri
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_050, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    int32_t id = 0;
    std::string thumbSizeValue = "local:/";
    std::string dataPath = "/1.jpg";
    std::string res = mtpMedialibraryManager_->GetThumbUri(id, thumbSizeValue, dataPath);

    mtpMedialibraryManager_->Clear();
    EXPECT_NE(res, "");
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumbUri
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_051, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    int32_t id = 0;
    std::string thumbSizeValue = "local://media";
    std::string dataPath = "/1.jpg";
    std::string res = mtpMedialibraryManager_->GetThumbUri(id, thumbSizeValue, dataPath);

    mtpMedialibraryManager_->Clear();
    EXPECT_NE(res, "");
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAssetById
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_052, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);

    int32_t id = 100000000;
    shared_ptr<FileAsset> outFileAsset;
    int32_t res = mtpMedialibraryManager_->GetAssetById(id, outFileAsset);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, E_NO_SUCH_FILE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAssetById
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_053, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);

    int32_t id = 100000001;
    shared_ptr<FileAsset> outFileAsset;
    int32_t res = mtpMedialibraryManager_->GetAssetById(id, outFileAsset);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, E_NO_SUCH_FILE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropList
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_056, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = 0;

    std::shared_ptr<std::vector<Property>> outProps = nullptr;
    int32_t res = mtpMedialibraryManager_->GetObjectPropList(context, outProps);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_PARAMETER_NOT_SUPPORTED);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropList
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_057, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = 1;

    std::shared_ptr<std::vector<Property>> outProps = nullptr;
    int32_t res = mtpMedialibraryManager_->GetObjectPropList(context, outProps);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropList
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_058, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = 1;
    context->handle = 100000000;

    std::shared_ptr<std::vector<Property>> outProps = nullptr;
    int32_t res = mtpMedialibraryManager_->GetObjectPropList(context, outProps);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropList
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_059, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = 1;
    context->handle = 100000000;
    context->parent = 1;

    std::shared_ptr<std::vector<Property>> outProps = nullptr;
    int32_t res = mtpMedialibraryManager_->GetObjectPropList(context, outProps);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropValue
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_060, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    string outStrVal = "";
    int32_t res = mtpMedialibraryManager_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropValue
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_061, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->parent = 1;

    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    string outStrVal = "";
    int32_t res = mtpMedialibraryManager_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumName
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_062, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);

    uint32_t fileId = 1;
    std::string albumName;
    int32_t res = mtpMedialibraryManager_->GetAlbumName(fileId, albumName);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetCopyAlbumObjectPath
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_063, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);

    uint32_t handle = 1;
    PathMap paths;
    int32_t res = mtpMedialibraryManager_->GetCopyAlbumObjectPath(handle, paths);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetCopyPhotoObjectPath
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_064, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);

    uint32_t handle = 1;
    PathMap paths;
    int32_t res = mtpMedialibraryManager_->GetCopyPhotoObjectPath(handle, paths);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetCopyObjectPath
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_065, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);

    uint32_t handle = COMMON_PHOTOS_OFFSET - 1;
    PathMap paths;
    int32_t res = mtpMedialibraryManager_->GetCopyObjectPath(handle, paths);
    EXPECT_EQ(res, MTP_SUCCESS);

    handle = 2 * COMMON_PHOTOS_OFFSET;
    res = mtpMedialibraryManager_->GetCopyObjectPath(handle, paths);
    EXPECT_EQ(res, MTP_SUCCESS);
}
} // namespace Media
} // namespace OHOS