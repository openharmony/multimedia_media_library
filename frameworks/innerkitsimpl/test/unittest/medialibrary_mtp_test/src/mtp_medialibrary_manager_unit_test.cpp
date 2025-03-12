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

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static constexpr int STORAGE_MANAGER_UID_TEST = 5003;

const std::shared_ptr<MtpMedialibraryManager> mtpMedialibraryManager_ = MtpMedialibraryManager::GetInstance();


void MtpMediaLibraryManagerUnitTest::SetUpTestCase(void) {}

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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_001, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_002, TestSize.Level0)
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
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Clear GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_003, TestSize.Level0)
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
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumCloud
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_004, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_005, TestSize.Level0)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
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
 * CaseDescription: GetAlbumCloudDisplay
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_006, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_007, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_008, TestSize.Level0)
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
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAlbumInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_009, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_010, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_011, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_012, TestSize.Level0)
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
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetOwnerAlbumIdList
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_013, TestSize.Level0)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
    auto res = mtpMedialibraryManager_->GetOwnerAlbumIdList();

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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_014, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_015, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_016, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_017, TestSize.Level0)
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
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetBurstKeyFromPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_018, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_019, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_020, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_021, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_022, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_023, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_024, TestSize.Level0)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID_TEST);

    mtpMedialibraryManager_->dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    ASSERT_NE(mtpMedialibraryManager_->dataShareHelper_, nullptr);
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
HWTEST_F(MtpMediaLibraryManagerUnitTest, medialibrary_PTP_message_testlevel_0_025, TestSize.Level0)
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
} // namespace Media
} // namespace OHOS