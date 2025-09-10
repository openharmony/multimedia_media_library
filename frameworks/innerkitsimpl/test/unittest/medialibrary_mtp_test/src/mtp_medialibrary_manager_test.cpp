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
#include "medialibrary_mock_tocken.h"
#include "userfile_manager_types.h"
#include "userfilemgr_uri.h"
#include "mtp_constants.h"
#include "medialibrary_errno.h"
#include "iservice_registry.h"
#include "media_file_utils.h"
#include "get_self_permissions.h"
#include "mtp_ptp_const.h"
#include "media_mtp_utils.h"
#include "mtp_medialibrary_manager_test.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static uint64_t g_shellToken = 0;
MediaLibraryMockHapToken* mockToken_test = nullptr;

const std::shared_ptr<MtpMedialibraryManager> mtpMedialibraryManager_ = MtpMedialibraryManager::GetInstance();

void MtpMediaLibraryManagerTest::SetUpTestCase(void)
{
    // mock hap token
    g_shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(g_shellToken);

    vector<string> perms;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO");
    mockToken_test = new MediaLibraryMockHapToken("com.ohos.medialibrary.medialibrarydata", perms);
    for (auto &perm : perms) {
        MediaLibraryMockTokenUtils::GrantPermissionByTest(IPCSkeleton::GetSelfTokenID(), perm, 0);
    }

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);
}

void MtpMediaLibraryManagerTest::TearDownTestCase(void)
{
    // recovery shell token id
    if (mockToken_test != nullptr) {
        delete mockToken_test;
        mockToken_test = nullptr;
    }

    SetSelfTokenID(g_shellToken);
    MediaLibraryMockTokenUtils::ResetToken();
    EXPECT_EQ(g_shellToken, IPCSkeleton::GetSelfTokenID());
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

// SetUp:Execute before each test case
void MtpMediaLibraryManagerTest::SetUp() {}
void MtpMediaLibraryManagerTest::TearDown(void) {}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Clear GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_001, TestSize.Level1)
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
 * CaseDescription: GetAlbumCloud
 */
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_004, TestSize.Level1)
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
 * CaseDescription: GetAlbumCloudDisplay
 */
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_006, TestSize.Level1)
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
 * CaseDescription: GetAlbumInfo
 */
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_009, TestSize.Level1)
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
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_010, TestSize.Level1)
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
 * CaseDescription: GetPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_014, TestSize.Level1)
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
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_015, TestSize.Level1)
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
 * CaseDescription: GetBurstKeyFromPhotosInfo
 */
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_018, TestSize.Level1)
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
 * CaseDescription: GetHandles
 */
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_023, TestSize.Level1)
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
 * CaseDescription: GetAllHandles
 */
HWTEST_F(MtpMediaLibraryManagerTest, medialibrary_PTP_message_testlevel_0_029, TestSize.Level1)
{
    ASSERT_NE(mtpMedialibraryManager_, nullptr);

    shared_ptr<MtpOperationContext> context = nullptr;
    mtpMedialibraryManager_->dataShareHelper_ = nullptr;
    std::shared_ptr<UInt32List> out = nullptr;
    int32_t res = mtpMedialibraryManager_->GetAllHandles(context, out);

    mtpMedialibraryManager_->Clear();
    EXPECT_EQ(res, MTP_ERROR_STORE_NOT_AVAILABLE);
}
} // namespace Media
} // namespace OHOS