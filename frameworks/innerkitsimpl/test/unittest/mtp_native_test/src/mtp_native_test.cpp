/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <thread>
#include "mtp_native_test.h"
#include "mtp_medialibrary_manager.h"
#include "mtp_event.h"
#include "mtp_service.h"
#include "property.h"
using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
void MtpNativeTest::SetUpTestCase()
{
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    const string processName = "MediaMTPNativeUnitTest";
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission(processName, perms, tokenId);
    EXPECT_TRUE(tokenId != 0);
}

void MtpNativeTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MtpNativeTest::SetUp() {}
void MtpNativeTest::TearDown(void) {}
static constexpr int TEST_UID = 5003;
static const string TEST_NAME = "test.jpg";
static const string PROP_VALUE = "01.jpg";
/**
 * @tc.number    : mtp_native_test_001
 * @tc.name      : mtp_native_test_001
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_001, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_001::End");
}

/**
 * @tc.number    : mtp_native_test_002
 * @tc.name      : mtp_native_test_002
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_002, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : all
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0xFFFFFFFF;
    context->depth = 0;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_002::End");
}

/**
 * @tc.number    : mtp_native_test_003
 * @tc.name      : mtp_native_test_003
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_003, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    uint32_t handle = 1;

    // get handle
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = handle;
    context->depth = 0;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_003::End");
}

/**
 * @tc.number    : mtp_native_test_004
 * @tc.name      : mtp_native_test_004
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_004, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    uint32_t handle = 1;

    // get handle children and handle deep : 1
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = handle;
    context->depth = 1;
    context->format = MTP_FORMAT_ASSOCIATION_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_004::End");
}

/**
 * @tc.number    : mtp_native_test_005
 * @tc.name      : mtp_native_test_005
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_005, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_005::End");
}

/**
 * @tc.number    : mtp_native_test_006
 * @tc.name      : mtp_native_test_006
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_006, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : all
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0xFFFFFFFF;
    context->depth = 0;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_006::End");
}

/**
 * @tc.number    : mtp_native_test_007
 * @tc.name      : mtp_native_test_007
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_007, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    uint32_t handle = 1;

    // get handle
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = handle;
    context->depth = 0;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_007::End");
}

/**
 * @tc.number    : mtp_native_test_008
 * @tc.name      : mtp_native_test_008
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_008, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_008::End");
}

/**
 * @tc.number    : mtp_native_test_009
 * @tc.name      : mtp_native_test_009
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_009, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : all
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0xFFFFFFFF;
    context->depth = 0;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_009::End");
}

/**
 * @tc.number    : mtp_native_test_010
 * @tc.name      : mtp_native_test_010
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_010, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    uint32_t handle = 1;

    // get handle
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = handle;
    context->depth = 0;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_010::End");
}

/**
 * @tc.number    : mtp_native_test_011
 * @tc.name      : mtp_native_test_011
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_011, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_011::End");
}

/**
 * @tc.number    : mtp_native_test_012
 * @tc.name      : mtp_native_test_012
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_012, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : all
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0xFFFFFFFF;
    context->depth = 0;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_012::End");
}

/**
 * @tc.number    : mtp_native_test_013
 * @tc.name      : mtp_native_test_013
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_013, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    uint32_t handle = 1;

    // get handle
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = handle;
    context->depth = 0;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_013::End");
}

/**
 * @tc.number    : mtp_native_test_014
 * @tc.name      : mtp_native_test_014
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_014, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_ASSOCIATION_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_014::End");
}

/**
 * @tc.number    : mtp_native_test_015
 * @tc.name      : mtp_native_test_015
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_015, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : all
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0xFFFFFFFF;
    context->depth = 0;
    context->format = MTP_FORMAT_ASSOCIATION_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_015::End");
}

/**
 * @tc.number    : mtp_native_test_016
 * @tc.name      : mtp_native_test_016
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_016, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    uint32_t handle = 1;

    // get handle
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = handle;
    context->depth = 0;
    context->format = MTP_FORMAT_ASSOCIATION_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_016::End");
}

/**
 * @tc.number    : mtp_native_test_020
 * @tc.name      : mtp_native_test_020
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_020, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 1000;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_020::End");
}

/**
 * @tc.number    : mtp_native_test_021
 * @tc.name      : mtp_native_test_021
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_021, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1000;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_021::End");
}

/**
 * @tc.number    : mtp_native_test_022
 * @tc.name      : mtp_native_test_022
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_022, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 1000;
    context->depth = 1;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_022::End");
}

/**
 * @tc.number    : mtp_native_test_023
 * @tc.name      : mtp_native_test_023
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_023, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1000;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_023::End");
}

/**
 * @tc.number    : mtp_native_test_024
 * @tc.name      : mtp_native_test_024
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_024, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = 0xffffffff;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = 1000;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_024::End");
}

/**
 * @tc.number    : mtp_native_test_025
 * @tc.name      : mtp_native_test_025
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_025, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_025::End");
}

/**
 * @tc.number    : mtp_native_test_026
 * @tc.name      : mtp_native_test_026
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_026, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_026::End");
}
/**
 * @tc.number    : mtp_native_test_027
 * @tc.name      : mtp_native_test_027
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_027, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_027::End");
}

/**
 * @tc.number    : mtp_native_test_028
 * @tc.name      : mtp_native_test_028
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_028, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 1;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_028::End");
}

/**
 * @tc.number    : mtp_native_test_029
 * @tc.name      : mtp_native_test_029
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_029, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 1;
    context->depth = 1;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_029::End");
}

/**
 * @tc.number    : mtp_native_test_030
 * @tc.name      : mtp_native_test_030
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_030, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 1;
    context->depth = 1;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_030::End");
}

/**
 * @tc.number    : mtp_native_test_031
 * @tc.name      : mtp_native_test_031
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_031, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 1;
    context->depth = 1;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_031::End");
}

/**
 * @tc.number    : mtp_native_test_032
 * @tc.name      : mtp_native_test_032
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_032, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 1;
    context->depth = 1;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_032::End");
}

/**
 * @tc.number    : mtp_native_test_033
 * @tc.name      : mtp_native_test_033
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_033, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0xffffffff;
    context->depth = 1;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_033::End");
}

/**
 * @tc.number    : mtp_native_test_034
 * @tc.name      : mtp_native_test_034
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_034, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0xffffffff;
    context->depth = 1;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_034::End");
}

/**
 * @tc.number    : mtp_native_test_035
 * @tc.name      : mtp_native_test_035
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_035, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0xffffffff;
    context->depth = 1;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_035::End");
}

/**
 * @tc.number    : mtp_native_test_036
 * @tc.name      : mtp_native_test_036
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_036, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0xffffffff;
    context->depth = 1;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_036::End");
}

/**
 * @tc.number    : mtp_native_test_037
 * @tc.name      : mtp_native_test_037
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_037, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 0;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_037::End");
}

/**
 * @tc.number    : mtp_native_test_038
 * @tc.name      : mtp_native_test_038
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_038, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 0;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_038::End");
}

/**
 * @tc.number    : mtp_native_test_039
 * @tc.name      : mtp_native_test_039
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_039, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 0;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_039::End");
}

/**
 * @tc.number    : mtp_native_test_040
 * @tc.name      : mtp_native_test_040
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_040, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0;
    context->depth = 0;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_040::End");
}

/**
 * @tc.number    : mtp_native_test_041
 * @tc.name      : mtp_native_test_041
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_041, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 1;
    context->depth = 0;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_041::End");
}

/**
 * @tc.number    : mtp_native_test_042
 * @tc.name      : mtp_native_test_042
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_042, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 1;
    context->depth = 0;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_042::End");
}

/**
 * @tc.number    : mtp_native_test_043
 * @tc.name      : mtp_native_test_043
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_043, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 1;
    context->depth = 0;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_043::End");
}

/**
 * @tc.number    : mtp_native_test_044
 * @tc.name      : mtp_native_test_044
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_044, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 1;
    context->depth = 0;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_044::End");
}

/**
 * @tc.number    : mtp_native_test_045
 * @tc.name      : mtp_native_test_045
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_045, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0xffffffff;
    context->depth = 0;
    context->format = MTP_FORMAT_TEXT_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_045::End");
}

/**
 * @tc.number    : mtp_native_test_046
 * @tc.name      : mtp_native_test_046
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_046, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0xffffffff;
    context->depth = 0;
    context->format = MTP_FORMAT_MP3_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_046::End");
}

/**
 * @tc.number    : mtp_native_test_047
 * @tc.name      : mtp_native_test_047
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_047, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0xffffffff;
    context->depth = 0;
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_047::End");
}

/**
 * @tc.number    : mtp_native_test_048
 * @tc.name      : mtp_native_test_048
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_048, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().
    GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);

    // get root dirs children deep : 1:success
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->property = MTP_PROPERTY_DISPLAY_NAME_CODE;
    context->groupCode = 1;
    context->handle = 0xffffffff;
    context->depth = 0;
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    for (Property property : *outProps) {
        property.Dump();
    }
    MEDIA_INFO_LOG("mtp_native_test_048::End");
}

/**
 * @tc.number    : mtp_native_test_049
 * @tc.name      : mtp_native_test_049
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_049, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_049 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_049 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_049::End");
}

/**
 * @tc.number    : mtp_native_test_050
 * @tc.name      : mtp_native_test_050
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_050, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 0xFFFFFFFF;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_050 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_050 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_050::End");
}
/**
 * @tc.number    : mtp_native_test_051
 * @tc.name      : mtp_native_test_051
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_051, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = MTP_FORMAT_EXIF_JPEG_CODE;
    context->parent = 0;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_051 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_051 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_051::End");
}

/**
 * @tc.number    : mtp_native_test_052
 * @tc.name      : mtp_native_test_052
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_052, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = MTP_FORMAT_MP4_CONTAINER_CODE;
    context->parent = 0;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_052 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_052 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_052::End");
}

/**
 * @tc.number    : mtp_native_test_053
 * @tc.name      : mtp_native_test_053
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_053, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = MTP_FORMAT_MP3_CODE;
    context->parent = 0;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_053 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_053 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_053::End");
}

/**
 * @tc.number    : mtp_native_test_054
 * @tc.name      : mtp_native_test_054
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_054, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = MTP_FORMAT_TEXT_CODE;
    context->parent = 0;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_054 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_054 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_054::End");
}

/**
 * @tc.number    : mtp_native_test_055
 * @tc.name      : mtp_native_test_055
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_055, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = MTP_FORMAT_ASSOCIATION_CODE;
    context->parent = 0;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_055 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_055 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_055::End");
}

/**
 * @tc.number    : mtp_native_test_058
 * @tc.name      : mtp_native_test_058
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_058, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_058 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_058 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_058::End");
}

/**
 * @tc.number    : mtp_native_test_059
 * @tc.name      : mtp_native_test_059
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_059, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = 1000;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_059 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_059 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    }
    MEDIA_INFO_LOG("mtp_native_test_059::End");
}
///
/**
 * @tc.number    : mtp_native_test_060
 * @tc.name      : mtp_native_test_060
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_060, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    uint32_t handle = 0;
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = handle;
    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
    MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
    MEDIA_INFO_LOG("mtp_native_test_060 handle = %{public}d", handle);
    MEDIA_INFO_LOG("mtp_native_test_060 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    int fd = 0;
    MtpMedialibraryManager::GetInstance()->GetFd(context, fd);
    MEDIA_INFO_LOG("mtp_native_test_060 fd = %{public}d", fd);
    MtpMedialibraryManager::GetInstance()->CloseFd(context, fd);
}

/**
 * @tc.number    : mtp_native_test_061
 * @tc.name      : mtp_native_test_061
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_061, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    uint32_t handle = 1000;
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = handle;
    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
    MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
    MEDIA_INFO_LOG("mtp_native_test_061 handle = %{public}d", handle);
    MEDIA_INFO_LOG("mtp_native_test_061 objectInfo->name = %{public}s", (objectInfo->name).c_str());
    int fd = 0;
    MtpMedialibraryManager::GetInstance()->GetFd(context, fd);
    MEDIA_INFO_LOG("mtp_native_test_061 fd = %{public}d", fd);
    MtpMedialibraryManager::GetInstance()->CloseFd(context, fd);
}

/**
 * @tc.number    : mtp_native_test_064
 * @tc.name      : mtp_native_test_064
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_064, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->name = TEST_NAME;
    context->parent = 1;
    uint32_t handle = 0;
    context->storageID = 1;
    context->format = 0x3801;
    MtpMedialibraryManager::GetInstance()->SendObjectInfo(context, context->storageID, context->parent, handle);

    MEDIA_INFO_LOG("mtp_native_test_064::End");
}

/**
 * @tc.number    : mtp_native_test_065
 * @tc.name      : mtp_native_test_065
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_065, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->name = "1000";
    context->parent = 1;
    uint32_t handle = 0;
    context->storageID = 1;
    context->format = 0x3801;
    MtpMedialibraryManager::GetInstance()->SendObjectInfo(context, context->storageID, context->parent, handle);

    MEDIA_INFO_LOG("mtp_native_test_065::End");
}

/**
 * @tc.number    : mtp_native_test_066
 * @tc.name      : mtp_native_test_066
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_066, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->name = TEST_NAME;
    context->parent = 1000;
    uint32_t handle = 0;
    context->storageID = 1;
    context->format = 0x3801;
    MtpMedialibraryManager::GetInstance()->SendObjectInfo(context, context->storageID, context->parent, handle);

    MEDIA_INFO_LOG("mtp_native_test_066::End");
}

/**
 * @tc.number    : mtp_native_test_067
 * @tc.name      : mtp_native_test_067
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_067, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->name = TEST_NAME;
    context->parent = 1;
    uint32_t handle = 0;
    context->storageID = 1000;
    context->format = 0x3801;
    MtpMedialibraryManager::GetInstance()->SendObjectInfo(context, context->storageID, context->parent, handle);

    MEDIA_INFO_LOG("mtp_native_test_067::End");
}

/**
 * @tc.number    : mtp_native_test_068
 * @tc.name      : mtp_native_test_068
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_068, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->name = TEST_NAME;
    context->parent = 1;
    uint32_t handle = 0;
    context->storageID = 1;
    context->format = 1000;
    MtpMedialibraryManager::GetInstance()->SendObjectInfo(context, context->storageID, context->parent, handle);

    MEDIA_INFO_LOG("mtp_native_test_068::End");
}

/**
 * @tc.number    : mtp_native_test_069
 * @tc.name      : mtp_native_test_069
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_069, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->name = TEST_NAME;
    context->parent = 1;
    uint32_t handle = 1000;
    context->storageID = 1;
    context->format = 0x3801;
    MtpMedialibraryManager::GetInstance()->SendObjectInfo(context, context->storageID, context->parent, handle);

    MEDIA_INFO_LOG("mtp_native_test_069::End");
}

/**
 * @tc.number    : mtp_native_test_070
 * @tc.name      : mtp_native_test_070
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_070, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1;
    context->parent = 1;
    context->storageID = 1;
    MtpMedialibraryManager::GetInstance()->MoveObject(context);
    MEDIA_INFO_LOG("mtp_native_test_070 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_070::End");
}

/**
 * @tc.number    : mtp_native_test_071
 * @tc.name      : mtp_native_test_071
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_071, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1;
    context->parent = 1000;
    context->storageID = 1;
    MtpMedialibraryManager::GetInstance()->MoveObject(context);
    MEDIA_INFO_LOG("mtp_native_test_071 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_071::End");
}

/**
 * @tc.number    : mtp_native_test_072
 * @tc.name      : mtp_native_test_072
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_072, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1;
    context->parent = 1000;
    context->storageID = 1;
    MtpMedialibraryManager::GetInstance()->MoveObject(context);
    MEDIA_INFO_LOG("mtp_native_test_072 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_072::End");
}

 /**
 * @tc.number    : mtp_native_test_073
 * @tc.name      : mtp_native_test_073
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_073, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1;
    context->parent = 1;
    context->storageID = 1000;
    MtpMedialibraryManager::GetInstance()->MoveObject(context);
    MEDIA_INFO_LOG("mtp_native_test_073 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_073::End");
}

/**
 * @tc.number    : mtp_native_test_074
 * @tc.name      : mtp_native_test_074
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_074, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 0;
    context->parent = 0;
    context->storageID = 0;
    uint32_t handle = 0;
    MtpMedialibraryManager::GetInstance()->CopyObject(context, handle);
    MEDIA_INFO_LOG("mtp_native_test_074 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_074::End");
}

/**
 * @tc.number    : mtp_native_test_075
 * @tc.name      : mtp_native_test_075
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_075, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1;
    context->parent = 1000;
    context->storageID = 1;
    uint32_t handle = 0;
    MtpMedialibraryManager::GetInstance()->CopyObject(context, handle);
    MEDIA_INFO_LOG("mtp_native_test_075 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_075::End");
}

/**
 * @tc.number    : mtp_native_test_076
 * @tc.name      : mtp_native_test_076
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_076, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1;
    context->parent = 1000;
    context->storageID = 1;
    uint32_t handle = 0;
    MtpMedialibraryManager::GetInstance()->CopyObject(context, handle);
    MEDIA_INFO_LOG("mtp_native_test_076 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_076::End");
}

/**
 * @tc.number    : mtp_native_test_077
 * @tc.name      : mtp_native_test_077
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_077, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1;
    context->parent = 1000;
    context->storageID = 1000;
    uint32_t handle = 0;
    MtpMedialibraryManager::GetInstance()->CopyObject(context, handle);
    MEDIA_INFO_LOG("mtp_native_test_077 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_077::End");
}

/**
 * @tc.number    : mtp_native_test_078
 * @tc.name      : mtp_native_test_078
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_078, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1;
    MtpMedialibraryManager::GetInstance()->DeleteObject(context);
    MEDIA_INFO_LOG("mtp_native_test_078::End");
}

/**
 * @tc.number    : mtp_native_test_079
 * @tc.name      : mtp_native_test_079
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_079, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1000;
    MtpMedialibraryManager::GetInstance()->DeleteObject(context);
    MEDIA_INFO_LOG("mtp_native_test_079::End");
}

/**
 * @tc.number    : mtp_native_test_080
 * @tc.name      : mtp_native_test_080
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_080, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 0;
    context->property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    context->properType = MTP_TYPE_STRING_CODE;
    context->properStrValue = PROP_VALUE;
    MtpMedialibraryManager::GetInstance()->SetObjectPropValue(context);
    MEDIA_INFO_LOG("mtp_native_test_080 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_080::End");
}

/**
 * @tc.number    : mtp_native_test_081
 * @tc.name      : mtp_native_test_081
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_081, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 1000;
    context->property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    context->properType = MTP_TYPE_STRING_CODE;
    context->properStrValue = PROP_VALUE;
    MtpMedialibraryManager::GetInstance()->SetObjectPropValue(context);
    MEDIA_INFO_LOG("mtp_native_test_081 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_081::End");
}

/**
 * @tc.number    : mtp_native_test_082
 * @tc.name      : mtp_native_test_082
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_082, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 0;
    context->property = 1000;
    context->properType = MTP_TYPE_STRING_CODE;
    context->properStrValue = PROP_VALUE;
    MtpMedialibraryManager::GetInstance()->SetObjectPropValue(context);
    MEDIA_INFO_LOG("mtp_native_test_082 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_082::End");
}

/**
 * @tc.number    : mtp_native_test_083
 * @tc.name      : mtp_native_test_083
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_083, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 0;
    context->property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    context->properType = 1000;
    context->properStrValue = PROP_VALUE;
    MtpMedialibraryManager::GetInstance()->SetObjectPropValue(context);
    MEDIA_INFO_LOG("mtp_native_test_083 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_083::End");
}

/**
 * @tc.number    : mtp_native_test_084
 * @tc.name      : mtp_native_test_084
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_084, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->handle = 0;
    context->property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    context->properType = MTP_TYPE_STRING_CODE;
    context->properStrValue = "1000";
    MtpMedialibraryManager::GetInstance()->SetObjectPropValue(context);
    MEDIA_INFO_LOG("mtp_native_test_084 context->name = %{public}s", (context->name).c_str());
    MEDIA_INFO_LOG("mtp_native_test_084::End");
}

/**
 * @tc.number    : mtp_native_test_085
 * @tc.name      : mtp_native_test_085
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_085, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = handle;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_085 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_085 objectInfo->name = %{public}s", (objectInfo->name).c_str());
        int fd = 0;
        MtpMedialibraryManager::GetInstance()->GetFd(context, fd);
        MEDIA_INFO_LOG("mtp_native_test_085 fd = %{public}d", fd);
        MtpMedialibraryManager::GetInstance()->CloseFd(context, fd);
    }
    MEDIA_INFO_LOG("mtp_native_test_085::End");
}

/**
 * @tc.number    : mtp_native_test_086
 * @tc.name      : mtp_native_test_086
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_086, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    MtpMedialibraryManager::GetInstance()->GetHandles(context, objectHandles);
    for (uint32_t handle : *objectHandles) {
        context = make_shared<MtpOperationContext>();
        context->handle = 1000;
        shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(handle);
        MtpMedialibraryManager::GetInstance()->GetObjectInfo(context, objectInfo);
        MEDIA_INFO_LOG("mtp_native_test_086 handle = %{public}d", handle);
        MEDIA_INFO_LOG("mtp_native_test_086 objectInfo->name = %{public}s", (objectInfo->name).c_str());
        int fd = 0;
        MtpMedialibraryManager::GetInstance()->GetFd(context, fd);
        MEDIA_INFO_LOG("mtp_native_test_086 fd = %{public}d", fd);
        MtpMedialibraryManager::GetInstance()->CloseFd(context, fd);
    }
    MEDIA_INFO_LOG("mtp_native_test_086::End");
}

/**
 * @tc.number    : mtp_native_test_087
 * @tc.name      : mtp_native_test_087
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_087, TestSize.Level0)
{
    MtpMedialibraryManager mtpMedialibraryManager;
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    uint64_t outIntVal = 0;
    uint128_t outLongVal;
    string outStrVal = "GetObjectPropValue";
    int32_t ret = mtpMedialibraryManager.GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
    EXPECT_EQ(ret, MTP_ERROR_INVALID_OBJECTHANDLE);
    context->handle = 1000;
    context->property = 1;
    ret = mtpMedialibraryManager.GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
    EXPECT_EQ(ret, MTP_ERROR_INVALID_OBJECTHANDLE);
    MEDIA_INFO_LOG("mtp_native_test_087::End");
}

/**
 * @tc.number    : mtp_native_test_088
 * @tc.name      : mtp_native_test_088
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_088, TestSize.Level0)
{
    MtpMedialibraryManager mtpMedialibraryManager;
    shared_ptr<ObjectInfo> outObjectInfo = make_shared<ObjectInfo>(0);
    MediaType mediaType = MEDIA_TYPE_ALBUM;
    unique_ptr<FileAsset> fileAsset = make_unique<FileAsset>();
    fileAsset->SetMediaType(mediaType);
    int32_t ret = mtpMedialibraryManager.SetObjectInfo(fileAsset, outObjectInfo);
    EXPECT_EQ(ret, MTP_SUCCESS);
    mediaType = MEDIA_TYPE_IMAGE;
    fileAsset->SetMediaType(mediaType);
    ret = mtpMedialibraryManager.SetObjectInfo(fileAsset, outObjectInfo);
    EXPECT_EQ(ret, MTP_SUCCESS);
    MEDIA_INFO_LOG("mtp_native_test_088::End");
}

/**
 * @tc.number    : mtp_native_test_089
 * @tc.name      : mtp_native_test_089
 * @tc.desc      : 1.
 */
HWTEST_F(MtpNativeTest, mtp_native_test_089, TestSize.Level0)
{
    auto mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    int32_t id = 0;
    shared_ptr<FileAsset> outFileAsset = make_shared<FileAsset>();
    int32_t ret = mtpMedialibraryManager->GetAssetById(id, outFileAsset);
    EXPECT_EQ(ret, E_NO_SUCH_FILE);;
    uint16_t format = 12287U;
    uint32_t handle = 1;
    mtpMedialibraryManager->GetAllRootsChildren(format);
    mtpMedialibraryManager->GetHandle(format, handle);
    uint16_t formatTest = MTP_FORMAT_CIFF_CODE;
    mtpMedialibraryManager->GetAllRootsChildren(formatTest);
    mtpMedialibraryManager->GetHandle(formatTest, handle);
    MEDIA_INFO_LOG("mtp_native_test_089::End");
}

/**
 * @tc.number    : mtp_header_data_001
 * @tc.name      : mtp_header_data_001
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_header_data_001, TestSize.Level0)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->format = 0;
    context->parent = 1;
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(context);
    headerData->Reset();
    headerData->SetCode(0);
    headerData->SetContainerType(0);
    uint32_t len = headerData->GetContainerLength();
    EXPECT_EQ(len == 0, true);
    headerData->SetTransactionId(1);
    uint32_t id = headerData->GetTransactionId();
    EXPECT_EQ(id == 1, true);

    MEDIA_INFO_LOG("mtp_header_data_001::End");
}

/**
 * @tc.number    : mtp_driver_001
 * @tc.name      : mtp_driver_001
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_driver_001, TestSize.Level0)
{
    shared_ptr<MtpDriver> mtpDriver = make_shared<MtpDriver>();
    int ret = mtpDriver->OpenDriver();
    EXPECT_EQ(ret, MTP_SUCCESS);
    vector<uint8_t> buffer;
    uint32_t size = 0;
    ret = mtpDriver->Read(buffer, size);
    EXPECT_EQ(ret, MTP_SUCCESS);
    mtpDriver->Write(buffer, size);
    MtpFileRange mfr;
    mtpDriver->SendObj(mfr);
    mtpDriver->ReceiveObj(mfr);
    EventMtp me;
    mtpDriver->WriteEvent(me);
    mtpDriver->CloseDriver();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->format = 0;
    context->parent = 1;
    shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    string path;
    mtpEvent->SendObjectAdded(path);
    mtpEvent->SendObjectRemoved(path);
    mtpEvent->SendObjectInfoChanged(path);
    shared_ptr<PayloadData> data = make_shared<ObjectEventData>(context);
    ret = mtpEvent->EventPayloadData(MTP_EVENT_OBJECT_ADDED_CODE, data);
    EXPECT_EQ(ret, MTP_OK_CODE);
    ret = mtpEvent->EventPayloadData(MTP_EVENT_DEVICE_PROP_CHANGED_CODE, data);
    EXPECT_EQ(ret, MTP_OK_CODE);
    ret = mtpEvent->EventPayloadData(MTP_EVENT_OBJECT_PROP_DESC_CHANGED_CODE, data);
    EXPECT_EQ(ret, MTP_UNDEFINED_CODE);
    mtpEvent->SendEvent(MTP_EVENT_DEVICE_PROP_CHANGED_CODE);
    MtpService mtpService;
    mtpService.Init();
    mtpService.StartService();
    mtpService.StopService();
    MEDIA_INFO_LOG("mtp_driver_001::End");
}

/**
 * @tc.number    : mtp_operation_utils_property_001
 * @tc.name      : mtp_operation_utils_property_001
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_property_001, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    context->property = MTP_DEVICE_PROPERTY_SYNCHRONIZATION_PARTNER_CODE;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    int errorCode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils->GetPropDesc(data, containerType, errorCode);
    mtpOperUtils->GetPropValue(data, containerType, errorCode);

    MEDIA_INFO_LOG("mtp_operation_utils_property_001::End");
}

/**
 * @tc.number    : mtp_operation_utils_property_002
 * @tc.name      : mtp_operation_utils_property_002
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_property_002, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    context->property = MTP_DEVICE_PROPERTY_DEVICE_FRIENDLY_NAME_CODE;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    int errorCode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils->GetPropDesc(data, containerType, errorCode);
    mtpOperUtils->GetPropValue(data, containerType, errorCode);

    MEDIA_INFO_LOG("mtp_operation_utils_property_002::End");
}

/**
 * @tc.number    : mtp_operation_utils_property_003
 * @tc.name      : mtp_operation_utils_property_003
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_property_003, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    context->property = MTP_DEVICE_PROPERTY_SESSION_INITIATOR_VERSION_INFO_CODE;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    int errorCode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils->GetPropDesc(data, containerType, errorCode);
    mtpOperUtils->GetPropValue(data, containerType, errorCode);

    MEDIA_INFO_LOG("mtp_operation_utils_property_003::End");
}

/**
 * @tc.number    : mtp_operation_utils_property_004
 * @tc.name      : mtp_operation_utils_property_004
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_property_004, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    context->property = MTP_DEVICE_PROPERTY_IMAGE_SIZE_CODE;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    int errorCode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils->GetPropDesc(data, containerType, errorCode);
    mtpOperUtils->GetPropValue(data, containerType, errorCode);

    MEDIA_INFO_LOG("mtp_operation_utils_property_004::End");
}

/**
 * @tc.number    : mtp_operation_utils_property_005
 * @tc.name      : mtp_operation_utils_property_005
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_property_005, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    context->property = MTP_DEVICE_PROPERTY_BATTERY_LEVEL_CODE;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    int errorCode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils->GetPropDesc(data, containerType, errorCode);
    mtpOperUtils->GetPropValue(data, containerType, errorCode);

    MEDIA_INFO_LOG("mtp_operation_utils_property_005::End");
}

/**
 * @tc.number    : mtp_operation_utils_property_006
 * @tc.name      : mtp_operation_utils_property_006
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_property_006, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    context->property = MTP_DEVICE_PROPERTY_PERCEIVED_DEVICE_TYPE_CODE;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    int errorCode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils->GetPropDesc(data, containerType, errorCode);
    mtpOperUtils->GetPropValue(data, containerType, errorCode);

    MEDIA_INFO_LOG("mtp_operation_utils_property_006::End");
}

/**
 * @tc.number    : mtp_operation_utils_property_007
 * @tc.name      : mtp_operation_utils_property_007
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_property_007, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    EXPECT_NE(context, nullptr);
    context->format = 0;
    context->parent = 1;
    context->property = 0;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    int errorCode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils->GetPropDesc(data, containerType, errorCode);
    mtpOperUtils->GetPropValue(data, containerType, errorCode);

    MEDIA_INFO_LOG("mtp_operation_utils_property_007::End");
}

/**
 * @tc.number    : mtp_operation_utils_property_008
 * @tc.name      : mtp_operation_utils_property_008
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_property_008, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->format = 0;
    context->parent = 1;
    context->property = 0;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    int errorCode = 0;
    uint16_t containerType = UNDEFINED_CONTAINER_TYPE;

    uint16_t ret = mtpOperUtils->GetPropDesc(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetPropValue(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);

    MEDIA_INFO_LOG("mtp_operation_utils_property_008::End");
}

/**
 * @tc.number    : mtp_operation_utils_001
 * @tc.name      : mtp_operation_utils_001
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_001, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(nullptr);
    shared_ptr<PayloadData> data;
    uint16_t containerType = UNDEFINED_CONTAINER_TYPE;
    int errorCode = 0;
    uint16_t ret = mtpOperUtils->GetDeviceInfo(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetNumObjects(data);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    mtpOperUtils->DoSetObjectPropValue(errorCode);
    ret = mtpOperUtils->GetObjectHandles(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetObjectPropDesc(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetObjectPropValue(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetObjectPropList(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->SendObjectInfo(data, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetPartialObject(data);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetObjectPropsSupported(data);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->DeleteObject(data, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->MoveObject(data, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->CopyObject(data, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetStorageIDs(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetStorageInfo(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    string path, realPath;
    uint32_t handle = 0;
    ret = mtpOperUtils->GetPathByHandle(handle, path, realPath);
    EXPECT_TRUE(ret == MTP_UNDEFINED_CODE);
    int32_t retInt = mtpOperUtils->GetHandleByPaths(path, handle);
    EXPECT_TRUE(retInt == MTP_UNDEFINED_CODE);

    MEDIA_INFO_LOG("mtp_operation_utils_001::End");
}

/**
 * @tc.number    : mtp_operation_utils_002
 * @tc.name      : mtp_operation_utils_002
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_002, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(nullptr);
    shared_ptr<PayloadData> data;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    int errorCode = 0;

    uint16_t ret = mtpOperUtils->GetObjectPropDesc(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetObjectPropValue(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetObjectPropList(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);

    MEDIA_INFO_LOG("mtp_operation_utils_002::End");
}

/**
 * @tc.number    : mtp_operation_utils_003
 * @tc.name      : mtp_operation_utils_003
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_003, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->format = 0;
    context->parent = 1;
    context->sessionOpen = false;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    int errorCode = 0;

    uint16_t ret = mtpOperUtils->GetObjectHandles(data, containerType, errorCode);
    EXPECT_TRUE(ret != MTP_SUCCESS);
    ret = mtpOperUtils->GetStorageIDs(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_SESSION_NOT_OPEN_CODE);
    ret = mtpOperUtils->GetStorageInfo(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_SESSION_NOT_OPEN_CODE);
    MEDIA_INFO_LOG("mtp_operation_utils_003::End");
}

/**
 * @tc.number    : mtp_operation_utils_004
 * @tc.name      : mtp_operation_utils_004
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_004, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->format = 0;
    context->parent = 1;
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    int errorCode = 0;

    uint16_t ret = mtpOperUtils->GetDeviceInfo(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    mtpOperUtils->GetObjectInfo(data, containerType, errorCode);
    ret = mtpOperUtils->GetObjectPropDesc(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetObjectPropValue(data, containerType, errorCode);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->SendObjectInfo(data, errorCode);
    EXPECT_TRUE(ret != MTP_OK_CODE);
    ret = mtpOperUtils->GetPartialObject(data);
    EXPECT_TRUE(ret == MTP_SUCCESS);
    ret = mtpOperUtils->GetObjectPropsSupported(data);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->GetOpenSession(data, errorCode);
    EXPECT_TRUE(ret != MTP_OK_CODE);
    ret = mtpOperUtils->GetCloseSession(data);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->SetDevicePropValueResp(data);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    ret = mtpOperUtils->ResetDevicePropResp(data);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    int32_t payload = 0;
    ret = mtpOperUtils->ObjectEvent(data, payload);
    EXPECT_TRUE(ret == MTP_OK_CODE);
    uint32_t handle = 1;
    string path, realPath;
    ret = mtpOperUtils->GetPathByHandle(handle, path, realPath);
    EXPECT_TRUE(ret == MTP_OK_CODE);

    MEDIA_INFO_LOG("mtp_operation_utils_004::End");
}

/**
 * @tc.number    : mtp_operation_utils_007
 * @tc.name      : mtp_operation_utils_007
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_operation_utils_007, TestSize.Level0)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> data = make_shared<CloseSessionData>(context);
    int errorCode = 0;
    uint16_t ret = mtpOperUtils->CheckErrorCode(errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_PACKET_INCORRECT);
    EXPECT_EQ(ret, MTP_INVALID_PARAMETER_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_SESSION_ALREADY_OPEN);
    EXPECT_EQ(ret, MTP_SESSION_ALREADY_OPEN_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_NO_THIS_FILE);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTHANDLE_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_INCOMPLETE_TRANSFER);
    EXPECT_EQ(ret, MTP_INCOMPLETE_TRANSFER_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_SESSION_NOT_OPEN);
    EXPECT_EQ(ret, MTP_SESSION_NOT_OPEN_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_INVALID_STORAGE_ID);
    EXPECT_EQ(ret, MTP_INVALID_STORAGEID_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTHANDLE_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_DEVICEPROP_NOT_SUPPORTED);
    EXPECT_EQ(ret, MTP_DEVICEPROP_NOT_SUPPORTED_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_STORE_NOT_AVAILABLE);
    EXPECT_EQ(ret, MTP_STORE_NOT_AVAILABLE_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_INVALID_PARENTOBJECT);
    EXPECT_EQ(ret, MTP_INVALID_PARENTOBJECT_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_PARAMETER_NOT_SUPPORTED);
    EXPECT_EQ(ret, MTP_PARAMETER_NOT_SUPPORTED_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_INVALID_OBJECTPROP_VALUE);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTPROP_VALUE_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_INVALID_OBJECTPROP_FORMAT);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTPROP_FORMAT_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_INVALID_OBJECTPROPCODE);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTPROPCODE_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_ACCESS_DENIED);
    EXPECT_EQ(ret, MTP_ACCESS_DENIED_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_SPECIFICATION_BY_GROUP_UNSUPPORTED);
    EXPECT_EQ(ret, MTP_SPECIFICATION_BY_GROUP_UNSUPPORTED_CODE);
    ret = mtpOperUtils->CheckErrorCode(MTP_ERROR_SPECIFICATION_BY_DEPTH_UNSUPPORTED);
    EXPECT_EQ(ret, MTP_SPECIFICATION_BY_DEPTH_UNSUPPORTED_CODE);
    mtpOperUtils->SendEventPacket(0, 0);
    MEDIA_INFO_LOG("mtp_operation_utils_007::End");
}


/**
 * @tc.number    : mtp_medialibrary_manager_001
 * @tc.name      : mtp_medialibrary_manager_001
 * @tc.desc      :
 */
HWTEST_F(MtpNativeTest, mtp_medialibrary_manager_001, TestSize.Level0)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->format = MTP_FORMAT_TEXT_CODE;
    context->handle = 1;
    context->property = 1;
    string outStrVal;
    shared_ptr<vector<Property>> outProps;

    context->depth = 0;
    int32_t ret = MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    EXPECT_TRUE(ret == MTP_ERROR_INVALID_OBJECTHANDLE);
    context->handle = MTP_ALL_HANDLE_ID;
    ret = MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    EXPECT_TRUE(ret == MTP_ERROR_INVALID_OBJECTHANDLE);
    context->depth = 1;
    MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    context->handle = 1;
    ret = MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    EXPECT_TRUE(ret != E_SUCCESS);
    context->depth = 1000;
    ret = MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    EXPECT_TRUE(ret == MTP_ERROR_SPECIFICATION_BY_DEPTH_UNSUPPORTED);
    context->depth = MTP_ALL_DEPTH;
    context->handle = 0;
    ret = MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    EXPECT_TRUE(ret == MTP_ERROR_INVALID_OBJECTHANDLE);
    context->property = 0;
    context->groupCode = 0;
    ret = MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    EXPECT_TRUE(ret == MTP_ERROR_PARAMETER_NOT_SUPPORTED);
    context->groupCode = 1;
    ret = MtpMedialibraryManager::GetInstance()->GetObjectPropList(context, outProps);
    EXPECT_TRUE(ret == MTP_ERROR_SPECIFICATION_BY_GROUP_UNSUPPORTED);
    MEDIA_INFO_LOG("mtp_medialibrary_manager_001::End");
}
} // namespace Media
} // ohos