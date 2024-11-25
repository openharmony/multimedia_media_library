/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "mtp_operation_utils_unit_test.h"
#include "mtp_operation_utils.h"
#include "medialibrary_errno.h"
#include "payload_data.h"
#include "mtp_constants.h"
#include "media_mtp_utils.h"
#include "mtp_manager.h"
#include "mtp_driver.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MtpOperationUtilsUnitTest::SetUpTestCase(void) {}
void MtpOperationUtilsUnitTest::TearDownTestCase(void) {}
void MtpOperationUtilsUnitTest::SetUp() {}
void MtpOperationUtilsUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetNumObjects
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_001, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t res = mtpOperationUtils->GetNumObjects(data);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetNumObjects
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_002, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->storageID = MTP_STORAGE_ID_ALL;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t res = mtpOperationUtils->GetNumObjects(data);
    EXPECT_EQ(res, MTP_INVALID_STORAGEID_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HasStorage
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_003, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    int errcode = 0;
    mtpOperationUtils->HasStorage(errcode);
    EXPECT_EQ(errcode, MTP_ERROR_CONTEXT_IS_NULL);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HasStorage
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_004, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->sessionOpen = false;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    int errcode = 0;
    mtpOperationUtils->HasStorage(errcode);
    EXPECT_EQ(errcode, MTP_ERROR_SESSION_NOT_OPEN);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HasStorage
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_005, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->sessionOpen = true;
    context->storageID = MTP_STORAGE_ID_ALL;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    int errcode = 0;
    mtpOperationUtils->HasStorage(errcode);
    EXPECT_EQ(errcode, MTP_ERROR_INVALID_STORAGE_ID);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropDesc
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_006, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    int errcode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    uint16_t res = mtpOperationUtils->GetObjectPropDesc(data, containerType, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropValue
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_007, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    int errcode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    uint16_t res = mtpOperationUtils->GetObjectPropValue(data, containerType, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DoSetObjectPropValue
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_008, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    int errcode = 0;
    mtpOperationUtils->DoSetObjectPropValue(errcode);
    EXPECT_EQ(errcode, MTP_ERROR_CONTEXT_IS_NULL);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DoSetObjectPropValue
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_009, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
    int errcode = 0;
    mtpOperationUtils->DoSetObjectPropValue(errcode);
    EXPECT_EQ(errcode, MTP_ERROR_INVALID_OBJECTPROP_VALUE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropList
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_010, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    int errcode = 0;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    uint16_t res = mtpOperationUtils->GetObjectPropList(data, containerType, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetObjectReferences
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_011, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t res = mtpOperationUtils->SetObjectReferences(data);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: RecevieSendObject
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_012, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    MtpFileRange object;
    int fd = 1;
    int32_t errcode = mtpOperationUtils->RecevieSendObject(object, fd);
    EXPECT_EQ(errcode, MTP_INVALID_PARAMETER_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: RecevieSendObject
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_013, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->mtpDriver = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    MtpFileRange object;
    int fd = 1;
    int32_t errcode = mtpOperationUtils->RecevieSendObject(object, fd);
    EXPECT_EQ(errcode, MTP_INVALID_PARAMETER_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: RecevieSendObject PreDealFd
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_014, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->mtpDriver = std::make_shared<MtpDriver>();
    ASSERT_NE(context->mtpDriver, nullptr);
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    MtpFileRange object;
    int fd = 1;
    int32_t errcode = mtpOperationUtils->RecevieSendObject(object, fd);
    bool deal = false;
    mtpOperationUtils->PreDealFd(deal, fd);
    EXPECT_EQ(errcode, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: PreDealFd
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_015, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->mtpDriver = std::make_shared<MtpDriver>();
    ASSERT_NE(context->mtpDriver, nullptr);
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    MtpFileRange object;
    int fd = 0;
    int32_t errcode = mtpOperationUtils->RecevieSendObject(object, fd);
    bool deal = true;
    mtpOperationUtils->PreDealFd(deal, fd);
    EXPECT_EQ(errcode, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: PreDealFd
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_016, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->mtpDriver = std::make_shared<MtpDriver>();
    ASSERT_NE(context->mtpDriver, nullptr);
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    MtpFileRange object;
    int fd = 1;
    int32_t errcode = mtpOperationUtils->RecevieSendObject(object, fd);
    bool deal = true;
    mtpOperationUtils->PreDealFd(deal, fd);
    EXPECT_EQ(errcode, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendObjectInfo
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_017, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    int32_t errcode = 0;
    uint16_t res = mtpOperationUtils->SendObjectInfo(data, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPartialObject
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_018, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t res = mtpOperationUtils->GetPartialObject(data);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropsSupported
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_019, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t res = mtpOperationUtils->GetObjectPropsSupported(data);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DeleteObject
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_020, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    int errcode = 0;
    uint16_t res = mtpOperationUtils->DeleteObject(data, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveObject
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_021, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    int errcode = 0;
    uint16_t res = mtpOperationUtils->MoveObject(data, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CopyObject
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_022, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    int errcode = 0;
    uint16_t res = mtpOperationUtils->CopyObject(data, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorageIDs
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_023, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    int errcode = 0;
    uint16_t res = mtpOperationUtils->GetStorageIDs(data, containerType, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorageIDs
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_024, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->sessionOpen = false;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    int errcode = 0;
    uint16_t res = mtpOperationUtils->GetStorageIDs(data, containerType, errcode);
    EXPECT_EQ(res, MTP_SESSION_NOT_OPEN_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorageIDs
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_025, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->sessionOpen = true;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    int errcode = 0;
    uint16_t res = mtpOperationUtils->GetStorageIDs(data, containerType, errcode);
    EXPECT_EQ(res, MTP_OK_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorageInfo
 */
HWTEST_F(MtpOperationUtilsUnitTest, medialibrary_MTP_message_testlevel_0_026, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->sessionOpen = false;
    std::shared_ptr<MtpOperationUtils> mtpOperationUtils = std::make_shared<MtpOperationUtils>(context);
    ASSERT_NE(mtpOperationUtils, nullptr);
    std::shared_ptr<PayloadData> data = nullptr;
    uint16_t containerType = DATA_CONTAINER_TYPE;
    int errcode = 0;
    uint16_t res = mtpOperationUtils->GetStorageInfo(data, containerType, errcode);
    EXPECT_EQ(res, MTP_SESSION_NOT_OPEN_CODE);
}
} // namespace Media
} // namespace OHOS