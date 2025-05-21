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
#include "mtp_unit_test.h"
#include "header_data.h"
#include "mtp_operation.h"
#include "media_mtp_utils.h"
#include "mtp_packet.h"
#include "mtp_manager.h"
#include "mtp_constants.h"
#include "mtp_service.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

const uint32_t MAX_SIZE = 200001;

void MtpUnitTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void MtpUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MtpUnitTest::SetUp() {}
void MtpUnitTest::TearDown(void) {}

/*
* Feature: MTP
* Function:
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Parser
*/
HWTEST_F(MtpUnitTest, medialibrary_MTP_testlevel_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);

    std::shared_ptr<HeaderData> headerData = std::make_shared<HeaderData>(context);
    ASSERT_NE(headerData, nullptr);

    vector<uint8_t> buffer = { 0x0C, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x10, 0x10, 0x00, 0x00, 0x00 };
    uint32_t readSize = 12;
    int res = headerData->Parser(buffer, readSize);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
* Feature: MTP
* Function:
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: ResetOperation
*/
HWTEST_F(MtpUnitTest, medialibrary_MTP_testlevel_002, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    mtpOperation->requestPacketPtr_ = nullptr;
    mtpOperation->dataPacketPtr_ = nullptr;
    mtpOperation->responsePacketPtr_ = nullptr;
    mtpOperation->mtpContextPtr_ = nullptr;
    mtpOperation->ResetOperation();

    shared_ptr<Storage> storage = nullptr;
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
    EXPECT_EQ(mtpOperation->responseCode_, MTP_OK_CODE);
}

/*
* Feature: MTP
* Function:
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Init
*/
HWTEST_F(MtpUnitTest, medialibrary_MTP_testlevel_003, TestSize.Level1)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpPacket> mtpPacket = std::make_shared<MtpPacket>(context);
    ASSERT_NE(mtpPacket, nullptr);
    std::shared_ptr<HeaderData> headerData = std::make_shared<HeaderData>(context);
    ASSERT_NE(headerData, nullptr);
    headerData->SetContainerType(DATA_CONTAINER_TYPE);
    mtpPacket->Init(headerData);

    mtpPacket->mtpDriver_ = std::make_shared<MtpDriver>();
    ASSERT_NE(mtpPacket->mtpDriver_, nullptr);

    mtpPacket->writeBuffer_.resize(MAX_SIZE);
    int32_t result;
    int res = mtpPacket->Write(result);
    EXPECT_EQ(res, MTP_SUCCESS);

    ASSERT_NE(mtpPacket->headerData_, nullptr);
    mtpPacket->headerData_->SetContainerType(EVENT_CONTAINER_TYPE);
    res = mtpPacket->Write(result);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
* Feature: MTP
* Function:
* SubFunction: NA
* FunctionPoints: NA
* EnvConditions: NA
* CaseDescription: Init
*/
HWTEST_F(MtpUnitTest, medialibrary_MTP_testlevel_004, TestSize.Level1)
{
    std::shared_ptr<MtpService> mtpService = std::make_shared<MtpService>();
    ASSERT_NE(mtpService, nullptr);

    mtpService->Init();
    EXPECT_NE(mtpService->monitorPtr_, nullptr);
}
} // namespace Media
} // namespace OHOS