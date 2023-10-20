/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "medialibrary_mtp_unit_test.h"
#include <iomanip>
#include <unistd.h>
#include "mtp_driver.h"
#include "media_log.h"
#include "mtp_operation.h"
#include "mtp_service.h"
#include "mtp_test.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
// MTP_OPERATION_OPEN_SESSION_CODE
static std::vector<uint8_t> testData_open = { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00};

void MediaLibraryMTPUnitTest::SetUpTestCase(void) {}
void MediaLibraryMTPUnitTest::TearDownTestCase(void) {}
// SetUp:Execute before each test case
void MediaLibraryMTPUnitTest::SetUp() {}
void MediaLibraryMTPUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_001, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();
    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 0, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_DEVICE_INFO_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_002, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // MTP_OPERATION_GET_DEVICE_INFO_CODE
    static std::vector<uint8_t> testData = { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x10, 0x01, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();
    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 1, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_STORAGE_IDS_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_003, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData = { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();
    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 33, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_STORAGE_INFO_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_004, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();
    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();
    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData =  { 12, 0, 0, 0, 3, 0, 1, 32, 140, 7, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_HANDLES_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_005, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData_2 =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData_2);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_HANDLES_CODE
    static std::vector<uint8_t> testData = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x10, 0x23,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
	mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData =  { 12, 0, 0, 0, 3, 0, 1, 32, 35, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_DEVICE_PROP_DESC_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_006, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_DEVICE_PROP_DESC_CODE
    static std::vector<uint8_t> testData =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x10, 0x05, 0x00, 0x00, 0x00, 0x02, 0xD4, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 5, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_007, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE
    static std::vector<uint8_t> testData = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x98, 0x24, 0x00,
        0x00, 0x00, 0x02, 0xDC, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 36, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_PROPS_SUPPORTED_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_008, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_PROPS_SUPPORTED_CODE, MTP_FORMAT_EXIF_JPEG_CODE
    static std::vector<uint8_t> testData =
       { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x98, 0x20, 0x00, 0x00, 0x00, 0x01, 0x38, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData =  { 40, 0, 0, 0, 3, 0, 1, 32, 32, 0, 0, 0, 12, 0, 0, 0, 1, 220, 2, 220,
        3, 220, 4, 220, 7, 220, 9, 220, 11, 220, 65, 220, 68, 220, 224, 220, 78, 220, 72, 220 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_PROP_VALUE_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_009, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_PROP_VALUE_CODE
    static std::vector<uint8_t> testData = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x98, 0x40, 0x00, 0x00,
        0x00, 0x89, 0x00, 0x00, 0x00, 0x01, 0xDC, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 64, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_SET_OBJECT_PROP_VALUE_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_010, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData_2 =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData_2);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_HANDLES_CODE
    static std::vector<uint8_t> testData_3 = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x10, 0x23, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
    mtpTest->setOutBuffer(testData_3);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_SET_OBJECT_PROP_VALUE_CODE
    static std::vector<uint8_t> testData = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x98, 0xc3, 0x00, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x07, 0xdc, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 195, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_PROP_LIST_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_011, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_PROP_LIST_CODE
    static std::vector<uint8_t> testData =
        { 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x98, 0x40, 0x00, 0x00, 0x00, 0x89, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x02, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 64, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_SEND_OBJECT_INFO_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_012, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_SEND_OBJECT_INFO_CODE
    static std::vector<uint8_t> testData = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x10, 0xac, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 24, 0, 0, 0, 3, 0, 1, 32, 172, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_SEND_OBJECT_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_013, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_SEND_OBJECT_CODE
    static std::vector<uint8_t> testData = { 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0d, 0x10, 0xbc, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 188, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_INFO_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_014, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData_2 =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData_2);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_HANDLES_CODE
    static std::vector<uint8_t> testData_3 = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x10, 0x23, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
	mtpTest->setOutBuffer(testData_3);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_INFO_CODE
    static std::vector<uint8_t> testData =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x10, 0x5c, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();
	
    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 92, 1, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_015, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData_2 =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData_2);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_HANDLES_CODE
    static std::vector<uint8_t> testData_3 = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x10, 0x23, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
	mtpTest->setOutBuffer(testData_3);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_CODE
    static std::vector<uint8_t> testData =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09, 0x10, 0x5f, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 95, 1, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_THUMB_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_016, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData_2 =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData_2);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_HANDLES_CODE
    static std::vector<uint8_t> testData_3 = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x10, 0x23, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
	mtpTest->setOutBuffer(testData_3);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_THUMB_CODE
    static std::vector<uint8_t> testData =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0a, 0x10, 0x71, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 113, 1, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}


/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_DELETE_OBJECT_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_017, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData_2 =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData_2);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_HANDLES_CODE
    static std::vector<uint8_t> testData_3 = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x10, 0x23, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
	mtpTest->setOutBuffer(testData_3);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_DELETE_OBJECT_CODE
    static std::vector<uint8_t> testData = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x10, 0xc8, 0x00, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 200, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_SET_DEVICE_PROP_VALUE_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_018, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_SET_DEVICE_PROP_VALUE_CODE
    static std::vector<uint8_t> testData =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x16, 0x10, 0x9d, 0x00, 0x00, 0x00, 0x02, 0xd4, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 157, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_DEVICE_PROP_VALUE_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_019, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_DEVICE_PROP_VALUE_CODE
    static std::vector<uint8_t> testData =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x15, 0x10, 0x05, 0x00, 0x00, 0x00, 0x02, 0xD4, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 5, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_COPY_OBJECT_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_020, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData_2 =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData_2);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_HANDLES_CODE
    static std::vector<uint8_t> testData_3 = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x10, 0x23, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
    mtpTest->setOutBuffer(testData_3);
    // execute
    operationPtr_->Execute();

    static std::vector<uint8_t> testData = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x1a, 0x10, 0xb7, 0x00, 0x00};
    mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 29, 32, 0, 0, 0, 0};

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_MOVE_OBJECT_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_021, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData_1 =
        { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData_1);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_STORAGE_INFO_CODE
    static std::vector<uint8_t> testData_2 =
        { 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x10, 0x8C, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData_2);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_HANDLES_CODE
    static std::vector<uint8_t> testData_3 = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x10, 0x23, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
    mtpTest->setOutBuffer(testData_3);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_MOVE_OBJECT_CODE
    static std::vector<uint8_t> testData = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x19, 0x10, 0x8b, 0x00, 0x00,
        0x00, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 139, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function: 
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_SESSION_NOT_OPEN_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_023, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // MTP_OPERATION_GET_STORAGE_IDS_CODE
    static std::vector<uint8_t> testData = { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x10, 0x21, 0x00, 0x00, 0x00 };
    // set test data
    mtpTest->setOutBuffer(testData);
    // execute
    operationPtr_->Execute();
    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto && i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    // MTP_SESSION_NOT_OPEN_CODE
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 3, 32, 33, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_024, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE
    static std::vector<uint8_t> testData = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x98, 0x24, 0x00,
        0x00, 0x00, 0x09, 0xDC, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 }; // MTP_PROPERTY_DATE_MODIFIED_CODE
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 36, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);

    // MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE
    static std::vector<uint8_t> testData2 = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x98, 0x24, 0x00,
        0x00, 0x00, 0x92, 0xDE, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 }; // MTP_PROPERTY_BITRATE_TYPE_CODE
    mtpTest->setOutBuffer(testData2);
    operationPtr_->Execute();

    // get output
    output.clear();
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);

    // MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE
    static std::vector<uint8_t> testData3 = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x98, 0x24, 0x00,
        0x00, 0x00, 0x9A, 0xDE, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 }; // MTP_PROPERTY_AUDIO_BITRATE_CODE
    mtpTest->setOutBuffer(testData3);
    operationPtr_->Execute();

    // get output
    output.clear();
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);

    // MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE
    static std::vector<uint8_t> testData4 = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x98, 0x24, 0x00,
        0x00, 0x00, 0x94, 0xDE, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 }; // MTP_PROPERTY_NUMBER_OF_CHANNELS_CODE
    mtpTest->setOutBuffer(testData4);
    operationPtr_->Execute();

    // get output
    output.clear();
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);

    // MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE
    static std::vector<uint8_t> testData5 = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x98, 0x24, 0x00,
        0x00, 0x00, 0x93, 0xDE, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 }; // MTP_PROPERTY_SAMPLE_RATE_CODE
    mtpTest->setOutBuffer(testData5);
    operationPtr_->Execute();

    // get output
    output.clear();
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_GET_OBJECT_PROP_VALUE_CODE
 */
HWTEST_F(MediaLibraryMTPUnitTest, medialibrary_MTP_message_testlevel0_025, TestSize.Level0)
{
    std::shared_ptr<OHOS::Media::MtpTest> mtpTest = OHOS::Media::MtpTest::GetInstance();
    std::shared_ptr<MtpOperation> operationPtr_;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }

    // set test data
    mtpTest->setOutBuffer(testData_open);
    // execute
    operationPtr_->Execute();

    // MTP_OPERATION_GET_OBJECT_PROP_VALUE_CODE
    static std::vector<uint8_t> testData = { 0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x98, 0x40, 0x00, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData);
    operationPtr_->Execute();

    // get output
    std::vector<uint8_t> output;
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    std::vector<uint8_t> targetData = { 12, 0, 0, 0, 3, 0, 1, 32, 64, 0, 0, 0 };

    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);

    // MTP_OPERATION_GET_OBJECT_PROP_VALUE_CODE
    static std::vector<uint8_t> testData2 = { 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x98, 0x40, 0x00, 0x00,
        0x00, 0x89, 0x00, 0x00, 0x00, 0x07, 0xDC, 0x00, 0x00 };
    mtpTest->setOutBuffer(testData2);
    operationPtr_->Execute();

    // get output
    output.clear();
    mtpTest->getOutBuffer(output);
    for (auto&& i : output) {
        MEDIA_DEBUG_LOG("i: %{public}d", i);
    }
    MEDIA_DEBUG_LOG("MtpDriver::output.size: %{public}d", output.size());
    EXPECT_EQ(output == targetData, true);
}
} // namespace Media
} // namespace OHOS
