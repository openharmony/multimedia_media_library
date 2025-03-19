/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "mtp_event_test.h"
#include "mtp_event.h"
#include <numeric>
#include <unistd.h>
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_constants.h"
#include "mtp_packet.h"
#include "mtp_packet_tools.h"
#include "mtp_manager.h"
#include "mtp_media_library.h"
#include "mtp_operation_context.h"
using namespace std;
using namespace testing::ext;
 
namespace OHOS {
namespace Media {
// storage file
const std::string STORAGE_FILE = "/storage/media/local/files/Docs";
// file path
const std::string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
// file real path
const std::string REAL_FILE_PATH = "/storage/media/100/local/files/Docs/Desktop";
// storage real path
const std::string REAL_STORAGE_FILE = "/storage/media/100/local/files/Docs";
// document real path
const std::string REAL_DOCUMENT_FILE = "/storage/media/100/local/files/Docs/Document";

void MtpEventTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void MtpEventTest::TearDownTestCase(void) {}
void MtpEventTest::SetUp() {}
void MtpEventTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendObjectAdded
 */
HWTEST_F(MtpEventTest, mtp_event_test_001, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    mtpEvent->SendObjectAdded(" ");
    mtpEvent->SendObjectRemoved(" ");
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendObjectAdded
 */
HWTEST_F(MtpEventTest, mtp_event_test_002, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    mtpEvent->SendObjectAdded(FILE_PATH);
    mtpEvent->SendObjectRemoved(FILE_PATH);
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendObjectRemovedByHandle
 */
HWTEST_F(MtpEventTest, mtp_event_test_003, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    uint32_t handle = {0};
    mtpEvent->SendObjectRemovedByHandle(handle);
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendObjectInfoChanged
 */
HWTEST_F(MtpEventTest, mtp_event_test_004, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    mtpEvent->SendObjectInfoChanged(FILE_PATH);
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendObjectInfoChanged
 */
HWTEST_F(MtpEventTest, mtp_event_test_005, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    mtpEvent->SendObjectInfoChanged(" ");
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendDevicePropertyChanged
 */
HWTEST_F(MtpEventTest, mtp_event_test_006, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    mtpEvent->SendDevicePropertyChanged();
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendStoreAdded
 */
HWTEST_F(MtpEventTest, mtp_event_test_007, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    mtpEvent->SendStoreAdded(REAL_DOCUMENT_FILE);
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendStoreAdded
 */
HWTEST_F(MtpEventTest, mtp_event_test_008, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    mtpEvent->SendStoreRemoved(" ");
    mtpEvent->SendStoreAdded("ttyusb0");
    mtpEvent->SendStoreRemoved("ttyusb0");
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpEventTest, mtp_event_test_009, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    uint16_t testcode = 0x4007;
    mtpEvent->SendEvent(testcode);
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpEventTest, mtp_event_test_0010, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    uint16_t testcode = 0x4006;
    mtpEvent->SendEvent(testcode);
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpEventTest, mtp_event_test_0011, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    uint16_t testcode = 0x4005;
    mtpEvent->SendEvent(testcode);
    context = nullptr;
    mtpEvent = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: EventPayloadData
 */
HWTEST_F(MtpEventTest, mtp_event_test_0012, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    uint16_t code = 0;
    shared_ptr<PayloadData> data = nullptr;
    uint16_t res = mtpEvent->EventPayloadData(code, data);
    EXPECT_EQ(res, MTP_UNDEFINED_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: EventPayloadData
 */
HWTEST_F(MtpEventTest, mtp_event_test_0013, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    ASSERT_NE(mtpEvent, nullptr);
    mtpEvent->handleptr_ = make_shared<MtpOperationUtils>(context);
    uint16_t code = MTP_EVENT_UNDEFINED_CODE;
    shared_ptr<PayloadData> data = nullptr;
    uint16_t res = mtpEvent->EventPayloadData(code, data);
    EXPECT_EQ(res, MTP_UNDEFINED_CODE);
}
} // namespace Media
} // namespace OHOS