/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "mtp_packet_tools.h"
#include "mtp_packet_tools_test.h"
#include "mtp_packet.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "media_log.h"
#include "parameters.h"
#include "mtp_service.h"
#include "mtp_manager.h"
#include "common_event_subscriber.h"
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MtpPacketToolsTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void MtpPacketToolsTest::TearDownTestCase(void) {}
void MtpPacketToolsTest::SetUp() {}
void MtpPacketToolsTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Put UInt/Int
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_001, TestSize.Level1)
{
    std::vector<uint8_t> outBuffer;
    uint64_t testValue = 0x123456789ABCDEF0;
    int64_t testValue_2 = 0x123456789ABCDEF0;
    MtpPacketTool::PutUInt128(outBuffer, testValue);
    EXPECT_EQ(outBuffer.size(), 16);
    MtpPacketTool::PutInt128(outBuffer, testValue_2);
    EXPECT_EQ(outBuffer.size(), 32);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get UInt/Int
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_002, TestSize.Level1)
{
    std::vector<uint8_t> buffer = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10
    };
    size_t offset = 0;
    uint128_t testValue;
    int128_t testValue_2;
    bool result1 = MtpPacketTool::GetUInt128(buffer, offset, testValue);
    offset = 0;
    bool result2 = MtpPacketTool::GetInt128(buffer, offset, testValue_2);
    EXPECT_TRUE(result1);
    EXPECT_TRUE(result2);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAUInt16
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_003, TestSize.Level1)
{
    std::vector<uint8_t> buffer = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10
    };
    size_t offset = 0;
    std::shared_ptr<UInt16List> result = MtpPacketTool::GetAUInt16(buffer, offset);
    EXPECT_NE(result, nullptr);
    result = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAUInt16
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_004, TestSize.Level1)
{
    std::vector<uint8_t> buffer = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08
    };
    size_t offset = 0;
    std::shared_ptr<UInt16List> result = MtpPacketTool::GetAUInt16(buffer, offset);
    ASSERT_NE(result, nullptr);
    result = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get*Name
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_005, TestSize.Level1)
{
    uint16_t testValue = 0x0001;
    int testValue_2 = 0x0002;
    string result = " ";
    result = MtpPacketTool::GetFormatName(testValue);
    result = MtpPacketTool::GetObjectPropName(testValue);
    result = MtpPacketTool::GetDataTypeName(testValue_2);
    result = MtpPacketTool::GetEventName(testValue);
    result = MtpPacketTool::GetAssociationName(testValue_2);
    EXPECT_NE(result, "");
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Int/UINT*ToString
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_006, TestSize.Level1)
{
    int8_t testValue = 1;
    uint8_t testValue_2 = 2;
    int16_t testValue_3 = 1;
    uint16_t testValue_4 = 2;
    int32_t testValue_5 = 1;
    uint32_t testValue_6 = 2;
    int64_t testValue_7 = 1;
    uint64_t testValue_8 = 2;
    int128_t testValue_9 = { 1, 2, 3, 4 };
    uint128_t testValue_10 = { 1, 2, 3, 4 };
    string outstr = "";
    EXPECT_EQ(MtpPacketTool::Int8ToString(testValue, outstr), true);
    EXPECT_EQ(MtpPacketTool::UInt8ToString(testValue_2, outstr), true);
    EXPECT_EQ(MtpPacketTool::Int16ToString(testValue_3, outstr), true);
    EXPECT_EQ(MtpPacketTool::UInt16ToString(testValue_4, outstr), true);
    EXPECT_EQ(MtpPacketTool::Int32ToString(testValue_5, outstr), true);
    EXPECT_EQ(MtpPacketTool::UInt32ToString(testValue_6, outstr), true);
    EXPECT_EQ(MtpPacketTool::Int64ToString(testValue_7, outstr), true);
    EXPECT_EQ(MtpPacketTool::UInt64ToString(testValue_8, outstr), true);
    EXPECT_EQ(MtpPacketTool::Int128ToString(testValue_9, outstr), true);
    EXPECT_EQ(MtpPacketTool::UInt128ToString(testValue_10, outstr), true);
    outstr = MtpPacketTool::StrToString(outstr);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIndentBlank&&DumpPacket
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_007, TestSize.Level1)
{
    OHOS::system::SetParameter("multimedia.medialibrary.mtp_show_dump", "false");
    std::vector<uint8_t> outbuffer = {
    0x01, 0x02, 0x03, 0x04,
    0x02, 0x00, 0x07, 0x08
    };
    MtpPacketTool::CanDump();
    EXPECT_NE(MtpPacketTool::GetIndentBlank(), "");
    MtpPacketTool::DumpPacket(outbuffer);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIndentBlank&&DumpPacket
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_008, TestSize.Level1)
{
    OHOS::system::SetParameter("multimedia.medialibrary.mtp_show_dump", "true");
    std::vector<uint8_t> outbuffer = {
    0x01, 0x02, 0x03, 0x04,
    0x00, 0x00, 0x07, 0x08
    };
    EXPECT_NE(MtpPacketTool::GetIndentBlank(), "");
    MtpPacketTool::CanDump();
    MtpPacketTool::DumpPacket(outbuffer);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIndentBlank&&DumpPacket
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_009, TestSize.Level1)
{
    OHOS::system::SetParameter("multimedia.medialibrary.mtp_show_dump", "true");
    std::vector<uint8_t> outbuffer = {
    0x01, 0x02, 0x03, 0x04,
    0x02, 0x00, 0x07, 0x08
    };
    MtpPacketTool::GetIndentBlank();
    EXPECT_FALSE(MtpPacketTool::CanDump());
    MtpPacketTool::DumpPacket(outbuffer);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Utf8ToUtf16
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_010, TestSize.Level1)
{
    std::string inputStr = "\xFF";
    auto res = MtpPacketTool::Utf8ToUtf16(inputStr);
    EXPECT_TRUE(res.empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Utf16ToUtf8
 */
HWTEST_F(MtpPacketToolsTest, mtp_packet_tools_test_1_011, TestSize.Level1)
{
    std::u16string inputStr = u"\xD800";
    auto res = MtpPacketTool::Utf16ToUtf8(inputStr);
    EXPECT_TRUE(res.empty());
}
} // namespace Media
} // namespace OHOS