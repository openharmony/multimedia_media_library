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
#include "medialibrary_errno.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void MtpUnitTest::SetUpTestCase(void) {}

void MtpUnitTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

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
HWTEST_F(MtpUnitTest, medialibrary_MTP_testlevel_001, TestSize.Level0)
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
} // namespace Media
} // namespace OHOS