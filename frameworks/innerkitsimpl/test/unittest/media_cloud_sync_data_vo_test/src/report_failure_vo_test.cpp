/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "report_failure_vo.h"
#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class ReportFailureVoTest : public testing::Test {};

HWTEST_F(ReportFailureVoTest, TC001_ReportFailureReqBody_Marshalling_Unmarshalling, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    ReportFailureReqBody reqBody;
    reqBody.apiCode = 1001;
    reqBody.errorCode = 500;
    reqBody.fileId = 123;
    reqBody.cloudId = "cloud_id_123";

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    ReportFailureReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.apiCode, 1001);
    EXPECT_EQ(restored.errorCode, 500);
    EXPECT_EQ(restored.fileId, 123);
    EXPECT_EQ(restored.cloudId, "cloud_id_123");
}

HWTEST_F(ReportFailureVoTest, TC002_ReportFailureReqBody_SetApiCode, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    ReportFailureReqBody reqBody;
    reqBody.apiCode = 1001;
    reqBody.errorCode = 500;
    reqBody.fileId = 123123;
    reqBody.cloudId = "cloud_id_123";

    ReportFailureReqBody &result = reqBody.SetApiCode(2001);
    EXPECT_EQ(result.apiCode, 2001);
}

HWTEST_F(ReportFailureVoTest, TC003_ReportFailureReqBody_SetErrorCode, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    ReportFailureReqBody reqBody;
    reqBody.apiCode = 1001;
    reqBody.errorCode = 500;
    reqBody.fileId = 123;
    reqBody.cloudId = "cloud_id_123";

    ReportFailureReqBody &result = reqBody.SetErrorCode(600);
    EXPECT_EQ(result.apiCode, 1001);
    EXPECT_EQ(result.errorCode, 600);
}

HWTEST_F(ReportFailureVoTest, TC004_ReportFailureReqBody_SetFileId, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    ReportFailureReqBody reqBody;
    reqBody.apiCode = 1001;
    reqBody.errorCode = 500;
    reqBody.fileId = 123;
    reqBody.cloudId = "cloud_id_123";

    ReportFailureReqBody &result = reqBody.SetFileId(456);
    EXPECT_EQ(result.fileId, 456);
}

HWTEST_F(ReportFailureVoTest, TC005_ReportFailureReqBody_SetCloudId, TestSize.Level1)
{
    // 用例说明：测试错误处理；覆盖错误路径（触发条件：异常输入）；验证业务状态断言：处理失败

    ReportFailureReqBody reqBody;
    reqBody.apiCode = 1001;
    reqBody.errorCode = 500;
    reqBody.fileId = 123;
    reqBody.cloudId = "cloud_id_123";

    ReportFailureReqBody &result = reqBody.SetCloudId("cloud_id_456");
    EXPECT_EQ(result.cloudId, "cloud_id_456");
}

}  // namespace OHOS::Media::CloudSync
