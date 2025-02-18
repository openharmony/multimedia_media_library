/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define MLOG_TAG "MediaAnalysisCallbackStubTest"

#include "media_analysis_callback_stub_test.h"

#include <thread>
#include "media_log.h"
#include "message_parcel.h"
#include "message_option.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;
using namespace std;

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void MediaAnalysisCallbackStubTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("MediaAnalysisCallbackStubTest SetUpTestCase");
}

void MediaAnalysisCallbackStubTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("MediaAnalysisCallbackStubTest TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MediaAnalysisCallbackStubTest::SetUp()
{
    MEDIA_INFO_LOG("MediaAnalysisCallbackStubTest SetUp");
    stub = new MediaAnalysisCallbackStub();
}

void MediaAnalysisCallbackStubTest::TearDown()
{
    MEDIA_INFO_LOG("MediaAnalysisCallbackStubTest TearDown");
    delete stub;
}

// Scenario1: Test when code is MediaAnalysisCallbackInterfaceCode::PORTRAIT_COVER_SELECTION_COMPLETED_CALLBACK
HWTEST_F(MediaAnalysisCallbackStubTest, OnRemoteRequest_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    uint32_t code =
        static_cast<uint32_t>(MediaAnalysisCallbackInterfaceCode::PORTRAIT_COVER_SELECTION_COMPLETED_CALLBACK);
    std::string albumId = "123";
    data.WriteInterfaceToken(MediaAnalysisCallbackStub::GetDescriptor());
    data.WriteString(albumId);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), ERR_NONE);
}

// Scenario2: Test when code is not MediaAnalysisCallbackInterfaceCode::PORTRAIT_COVER_SELECTION_COMPLETED_CALLBACK
HWTEST_F(MediaAnalysisCallbackStubTest, OnRemoteRequest_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    uint32_t code = 100;
    std::string albumId = "123";
    data.WriteInterfaceToken(MediaAnalysisCallbackStub::GetDescriptor());
    data.WriteString(albumId);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), IPC_STUB_UNKNOW_TRANS_ERR);
}

// Scenario3: Test when data.ReadInterfaceToken() is not GetDescriptor()
HWTEST_F(MediaAnalysisCallbackStubTest, OnRemoteRequest_003, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    uint32_t code =
        static_cast<uint32_t>(MediaAnalysisCallbackInterfaceCode::PORTRAIT_COVER_SELECTION_COMPLETED_CALLBACK);
    std::string albumId = "123";
    data.WriteInterfaceToken(u"wrong token");
    data.WriteString(albumId);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), ERR_UNKNOWN_TRANSACTION);
}

// Scenario4: Test when albumId is empty
HWTEST_F(MediaAnalysisCallbackStubTest, OnRemoteRequest_004, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    uint32_t code =
        static_cast<uint32_t>(MediaAnalysisCallbackInterfaceCode::PORTRAIT_COVER_SELECTION_COMPLETED_CALLBACK);
    std::string albumId = "";
    data.WriteInterfaceToken(MediaAnalysisCallbackStub::GetDescriptor());
    data.WriteString(albumId);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), ERR_INVALID_DATA);
}

// Scenario5: Test when albumId can not convert Int
HWTEST_F(MediaAnalysisCallbackStubTest, OnRemoteRequest_005, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    uint32_t code =
        static_cast<uint32_t>(MediaAnalysisCallbackInterfaceCode::PORTRAIT_COVER_SELECTION_COMPLETED_CALLBACK);
    std::string albumId = "testAlbumId";
    data.WriteInterfaceToken(MediaAnalysisCallbackStub::GetDescriptor());
    data.WriteString(albumId);
    EXPECT_EQ(stub->OnRemoteRequest(code, data, reply, option), ERR_INVALID_DATA);
}
} // namespace Media
} // namespace OHOS