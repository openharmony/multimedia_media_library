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

#include "analysis_data_manager.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;
using namespace std;
using namespace AnalysisData;

void MediaAnalysisCallbackStubTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("MediaAnalysisCallbackStubTest SetUpTestCase");
}

void MediaAnalysisCallbackStubTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("MediaAnalysisCallbackStubTest TearDownTestCase");
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

HWTEST_F(MediaAnalysisCallbackStubTest, GetInstance_SingletonTest, TestSize.Level1)
{
    // 用例说明：测试GetInstance单例功能；覆盖单例模式分支（触发条件：多次调用GetInstance）；验证返回同一实例
    auto& instance1 = AnalysisDataManager::GetInstance();
    auto& instance2 = AnalysisDataManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(MediaAnalysisCallbackStubTest, GetInstance_MultipleCalls, TestSize.Level1)
{
    // 用例说明：测试GetInstance多次调用功能；覆盖多次获取分支（触发条件：连续调用10次GetInstance）；验证所有调用返回同一实例
    auto& firstInstance = AnalysisDataManager::GetInstance();
    for (int i = 0; i < 10; i++) {
        auto& instance = AnalysisDataManager::GetInstance();
        EXPECT_EQ(&instance, &firstInstance);
    }
}

HWTEST_F(MediaAnalysisCallbackStubTest, GetInstance_ThreadSafety, TestSize.Level1)
{
    // 用例说明：测试GetInstance线程安全功能；覆盖多线程并发分支（触发条件：多线程同时调用GetInstance）；验证所有线程获取到同一实例
    auto& mainInstance = AnalysisDataManager::GetInstance();
    std::vector<std::thread> threads;
    std::vector<AnalysisDataManager*> instancePointers(10);
    
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([i, &instancePointers]() {
            auto& instance = AnalysisDataManager::GetInstance();
            instancePointers[i] = &instance;
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    for (auto ptr : instancePointers) {
        EXPECT_EQ(ptr, &mainInstance);
    }
}

HWTEST_F(MediaAnalysisCallbackStubTest, GetInstance_ReferenceStability, TestSize.Level1)
{
    // 用例说明：测试GetInstance引用稳定性功能；覆盖引用生命周期分支（触发条件：存储引用并多次调用）；验证引用保持有效
    auto& instance1 = AnalysisDataManager::GetInstance();
    auto* ptr1 = &instance1;
    
    auto& instance2 = AnalysisDataManager::GetInstance();
    auto* ptr2 = &instance2;
    
    EXPECT_EQ(ptr1, ptr2);
    EXPECT_EQ(&instance1, &instance2);
}
} // namespace Media
} // namespace OHOS