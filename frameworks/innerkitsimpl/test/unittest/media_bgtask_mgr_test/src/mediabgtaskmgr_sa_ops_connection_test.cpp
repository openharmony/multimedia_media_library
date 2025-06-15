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

#define MLOG_TAG "MediaBgTask_TaskInfoMgrTest"

#include "mediabgtaskmgr_sa_ops_connection_test.h"
#define private public
#include "sa_ops_connection.h"
#undef private
#include <vector>
#include "media_bgtask_mgr_log.h"
#include "stub.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

void MediaBgtaskMgrSaOpsConnectionTest::SetUpTestCase() {}

void MediaBgtaskMgrSaOpsConnectionTest::TearDownTestCase() {}

void MediaBgtaskMgrSaOpsConnectionTest::SetUp() {}

void MediaBgtaskMgrSaOpsConnectionTest::TearDown() {}

/**
 * Init
 */
static sptr<ISystemAbilityManager> GetSystemAbilityManagerFailedStub(SystemAbilityManagerClient *obj)
{
    return nullptr;
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_Init_test_001, TestSize.Level1)
{
    // 1. 测试当系统能力管理器有效时，Init函数应返回ERR_OK
    int32_t testSaId = 0;
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(testSaId, callback);

    Stub stub;
    stub.set(ADDR(SystemAbilityManagerClient, GetSystemAbilityManager), GetSystemAbilityManagerFailedStub);
    int32_t result = connection.Init();
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * InputParaSet
 */
bool WriteStringStub(const std::string &value) { return true; }

bool WriteStringFailStub(const std::string &value) { return false; }

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_InputParaSet_test_001, TestSize
.Level1) {
    int32_t testSaId = 0;
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(testSaId, callback);

    Stub stub;
    stub.set(ADDR(MessageParcel, WriteString), WriteStringFailStub);
    MessageParcel data;
    bool result = connection.InputParaSet(data);
    EXPECT_EQ(result, false);
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_InputParaSet_test_002, TestSize.Level1)
{
    int32_t testSaId = 0;
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(testSaId, callback);

    Stub stub;
    stub.set(ADDR(MessageParcel, WriteString), WriteStringStub);
    MessageParcel data;
    bool result = connection.InputParaSet(data);
    EXPECT_EQ(result, true);
}

/**
 * OutputParaGet
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_OutputParaGet_test_001, TestSize.Level1)
{
    int32_t testSaId = 0;
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(testSaId, callback);
    MessageParcel reply;
    bool result = connection.OutputParaGet(reply);
    EXPECT_EQ(result, true);
}

/**
 * LoadSAExtension
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_LoadSAExtension_test_001, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    // 1. 测试当已经连接时，LoadSAExtension函数应返回ERR_OK
    connection.isConnected_.store(true);
    connection.IsSAConnected();
    int32_t result = connection.LoadSAExtension();
    EXPECT_EQ(result, ERR_OK);
}

static int32_t GetSAExtensionProxySuccessStub(SAOpsConnection *obj, bool isSync)
{
    return ERR_OK;
}

static int32_t GetSAExtensionProxyFailedStub(SAOpsConnection *obj, bool isSync)
{
    return -1;
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_LoadSAExtension_test_002, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isConnected_.store(false);

    Stub stub;
    stub.set(ADDR(SAOpsConnection, GetSAExtensionProxy), GetSAExtensionProxySuccessStub);

    // 2. 测试当获取SA扩展代理成功时，LoadSAExtension函数应返回ERR_OK
    int32_t result = connection.LoadSAExtension();
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_LoadSAExtension_test_003, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isConnected_.store(false);

    Stub stub;
    stub.set(ADDR(SAOpsConnection, GetSAExtensionProxy), GetSAExtensionProxyFailedStub);
    stub.set(ADDR(SystemAbilityManagerClient, GetSystemAbilityManager), GetSystemAbilityManagerFailedStub);

    // 2. 测试当获取SA扩展代理成功时，LoadSAExtension函数应返回ERR_OK
    int32_t result = connection.LoadSAExtension();
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * LoadSAExtensionSync
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_LoadSAExtensionSync_test_001, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    // 1. 测试当已经连接时，LoadSAExtensionSync函数应返回ERR_OK
    connection.isConnected_.store(true);
    int32_t result = connection.LoadSAExtensionSync();
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_LoadSAExtensionSync_test_002, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isConnected_.store(false);

    Stub stub;
    stub.set(ADDR(SAOpsConnection, GetSAExtensionProxy), GetSAExtensionProxySuccessStub);

    // 2. 测试当获取SA扩展代理成功时，LoadSAExtensionSync函数应返回ERR_OK
    int32_t result = connection.LoadSAExtensionSync();
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_LoadSAExtensionSync_test_003, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isConnected_.store(false);

    Stub stub;
    stub.set(ADDR(SAOpsConnection, GetSAExtensionProxy), GetSAExtensionProxyFailedStub);
    stub.set(ADDR(SystemAbilityManagerClient, GetSystemAbilityManager), GetSystemAbilityManagerFailedStub);

    // 2. 测试当获取SA扩展代理成功时，LoadSAExtensionSync函数应返回ERR_OK
    int32_t result = connection.LoadSAExtensionSync();
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * CallOps
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_CallOps_test_001, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.extensionProxy_ = nullptr;
    int32_t result = connection.CallOps("", "", "");
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * TaskOpsSync
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_TaskOpsSync_test_001, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isConnected_.store(true);
    connection.extensionProxy_ = nullptr;
    int32_t result = connection.TaskOpsSync("", "", "");
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_TaskOpsSync_test_002, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isConnected_.store(false);
    connection.extensionProxy_ = nullptr;
    Stub stub;
    stub.set(ADDR(SAOpsConnection, GetSAExtensionProxy), GetSAExtensionProxyFailedStub);
    int32_t result = connection.TaskOpsSync("", "", "");
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_TaskOpsSync_test_003, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isConnected_.store(false);
    connection.extensionProxy_ = nullptr;
    Stub stub;
    stub.set(ADDR(SAOpsConnection, GetSAExtensionProxy), GetSAExtensionProxySuccessStub);
    int32_t result = connection.TaskOpsSync("", "", "");
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * GetSAExtensionProxy
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_GetSAExtensionProxy_test_001, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);

    Stub stub;
    stub.set(ADDR(SystemAbilityManagerClient, GetSystemAbilityManager), GetSystemAbilityManagerFailedStub);

    int32_t result = connection.GetSAExtensionProxy(true);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * OnSystemAbilityRemove
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_OnSystemAbilityRemove_test_001, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isLoaded_.store(true);

    connection.OnSystemAbilityRemove(1, "");
    EXPECT_TRUE(connection.isLoaded_.load());
}

HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_OnSystemAbilityRemove_test_002, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isLoaded_.store(true);

    connection.OnSystemAbilityRemove(0, "");
    EXPECT_FALSE(connection.IsSALoaded());
}

/**
 * OnSystemAbilityLoadSuccess
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_OnSystemAbilityLoadSuccess_test_001, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);

    connection.OnSystemAbilityLoadSuccess(1, nullptr);
    connection.OnSystemAbilityLoadSuccess(0, nullptr);
}

/**
 * OnSystemAbilityLoadFail
 */
HWTEST_F(MediaBgtaskMgrSaOpsConnectionTest, media_bgtask_mgr_OnSystemAbilityLoadFail_test_001, TestSize.Level1)
{
    auto callback = [](const int32_t, SAOpsConnection::ConnectionStatus) {};
    SAOpsConnection connection(0, callback);
    connection.isLoaded_.store(true);

    connection.OnSystemAbilityLoadFail(1);
    EXPECT_TRUE(connection.isLoaded_.load());

    connection.OnSystemAbilityLoadFail(0);
    EXPECT_FALSE(connection.isLoaded_.load());
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

