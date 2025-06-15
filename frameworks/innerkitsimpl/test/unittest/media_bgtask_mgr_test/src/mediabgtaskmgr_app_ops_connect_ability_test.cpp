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

#define MLOG_TAG "MediaBgTask_AppOpsConnectAbilityTest"

#include "mediabgtaskmgr_app_ops_connect_ability_test.h"
#define private public
#include "app_ops_connect_ability.h"
#undef private
#include "media_bgtask_mgr_log.h"
#include "stub.h"

static const int32_t ERR_OK = 0;
static const int32_t E_OK = 0;
static const int32_t E_ERR = -1;

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

void MediaBgtaskMgrAppOpsConnectAbilityTest::SetUpTestCase() {}

void MediaBgtaskMgrAppOpsConnectAbilityTest::TearDownTestCase() {}

void MediaBgtaskMgrAppOpsConnectAbilityTest::SetUp() {}

void MediaBgtaskMgrAppOpsConnectAbilityTest::TearDown()
{
    DelayedSingleton<AppOpsConnectAbility>::GetInstance()->appConnections_.clear();
}

/**
 * ConnectAbility
 */
HWTEST_F(MediaBgtaskMgrAppOpsConnectAbilityTest, media_bgtask_mgr_ConnectAbility_test_001, TestSize.Level1)
{
    auto inst = DelayedSingleton<AppOpsConnectAbility>::GetInstance();
    // 1. 测试当userId已存在时，ConnectAbility应返回ALREADY_EXISTS
    AppSvcInfo svcName;
    AppOpsConnection* conn = new AppOpsConnection(svcName, 1);
    inst->appConnections_[1] = conn;
    int32_t result = inst->ConnectAbility(svcName, 1, "", "", "");
    EXPECT_EQ(result, AppConnectionStatus::ALREADY_EXISTS);
}

static ErrCode ConnectAbilityFailedStub(const AAFwk::Want &want, sptr<AAFwk::IAbilityConnection> connect,
                                        int32_t userId)
{
    return E_ERR;
}

static ErrCode ConnectAbilitySuccessStub(const AAFwk::Want &want, sptr<AAFwk::IAbilityConnection> connect,
                                         int32_t userId)
{
    return E_OK;
}

HWTEST_F(MediaBgtaskMgrAppOpsConnectAbilityTest, media_bgtask_mgr_ConnectAbility_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set((ErrCode(AAFwk::AbilityManagerClient::*)(const AAFwk::Want &, sptr<AAFwk::IAbilityConnection>,
            int32_t))&AAFwk::AbilityManagerClient::ConnectAbility, ConnectAbilityFailedStub);

    auto inst = DelayedSingleton<AppOpsConnectAbility>::GetInstance();
    AppSvcInfo svcName;
    int32_t result = inst->ConnectAbility(svcName, 1, "", "", "");
    EXPECT_EQ(result, AppConnectionStatus::FAILED_TO_CONNECT);
}

static int32_t TaskOpsSyncStub(AppOpsConnection *obj, const std::string& ops,
                               const std::string& taskName, const std::string extra)
{
    return E_OK;
}

HWTEST_F(MediaBgtaskMgrAppOpsConnectAbilityTest, media_bgtask_mgr_ConnectAbility_test_003, TestSize.Level1)
{
    Stub stub;
    stub.set((ErrCode(AAFwk::AbilityManagerClient::*)(const AAFwk::Want &, sptr<AAFwk::IAbilityConnection>,
            int32_t))&AAFwk::AbilityManagerClient::ConnectAbility, ConnectAbilitySuccessStub);
    stub.set(ADDR(AppOpsConnection, TaskOpsSync), TaskOpsSyncStub);

    auto inst = DelayedSingleton<AppOpsConnectAbility>::GetInstance();
    AppSvcInfo svcName;
    int32_t result = inst->ConnectAbility(svcName, 1, "", "", "");
    EXPECT_EQ(result, E_OK);
}

/**
 * DisconnectAbility
 */
static ErrCode DisconnectAbilityStubSuccessStub(AAFwk::AbilityManagerClient *obj, sptr<AAFwk::IAbilityConnection> con)
{
    return E_OK;
}

static ErrCode DisconnectAbilityStubFailedStub(AAFwk::AbilityManagerClient *obj, sptr<AAFwk::IAbilityConnection> con)
{
    return E_ERR;
}

HWTEST_F(MediaBgtaskMgrAppOpsConnectAbilityTest, media_bgtask_mgr_DisconnectAbility_test_001, TestSize.Level1)
{
    auto inst = DelayedSingleton<AppOpsConnectAbility>::GetInstance();
    // 1. 测试当userId不存在时，DisconnectAbility应返回E_ERR
    int32_t result = inst->DisconnectAbility(1);
    EXPECT_EQ(result, E_ERR);

    // 2. DisconnectAbilityStubFailedStub
    Stub stub;
    stub.set(ADDR(AAFwk::AbilityManagerClient, DisconnectAbility), DisconnectAbilityStubFailedStub);
    AppSvcInfo svcName;
    AppOpsConnection* conn = new AppOpsConnection(svcName, 1);
    inst->appConnections_[1] = conn;
    result = inst->DisconnectAbility(1);
    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(MediaBgtaskMgrAppOpsConnectAbilityTest, media_bgtask_mgr_DisconnectAbility_test_002, TestSize.Level1)
{
    auto inst = DelayedSingleton<AppOpsConnectAbility>::GetInstance();

    // 3. DisconnectAbilityStubSuccessStub
    Stub stub;
    stub.set(ADDR(AAFwk::AbilityManagerClient, DisconnectAbility), DisconnectAbilityStubSuccessStub);
    AppSvcInfo svcName;
    AppOpsConnection* conn = new AppOpsConnection(svcName, 1);
    inst->appConnections_[1] = conn;
    int32_t result = inst->DisconnectAbility(1);
    EXPECT_EQ(result, E_OK);
}

/**
 * TaskOpsSync
 */
HWTEST_F(MediaBgtaskMgrAppOpsConnectAbilityTest, media_bgtask_mgr_TaskOpsSync_test_001, TestSize.Level1)
{
    auto inst = DelayedSingleton<AppOpsConnectAbility>::GetInstance();
    int32_t userId = 1;
    inst->appConnections_[userId] = nullptr;

    AppSvcInfo svcName;
    int32_t result = inst->TaskOpsSync(svcName, userId, "", "", "");
    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(MediaBgtaskMgrAppOpsConnectAbilityTest, media_bgtask_mgr_TaskOpsSync_test_002, TestSize.Level1)
{
    auto inst = DelayedSingleton<AppOpsConnectAbility>::GetInstance();
    int32_t userId = 1;
    AppSvcInfo svcInfo;
    inst->appConnections_[userId] = new AppOpsConnection(svcInfo, 1);

    Stub stub;
    stub.set(ADDR(AppOpsConnection, TaskOpsSync), TaskOpsSyncStub);

    AppSvcInfo svcName;
    int32_t result = inst->TaskOpsSync(svcName, userId, "", "", "");
    EXPECT_EQ(result, E_OK);
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

