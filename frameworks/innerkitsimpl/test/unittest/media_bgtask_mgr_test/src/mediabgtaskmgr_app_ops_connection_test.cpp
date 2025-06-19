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

#include "mediabgtaskmgr_app_ops_connection_test.h"

#include "media_bgtask_mgr_log.h"
#include "app_task_ops_proxy.h"
#include "stub.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

static const int32_t E_ERR = -1;
static const int32_t CONNECT_ABILITY_SUCCESS = 0;

void MediaBgtaskMgrAppOpsConnectionTest::SetUpTestCase() {}

void MediaBgtaskMgrAppOpsConnectionTest::TearDownTestCase() {}

void MediaBgtaskMgrAppOpsConnectionTest::SetUp() {}

void MediaBgtaskMgrAppOpsConnectionTest::TearDown() {}

/**
 * OnAbilityConnectDone
 */
HWTEST_F(MediaBgtaskMgrAppOpsConnectionTest, media_bgtask_mgr_OnAbilityConnectDone_test_001, TestSize.Level1)
{
    AppSvcInfo svcInfo;
    AppOpsConnection connection_(svcInfo, 0);
    // 1. 测试当resultCode不等于CONNECT_ABILITY_SUCCESS时，函数直接返回
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject;

    connection_.OnAbilityConnectDone(element, remoteObject, E_ERR);
    EXPECT_EQ(connection_.remoteObject_, nullptr);
    EXPECT_EQ(connection_.proxy_, nullptr);
}

HWTEST_F(MediaBgtaskMgrAppOpsConnectionTest, media_bgtask_mgr_OnAbilityConnectDone_test_002, TestSize.Level1)
{
    AppSvcInfo svcInfo;
    AppOpsConnection connection_(svcInfo, 0);
    // 2. 测试当resultCode等于CONNECT_ABILITY_SUCCESS时，正确设置remoteObject和proxy
    std::u16string descriptor;
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject(descriptor);
    AppExecFwk::ElementName element;
    connection_.OnAbilityConnectDone(element, remoteObject, CONNECT_ABILITY_SUCCESS);
    EXPECT_NE(connection_.proxy_, nullptr);
}

HWTEST_F(MediaBgtaskMgrAppOpsConnectionTest, media_bgtask_mgr_OnAbilityConnectDone_test_003, TestSize.Level1)
{
    AppSvcInfo svcInfo;
    AppOpsConnection connection_(svcInfo, 0);
    // 3. 测试当resultCode等于CONNECT_ABILITY_SUCCESS时，正确设置callback
    std::u16string descriptor;
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject(descriptor);
    AppExecFwk::ElementName element;
    connection_.AddConnectedCallback([]() {});
    connection_.OnAbilityConnectDone(element, remoteObject, CONNECT_ABILITY_SUCCESS);
    EXPECT_NE(connection_.proxy_, nullptr);
}

/**
 * OnAbilityDisconnectDone
 */
HWTEST_F(MediaBgtaskMgrAppOpsConnectionTest, media_bgtask_mgr_OnAbilityDisconnectDone_test_001, TestSize.Level1)
{
    AppSvcInfo svcInfo;
    AppOpsConnection connection_(svcInfo, 0);
    AppExecFwk::ElementName element;
    connection_.OnAbilityDisconnectDone(element, 0);
    EXPECT_EQ(connection_.proxy_, nullptr);
}

/**
 * TaskOpsSync
 */
HWTEST_F(MediaBgtaskMgrAppOpsConnectionTest, media_bgtask_mgr_TaskOpsSync_test_001, TestSize.Level1)
{
    auto mock = new MockAppTaskOpsProxy(nullptr);
    EXPECT_CALL(*mock, DoTaskOps(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));

    AppSvcInfo svcInfo;
    AppOpsConnection connection_(svcInfo, 0);
    connection_.proxy_ = mock;
    int32_t result = connection_.TaskOpsSync("", "", "");
    EXPECT_EQ(result, 0);
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

