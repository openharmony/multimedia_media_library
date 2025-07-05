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

#define MLOG_TAG "MediaBgTask_TaskRunnerTest"

#include "mediabgtaskmgr_task_runner_test.h"

#define private public
#include "task_runner.h"
#include "sa_ops_connection.h"
#include "sa_ops_connection_manager.h"
#undef private
#include "app_ops_connect_ability.h"
#include "media_bgtask_utils.h"
#include "media_bgtask_mgr_log.h"
#include "os_account_manager_wrapper.h"
#include "singleton.h"
#include "stub.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

static const int32_t E_OK = 0;
static const int32_t E_ERR = -1;
static const int32_t E_FAILED = 1;
static const int32_t E_SYNC_STUB = 2;

void MediaBgtaskMgrTaskRunnerTest::SetUpTestCase() {}

void MediaBgtaskMgrTaskRunnerTest::TearDownTestCase() {}

void MediaBgtaskMgrTaskRunnerTest::SetUp()
{
    SAOpsConnectionManager::GetInstance().connections_.clear();
}

void MediaBgtaskMgrTaskRunnerTest::TearDown() {}

static int32_t InitStubSuccess(SAOpsConnection* obj)
{
    return E_OK;
}

static int32_t InitStubFailed(SAOpsConnection* obj)
{
    return E_FAILED;
}

static int32_t TaskOpsSyncStub(SAOpsConnection* obj, const std::string& ops, const std::string& taskName,
                               const std::string extra)
{
    return E_SYNC_STUB;
}

static ErrCode QueryActiveOsAccountIdsStub(AppExecFwk::OsAccountManagerWrapper* obj, std::vector<int32_t>& ids)
{
    return ERR_OK;
}

static int32_t ConnectAbilityStub(AppOpsConnectAbility* obj, const AppSvcInfo &svcName, std::string ops,
                                  std::string taskName, std::string extra)
{
    if (taskName == "success") {
        return AppConnectionStatus::ALREADY_EXISTS;
    } else {
        return E_ERR;
    }
}

static int32_t AppTaskOpsSyncStub(AppOpsConnectAbility* obj, const AppSvcInfo &svcName,
                                  const std::string& ops, const std::string& taskName, const std::string extra)
{
    if (extra == "success") {
        return E_OK;
    } else {
        return E_ERR;
    }
}

/**
 * OpsSaTask
 */
HWTEST_F(MediaBgtaskMgrTaskRunnerTest, media_bgtask_mgr_OpsSaTask_test_001, TestSize.Level1)
{
    int32_t saId = 1;
    Stub stub;
    stub.set(ADDR(SAOpsConnection, Init), InitStubFailed);
    stub.set(ADDR(SAOpsConnection, TaskOpsSync), TaskOpsSyncStub);
    // saConnections unordered_map中存在对应的saID
    auto connection = std::make_shared<SAOpsConnection>(saId, [](const int32_t, SAOpsConnection::ConnectionStatus) {});
    SAOpsConnectionManager::GetInstance().connections_[saId] = connection;
    int result = TaskRunner::OpsSaTask(TaskOps::START, saId, "", "");
    EXPECT_TRUE(2 == result);

    // saConnections unordered_map中不存在对应的saID: 0,并且init成功
    result = TaskRunner::OpsSaTask(TaskOps::START, 0, "", "");
    EXPECT_TRUE(ERR_INVALID_DATA == result);

    // init失败
    stub.set(ADDR(SAOpsConnection, Init), InitStubSuccess);
    result = TaskRunner::OpsSaTask(TaskOps::START, 0, "", "");
    EXPECT_TRUE(2 == result);
}

/**
 * OpsAppTask
 */
HWTEST_F(MediaBgtaskMgrTaskRunnerTest, media_bgtask_mgr_OpsAppTask_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(AppExecFwk::OsAccountManagerWrapper, QueryActiveOsAccountIds), QueryActiveOsAccountIdsStub);
    stub.set(ADDR(AppOpsConnectAbility, ConnectAbility), ConnectAbilityStub);
    stub.set(ADDR(AppOpsConnectAbility, TaskOpsSync), AppTaskOpsSyncStub);

    AppSvcInfo svcName;
    int result = TaskRunner::OpsAppTask(TaskOps::START, svcName, "success", "success");
    EXPECT_EQ(E_OK, result);

    result = TaskRunner::OpsAppTask(TaskOps::START, svcName, "success", "");
    EXPECT_EQ(E_ERR, result);

    result = TaskRunner::OpsAppTask(TaskOps::START, svcName, "", "");
    EXPECT_EQ(E_ERR, result);
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS
