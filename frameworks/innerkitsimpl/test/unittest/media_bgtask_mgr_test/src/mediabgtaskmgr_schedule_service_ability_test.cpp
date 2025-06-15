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

#define MLOG_TAG "MediaBgtaskScheduleServiceAbilityTest"

#include "mediabgtaskmgr_schedule_service_ability_test.h"
#include "system_ability_definition.h"
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_schedule_service.h"
#include "media_bgtask_utils.h"
#include "task_runner.h"
#include "stub.h"

using namespace testing::ext;

#define MEDIA_TASK_SCHEDULE_SERVICE_ID 3016

namespace OHOS {
namespace MediaBgtaskSchedule {

static void InitStub(MediaBgtaskScheduleService *obj) {}

void MediaBgtaskMgrScheduleServiceAbilityTest::SetUpTestCase() {}

void MediaBgtaskMgrScheduleServiceAbilityTest::TearDownTestCase() {}

void MediaBgtaskMgrScheduleServiceAbilityTest::SetUp() {}

void MediaBgtaskMgrScheduleServiceAbilityTest::TearDown()
{
    MediaBgtaskScheduleService::GetInstance().ClearAllSchedule();
}

/**
 * OnStart
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_OnStart_test_001, TestSize.Level1)
{
    // 1. 测试当服务已注册时
    auto ability = std::make_unique<MediaBgtaskScheduleServiceAbility>(MEDIA_TASK_SCHEDULE_SERVICE_ID, false);
    ability->registerToService_ = true;
    SystemAbilityOnDemandReason reason;
    ability->OnStart(reason);
    EXPECT_TRUE(ability->registerToService_);
}

HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_OnStart_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, Init), InitStub);
    // 2. 测试当服务未注册时. Publish失败
    auto ability = new MediaBgtaskScheduleServiceAbilityMock(0, false);
    ability->registerToService_ = false;
    SystemAbilityOnDemandReason reason;
    ability->OnStart(reason);
    EXPECT_FALSE(ability->registerToService_);
}

/**
 * OnStop
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_OnStop_test_001, TestSize.Level1)
{
    auto ability = std::make_unique<MediaBgtaskScheduleServiceAbility>(MEDIA_TASK_SCHEDULE_SERVICE_ID, false);
    ability->registerToService_ = true;
    ability->OnStop();
    EXPECT_FALSE(ability->registerToService_);
}

/**
 * OnIdle & OnActive
 */
static void HandleSystemStateChangeStub(MediaBgtaskScheduleService *obj) {}

HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_OnIdle_test_001, TestSize.Level1)
{
    auto ability = new MediaBgtaskScheduleServiceAbilityMock(0, false);
    SystemAbilityOnDemandReason reason;
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, HandleSystemStateChange), HandleSystemStateChangeStub);
    ability->OnActive(reason);

    int32_t result = ability->OnIdle(reason);
    EXPECT_TRUE(result == 0);
}

/**
 * OnSvcCmd
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_OnSvcCmd_test_001, TestSize.Level1)
{
    auto ability = std::make_unique<MediaBgtaskScheduleServiceAbility>(MEDIA_TASK_SCHEDULE_SERVICE_ID, false);
    int32_t fd = 0;
    std::vector<std::u16string> args;
    int32_t result = ability->OnSvcCmd(fd, args);
    EXPECT_TRUE(result == 0);
}

/**
 * Dump
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_Dump_test_001, TestSize.Level1)
{
    auto ability = std::make_unique<MediaBgtaskScheduleServiceAbility>(MEDIA_TASK_SCHEDULE_SERVICE_ID, false);
    // 1. 测试当文件描述符无效时返回错误
    int32_t fd = -1;
    std::vector<std::u16string> args;
    int32_t ret = ability->Dump(fd, args);
    EXPECT_EQ(ret, OHOS::INVALID_OPERATION);

    // 2. 测试当没有参数时的处理
    fd = 1;
    ret = ability->Dump(fd, args);
    EXPECT_EQ(ret, OHOS::NO_ERROR);

    // 3. 测试当参数数量不为5时返回错误
    args = {u"-test", u"sa", u"start"};
    ret = ability->Dump(fd, args);
    EXPECT_EQ(ret, OHOS::NO_ERROR);
}

HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_Dump_test_002, TestSize.Level1)
{
    auto ability = std::make_unique<MediaBgtaskScheduleServiceAbility>(MEDIA_TASK_SCHEDULE_SERVICE_ID, false);
    // 4. 测试当args[1]参数无效时返回错误
    int32_t fd = 1;
    std::vector<std::u16string> args = {u"-test", u"invalid", u"start", u"123", u"task"};
    int32_t ret = ability->Dump(fd, args);
    EXPECT_EQ(ret, OHOS::NO_ERROR);

    // 5. 测试当args[2]参数无效时返回错误
    args = {u"-test", u"sa", u"", u"123", u"task"};
    ret = ability->Dump(fd, args);
    EXPECT_EQ(ret, OHOS::INVALID_OPERATION);

    args = {u"-test", u"app", u"", u"123", u"task"};
    ret = ability->Dump(fd, args);
    EXPECT_EQ(ret, OHOS::INVALID_OPERATION);

    args = {u"-test", u"sa", u"start", u"123", u"task"};
    ret = ability->Dump(fd, args);
    EXPECT_EQ(ret, OHOS::NO_ERROR);

    args = {u"-test", u"app", u"start", u"123", u"task"};
    ret = ability->Dump(fd, args);
    EXPECT_EQ(ret, OHOS::NO_ERROR);
}

/**
 * ReportTaskComplete
 */
static bool reportTaskCompleteStub(MediaBgtaskScheduleService *obj, const std::string &taskId, int32_t &funcResult)
{
    return true;
}

static bool modifyTaskStub(MediaBgtaskScheduleService *obj, const std::string &taskId, const std::string &modifyInfo,
    int32_t &funcResult)
{
    return true;
}

HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_ReportTaskComplete_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, reportTaskComplete), reportTaskCompleteStub);
    // success
    auto ability = std::make_unique<MediaBgtaskScheduleServiceAbility>(MEDIA_TASK_SCHEDULE_SERVICE_ID, false);
    int32_t funcResult = 0;
    ErrCode result = ability->ReportTaskComplete("", funcResult);
    EXPECT_TRUE(result == 0);
}

/**
 * ModifyTask
 */
HWTEST_F(MediaBgtaskMgrScheduleServiceAbilityTest, media_bgtask_mgr_ModifyTask_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MediaBgtaskScheduleService, modifyTask), modifyTaskStub);
    auto ability = std::make_unique<MediaBgtaskScheduleServiceAbility>(MEDIA_TASK_SCHEDULE_SERVICE_ID, false);
    int32_t funcResult = 0;
    ErrCode result = ability->ModifyTask("", "", funcResult);
    EXPECT_TRUE(result == 0);
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

