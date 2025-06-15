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

#include "mediabgtaskmgr_app_bgtask_schedule_stub_test.h"

#include "media_bgtask_mgr_log.h"
#include "stub.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

void MediaBgtaskMgrAppBgTaskScheduleStubTest::SetUpTestCase() {}

void MediaBgtaskMgrAppBgTaskScheduleStubTest::TearDownTestCase() {}

void MediaBgtaskMgrAppBgTaskScheduleStubTest::SetUp() {}

void MediaBgtaskMgrAppBgTaskScheduleStubTest::TearDown() {}

/**
 * OnRemoteRequest
 */
HWTEST_F(MediaBgtaskMgrAppBgTaskScheduleStubTest, media_bgtask_mgr_OnRemoteRequest_test_001, TestSize.Level1)
{
    AppBgTaskScheduleStubMock scheduleStub;
    // 1. 设置不同的描述符
    uint32_t code = 0;
    MessageParcel data = MessageParcel();
    MessageParcel reply = MessageParcel();
    MessageOption option = MessageOption();
    std::u16string descriptor = scheduleStub.GetDescriptor();
    std::u16string localDescriptor = descriptor + u"test";
    data.WriteInterfaceToken(localDescriptor);

    int32_t result = scheduleStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_TRANSACTION_FAILED);
}

HWTEST_F(MediaBgtaskMgrAppBgTaskScheduleStubTest, media_bgtask_mgr_OnRemoteRequest_test_002, TestSize.Level1)
{
    AppBgTaskScheduleStubMock scheduleStub;
    // 1. 设置相同的描述符
    MessageParcel data = MessageParcel();
    MessageParcel reply = MessageParcel();
    MessageOption option = MessageOption();
    std::u16string descriptor = scheduleStub.GetDescriptor();
    uint32_t code = 0;
    data.WriteInterfaceToken(descriptor);
    int32_t result = scheduleStub.OnRemoteRequest(code, data, reply, option);

    code = 1;
    data.WriteInterfaceToken(descriptor);
    result = scheduleStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);

    code = 2;
    data.WriteInterfaceToken(descriptor);
    result = scheduleStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}


/**
 * CmdReportTaskComplete
 */
static bool WriteInt32FailStub(MessageParcel *obj, int32_t value)
{
    return false;
}

static bool WriteInt32Stub(MessageParcel *obj, int32_t value)
{
    return value == 0;
}

/**
 * CmdReportTaskComplete & CmdModifyTask
 */
HWTEST_F(MediaBgtaskMgrAppBgTaskScheduleStubTest, media_bgtask_mgr_CmdReportTaskComplete_test_001, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInt32), WriteInt32FailStub);
    // 1. WriteInt32失败
    AppBgTaskScheduleStubMock scheduleStubMock;
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = scheduleStubMock.CmdReportTaskComplete(data, reply);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);

    ret = scheduleStubMock.CmdModifyTask(data, reply);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

HWTEST_F(MediaBgtaskMgrAppBgTaskScheduleStubTest, media_bgtask_mgr_CmdReportTaskComplete_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInt32), WriteInt32Stub);
    // 1. WriteInt32先成功后失败
    AppBgTaskScheduleStubMock scheduleStubMock;
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = scheduleStubMock.CmdReportTaskComplete(data, reply);
    EXPECT_EQ(ret, ERR_INVALID_DATA);

    ret = scheduleStubMock.CmdModifyTask(data, reply);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

