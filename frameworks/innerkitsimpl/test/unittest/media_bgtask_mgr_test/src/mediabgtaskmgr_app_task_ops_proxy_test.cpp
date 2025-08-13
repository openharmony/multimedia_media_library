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

#define MLOG_TAG "MediaBgTask_AppTaskOpsProxyTest"

#include "mediabgtaskmgr_app_task_ops_proxy_test.h"
#include "mediabgtaskmgr_app_ops_connection_test.h"

#define private public
#include "app_task_ops_proxy.h"
#undef private

#include "media_bgtask_mgr_log.h"
#include "stub.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

void MediaBgtaskMgrAppTaskOpsProxyTest::SetUpTestCase() {}

void MediaBgtaskMgrAppTaskOpsProxyTest::TearDownTestCase() {}

void MediaBgtaskMgrAppTaskOpsProxyTest::SetUp() {}

void MediaBgtaskMgrAppTaskOpsProxyTest::TearDown() {}

/**
 * DoTaskOps
 */
static bool WriteInterfaceTokenSuccessStub(MessageParcel *obj, std::u16string name)
{
    return true;
}

static bool WriteInterfaceTokenFailStub(MessageParcel *obj, std::u16string name)
{
    return false;
}

static ErrCode ReadInt32Stub(MessageParcel *obj)
{
    return 0;
}

static ErrCode ReadInt32FailStub(MessageParcel *obj)
{
    return -1;
}

static bool WriteString16Stub(MessageParcel *obj, const std::u16string &value)
{
    std::string opsSucc = "ops_succ";
    std::string taskNameSucc = "name_succ";
    std::string extraSucc = "extra_succ";
    if (value == Str8ToStr16(opsSucc) || value == Str8ToStr16(taskNameSucc) || value == Str8ToStr16(extraSucc)) {
        return true;
    }
    return false;
}

HWTEST_F(MediaBgtaskMgrAppTaskOpsProxyTest, media_bgtask_mgr_DoTaskOps_test_001, TestSize.Level1)
{
    // 1. 测试当接口令牌写入失败时返回ERR_INVALID_VALUE
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInterfaceToken), WriteInterfaceTokenFailStub);

    AppTaskOpsProxy proxy = AppTaskOpsProxy(nullptr);
    std::string ops = "";
    std::string taskName = "";
    std::string taskExtra = "";
    int32_t funcResult = 0;
    ErrCode result = proxy.DoTaskOps(ops, taskName, taskExtra, funcResult);
    EXPECT_NE(result, 0);
}

HWTEST_F(MediaBgtaskMgrAppTaskOpsProxyTest, media_bgtask_mgr_DoTaskOps_test_002, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInterfaceToken), WriteInterfaceTokenSuccessStub);
    stub.set(ADDR(MessageParcel, WriteString16), WriteString16Stub);

    AppTaskOpsProxy proxy = AppTaskOpsProxy(nullptr);
    std::string ops = "ops_fail";
    std::string taskName = "";
    std::string taskExtra = "";
    int32_t funcResult = 0;
    ErrCode result = proxy.DoTaskOps(ops, taskName, taskExtra, funcResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

HWTEST_F(MediaBgtaskMgrAppTaskOpsProxyTest, media_bgtask_mgr_DoTaskOps_test_003, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInterfaceToken), WriteInterfaceTokenSuccessStub);
    stub.set(ADDR(MessageParcel, WriteString16), WriteString16Stub);

    AppTaskOpsProxy proxy = AppTaskOpsProxy(nullptr);
    std::string ops = "ops_succ";
    std::string taskName = "name_fail";
    std::string taskExtra = "";
    int32_t funcResult = 0;
    ErrCode result = proxy.DoTaskOps(ops, taskName, taskExtra, funcResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

HWTEST_F(MediaBgtaskMgrAppTaskOpsProxyTest, media_bgtask_mgr_DoTaskOps_test_004, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInterfaceToken), WriteInterfaceTokenSuccessStub);
    stub.set(ADDR(MessageParcel, WriteString16), WriteString16Stub);

    AppTaskOpsProxy proxy = AppTaskOpsProxy(nullptr);
    std::string ops = "ops_succ";
    std::string taskName = "name_succ";
    std::string taskExtra = "extra_fail";
    int32_t funcResult = 0;
    ErrCode result = proxy.DoTaskOps(ops, taskName, taskExtra, funcResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

HWTEST_F(MediaBgtaskMgrAppTaskOpsProxyTest, media_bgtask_mgr_DoTaskOps_test_005, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInterfaceToken), WriteInterfaceTokenSuccessStub);
    stub.set(ADDR(MessageParcel, WriteString16), WriteString16Stub);

    AppTaskOpsProxy proxy = AppTaskOpsProxy(nullptr);
    std::string ops = "ops_succ";
    std::string taskName = "name_succ";
    std::string taskExtra = "extra_succ";
    int32_t funcResult = 0;
    ErrCode result = proxy.DoTaskOps(ops, taskName, taskExtra, funcResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

HWTEST_F(MediaBgtaskMgrAppTaskOpsProxyTest, media_bgtask_mgr_DoTaskOps_test_006, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInterfaceToken), WriteInterfaceTokenSuccessStub);
    stub.set(ADDR(MessageParcel, WriteString16), WriteString16Stub);

    AppTaskOpsProxy proxy = AppTaskOpsProxy(nullptr);
    std::string ops = "ops_succ";
    std::string taskName = "name_succ";
    std::string taskExtra = "extra_succ";
    int32_t funcResult = 0;
    ErrCode result = proxy.DoTaskOps(ops, taskName, taskExtra, funcResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

HWTEST_F(MediaBgtaskMgrAppTaskOpsProxyTest, media_bgtask_mgr_DoTaskOps_test_007, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInterfaceToken), WriteInterfaceTokenSuccessStub);
    stub.set(ADDR(MessageParcel, WriteString16), WriteString16Stub);
    stub.set((ErrCode(MessageParcel::*)())&MessageParcel::ReadInt32, ReadInt32FailStub);

    std::u16string descriptor = u"";
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject(descriptor);

    AppTaskOpsProxy proxy = AppTaskOpsProxy(remoteObject);
    std::string ops = "ops_succ";
    std::string taskName = "name_succ";
    std::string taskExtra = "extra_succ";
    int32_t funcResult = 0;
    ErrCode result = proxy.DoTaskOps(ops, taskName, taskExtra, funcResult);
    EXPECT_EQ(result, 0);
}

HWTEST_F(MediaBgtaskMgrAppTaskOpsProxyTest, media_bgtask_mgr_DoTaskOps_test_008, TestSize.Level1)
{
    Stub stub;
    stub.set(ADDR(MessageParcel, WriteInterfaceToken), WriteInterfaceTokenSuccessStub);
    stub.set(ADDR(MessageParcel, WriteString16), WriteString16Stub);
    stub.set((ErrCode(MessageParcel::*)())&MessageParcel::ReadInt32, ReadInt32Stub);

    std::u16string descriptor = u"";
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject(descriptor);

    AppTaskOpsProxy proxy = AppTaskOpsProxy(remoteObject);
    std::string ops = "ops_succ";
    std::string taskName = "name_succ";
    std::string taskExtra = "extra_succ";
    int32_t funcResult = 0;
    ErrCode result = proxy.DoTaskOps(ops, taskName, taskExtra, funcResult);
    EXPECT_EQ(result, 0);
}
} // namespace MediaBgtaskSchedule
} // namespace OHOS

