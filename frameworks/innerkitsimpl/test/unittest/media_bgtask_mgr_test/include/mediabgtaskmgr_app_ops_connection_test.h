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

#ifndef MEDIABGTASKMGR_APP_OPS_CONNECTION_H
#define MEDIABGTASKMGR_APP_OPS_CONNECTION_H

#include <gtest/gtest.h>
#include "gmock/gmock.h"
#define private public
#include "app_ops_connection.h"
#undef private

namespace OHOS {
namespace MediaBgtaskSchedule {
static const int32_t E_OK = 0;

class MediaBgtaskMgrAppOpsConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject(std::u16string descriptor = nullptr) : IRemoteObject(descriptor) {}
    ~MockIRemoteObject() {};

    inline int32_t GetObjectRefCount() override
    {
        return E_OK;
    }

    inline int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return E_OK;
    }

    inline bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    inline bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    inline int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return E_OK;
    }
};

class MockAppTaskOpsProxy : public AppTaskOpsProxy {
    MockAppTaskOpsProxy(const sptr<IRemoteObject>& remote) : AppTaskOpsProxy(remote) {}
    ~MockAppTaskOpsProxy() {}

    MOCK_METHOD(ErrCode, DoTaskOps, (const std::string& ops, const std::string& taskName, const std::string& taskExtra,
        int32_t& funcResult), (override));
};

} // namespace MediaBgtaskSchedule
} // namespace OHOS

#endif // MEDIABGTASKMGR_APP_OPS_CONNECTION_H
