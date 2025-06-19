/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaRefreshControllerServiceTest"

#include "media_refresh_controller_service_test.h"

#include "medialibrary_business_code.h"
#include "user_define_ipc.h"

#define protected public
#define private public
#include "media_refresh_controller_service.h"
#undef protected
#undef private

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MediaRefreshControllerServiceTest::SetUpTestCase(void) {}

void MediaRefreshControllerServiceTest::TearDownTestCase(void) {}

void MediaRefreshControllerServiceTest::SetUp(void) {}

void MediaRefreshControllerServiceTest::TearDown(void) {}

HWTEST_F(MediaRefreshControllerServiceTest, Accept_test_001, TestSize.Level0)
{
    auto testService = std::make_shared<MediaRefreshControllerService>();
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::NOTIFY_FOR_RECHECK);
    EXPECT_TRUE(testService->Accept(businessCode));
    businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::MEDIA_BUSINESS_CODE_START);
    EXPECT_FALSE(testService->Accept(businessCode));
}

HWTEST_F(MediaRefreshControllerServiceTest, OnRemoteRequest_test_001, TestSize.Level0)
{
    auto testService = std::make_shared<MediaRefreshControllerService>();
    MessageParcel data;
    MessageParcel reply;
    IPC::IPCContext context(MessageOption(), 0);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::NOTIFY_FOR_RECHECK);
    testService->OnRemoteRequest(businessCode, data, reply, context);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);
    EXPECT_EQ(respVo.GetErrCode(), 0);
}

HWTEST_F(MediaRefreshControllerServiceTest, OnRemoteRequest_test_002, TestSize.Level0)
{
    auto testService = std::make_shared<MediaRefreshControllerService>();
    MessageParcel data;
    MessageParcel reply;
    IPC::IPCContext context(MessageOption(), 0);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::MEDIA_BUSINESS_CODE_START);
    testService->OnRemoteRequest(businessCode, data, reply, context);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);
    EXPECT_EQ(respVo.GetErrCode(), E_IPC_SEVICE_NOT_FOUND);
}

HWTEST_F(MediaRefreshControllerServiceTest, GetPermissionPolicy_test_001, TestSize.Level0)
{
    auto testService = std::make_shared<MediaRefreshControllerService>();
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::NOTIFY_FOR_RECHECK);
    std::vector<std::vector<PermissionType>> permissionPolicy;
    bool isBypass = false;
    EXPECT_EQ(testService->GetPermissionPolicy(businessCode, permissionPolicy, isBypass), E_SUCCESS);
    businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::MEDIA_BUSINESS_CODE_START);
    EXPECT_EQ(testService->GetPermissionPolicy(businessCode, permissionPolicy, isBypass), E_FAIL);
}
} // namespace Media
} // namespace OHOS