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

#define MLOG_TAG "MediaAssetsControllerServiceTest"

#include "sync_cloud_enhancement_task_status_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "cloud_enhancement_vo.h"

#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"
#include "media_file_uri.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;

void SyncCloudEnhancementTaskStatusTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void SyncCloudEnhancementTaskStatusTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void SyncCloudEnhancementTaskStatusTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void SyncCloudEnhancementTaskStatusTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

static int32_t SyncCloudEnhancementTaskStatus()
{
    CloudEnhancementReqBody reqBody;
    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }
    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->SyncCloudEnhancementTaskStatus(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }
    MEDIA_INFO_LOG("ErrCode:%{public}d", respVo.GetErrCode());
    return respVo.GetErrCode();
}

HWTEST_F(SyncCloudEnhancementTaskStatusTest, SyncCloudEnhancementTaskStatus_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("SyncCloudEnhancementTaskStatus_Test_001 Begin");
    int32_t result = SyncCloudEnhancementTaskStatus();
    ASSERT_LT(result, 0);
}
}  // namespace OHOS::Media