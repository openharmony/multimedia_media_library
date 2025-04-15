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
#define MLOG_TAG "MovingPhotoImplTest"
#include <fcntl.h>
#include "moving_photo_impl_test.h"
#include "datashare_helper.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "file_uri.h"
#include "get_self_permissions.h"
#include "hilog/log.h"
#include "userfilemgr_uri.h"
#include "iservice_registry.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "moving_photo_impl.h"
#include "media_log.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void MovingPhotoImplTest::SetUpTestCase(void) {}

void MovingPhotoImplTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MovingPhotoImplTest::SetUp(void) {}

void MovingPhotoImplTest::TearDown(void) {}

HWTEST_F(MovingPhotoImplTest, moving_photo_impl_test_001, TestSize.Level0)
{
    std::string imageUri = "imageUri";
    MovingPhotoImpl impl(imageUri);
    std::string videoUri = "videoUri";
    bool isMediaLibUri = true;
    int32_t result = impl.OpenReadOnlyVideo(videoUri, isMediaLibUri);
    EXPECT_EQ(result, E_FAIL);
    isMediaLibUri = false;
    result = impl.OpenReadOnlyVideo(videoUri, isMediaLibUri);
    EXPECT_EQ(result, -1);
}
} // namespace Media
} // namespace OHOS
