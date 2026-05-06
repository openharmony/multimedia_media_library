/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "media_share_dirty_data_task_test.h"

#define private public
#include "media_share_dirty_data_task.h"
#undef private
#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace testing::ext;
using namespace OHOS::Media::Background;

void MediaShareDirtyDataTaskTest::SetUpTestCase(void) {}

void MediaShareDirtyDataTaskTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaShareDirtyDataTaskTest::SetUp() {}

void MediaShareDirtyDataTaskTest::TearDown(void) {}

HWTEST_F(MediaShareDirtyDataTaskTest, MediaShareDirtyDataTask_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaShareDirtyDataTask_test_001");
    MediaShareDirtyDataTask task;
    auto ret = task.HandleDirtyData();
    EXPECT_TRUE(ret);
    MEDIA_INFO_LOG("MediaShareDirtyDataTask_test_001 end");
}
} // namespace Media
} // namespace OHOS