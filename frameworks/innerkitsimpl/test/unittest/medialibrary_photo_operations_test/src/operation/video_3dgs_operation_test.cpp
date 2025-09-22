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

#include "video_3dgs_operation_test.h"
#include <string>
#include "media_log.h"
#include "video_3dgs_operation.h"

using namespace testing::ext;

namespace OHOS::Media {
void Video3DgsOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void Video3DgsOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void Video3DgsOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void Video3DgsOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(Video3DgsOperationTest, Video_3DGS_Operation_Test_001, TestSize.Level1)
{
    Video3DgsOperation::Update3DgsType();
    int32_t testFileId = 1000000;
    auto ret = Video3DgsOperation::QueryVideoCount(testFileId);
    EXPECT_EQ(ret, 0);
    auto infos = Video3DgsOperation::QueryVideoInfo(testFileId);
    EXPECT_TRUE(infos.empty());
}
}  // namespace OHOS::Media