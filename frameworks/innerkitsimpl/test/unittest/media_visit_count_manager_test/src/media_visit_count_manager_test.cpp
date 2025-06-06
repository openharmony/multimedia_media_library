/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_visit_count_manager_test.h"

#include <cstdlib>
#include <thread>
#include "media_visit_count_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
void MediaVisitCountManagerUnitTest::SetUpTestCase(void) {}
void MediaVisitCountManagerUnitTest::TearDownTestCase(void) {}
void MediaVisitCountManagerUnitTest::SetUp() {}
void MediaVisitCountManagerUnitTest::TearDown(void) {}

HWTEST_F(MediaVisitCountManagerUnitTest, mediaVisitCountManagerTest_001, TestSize.Level1)
{
    MediaVisitCountManager::isThreadRunning_.store(true);
    MediaVisitCountManager::VisitCountThread();
    EXPECT_FALSE(MediaVisitCountManager::isTimerRefresh_.load());
}

HWTEST_F(MediaVisitCountManagerUnitTest, mediaVisitCountManagerTest_002, TestSize.Level1)
{
    MediaVisitCountManager::isThreadRunning_.store(true);
    MediaVisitCountManager::queue_.push(std::make_pair(MediaVisitCountManager::VisitCountType::PHOTO_FS, "1"));
    MediaVisitCountManager::VisitCountThread();
    EXPECT_FALSE(MediaVisitCountManager::isTimerRefresh_.load());
}

HWTEST_F(MediaVisitCountManagerUnitTest, mediaVisitCountManagerTest_003, TestSize.Level1)
{
    auto visitCountType = MediaVisitCountManager::VisitCountType::PHOTO_FS;
    std::string fileId = "1";
    MediaVisitCountManager::AddVisitCount(visitCountType, fileId);
    bool ret = MediaVisitCountManager::IsValidType(MediaVisitCountManager::VisitCountType::PHOTO_FS);
    EXPECT_TRUE(ret);
}

HWTEST_F(MediaVisitCountManagerUnitTest, mediaVisitCountManagerTest_004, TestSize.Level1)
{
    bool ret = MediaVisitCountManager::IsValidType(MediaVisitCountManager::VisitCountType::PHOTO_LCD);
    EXPECT_TRUE(ret);
}
} // namespace Media
} // namespace OHOS