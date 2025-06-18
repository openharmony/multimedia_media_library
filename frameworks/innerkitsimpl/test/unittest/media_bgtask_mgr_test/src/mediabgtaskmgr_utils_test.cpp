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

#define MLOG_TAG "MediaBgTaskUtilsTest"

#include "mediabgtaskmgr_utils_test.h"

#include "media_bgtask_utils.h"
#include <string>
#include "parameters.h"
#include "string_ex.h"
#include "media_bgtask_mgr_log.h"

using namespace testing::ext;

namespace OHOS {
namespace MediaBgtaskSchedule {

void MediaBgtaskMgrUtilsTest::SetUpTestCase() {}

void MediaBgtaskMgrUtilsTest::TearDownTestCase() {}

void MediaBgtaskMgrUtilsTest::SetUp() {}

void MediaBgtaskMgrUtilsTest::TearDown() {}

/**
 * IsParamTrueOrLtZero & IsStrTrueOrLtZero
 */
HWTEST_F(MediaBgtaskMgrUtilsTest, media_bgtask_mgr_IsParamTrueOrLtZero_test_001, TestSize.Level1)
{
    system::SetParameter("key", "true");
    EXPECT_TRUE(MediaBgTaskUtils::IsParamTrueOrLtZero("key"));

    system::SetParameter("1", "1");
    EXPECT_TRUE(MediaBgTaskUtils::IsParamTrueOrLtZero("1"));

    system::SetParameter("0", "0");
    EXPECT_FALSE(MediaBgTaskUtils::IsParamTrueOrLtZero("0"));

    system::SetParameter("other", "other");
    EXPECT_FALSE(MediaBgTaskUtils::IsParamTrueOrLtZero("other"));
}

/**
 * TaskOpsToString
 */
HWTEST_F(MediaBgtaskMgrUtilsTest, media_bgtask_mgr_TaskOpsToString_test_001, TestSize.Level1)
{
    std::string start = "start";
    std::string stop = "stop";
    std::string none = "None";
    EXPECT_EQ(start, MediaBgTaskUtils::TaskOpsToString(TaskOps::START));
    EXPECT_EQ(stop, MediaBgTaskUtils::TaskOpsToString(TaskOps::STOP));
    EXPECT_EQ(none, MediaBgTaskUtils::TaskOpsToString(TaskOps::NONE));
}

/**
 * StringToTaskOps
 */
HWTEST_F(MediaBgtaskMgrUtilsTest, media_bgtask_mgr_StringToTaskOpstest_001, TestSize.Level1)
{
    std::string start = "start";
    std::string stop = "stop";
    std::string none = "None";
    EXPECT_EQ(TaskOps::START, MediaBgTaskUtils::StringToTaskOps(start));
    EXPECT_EQ(TaskOps::STOP, MediaBgTaskUtils::StringToTaskOps(stop));
    EXPECT_EQ(TaskOps::NONE, MediaBgTaskUtils::StringToTaskOps(none));
}

/**
 * DesensitizeUri
 */
HWTEST_F(MediaBgtaskMgrUtilsTest, media_bgtask_mgr_DesensitizeUri_001, TestSize.Level1)
{
    std::string fileUri = "tmp/code";
    EXPECT_NE("", MediaBgTaskUtils::DesensitizeUri(fileUri));
}

/**
 * GetNowTime
 */
HWTEST_F(MediaBgtaskMgrUtilsTest, media_bgtask_mgr_GetNowTime_001, TestSize.Level1)
{
    EXPECT_EQ(time(0), MediaBgTaskUtils::GetNowTime());
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS

