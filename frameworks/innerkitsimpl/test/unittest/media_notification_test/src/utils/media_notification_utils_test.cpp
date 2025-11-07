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

#define MLOG_TAG "NotificationUtilsTest"

#include "media_notification_utils_test.h"

#include "media_log.h"
#include "media_notification_utils.h"
#include "parameters.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const std::string PARAM_NEED_DC_BASE_QUOTA_ANALYSIS = "persist.multimedia.media_analysis.dc_base_quota_analysis";
const std::string NO_NEED_DC_BASE_QUOTA_ANALYSIS = "0";
const std::string NEED_DC_BASE_QUOTA_ANALYSIS = "1";

const std::string PARAM_NEED_DC_EXTRA_QUOTA_ANALYSIS = "persist.multimedia.media_analysis.dc_extra_quota_analysis";
const std::string NO_NEED_DC_EXTRA_QUOTA_ANALYSIS = "0";
const std::string NEED_DC_EXTRA_QUOTA_ANALYSIS = "1";

const std::string PARAM_NEED_DC_PROACTIVE_ANALYSIS = "persist.multimedia.media_analysis.dc_proactive_analysis";
const std::string NO_NEED_DC_PROACTIVE_ANALYSIS = "0";
const std::string NEED_DC_PROACTIVE_ANALYSIS = "1";

void NotificationUtilsTest::SetUpTestCase(void) {}

void NotificationUtilsTest::TearDownTestCase(void) {}

void NotificationUtilsTest::SetUp()
{
    baseQuotaVal_ = system::GetParameter(PARAM_NEED_DC_BASE_QUOTA_ANALYSIS, NO_NEED_DC_BASE_QUOTA_ANALYSIS);
    extraQuotaVal_ = system::GetParameter(PARAM_NEED_DC_EXTRA_QUOTA_ANALYSIS, NO_NEED_DC_EXTRA_QUOTA_ANALYSIS);
    proactiveVal_ = system::GetParameter(PARAM_NEED_DC_PROACTIVE_ANALYSIS, NO_NEED_DC_PROACTIVE_ANALYSIS);
    system::SetParameter(PARAM_NEED_DC_BASE_QUOTA_ANALYSIS, NO_NEED_DC_BASE_QUOTA_ANALYSIS);
    system::SetParameter(PARAM_NEED_DC_EXTRA_QUOTA_ANALYSIS, NO_NEED_DC_EXTRA_QUOTA_ANALYSIS);
    system::SetParameter(PARAM_NEED_DC_PROACTIVE_ANALYSIS, NO_NEED_DC_PROACTIVE_ANALYSIS);
}

void NotificationUtilsTest::TearDown(void)
{
    system::SetParameter(PARAM_NEED_DC_BASE_QUOTA_ANALYSIS, baseQuotaVal_);
    system::SetParameter(PARAM_NEED_DC_EXTRA_QUOTA_ANALYSIS, extraQuotaVal_);
    system::SetParameter(PARAM_NEED_DC_PROACTIVE_ANALYSIS, proactiveVal_);
}

HWTEST_F(NotificationUtilsTest, medialib_notification_utils_test001, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_utils_test001");
    NotificationUtils::UpdateNotificationProp();
    EXPECT_EQ(NEED_DC_BASE_QUOTA_ANALYSIS, system::GetParameter(
        PARAM_NEED_DC_BASE_QUOTA_ANALYSIS, NO_NEED_DC_BASE_QUOTA_ANALYSIS));
    EXPECT_EQ(NEED_DC_EXTRA_QUOTA_ANALYSIS, system::GetParameter(
        PARAM_NEED_DC_EXTRA_QUOTA_ANALYSIS, NO_NEED_DC_EXTRA_QUOTA_ANALYSIS));
    EXPECT_EQ(NEED_DC_PROACTIVE_ANALYSIS, system::GetParameter(
        PARAM_NEED_DC_PROACTIVE_ANALYSIS, NO_NEED_DC_PROACTIVE_ANALYSIS));
    MEDIA_INFO_LOG("end medialib_notification_utils_test001");
}

} // namespace Media
} // namespace OHOS