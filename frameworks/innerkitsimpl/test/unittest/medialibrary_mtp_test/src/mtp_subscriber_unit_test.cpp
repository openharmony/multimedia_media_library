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
#include <vector>
#include <string>
#include <variant>
#include "mtp_subscriber_unit_test.h"
#include "mtp_subscriber.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "media_log.h"
#include "parameters.h"
#include "mtp_service.h"
#include "mtp_manager.h"
#include "common_event_subscriber.h"
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MtpSubcriberUnitTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void MtpSubcriberUnitTest::TearDownTestCase(void) {}
void MtpSubcriberUnitTest::SetUp() {}
void MtpSubcriberUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Subscribe
 */
HWTEST_F(MtpSubcriberUnitTest, medialibrary_parser_test_001, TestSize.Level0)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("SomeEvent");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<MtpSubscriber> mtpSubscriber = std::make_shared<MtpSubscriber>(subscribeInfo);
    ASSERT_NE(mtpSubscriber, nullptr);
    EXPECT_NE(mtpSubscriber->Subscribe(), false);
    mtpSubscriber = nullptr;
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent
 */
HWTEST_F(MtpSubcriberUnitTest, medialibrary_parser_test_002, TestSize.Level0)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("SomeEvent");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    std::shared_ptr<MtpSubscriber> mtpSubscriber = std::make_shared<MtpSubscriber>(subscribeInfo);
    ASSERT_NE(mtpSubscriber, nullptr);
    EventFwk::CommonEventData eventData;
    string action = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF;
    AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    mtpSubscriber->OnReceiveEvent(eventData);
    EXPECT_EQ(want.GetAction(), EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    mtpSubscriber = nullptr;
}
} // namespace Media
} // namespace OHOS