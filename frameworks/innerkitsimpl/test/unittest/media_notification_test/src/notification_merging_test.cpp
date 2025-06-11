/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "NotificationMergingTest"

#include "notification_merging_test.h"
#include "notification_merging.h"
#include "media_log.h"
#include "notify_info.h"
#include "notification_test_data.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void NotificationMergingTest::SetUpTestCase(void)
{}

void NotificationMergingTest::TearDownTestCase(void)
{}

void NotificationMergingTest::SetUp()
{}

void NotificationMergingTest::TearDown(void)
{}

HWTEST_F(NotificationMergingTest, medialib_notification_test001, TestSize.Level1)
{
    MEDIA_ERR_LOG("enter medialib_notification_test001");
    OHOS::Media::Notification::NotificationMerging mergeNotifyInfo;
    std::vector<Notification::NotifyInfo> resultNotifyInfo = mergeNotifyInfo.MergeNotifyInfo({});
    EXPECT_TRUE(resultNotifyInfo.empty());
    MEDIA_ERR_LOG("end medialib_notification_test001");
}

HWTEST_F(NotificationMergingTest, medialib_notification_test002, TestSize.Level1)
{
    MEDIA_ERR_LOG("enter medialib_notification_test002");
    OHOS::Media::Notification::NotificationMerging mergeNotifyInfo;
    std::vector<Notification::NotifyInfo> resultNotifyInfo =
        mergeNotifyInfo.MergeNotifyInfo(OHOS::Media::Notification::NotificationTestData::buildAssetsMediaChangeInfo());
    EXPECT_TRUE(!resultNotifyInfo.empty());
    MEDIA_ERR_LOG("end medialib_notification_test002");
}

} // namespace Media
} // namespace OHOS