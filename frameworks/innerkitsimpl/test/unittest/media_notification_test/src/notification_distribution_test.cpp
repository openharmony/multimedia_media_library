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

#define MLOG_TAG "NotificationDistributionTest"

#include "notification_distribution_test.h"
#include "notification_merging_test.h"
#include "notification_distribution.h"
#include "media_log.h"
#include "media_change_info.h"
#include "photo_asset_change_info.h"
#include "album_change_info.h"
#include "notify_info.h"
#include "media_observer_manager.h"
#include "medialibrary_errno.h"
#include "notification_test_data.h"

#include <string>
#include <unordered_set>


using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void NotificationDistributionTest::SetUpTestCase(void) {}

void NotificationDistributionTest::TearDownTestCase(void) {}

void NotificationDistributionTest::SetUp() {}

void NotificationDistributionTest::TearDown(void) {}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test001, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test001");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo({});
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test001");
}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test002, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test002");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test002");
    EXPECT_TRUE(!notifyInfos.empty());
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test002");
}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test003, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test003");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test003");
    EXPECT_TRUE(!notifyInfos.empty());
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test003");
}
HWTEST_F(NotificationDistributionTest, medialib_distribution_test004, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test004");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test004");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test004");
}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test005, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test005");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test005");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test005");
}


HWTEST_F(NotificationDistributionTest, medialib_distribution_test006, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test006");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test006");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test006");
}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test007, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test007");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test007");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test007");
}
HWTEST_F(NotificationDistributionTest, medialib_distribution_test008, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test008");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test008");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test008");
}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test009, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test009");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test009");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test009");
}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test010, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test010");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test010");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test010");
}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test011, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test011");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test011");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test011");
}

HWTEST_F(NotificationDistributionTest, medialib_distribution_test012, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_distribution_test012");
    std::vector<Notification::NotifyInfo> notifyInfos =
        Notification::NotificationTestData::buildAssetsNotifyInfo("test012");
    int32_t ret = Media::Notification::NotificationDistribution::DistributeNotifyInfo(notifyInfos);
    EXPECT_TRUE(ret == E_OK);
    MEDIA_INFO_LOG("end medialib_distribution_test012");
}

} // namespace Media
} // namespace OHOS