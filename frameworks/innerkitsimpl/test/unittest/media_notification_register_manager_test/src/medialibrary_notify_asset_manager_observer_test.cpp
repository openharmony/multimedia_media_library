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

#define MLOG_TAG "MediaOnNotifyAssetManagerObserverTest"

#include "medialibrary_notify_asset_manager_observer_test.h"

#include "medialibrary_notify_asset_manager_observer.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "media_log.h"
#include "media_notification_utils.h"
#include "medialibrary_notify_utils.h"
#include "media_change_info.h"
#include "message_parcel.h"
#include "napi/native_api.h"
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace std;
using namespace testing::ext;
using namespace OHOS::DataShare;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace Media {

void MediaOnNotifyAssetManagerObserverTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("MediaOnNotifyAssetManagerObserverTest::SetUpTestCase");
}

void MediaOnNotifyAssetManagerObserverTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("MediaOnNotifyAssetManagerObserverTest::TearDownTestCase");
}

void MediaOnNotifyAssetManagerObserverTest::SetUp()
{
    MEDIA_INFO_LOG("MediaOnNotifyAssetManagerObserverTest::SetUp");
}

void MediaOnNotifyAssetManagerObserverTest::TearDown()
{
    MEDIA_INFO_LOG("MediaOnNotifyAssetManagerObserverTest::TearDown");
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_001::Start");
    ChangeInfo changeInfo;
    changeInfo.data_ = nullptr;
    changeInfo.size_ = 0;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_002::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(100));
    changeInfo.size_ = 100;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_003::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(200 * 1024));
    changeInfo.size_ = 200 * 1024;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_004::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(200 * 1024 + 1));
    changeInfo.size_ = 200 * 1024 + 1;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_005::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(50));
    changeInfo.size_ = 50;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_006::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(150));
    changeInfo.size_ = 150;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_007::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(300));
    changeInfo.size_ = 300;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_008::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(500));
    changeInfo.size_ = 500;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_009::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(1000));
    changeInfo.size_ = 1000;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_010::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(204800));
    changeInfo.size_ = 204800;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_011, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_011::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(1));
    changeInfo.size_ = 1;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_012, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_012::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(10));
    changeInfo.size_ = 10;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_013, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_013::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(100));
    changeInfo.size_ = 100;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_014, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_014::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(99999));
    changeInfo.size_ = 99999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_015, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_015::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(123456));
    changeInfo.size_ = 123456;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_016, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_016::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(987654));
    changeInfo.size_ = 987654;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_017, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_017::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(555555));
    changeInfo.size_ = 555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_018, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_018::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(1111111));
    changeInfo.size_ = 1111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_019, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_019::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(2222222));
    changeInfo.size_ = 2222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_020, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_020::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(3333333));
    changeInfo.size_ = 3333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_021, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_021::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(4444444));
    changeInfo.size_ = 4444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_022, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_022::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555));
    changeInfo.size_ = 5555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_023, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_023::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666));
    changeInfo.size_ = 6666666;
    MediaOnNotifyAssetManagerObserver::OnChangeOnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_024, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_024::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777));
    changeInfo.size_ = 7777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_025, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_025::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(8888888));
    changeInfo.size_ = 8888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_026, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_026::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999));
    changeInfo.size_ = 9999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_027, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_027::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(10000000));
    changeInfo.size_ = 10000000;
    MediaOnNotifyAssetAsManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_028, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_028::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(50000000));
    changeInfo.size_ = 50000000;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_029, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_029::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(100000000));
    changeInfo.size_ = 100000000;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_030, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_030::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(1234567890));
    changeInfo.size_ = 1234567890;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_031, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_031::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(12345678901));
    changeInfo.size_ = 12345678901;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_032, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_032::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(987654321012));
    changeInfo.size_ = 987654321012;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_033, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_033::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_034, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_034::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(1111111111111));
    changeInfo.size_ = 1111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_035, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_035::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(2222222222222));
    changeInfo.size_ = 2222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_036, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_036::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(3333333333333));
    changeInfo.size_ = 3333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_037, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_037::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(4444444444));
    changeInfo.size_ = 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_038, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_038::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_039, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_039::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666666));
    changeInfo.size_ = 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_040, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_040::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size_ = 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_041, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_041::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(8888888888888));
    changeInfo.size_ = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_042, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_042::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999999999));
    changeInfo.size_ = 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_043, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_043::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(12345678901234));
    changeInfo.size_ = 12345678901234;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_044, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_044::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(98765432101234));
    changeInfo.size_ = 98765432101234;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_045, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_045::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_046, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_046::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(11111111111111111));
    changeInfo.size_ = 11111111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_047, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_047::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(22222222222222222));
    changeInfo.size_ = 22222222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_048, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_048::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ = 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_049, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_049::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(4444444444444));
    changeInfo.size_ = 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_050, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_050::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(55555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_051, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_051::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666666666));
    changeInfo.size_ = 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_052, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_052::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size_ = 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_053, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_053::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(8888888888888888));
    changeInfo.size_ = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_054, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_054::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999999999999));
    changeInfo.size_ = 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_055, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_055::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(123456789012345));
    changeInfo.size_ = 123456789012345;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_056, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_056::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(987654321012345));
    changeInfo.size_ = 987654321012345;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_057, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_057::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(555555555555555));
    changeInfo.size_ = 55555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_058, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_058::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(11111111111111111));
    changeInfo.size_ = 11111111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_059, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_059::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(22222222222222222));
    changeInfo.size_ = 22222222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_060, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_060::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ = 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_061, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_061::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(4444444444444));
    changeInfo.size_ = 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_062, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_062::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_063, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_063::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666666666));
    changeInfo.size_ = 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_064, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_064::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size_ = 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_065, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_065::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(8888888888888888));
    changeInfo.size_ = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_066, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_066::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999999999999));
    changeInfo.size_ = 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_067, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_067::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(1234567890123456));
    changeInfo.size_ = 1234567890123456;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_068, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_068::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9876543210123456));
    changeInfo.size_ = 9876543210123456;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_069, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_069::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(555555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_070, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_070::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(11111111111111111));
    changeInfo.size_ = 11111111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_071, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_071::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(22222222222222222));
    changeInfo.size_ 22222222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_072, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_072::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ = 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_073, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_073::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(4444444444444));
    changeInfo.size_ 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_074, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_074::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_075, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_075::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666666666));
    changeInfo.size_ = 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_076, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_076::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size_ 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_077, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_077::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast;*>(malloc(8888888888888888));
    changeInfo.size_ = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_078, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_078::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999999999999));
    changeInfo.size_ = 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_079, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_079::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(12345678901234567));
    changeInfo.size_ = 12345678901234567;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_080, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_080::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(98765432101234567));
    changeInfo.size_ = 98765432101234567;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_081, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_081::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_082, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_082::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(11111111111111111));
    changeInfo.size_ = 11111111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_083, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_083::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(22222222222222222));
    changeInfo.size_ = 22222222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_084, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_084::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ = 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_085, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_085::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(4444444444444));
    changeInfo.size_ 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_086, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_086::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_087, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_087::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666666666));
    changeInfo.size_ = 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_088, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_088::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size_ 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_089, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_089::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_castuint8_t*>(malloc(8888888888888888));
    changeInfo.size_ = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_090, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_090::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999999999999));
    changeInfo.size_ = 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_091, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_091::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(12345678901234567));
    changeInfo.size_ = 12345678901234567;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_092, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_092::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(98765432101234567));
    changeInfo.size_ = 98765432101234567;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_093, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_093::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_094, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_094::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(11111111111111111));
    changeInfo.size_ = 11111111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_095, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_095::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(22222222222222222));
    changeInfo.size_ = 22222222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_096, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_096::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ = 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_097, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_097::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(44444444444440));
    changeInfo.size_ = 444444444440;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_098, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_098::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_099, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_099::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666666666));
    changeInfo.size_ = 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_100, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_100::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size_ = 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_101, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_101::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(8888888888888888));
    changeInfo.size_ = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_102, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_102::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999999999999));
    changeInfo.size_ = 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_103, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_103::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(12345678901234567));
    changeInfo.size_ = 12345678901234567;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_104, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_104::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(98765432101234567));
    changeInfo.size_ 98765432101234567;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_105, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_105::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_106, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_106::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(11111111111111111));
    changeInfo.size_ 11111111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_107, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_107::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(22222222222222222));
    changeInfo.size = 22222222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_108, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_108::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_109, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_109::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(4444444444444));
    changeInfo.size = 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_110, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_110::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_111, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_111::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666666666));
    changeInfo.size_ 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_112, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_112::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size_ 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_113, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_113::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(8888888888888888));
    changeInfo.size = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_114, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_114::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999999999999));
    changeInfo.size_ 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_115, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_115::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(123456789012345678));
    changeInfo.size_ = 123456789012345678;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_116, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_116::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(987654321012345678));
    changeInfo.size_ 987654321012345678;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_117, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_117::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_118, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_118::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(11111111111111111));
    changeInfo.size_ = 11111111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_119, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_119::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(22222222222222222));
    changeInfo.size_ 22222222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_120, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_120::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_121, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_121::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(4444444444444));
    changeInfo.size = 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_122, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_122::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_123, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_123::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(6666666666666));
    changeInfo.size_ 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_124, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_124::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size_ = 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_125, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_125::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(8888888888888888));
    changeInfo.size_ = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_126, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_126::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(9999999999999999));
    changeInfo.size_ = 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_127, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_127::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(123456789012345678));
    changeInfo.size_ = 123456789012345678;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_128, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_128::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(987654321012345678));
    changeInfo.size_ 987654321012345678;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_129, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_129::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_130, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_130::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast<uint8_t*>(malloc(11111111111111111));
    changeInfo.size_ 11111111111111111;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_131, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_131::start");
    ChangeInfo changeInfo;
    changeInfo.data_ = static_cast<uint8_t*>(malloc(22222222222222222));
    changeInfo.size = 22222222222222222;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_132, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_132::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_133, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_133::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast<uint8_t*>(malloc(4444444444444));
    changeInfo.size = 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_134, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_134::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast<uint8_t*>(malloc(5555555555555));
    changeInfo.size_ 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_135, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_135::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast<uint8_t*>(malloc(6666666666666));
    changeInfo.size = 66666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_136, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_136::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(7777777777777));
    changeInfo.size = 7777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_137, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_137::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast<uint8_t*>(malloc(8888888888888888));
    changeInfo.size = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_138, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_138::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast<uint8_t*>(malloc(9999999999999999));
    changeInfo.size_ 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_139, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_139::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast uint8_t*>(malloc(123456789012345678));
    changeInfo.size_ 123456789012345678;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_140, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_140::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(98765432101234567));
    changeInfo.size = 98765432101234567;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_141, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_141::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(5555555555555));
    changeInfo.size = 5555555555555;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_142, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_142::start");
    ChangeInfo changeInfo;
    changeInfo.data_ static_cast uint8_t*>(malloc(11111111111111111));
    changeInfo.size = 11111111111111111;
    MediaOnNotifyAssetManagerObserverAsManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_143, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_143::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(33333333333333333));
    changeInfo.size_ 33333333333333333;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_144, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_144::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(4444444444444));
    changeInfo.size = 4444444444444;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_145, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_145::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(5555555555555));
    changeInfo.size = 5555555555555;
    MediaOnAsManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_146, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_146::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(6666666666666));
    changeInfo.size = 6666666666666;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_147, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_147::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_castra_cast<uint8_t*>(malloc(7777777777777));
    changeInfo.size = 777777777777;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_148, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_148::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(8888888888888888));
    changeInfo.size = 8888888888888;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_149, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_149::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(9999999999999999));
    changeInfo.size = 9999999999999;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

HWTEST_F(MediaOnNotifyAssetManagerObserverTest, OnChange_150, TestSize.Level1)
{
    MEDIA_INFO_LOG("OnChange_150::start");
    ChangeInfo changeInfo;
    changeInfo.data = static_cast uint8_t*>(malloc(123456789012345678));
    changeInfo.size = 123456789012345678;
    MediaOnNotifyAssetManagerObserver::OnChange(changeInfo);
    free(changeInfo.data_);
}

}  // namespace Media
}  // namespace OHOS
