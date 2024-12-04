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

#include <cstdlib>
#include "ptp_media_sync_observer_unit_test.h"
#include "ptp_media_sync_observer.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "mtp_storage_manager.h"
#include "object_info.h"
#include "mtp_constants.h"
#include "ptp_media_sync_observer.h"
#include "ptp_album_handles.h"
#include "datashare_helper.h"

using namespace std;
using namespace testing::ext;
using ChangeType = OHOS::DataShare::DataShareObserver::ChangeType;
using MediaSyncObserver = OHOS::Media::MediaSyncObserver;
using ChangeInfo = OHOS::AAFwk::ChangeInfo;
std::shared_ptr<MediaSyncObserver> observer = std::make_shared<MediaSyncObserver>();
namespace OHOS {
namespace Media {

void PtpMediaASyncObserverUnitTest::SetUpTestCase(void) {}
void PtpMediaASyncObserverUnitTest::TearDownTestCase(void) {}
// SetUp:Execute before each test case
void PtpMediaASyncObserverUnitTest::SetUp() {}
void PtpMediaASyncObserverUnitTest::TearDown(void) {}

/*
 * Feature: PtpMediaASyncObserverUnitTest
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendPhotoEvent test
 */
HWTEST_F(PtpMediaASyncObserverUnitTest, medialibrary_PTP_async_observer_001, TestSize.Level0)
{
    ASSERT_NE(observer, nullptr);
    ChangeType changeType = ChangeType::INSERT;
    string suffixString = "100000001";
    observer->SendPhotoEvent(changeType, suffixString);

    changeType = ChangeType::UPDATE;
    observer->SendPhotoEvent(changeType, suffixString);

    changeType = ChangeType::DELETE;
    observer->SendPhotoEvent(changeType, suffixString);
}

/*
 * Feature: PtpMediaASyncObserverUnitTest
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAddEditPhotoHandles test
 */
HWTEST_F(PtpMediaASyncObserverUnitTest, medialibrary_PTP_async_observer_002, TestSize.Level0)
{
    ASSERT_NE(observer, nullptr);
    int32_t handle = 100000001;
    (void)observer->GetAddEditPhotoHandles(handle);
}

/*
 * Feature: PtpMediaASyncObserverUnitTest
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandlesFromPhotosInfoBurstKeys test
 */
HWTEST_F(PtpMediaASyncObserverUnitTest, medialibrary_PTP_async_observer_003, TestSize.Level0)
{
    ASSERT_NE(observer, nullptr);
    vector<std::string> handle = {"100000001", "100000002"};
    (void)observer->GetHandlesFromPhotosInfoBurstKeys(handle);
}

/*
 * Feature: PtpMediaASyncObserverUnitTest
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandlesFromPhotosInfoBurstKeys test
 */
HWTEST_F(PtpMediaASyncObserverUnitTest, medialibrary_PTP_async_observer_004, TestSize.Level0)
{
    ASSERT_NE(observer, nullptr);
    (void)observer->GetAllDeleteHandles();
}

/*
 * Feature: PtpMediaASyncObserverUnitTest
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddMovingPhotoHandle test
 */
HWTEST_F(PtpMediaASyncObserverUnitTest, medialibrary_PTP_async_observer_005, TestSize.Level0)
{
    ASSERT_NE(observer, nullptr);
    int32_t handle = 100000001;
    (void)observer->AddPhotoHandle(handle);
}

/*
 * Feature: PtpMediaASyncObserverUnitTest
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAddEditPhotoHandles test
 */
HWTEST_F(PtpMediaASyncObserverUnitTest, medialibrary_PTP_async_observer_006, TestSize.Level0)
{
    ASSERT_NE(observer, nullptr);
    int32_t handle = 100000001;
    (void)observer->GetAddEditPhotoHandles(handle);
}

/*
 * Feature: PtpMediaASyncObserverUnitTest
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendPhotoRemoveEvent test
 */
HWTEST_F(PtpMediaASyncObserverUnitTest, medialibrary_PTP_async_observer_007, TestSize.Level0)
{
    ASSERT_NE(observer, nullptr);
    std::string suffixString = "";
    observer->SendPhotoRemoveEvent(suffixString);

    suffixString = "1";
    observer->SendPhotoRemoveEvent(suffixString);
}
} // namespace Media
} // namespace OHOS