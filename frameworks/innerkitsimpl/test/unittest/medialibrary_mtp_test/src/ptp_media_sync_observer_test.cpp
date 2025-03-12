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

#include "ptp_media_sync_observer_test.h"
#include "mtp_data_utils.h"
#include "media_mtp_utils.h"
#include "datashare_result_set.h"
#include "userfile_manager_types.h"
#include "mtp_constants.h"
#include "medialibrary_errno.h"
#include "ptp_media_sync_observer.h"
#include "property.h"
#include <vector>
#include <string>
#include <variant>

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const uint16_t MTP_FORMAT_TEST_CODE = 0x1001;
const uint32_t MTP_FORMAT_TEST_CODE_2 = 1234;

void PtpMediaSyncObserverUnitTest::SetUpTestCase(void) {}
void PtpMediaSyncObserverUnitTest::TearDownTestCase(void) {}
void PtpMediaSyncObserverUnitTest::SetUp() {}
void PtpMediaSyncObserverUnitTest::TearDown(void) {}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEventPackets SendEventPacketAlbum
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_001, TestSize.Level0)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    mediaSyncObserver->SendEventPackets(MTP_FORMAT_TEST_CODE_2, MTP_FORMAT_TEST_CODE);
    mediaSyncObserver->SendEventPacketAlbum(MTP_FORMAT_TEST_CODE_2, MTP_FORMAT_TEST_CODE);
}

} // namespace Media
} // namespace OHOS