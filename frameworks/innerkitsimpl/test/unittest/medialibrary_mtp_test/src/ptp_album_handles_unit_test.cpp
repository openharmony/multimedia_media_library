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

#include <thread>
#include "ptp_album_handles_unit_test.h"
#include "ptp_album_handles.h"
#include "mtp_manager.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void PtpAlbumHandlesUnitTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void PtpAlbumHandlesUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void PtpAlbumHandlesUnitTest::SetUp() {}
void PtpAlbumHandlesUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddHandle RemoveHandle FindHandle
 */
HWTEST_F(PtpAlbumHandlesUnitTest, medialibrary_PTP_message_testlevel_01, TestSize.Level1)
{
    std::shared_ptr<PtpAlbumHandles> ptpAlbumHandles = PtpAlbumHandles::GetInstance();
    ASSERT_NE(ptpAlbumHandles, nullptr);

    for (int32_t i = 1; i <= 5; i++) {
        ptpAlbumHandles->AddHandle(i);
    }
    int32_t testHandle_1 = 2;
    ptpAlbumHandles->AddHandle(testHandle_1);

    int32_t removeHandle = 3;
    ptpAlbumHandles->RemoveHandle(removeHandle);

    int32_t testHandle_2 = 6;
    ptpAlbumHandles->RemoveHandle(testHandle_2);

    bool res = ptpAlbumHandles->FindHandle(testHandle_1);
    EXPECT_TRUE(res);

    res = ptpAlbumHandles->FindHandle(testHandle_2);
    EXPECT_FALSE(res);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddHandle AddAlbumHandles FindHandle
 */
HWTEST_F(PtpAlbumHandlesUnitTest, medialibrary_PTP_message_testlevel_02, TestSize.Level1)
{
    std::shared_ptr<PtpAlbumHandles> ptpAlbumHandles = PtpAlbumHandles::GetInstance();
    ASSERT_NE(ptpAlbumHandles, nullptr);

    for (int32_t i = 1; i <= 5; i++) {
        ptpAlbumHandles->AddHandle(i);
    }

    std::shared_ptr<DataShare::DataShareResultSet> resultSet = nullptr;
    ptpAlbumHandles->AddAlbumHandles(resultSet);

    int32_t testHandle_1 = 2;
    bool res = ptpAlbumHandles->FindHandle(testHandle_1);
    EXPECT_TRUE(res);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddHandle AddAlbumHandles FindHandle
 */
HWTEST_F(PtpAlbumHandlesUnitTest, medialibrary_PTP_message_testlevel_03, TestSize.Level1)
{
    std::shared_ptr<PtpAlbumHandles> ptpAlbumHandles = PtpAlbumHandles::GetInstance();
    ASSERT_NE(ptpAlbumHandles, nullptr);

    std::set<int32_t> albumIds;
    albumIds.insert(1);
    albumIds.insert(2);
    albumIds.insert(3);

    for (int32_t i = 1; i <= 5; i++) {
        ptpAlbumHandles->AddHandle(i);
    }

    std::vector<int32_t> removeIds;
    ptpAlbumHandles->UpdateHandle(albumIds, removeIds);
    EXPECT_TRUE(removeIds.size() > 0);
}
} // namespace Media
} // namespace OHOS