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
#include "datashare_helper.h"
#include "datashare_result_set.h"
#include "iservice_registry.h"
#include "userfile_manager_types.h"
#include "mtp_constants.h"
#include "medialibrary_errno.h"
#include "ptp_album_handles.h"
#include "ptp_media_sync_observer.h"
#include "property.h"
#include <vector>
#include <string>

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const uint16_t MTP_FORMAT_TEST_CODE = 0x1001;
const uint32_t MTP_FORMAT_TEST_CODE_2 = 1234;
static std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_ = nullptr;
static constexpr int32_t HANDLE_TEST = 1;
static constexpr int STORAGE_MANAGER_UID = 5003;
const int32_t ERR_NUM = -1;

void PtpMediaSyncObserverUnitTest::SetUpTestCase(void)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return;
    }
    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID);
    if (dataShareHelper_ == nullptr) {
        dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
}

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
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_001, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    mediaSyncObserver->SendEventPackets(MTP_FORMAT_TEST_CODE_2, MTP_FORMAT_TEST_CODE);
    mediaSyncObserver->context_ = std::make_shared<MtpOperationContext>();
    ASSERT_NE(mediaSyncObserver->context_, nullptr);
    mediaSyncObserver->SendEventPacketAlbum(MTP_FORMAT_TEST_CODE_2, MTP_FORMAT_TEST_CODE);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandlesFromPhotosInfoBurstKeys
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_002, TestSize.Level1)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    vector<string> handles = {"1", "2"};
    mediaSyncObserver->GetHandlesFromPhotosInfoBurstKeys(handles);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAllDeleteHandles
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_003, TestSize.Level1)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    mediaSyncObserver->GetAllDeleteHandles();

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPhotoHandle
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_004, TestSize.Level1)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    mediaSyncObserver->AddPhotoHandle(HANDLE_TEST);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAddEditPhotoHandles
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_005, TestSize.Level1)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    mediaSyncObserver->GetAddEditPhotoHandles(HANDLE_TEST);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetAddEditAlbumHandle
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_006, TestSize.Level1)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendPhotoRemoveEvent
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_007, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    std::string suffixString = "";
    mediaSyncObserver->SendPhotoRemoveEvent(suffixString);
    suffixString = "123";
    mediaSyncObserver->SendPhotoRemoveEvent(suffixString);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendPhotoEvent
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_008, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    std::string suffixString = "123";
    mediaSyncObserver->SendPhotoEvent(OHOS::DataShare::DataShareObserver::ChangeType::INSERT, suffixString);
    mediaSyncObserver->SendPhotoEvent(OHOS::DataShare::DataShareObserver::ChangeType::DELETE, suffixString);
    mediaSyncObserver->SendPhotoEvent(OHOS::DataShare::DataShareObserver::ChangeType::UPDATE, suffixString);
    mediaSyncObserver->SendPhotoEvent(OHOS::DataShare::DataShareObserver::ChangeType::INVAILD, suffixString);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendPhotoEvent GetOwnerAlbumIdList
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_009, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);

    std::set<int32_t> albumIds = {1, 2, 3, 4, 5};
    mediaSyncObserver->GetAlbumIdList(albumIds);
    mediaSyncObserver->GetOwnerAlbumIdList(albumIds);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEventToPTP
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_010, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    auto albumHandles = PtpAlbumHandles::GetInstance();
    if (albumHandles == nullptr) {
        albumHandles->AddHandle(1);
    }

    mediaSyncObserver->context_ = std::make_shared<MtpOperationContext>();
    ASSERT_NE(mediaSyncObserver->context_, nullptr);

    std::vector<int32_t> albumIds = {1, 2, 3, 4, 5};
    mediaSyncObserver->SendEventToPTP(OHOS::DataShare::DataShareObserver::ChangeType::INSERT, albumIds);
    mediaSyncObserver->SendEventToPTP(OHOS::DataShare::DataShareObserver::ChangeType::DELETE, albumIds);
    mediaSyncObserver->SendEventToPTP(OHOS::DataShare::DataShareObserver::ChangeType::UPDATE, albumIds);
    mediaSyncObserver->SendEventToPTP(OHOS::DataShare::DataShareObserver::ChangeType::INVAILD, albumIds);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ParseNotifyData
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_011, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    DataShare::DataShareObserver::ChangeInfo changeInfo;
    vector<string> fileIds = {"file_001", "file_002", "file_003"};
    mediaSyncObserver->ParseNotifyData(changeInfo, fileIds);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnChange
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_014, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    DataShare::DataShareObserver::ChangeInfo changeInfo;
    mediaSyncObserver->OnChange(changeInfo);

    int32_t res = mediaSyncObserver->GetAddEditAlbumHandle(HANDLE_TEST);
    EXPECT_EQ(res, ERR_NUM);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ParseNotifyData
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_015, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    DataShare::DataShareObserver::ChangeInfo changeInfo;
    changeInfo.data_ = nullptr;
    vector<string> fileIds = {"file_001", "file_002", "file_003"};
    bool res = mediaSyncObserver->ParseNotifyData(changeInfo, fileIds);
    EXPECT_FALSE(res);

    changeInfo.size_ = 0;
    size_t size = 5;
    changeInfo.data_ = malloc(size);
    ASSERT_NE(changeInfo.data_, nullptr);
    res = mediaSyncObserver->ParseNotifyData(changeInfo, fileIds);
    free(const_cast<void*>(changeInfo.data_));
    changeInfo.data_ = nullptr;
    EXPECT_FALSE(res);

    changeInfo.size_ = 1;
    changeInfo.data_ = malloc(changeInfo.size_);
    ASSERT_NE(changeInfo.data_, nullptr);
    res = mediaSyncObserver->ParseNotifyData(changeInfo, fileIds);
    free(const_cast<void*>(changeInfo.data_));
    changeInfo.data_ = nullptr;
    EXPECT_FALSE(res);
}

/*
 * Feature: ptp_media_sync_observer.cpp
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HandleMovePhotoEvent
 */
HWTEST_F(PtpMediaSyncObserverUnitTest, ptp_media_sync_observer_016, TestSize.Level1)
{
    std::shared_ptr<MediaSyncObserver> mediaSyncObserver = std::make_shared<MediaSyncObserver>();
    ASSERT_NE(mediaSyncObserver, nullptr);
    DataShare::DataShareObserver::ChangeInfo changeInfo;
    changeInfo.changeType_ = DataShare::DataShareObserver::ChangeType::INSERT;
    mediaSyncObserver->HandleMovePhotoEvent(changeInfo);

    changeInfo.changeType_ = DataShare::DataShareObserver::ChangeType::DELETE;
    mediaSyncObserver->HandleMovePhotoEvent(changeInfo);
}
} // namespace Media
} // namespace OHOS