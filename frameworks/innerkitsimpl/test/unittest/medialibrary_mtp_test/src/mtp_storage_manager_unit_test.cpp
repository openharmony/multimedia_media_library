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

#include <thread>
#include "mtp_storage_manager_unit_test.h"
#include "mtp_storage_manager.h"
#include "mtp_manager.h"
#include "mtp_constants.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

const std::string TEST_PATH_DATA = "/storage/media/local/files/Docs/Desktop";
const std::shared_ptr<MtpStorageManager> mtpStorageManager_ = MtpStorageManager::GetInstance();

void MtpStorageManagerUnitTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void MtpStorageManagerUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MtpStorageManagerUnitTest::SetUp() {}
void MtpStorageManagerUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetTotalSize
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_01, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    int64_t res = mtpStorageManager_->GetTotalSize(TEST_PATH_DATA);
    EXPECT_GE(res, 0);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetTotalSize
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_02, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    int64_t res = mtpStorageManager_->GetTotalSize("");
    EXPECT_GE(res, 0);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFreeSize
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_03, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    int64_t res = mtpStorageManager_->GetFreeSize(TEST_PATH_DATA);
    EXPECT_GE(res, 0);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFreeSize
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_04, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    int64_t res = mtpStorageManager_->GetFreeSize(TEST_PATH_DATA);
    EXPECT_GE(res, 0);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddStorage
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_05, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpStorageManager_->AddStorage(storage);
    EXPECT_FALSE(mtpStorageManager_->storages.empty());
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: RemoveStorage GetStorage
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_06, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpStorageManager_->RemoveStorage(storage);

    uint32_t id = 1;
    shared_ptr<Storage> res = mtpStorageManager_->GetStorage(id);
    EXPECT_EQ(res, nullptr);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HasStorage
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_07, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    uint32_t id = 1;
    bool res = mtpStorageManager_->HasStorage(id);
    EXPECT_FALSE(res);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HasStorage ClearStorages
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_08, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    mtpStorageManager_->ClearStorages();

    uint32_t id = MTP_STORAGE_ID_ALL;
    bool res = mtpStorageManager_->HasStorage(id);
    EXPECT_FALSE(res);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: HasStorage
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_09, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    uint32_t id = MTP_STORAGE_ID_ALL2;
    bool res = mtpStorageManager_->HasStorage(id);
    EXPECT_FALSE(res);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorages
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_10, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    std::vector<std::shared_ptr<Storage>> storages = mtpStorageManager_->GetStorages();
    EXPECT_TRUE(storages.empty());
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorageDescription
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_11, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    uint16_t type = MTP_STORAGE_FIXEDRAM;
    std::string description = mtpStorageManager_->GetStorageDescription(type);
    EXPECT_NE(description, "");
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorageDescription
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_12, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    uint16_t type = MTP_STORAGE_REMOVABLERAM;
    std::string description = mtpStorageManager_->GetStorageDescription(type);
    EXPECT_NE(description, "");
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorageDescription
 */
HWTEST_F(MtpStorageManagerUnitTest, medialibrary_PTP_message_testlevel_0_13, TestSize.Level1)
{
    ASSERT_NE(mtpStorageManager_, nullptr);
    mtpStorageManager_->ClearStorages();

    uint16_t type = MTP_STORAGE_REMOVABLEROM;
    std::string UNSPECIFIED = "Unspecified";
    std::string description = mtpStorageManager_->GetStorageDescription(type);
    EXPECT_EQ(description, UNSPECIFIED);
}
} // namespace Media
} // namespace OHOS