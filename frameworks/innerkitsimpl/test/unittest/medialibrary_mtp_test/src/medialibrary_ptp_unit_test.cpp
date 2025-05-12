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

#include "medialibrary_ptp_unit_test.h"

#include <thread>
#include <iomanip>
#include <unistd.h>
#include "mtp_driver.h"
#include "media_log.h"
#include "mtp_operation.h"
#include "mtp_service.h"
#include "mtp_test.h"
#include "mtp_manager.h"
#include "mtp_medialibrary_manager.h"
#include "system_ability_definition.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

const int32_t DEFAULT_PHOTO_ID = 100000001;
const std::string MEDIA_FILEMODE_READWRITE = "rw";
const std::shared_ptr<MtpOperationContext> g_context = {};
const sptr<IRemoteObject> token = nullptr;
std::shared_ptr<MtpOperation> operationPtr_;
const std::string DEFAULT_THUMBSIZE = "100x100";
const std::string DEFAULT_DATA_PATH = "/data/media/image";

void MediaLibraryPTPUnitTest::SetUpTestCase(void) {}

void MediaLibraryPTPUnitTest::TearDownTestCase(void) {}
// SetUp:Execute before each test case
void MediaLibraryPTPUnitTest::SetUp()
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::PTP_MODE;
    if (operationPtr_ == nullptr) {
        operationPtr_ = make_shared<MtpOperation>();
    }
}

void MediaLibraryPTPUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_001, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);
    (void) mtpMedialibraryManager->Clear();
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_002, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);
    int32_t parentId = 0;
    vector<int> outHandles = {};
    MediaType mediaType = MediaType::MEDIA_TYPE_IMAGE;
    mtpMedialibraryManager->GetHandles(parentId, outHandles, mediaType);

    parentId = DEFAULT_PHOTO_ID;
    mtpMedialibraryManager->GetHandles(parentId, outHandles, mediaType);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_003, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);
    bool isHandle = true;
    mtpMedialibraryManager->GetAlbumInfo(g_context, isHandle);

    isHandle = false;
    mtpMedialibraryManager->GetAlbumInfo(g_context, isHandle);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_004, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);
    bool isHandle = true;
    mtpMedialibraryManager->GetPhotosInfo(g_context, isHandle);

    isHandle = false;
    mtpMedialibraryManager->GetPhotosInfo(g_context, isHandle);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_005, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);
    (void) mtpMedialibraryManager->GetBurstKeyFromPhotosInfo();
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_006, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    const shared_ptr<DataShare::DataShareResultSet> resultSet = nullptr;
    shared_ptr<UInt32List> outHandles = {};
    const uint32_t parent = DEFAULT_PHOTO_ID;
    FileCountInfo fileCountInfo;
    int32_t ret = mtpMedialibraryManager->HaveMovingPhotesHandle(resultSet, outHandles, parent, fileCountInfo);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_07, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    const off_t offset = 0;
    (void) mtpMedialibraryManager->GetSizeFromOfft(offset);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_008, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    const shared_ptr<DataShare::DataShareResultSet> resultSet = nullptr;
    mtpMedialibraryManager->SetObject(resultSet, g_context, outObjectInfo);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_009, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    const unique_ptr<FileAsset> fileAsset = make_unique<FileAsset>();
    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    mtpMedialibraryManager->SetObjectInfo(fileAsset, outObjectInfo);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_010, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    int32_t outFd = 1;
    const std::string mode = MEDIA_FILEMODE_READWRITE;
    mtpMedialibraryManager->GetFd(g_context, outFd, mode);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_011, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    int32_t outFd = 1;
    mtpMedialibraryManager->GetFdByOpenFile(g_context, outFd);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_012, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    std::unique_ptr<PixelMap> pixelMap = nullptr;
    std::vector<uint8_t> data  = {};
    mtpMedialibraryManager->CompressImage(pixelMap, data);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_013, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    shared_ptr<UInt8List> outThumb = nullptr;
    mtpMedialibraryManager->GetThumb(g_context, outThumb);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_014, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    const int32_t handle = DEFAULT_PHOTO_ID;
    const std::string thumbSizeValue = DEFAULT_THUMBSIZE;
    const std::string dataPath = DEFAULT_DATA_PATH;
    mtpMedialibraryManager->GetThumbUri(handle, thumbSizeValue, dataPath);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_015, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    bool isConditionTrue = true;
    const int fd = 0;
    mtpMedialibraryManager->CondCloseFd(isConditionTrue, fd);
    isConditionTrue = false;
    mtpMedialibraryManager->CondCloseFd(isConditionTrue, fd);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_016, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    std::shared_ptr<UInt8List> outThumb = nullptr;
    mtpMedialibraryManager->GetPictureThumb(g_context, outThumb);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_017, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    std::shared_ptr<UInt8List> outThumb = nullptr;
    mtpMedialibraryManager->GetVideoThumb(g_context, outThumb);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_018, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    const std::string path = DEFAULT_DATA_PATH;
    uint32_t outId = 0;
    mtpMedialibraryManager->GetIdByPath(path, outId);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_019, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    uint32_t outStorageID = 0;
    uint32_t outParent = 0;
    uint32_t outHandle = 0;
    mtpMedialibraryManager->SendObjectInfo(g_context, outStorageID, outParent, outHandle);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_020, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    mtpMedialibraryManager->MoveObject(g_context);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_021, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    uint32_t outObjectHandle = 0;
    mtpMedialibraryManager->CopyObject(g_context, outObjectHandle);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_022, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    mtpMedialibraryManager->DeleteObject(g_context);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_023, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    mtpMedialibraryManager->SetObjectPropValue(g_context);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_024, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    int32_t fd = 1;
    mtpMedialibraryManager->CloseFdForGet(g_context, fd);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_025, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    int32_t fd = 1;
    mtpMedialibraryManager->CloseFd(g_context, fd);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_026, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    std::shared_ptr<std::vector<Property>> outProps = nullptr;
    mtpMedialibraryManager->GetObjectPropList(g_context, outProps);
}

/*
 * Feature: MediaLibraryPTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MTP_OPERATION_OPEN_SESSION_CODE
 */
HWTEST_F(MediaLibraryPTPUnitTest, medialibrary_PTP_message_testlevel0_027, TestSize.Level1)
{
    std::shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    EXPECT_NE(mtpMedialibraryManager, nullptr);

    uint64_t outIntVal = 0;
    uint128_t outLongVal = {0};
    std::string outStrVal = "";
    mtpMedialibraryManager->GetObjectPropValue(g_context, outIntVal, outLongVal, outStrVal);
}
} // namespace Media
} // namespace OHOS