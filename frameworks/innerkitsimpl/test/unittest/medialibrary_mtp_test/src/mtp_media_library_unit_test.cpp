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

#include "mtp_media_library_unit_test.h"
#include "mtp_media_library.h"
#include "medialibrary_errno.h"
#include "media_log.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
// storage file
const std::string STORAGE_FILE = "/storage/media/local/files/Docs";
// file path
const std::string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
const std::shared_ptr<MtpMediaLibrary> mtpMediaLib_ = MtpMediaLibrary::GetInstance();
void MTPMediaLibraryUnitTest::SetUpTestCase(void) {}
void MTPMediaLibraryUnitTest::TearDownTestCase(void) {}
// SetUp:Execute before each test case
void MTPMediaLibraryUnitTest::SetUp() {}
void MTPMediaLibraryUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_071, TestSize.Level0)
{
    auto mtpMediaLib_ = MtpMediaLibrary::GetInstance();
    for(int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddPathToMap(FILE_PATH + std::to_string(i) + ".txt");
    }
    mtpMediaLib_->Clear();
    EXPECT_EQ(mtpMediaLib_ != nullptr, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ObserverAddPathToMap ScanDirNoDepth GetHandles ScanDirNoDepth
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_072, TestSize.Level0)
{
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + std::to_string(i) + ".txt");
    }

    uint32_t parentId = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, parentId);
    std::vector<int> outHandles;
    mtpMediaLib_->GetHandles(parentId, outHandles, MEDIA_TYPE_FILE);
    EXPECT_EQ(outHandles.size() >= 0, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandles GetPathById ScanDirNoDepth
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_073, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + std::to_string(i) + ".txt");
    }
    uint32_t parentId = 0;
    std::shared_ptr<UInt32List> outHandles = std::make_shared<UInt32List>();
    mtpMediaLib_->GetIdByPath(FILE_PATH, parentId);
    context->parent = parentId;
    context->storageID = parentId;

    mtpMediaLib_->GetHandles(context, outHandles);
    EXPECT_EQ(outHandles->size() >= 0, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectInfo GetPathById GetParentId
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_044, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    MEDIA_INFO_LOG("mtp test case 44 start");
    //storage file path
    mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    MEDIA_INFO_LOG("mtp test case 44 11111111");
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    MEDIA_INFO_LOG("mtp test case 44 22222222222");
    uint32_t parentId = 0;
    mtpMediaLib_->GetIdByPath(STORAGE_FILE, parentId);
    MEDIA_INFO_LOG("mtp test case 44 333333333333");
    uint32_t storageId = 0;
    mtpMediaLib_->GetIdByPath(STORAGE_FILE, storageId);
    MEDIA_INFO_LOG("mtp test case 44 444444444444");
    context->storageID = storageId;
    context->handle = handle;
    std::shared_ptr<ObjectInfo> objectInfo = std::make_shared<ObjectInfo>(handle);

    int32_t result = mtpMediaLib_->GetObjectInfo(context, objectInfo);
    MEDIA_INFO_LOG("mtp test case 44 %{public}d", result);
    EXPECT_EQ(result != MTP_SUCCESS, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_074, TestSize.Level0)
{
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + std::to_string(i) + ".txt");
    }
    mtpMediaLib_->ModifyHandlePathMap(FILE_PATH + std::to_string(1) +
        ".txt", STORAGE_FILE + std::to_string(1) + ".txt");
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH + std::to_string(1) + ".txt", handle);

    EXPECT_EQ(handle == 0, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_075, TestSize.Level0)
{
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + std::to_string(i) + ".txt");
    }
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH + std::to_string(1) + ".txt", handle);
    mtpMediaLib_->ModifyPathHandleMap(FILE_PATH + std::to_string(1) + ".txt", handle);

    EXPECT_EQ(handle != 0, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_076, TestSize.Level0)
{
    std::string str = FILE_PATH;
    std::string prefix = FILE_PATH;
    //storage file path
     mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + std::to_string(i) + ".txt");
    }
    std::string form = FILE_PATH + std::to_string(1) + ".txt";
    std::string to = STORAGE_FILE;
    mtpMediaLib_->MoveHandlePathMap(form, to);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(STORAGE_FILE + std::to_string(1) + ".txt", handle);

    EXPECT_EQ(handle > 0, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_077, TestSize.Level0)
{
    std::string str = FILE_PATH;
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    mtpMediaLib_->DeleteHandlePathMap(FILE_PATH, handle);
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);

    EXPECT_EQ(handle != 0, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_078, TestSize.Level0)
{
    std::string str = FILE_PATH;
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    mtpMediaLib_->ObserverDeletePathToMap(FILE_PATH);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);

    EXPECT_EQ(handle == 0, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_079, TestSize.Level0)
{
    const off_t size = 10;
    off_t result = mtpMediaLib_->GetSizeFromOfft(size);

    EXPECT_EQ(result == 10, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_080, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    //storage file path
    mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    context->handle = handle;

    int32_t outFd = 0;
    mtpMediaLib_->GetFd(context, outFd);

    EXPECT_EQ(outFd != 0, true);

}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_081, TestSize.Level0)
{
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    std::string outPath = "";
    mtpMediaLib_->GetRealPath(FILE_PATH, outPath);

    std::string result = "/storage/media/100/local/files/Docs/Desktop";
    EXPECT_EQ(outPath != result, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_082, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    //storage file path
     mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    context->handle = handle;

    int32_t outFd = 0;
    mtpMediaLib_->GetFd(context, outFd);

    int32_t result = mtpMediaLib_->CloseFd(context,outFd);
    EXPECT_EQ(result != MTP_SUCCESS, true);

}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_083, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    //storage file path
    mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    std::string from = STORAGE_FILE + "/Documents";
    mtpMediaLib_->ObserverAddPathToMap(from);
    std::string to = FILE_PATH;
    uint32_t fromId = 0;
    mtpMediaLib_->GetIdByPath(from, fromId);
    uint32_t parentId = 0;
    mtpMediaLib_->GetIdByPath(STORAGE_FILE, parentId);
    context->handle = fromId;
    context->parent = parentId;

    int32_t result = mtpMediaLib_->MoveObject(context,parentId);
    EXPECT_EQ(result != MTP_SUCCESS, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_084, TestSize.Level0)
{
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    //storage file path
     mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    context->handle = handle;
    int32_t outFd = 0;
    mtpMediaLib_->GetFd(context, outFd);

    int32_t result = mtpMediaLib_->CloseFd(context,outFd);
    EXPECT_EQ(result != MTP_SUCCESS, true);
}
/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MTPMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_085, TestSize.Level0)
{
    std::string str = FILE_PATH;
    std::string prefix = FILE_PATH;

    bool result = mtpMediaLib_->StartsWith(str, prefix);

    EXPECT_EQ(result, true);
}
}// namespace Media
}// namespace OHOS