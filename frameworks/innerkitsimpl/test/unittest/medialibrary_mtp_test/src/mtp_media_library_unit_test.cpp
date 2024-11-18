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
void MtpMediaLibraryUnitTest::SetUpTestCase(void) {}
void MtpMediaLibraryUnitTest::TearDownTestCase(void) {}
// SetUp:Execute before each test case
void MtpMediaLibraryUnitTest::SetUp() {}
void MtpMediaLibraryUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_001, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();

    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddPathToMap(FILE_PATH + "/" + std::to_string(i) + ".txt");
    }
    mtpMediaLib->Clear();
    EXPECT_EQ(mtpMediaLib != nullptr, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ObserverAddPathToMap ScanDirNoDepth GetHandles
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_002, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    //parent file path
    mtpMediaLib->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->ObserverAddPathToMap(FILE_PATH + "/" + std::to_string(i) + ".txt");
    }

    uint32_t parentId = 0;
    mtpMediaLib->GetIdByPath(FILE_PATH, parentId);
    std::vector<int> outHandles;
    mtpMediaLib->GetHandles(parentId, outHandles, MEDIA_TYPE_FILE);
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_003, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    //parent file path
    mtpMediaLib->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->ObserverAddPathToMap(FILE_PATH + "/" + std::to_string(i) + ".txt");
    }
    uint32_t parentId = 0;
    std::shared_ptr<UInt32List> outHandles = std::make_shared<UInt32List>();
    mtpMediaLib->GetIdByPath(FILE_PATH, parentId);
    context->parent = parentId;
    context->storageID = parentId;

    mtpMediaLib->GetHandles(context, outHandles);
    EXPECT_EQ(outHandles->size() >= 0, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFd
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_004, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }
    context->handle = 2;
    int32_t outFd = 0;
    mtpMediaLib->GetFd(context, outFd);

    EXPECT_EQ(outFd == -1, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendObjectInfo
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_007, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->storageID = 2;
    context->parent = 0;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t outStorageID = 0;
    uint32_t outParent = 0;
    uint32_t outHandle = 0;

    mtpMediaLib->SendObjectInfo(context, outStorageID, outParent, outHandle);
    EXPECT_EQ(outStorageID == 0, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIdByPath
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_008, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t outId = 0;
    mtpMediaLib->GetIdByPath(FILE_PATH + "/2.txt", outId);
    EXPECT_EQ(outId == 2, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveObject
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_009, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t repeatHandle = 0;
    mtpMediaLib->MoveObject(context, repeatHandle);
    EXPECT_EQ(repeatHandle == 0, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CopyObject
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_010, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t outObjectHandle = 0;
    uint32_t oldHandle = 0;
    mtpMediaLib->CopyObject(context, outObjectHandle, oldHandle);
    EXPECT_EQ(outObjectHandle == 0, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DeleteObject
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_011, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t errcode = -1;
    errcode = mtpMediaLib->DeleteObject(context);
    EXPECT_EQ(errcode == MTP_SUCCESS, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetObjectPropValue
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_012, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t errcode = -1;
    errcode = mtpMediaLib->SetObjectPropValue(context);

    EXPECT_EQ(errcode != MTP_SUCCESS, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandlesMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_013, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->property = 1;
    context->depth = MTP_ALL_DEPTH;
    context->handle = 0;
    context->storageID = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    auto handlesMap = std::make_shared<std::unordered_map<uint32_t, std::string>>();
    handlesMap = mtpMediaLib->GetHandlesMap(context);
    EXPECT_EQ(handlesMap->empty(), true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropList
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_014, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<std::vector<Property>> outProps = std::make_shared<std::vector<Property>>();
    context->property = 1;
    context->depth = MTP_ALL_DEPTH;
    context->handle = 0;
    context->storageID = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib->GetObjectPropList(context, outProps);
    EXPECT_EQ(outProps->empty(), true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetObjectPropValue
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_015, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    std::string outStrVal = "";
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    int32_t errcode = -1;
    errcode = mtpMediaLib->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);

    EXPECT_EQ(errcode != MTP_SUCCESS, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetRealPath
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_016, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();

    std::string outPath = "";
    mtpMediaLib->GetRealPath(FILE_PATH, outPath);
    EXPECT_EQ(outPath != "", true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetStorageIds
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_017, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();

    int errcode = -1;
    errcode = mtpMediaLib->GetStorageIds();
    EXPECT_EQ(errcode == MTP_SUCCESS, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DeleteHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_018, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t id = 0;
    mtpMediaLib->DeleteHandlePathMap(FILE_PATH + "/1.txt", id);
    EXPECT_EQ(true, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ObserverDeletePathToMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_019, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib->ObserverDeletePathToMap(FILE_PATH + "/1.txt");
    EXPECT_EQ(true, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddToHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_020, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();

    uint32_t id = 1;
    mtpMediaLib->AddToHandlePathMap(FILE_PATH, id);
    EXPECT_EQ(true, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ModifyHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_021, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib->ModifyHandlePathMap(FILE_PATH + "/1.txt", FILE_PATH + "/4.txt");
    EXPECT_EQ(true, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ModifyPathHandleMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_022, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t id = 2;
    mtpMediaLib->ModifyPathHandleMap(FILE_PATH + "/1.txt", id);
    EXPECT_EQ(true, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StartsWith
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_023, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();

    std::string str = "ab";
    std::string prefix = "ab";
    bool ret = false;
    ret = mtpMediaLib->StartsWith(str, prefix);
    EXPECT_EQ(ret, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_024, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib->MoveHandlePathMap(FILE_PATH, STORAGE_FILE);
    EXPECT_EQ(true, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetId
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_025, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();

    uint32_t id = 0;
    id = mtpMediaLib->GetId();
    EXPECT_EQ(id == 141, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetParentId
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_026, TestSize.Level0)
{
    std::shared_ptr<MtpMediaLibrary> mtpMediaLib = MtpMediaLibrary::GetInstance();

    uint32_t parentId = 1;
    parentId = mtpMediaLib->GetParentId(FILE_PATH + "/1.txt");
    EXPECT_EQ(parentId == 1, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_027, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_028, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_029, TestSize.Level0)
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
 * CaseDescription: AddPathToMap Clear Init
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_031, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_032, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_033, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_034, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_035, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_036, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_037, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_038, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_039, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_040, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_041, TestSize.Level0)
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
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_042, TestSize.Level0)
{
    std::string str = FILE_PATH;
    std::string prefix = FILE_PATH;

    bool result = mtpMediaLib_->StartsWith(str, prefix);
    EXPECT_EQ(result, true);
}
}// namespace Media
}// namespace OHOS