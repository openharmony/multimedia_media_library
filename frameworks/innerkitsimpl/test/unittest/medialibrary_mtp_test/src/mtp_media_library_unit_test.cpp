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
#include "mtp_storage_manager.h"
#include "object_info.h"

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
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddPathToMap(FILE_PATH + "/" + std::to_string(i) + ".txt");
    }

    mtpMediaLib_->Clear();
    EXPECT_EQ(mtpMediaLib_->id_, 130);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + "/" + std::to_string(i) + ".txt");
    }

    uint32_t parentId = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, parentId);
    std::vector<int> outHandles;
    mtpMediaLib_->GetHandles(parentId, outHandles, MEDIA_TYPE_FILE);
    EXPECT_GE(outHandles.size(), 0);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + "/" + std::to_string(i) + ".txt");
    }

    uint32_t parentId = 0;
    std::shared_ptr<UInt32List> outHandles = std::make_shared<UInt32List>();
    mtpMediaLib_->GetIdByPath(FILE_PATH, parentId);
    context->parent = parentId;
    context->storageID = parentId;
    mtpMediaLib_->GetHandles(context, outHandles);
    EXPECT_GE(outHandles->size(), 0);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    context->handle = 2;
    int32_t outFd = 0;
    mtpMediaLib_->GetFd(context, outFd);
    EXPECT_EQ(outFd, -1);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->storageID = 2;
    context->parent = 0;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t outStorageID = 0;
    uint32_t outParent = 0;
    uint32_t outHandle = 0;
    mtpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);
    EXPECT_EQ(outStorageID, 0);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t outId = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH + "/2.txt", outId);
    EXPECT_EQ(outId, 2);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t repeatHandle = 0;
    mtpMediaLib_->MoveObject(context, repeatHandle);
    EXPECT_EQ(repeatHandle, 0);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t outObjectHandle = 0;
    uint32_t oldHandle = 0;
    mtpMediaLib_->CopyObject(context, outObjectHandle, oldHandle);
    EXPECT_EQ(outObjectHandle, 0);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t errcode = 1;
    errcode = mtpMediaLib_->DeleteObject(context);
    EXPECT_EQ(errcode, MTP_SUCCESS);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t errcode = -1;
    errcode = mtpMediaLib_->SetObjectPropValue(context);
    EXPECT_NE(errcode, MTP_SUCCESS);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    context->property = 1;
    context->depth = MTP_ALL_DEPTH;
    context->handle = 0;
    context->storageID = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    auto handlesMap = std::make_shared<std::unordered_map<uint32_t, std::string>>();
    handlesMap = mtpMediaLib_->GetHandlesMap(context);
    EXPECT_TRUE(handlesMap->empty());
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<std::vector<Property>> outProps = std::make_shared<std::vector<Property>>();
    context->property = 1;
    context->depth = MTP_ALL_DEPTH;
    context->handle = 0;
    context->storageID = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->GetObjectPropList(context, outProps);
    EXPECT_TRUE(outProps->empty());
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    std::string outStrVal = "";
    context->handle = 1;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    int32_t errcode = -1;
    errcode = mtpMediaLib_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
    EXPECT_NE(errcode, MTP_SUCCESS);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::string outPath = "";
    mtpMediaLib_->GetRealPath(FILE_PATH, outPath);
    EXPECT_NE(outPath, "");
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    int errcode = -1;
    errcode = mtpMediaLib_->GetStorageIds();
    EXPECT_EQ(errcode, MTP_SUCCESS);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t id = 0;
    mtpMediaLib_->DeleteHandlePathMap(FILE_PATH + "/1.txt", id);
    uint32_t outId = 0;
    int32_t errcode = mtpMediaLib_->GetIdByPath(FILE_PATH + "/1.txt", outId);
    EXPECT_EQ(errcode, E_NO_SUCH_FILE);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->ObserverDeletePathToMap(FILE_PATH + "/1.txt");
    uint32_t outId = 0;
    int32_t errcode = mtpMediaLib_->GetIdByPath(FILE_PATH + "/1.txt", outId);
    EXPECT_EQ(errcode, E_NO_SUCH_FILE);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    uint32_t id = 1;
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH, id);
    uint32_t outId = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, outId);
    EXPECT_EQ(outId, 1);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->ModifyHandlePathMap(FILE_PATH + "/1.txt", FILE_PATH + "/11.txt");
    uint32_t outId = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH + "/11.txt", outId);
    EXPECT_EQ(outId, 1);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t id = 12;
    mtpMediaLib_->ModifyPathHandleMap(FILE_PATH + "/1.txt", id);
    uint32_t outId = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH + "/1.txt", outId);
    EXPECT_EQ(outId, 12);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::string str = "ab";
    std::string prefix = "ab";
    bool ret = false;
    ret = mtpMediaLib_->StartsWith(str, prefix);
    EXPECT_TRUE(ret);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->MoveHandlePathMap(FILE_PATH, STORAGE_FILE);
    uint32_t outId = 0;
    int32_t errcode = mtpMediaLib_->GetIdByPath(FILE_PATH + "/1.txt", outId);
    EXPECT_EQ(errcode, E_NO_SUCH_FILE);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    uint32_t id = 0;
    id = mtpMediaLib_->GetId();
    EXPECT_EQ(id, 141);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    uint32_t parentId = 1;
    parentId = mtpMediaLib_->GetParentId(FILE_PATH + "/1.txt");
    EXPECT_EQ(parentId, 1);
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
    ASSERT_NE(mtpMediaLib_, nullptr);
    for(int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddPathToMap(FILE_PATH + std::to_string(i) + ".txt");
    }

    mtpMediaLib_->Clear();
    EXPECT_EQ(mtpMediaLib_->id_, 130);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandles
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_028, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
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
    EXPECT_GE(outHandles.size(), 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetHandles
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_029, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
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
    EXPECT_GE(outHandles->size(), 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ModifyHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_031, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
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
    EXPECT_EQ(handle, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ModifyPathHandleMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_032, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + std::to_string(i) + ".txt");
    }

    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH + std::to_string(1) + ".txt", handle);
    mtpMediaLib_->ModifyPathHandleMap(FILE_PATH + std::to_string(1) + ".txt", handle);
    EXPECT_NE(handle, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_033, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
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
    EXPECT_GT(handle, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIdByPath
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_034, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::string str = FILE_PATH;
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    mtpMediaLib_->DeleteHandlePathMap(FILE_PATH, handle);
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    EXPECT_NE(handle, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetIdByPath
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_035, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::string str = FILE_PATH;
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    mtpMediaLib_->ObserverDeletePathToMap(FILE_PATH);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    EXPECT_EQ(handle, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetSizeFromOfft
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_036, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    const off_t size = 10;
    off_t result = mtpMediaLib_->GetSizeFromOfft(size);
    EXPECT_EQ(result, 10);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFd
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_037, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
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
    EXPECT_NE(outFd, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetRealPath
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_038, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    std::string outPath = "";
    mtpMediaLib_->GetRealPath(FILE_PATH, outPath);
    std::string result = "/storage/media/100/local/files/Docs/Desktop";
    EXPECT_NE(outPath, result);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CloseFd
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_039, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
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
    EXPECT_NE(result, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveObject
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_040, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
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
    EXPECT_NE(result, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StartsWith
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_041, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
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
    int32_t result = mtpMediaLib_->CloseFd(context, outFd);
    EXPECT_NE(result, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StartsWith
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_042, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::string str = FILE_PATH;
    std::string prefix = FILE_PATH;
    bool result = mtpMediaLib_->StartsWith(str, prefix);
    EXPECT_TRUE(result);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CompressImage
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_045, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    OHOS::Media::PixelMap pixelMap;
    std::vector<uint8_t> data;
    bool res = false;
    res = mtpMediaLib_->CompressImage(pixelMap, data);
    EXPECT_FALSE(res);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveObjectSub
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_046, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->AddToHandlePathMap(STORAGE_FILE, 11);
    bool isDir = false;
    uint32_t repeatHandle = 0;
    uint32_t errcode = 1;
    errcode = mtpMediaLib_->MoveObjectSub(FILE_PATH, STORAGE_FILE, isDir, repeatHandle);
    EXPECT_EQ(errcode, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetThumb
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_047, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<UInt8List> outThumb = std::make_shared<UInt8List>();
    context->handle = 2;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t errcode = 1;
    errcode = mtpMediaLib_->GetThumb(context, outThumb);
    EXPECT_EQ(errcode, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CloseFd
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_048, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    context->handle = handle;
    int32_t outFd = 0;
    mtpMediaLib_->GetFd(context, outFd);
    uint32_t errcode = 1;
    errcode = mtpMediaLib_->CloseFd(context, outFd);
    EXPECT_NE(errcode, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetVideoThumb
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_049, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<UInt8List> outThumb = std::make_shared<UInt8List>();
    context->handle = 2;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->GetVideoThumb(context, outThumb);
    EXPECT_EQ(outThumb->size(), 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPictureThumb
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_050, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<UInt8List> outThumb = std::make_shared<UInt8List>();
    context->handle = 2;
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->GetPictureThumb(context, outThumb);
    EXPECT_EQ(outThumb->size(), 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ScanDirWithType
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_051, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> out =
        std::make_shared<std::unordered_map<uint32_t, std::string>>();
    uint32_t errcode = 1;
    errcode = mtpMediaLib_->ScanDirWithType(STORAGE_FILE, out);
    EXPECT_NE(errcode, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveRepeatDirHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_052, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->AddToHandlePathMap(FILE_PATH, 11);
    mtpMediaLib_->AddToHandlePathMap(STORAGE_FILE, 12);
    mtpMediaLib_->MoveRepeatDirHandlePathMap(FILE_PATH, STORAGE_FILE);
    uint32_t outId = 0;
    int32_t errcode = mtpMediaLib_->GetIdByPath(FILE_PATH + "/1.txt", outId);
    EXPECT_EQ(errcode, E_NO_SUCH_FILE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ScanDirTraverseWithType
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_053, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> out =
        std::make_shared<std::unordered_map<uint32_t, std::string>>();
    uint32_t errcode = 1;
    errcode = mtpMediaLib_->ScanDirTraverseWithType(STORAGE_FILE, out);
    EXPECT_NE(errcode, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ErasePathInfo
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_055, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t handle = 12;
    mtpMediaLib_->ErasePathInfo(handle, STORAGE_FILE);
    uint32_t outId = 0;
    int32_t errcode = mtpMediaLib_->GetIdByPath(FILE_PATH + "/1.txt", outId);
    EXPECT_EQ(errcode, E_NO_SUCH_FILE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetExternalStorages
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_056, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::string path = FILE_PATH;
    mtpMediaLib_->GetExternalStorages();

    int64_t result = MtpStorageManager::GetInstance()->GetTotalSize(STORAGE_FILE);
    EXPECT_EQ(result, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveRepeatDirHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_057, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    // storage file path
     mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    // parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);

    std::string from = STORAGE_FILE;
    std::string to = FILE_PATH;
    mtpMediaLib_->MoveRepeatDirHandlePathMap(from, to);

    uint32_t outId = 0;
    std::string resultPath = FILE_PATH + "/Docs";
    mtpMediaLib_->GetIdByPath(FILE_PATH, outId);
    EXPECT_GT(outId, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveObjectSub
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_058, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    // storage file path
     mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    // parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    std::string from = STORAGE_FILE;
    std::string to = FILE_PATH;
    uint32_t repeatHandle = 0;
    uint32_t result = mtpMediaLib_->MoveObjectSub(from, to, false, repeatHandle);

    EXPECT_EQ(result, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ScanDirWithType
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_059, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    std::string root = FILE_PATH;
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> outMap;
    mtpMediaLib_->ScanDirWithType(root, outMap);

    EXPECT_GE(outMap->size(), 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ErasePathInfo
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_060, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    // parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, handle);
    mtpMediaLib_->ErasePathInfo(handle, FILE_PATH);

    std::string outResult;
    mtpMediaLib_->GetPathById(handle, outResult);
    EXPECT_TRUE(outResult.empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetParentId
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_061, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    uint32_t parentId = 1;
    parentId = mtpMediaLib_->GetParentId(FILE_PATH + "/3.txt");
    EXPECT_EQ(parentId, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetParentId
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_062, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    mtpMediaLib_->AddToHandlePathMap(FILE_PATH, 11);
    uint32_t parentId = 0;
    parentId = mtpMediaLib_->GetParentId(FILE_PATH + "/3.txt");
    EXPECT_EQ(parentId, 11);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ModifyHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_063, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    std::string from = FILE_PATH + "/11.txt";
    std::string to = STORAGE_FILE + "/11.txt";
    mtpMediaLib_->ModifyHandlePathMap(from, to);
    uint32_t outId = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH + "/1.txt", outId);
    EXPECT_EQ(outId, 1);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ModifyPathHandleMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_064, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    std::string path = FILE_PATH;
    uint32_t id = 11;
    mtpMediaLib_->ModifyPathHandleMap(path, id);
    uint32_t outId = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH + "/1.txt", outId);
    EXPECT_EQ(outId, 1);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ScanDirNoDepth
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_065, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();

    std::string root = FILE_PATH;
    std::shared_ptr<UInt32List> out = std::make_shared<UInt32List>();
    uint32_t errcode = 0;
    errcode = mtpMediaLib_->ScanDirNoDepth(root, out);
    EXPECT_EQ(errcode, E_ERR);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ScanDirNoDepth
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_066, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();

    std::string root = FILE_PATH;
    std::shared_ptr<UInt32List> out = nullptr;
    uint32_t errcode = 0;
    errcode = mtpMediaLib_->ScanDirNoDepth(root, out);
    EXPECT_EQ(errcode, E_ERR);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StartsWith
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_067, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();

    std::string str = "ab";
    std::string prefix = "abc";
    bool res = mtpMediaLib_->StartsWith(str, prefix);
    EXPECT_FALSE(res);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StartsWith
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_068, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();

    std::string str = "ab";
    std::string prefix = "";
    bool res = mtpMediaLib_->StartsWith(str, prefix);
    EXPECT_FALSE(res);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StartsWith
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_069, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();

    std::string str = "ab";
    std::string prefix = "ab";
    bool res = mtpMediaLib_->StartsWith(str, prefix);
    EXPECT_TRUE(res);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StartsWith
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_070, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();

    std::string str = "ab";
    std::string prefix = "bc";
    bool res = mtpMediaLib_->StartsWith(str, prefix);
    EXPECT_FALSE(res);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DeleteHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_071, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    std::string path = FILE_PATH;
    uint32_t id = 2;
    mtpMediaLib_->DeleteHandlePathMap(path, id);
    uint32_t outId = 0;
    int32_t errcode = mtpMediaLib_->GetIdByPath(path, outId);
    EXPECT_EQ(errcode, E_NO_SUCH_FILE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DeleteHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_072, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    std::string path = FILE_PATH + "/1.txt";
    uint32_t id = 12;
    mtpMediaLib_->DeleteHandlePathMap(path, id);
    std::string outPath = "";
    int32_t errcode = mtpMediaLib_->GetPathById(id, outPath);
    EXPECT_EQ(errcode, E_ERR);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ObserverAddPathToMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_073, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    std::string path = FILE_PATH + "/11.txt";
    uint32_t id = mtpMediaLib_->ObserverAddPathToMap(path);
    EXPECT_EQ(id, 130);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ObserverAddPathToMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_074, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    std::string path = FILE_PATH + "/2.txt";
    uint32_t id = mtpMediaLib_->ObserverAddPathToMap(path);
    EXPECT_EQ(id, 2);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ObserverDeletePathToMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_075, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();

    std::string path = FILE_PATH;
    mtpMediaLib_->ObserverDeletePathToMap(path);
    uint32_t outId = 0;
    int32_t errcode = mtpMediaLib_->GetIdByPath(path, outId);
    EXPECT_EQ(errcode, E_NO_SUCH_FILE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: MoveHandlePathMap
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_076, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    for (int i = 1; i <= 10; i++) {
        mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + std::to_string(i) + ".txt", i);
    }

    std::string from = "/storage/media/local/files/Docss";
    std::string to = FILE_PATH;
    mtpMediaLib_->MoveHandlePathMap(from, to);
    uint32_t outId = 0;
    int32_t errcode = mtpMediaLib_->GetIdByPath(from, outId);
    EXPECT_EQ(errcode, E_NO_SUCH_FILE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:GetObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_077, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<ObjectInfo> objectInfo = std::make_shared<ObjectInfo>(0);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(objectInfo, nullptr);
    context->handle = 0;

    int32_t result = mtpMediaLib_->GetObjectInfo(context, objectInfo);
    EXPECT_EQ(result, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:GetObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_078, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<ObjectInfo> objectInfo = std::make_shared<ObjectInfo>(0);
    ASSERT_NE(objectInfo, nullptr);

    int32_t result = mtpMediaLib_->GetObjectInfo(context, objectInfo);
    EXPECT_EQ(result, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:GetObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_079, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<ObjectInfo> objectInfo = std::make_shared<ObjectInfo>(0);
    ASSERT_NE(context, nullptr);
    context->handle = 0;

    int32_t result = mtpMediaLib_->GetObjectInfo(context, objectInfo);
    EXPECT_EQ(result, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:GetObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_080, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<ObjectInfo> objectInfo = std::make_shared<ObjectInfo>(0);
    ASSERT_NE(context, nullptr);
    context->handle = 1;

    int32_t result = mtpMediaLib_->GetObjectInfo(context, objectInfo);
    EXPECT_EQ(result, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:GetObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel0_081, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    std::shared_ptr<ObjectInfo> objectInfo = std::make_shared<ObjectInfo>(0);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(objectInfo, nullptr);
    context->handle = 100;
    context->storageID = 1;

    int32_t result = mtpMediaLib_->GetObjectInfo(context, objectInfo);
    EXPECT_EQ(result, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:SendObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_082, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    uint32_t outStorageID = 0;
    uint32_t outParent = 0;
    uint32_t outHandle = 0;

    int32_t result = mtpMediaLib_->SendObjectInfo(nullptr, outStorageID, outParent, outHandle);
    EXPECT_EQ(result, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:SendObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_083, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->storageID = 2;
    context->parent = MTP_ALL_HANDLE_ID;

    uint32_t outStorageID = 0;
    uint32_t outParent = 0;
    uint32_t outHandle = 0;

    int32_t result = mtpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);
    EXPECT_EQ(result, MTP_ERROR_STORE_NOT_AVAILABLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:SendObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_084, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    // parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    uint32_t parent = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, parent);
    context->storageID = 2;
    context->parent = parent;
    context->format = MTP_FORMAT_TEXT_CODE;
    context->name = "1.txt";

    uint32_t outStorageID = 0;
    uint32_t outParent = 0;
    uint32_t outHandle = 0;

    mtpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);
    EXPECT_EQ(outStorageID, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:SendObjectInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_085, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    // storage file path
    mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    uint32_t parent = 0;
    mtpMediaLib_->GetIdByPath(FILE_PATH, parent);
    context->storageID = parent;
    context->parent = parent;
    context->format = MTP_FORMAT_ASSOCIATION_CODE;

    uint32_t outStorageID = 0;
    uint32_t outParent = 0;
    uint32_t outHandle = 0;

    mtpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);
    EXPECT_EQ(outStorageID, 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:GetObjectPropList
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_086, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<std::vector<Property>> outProps = std::make_shared<std::vector<Property>>();

    context->property = 0;
    context->groupCode = 0;
    context->depth = MTP_ALL_DEPTH;
    context->handle = 0;
    context->storageID = 1;

    int32_t result = mtpMediaLib_->GetObjectPropList(context, outProps);
    EXPECT_EQ(result, MTP_ERROR_PARAMETER_NOT_SUPPORTED);
}

/*
 * Feature: MediaLibraryMTP
 * Function:GetObjectPropList
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_087, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<std::vector<Property>> outProps = std::make_shared<std::vector<Property>>();

    context->property = 0;
    context->groupCode = 1;
    context->depth = 0;
    context->handle = 0;
    context->storageID = 1;

    int32_t result = mtpMediaLib_->GetObjectPropList(context, outProps);
    EXPECT_EQ(result, MTP_ERROR_SPECIFICATION_BY_GROUP_UNSUPPORTED);
}

/*
 * Feature: MediaLibraryMTP
 * Function:GetObjectPropList
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Branch
 */
HWTEST_F(MtpMediaLibraryUnitTest, medialibrary_MTP_message_testlevel_088, TestSize.Level0)
{
    ASSERT_NE(mtpMediaLib_, nullptr);
    mtpMediaLib_->Clear();
    mtpMediaLib_->ObserverAddPathToMap(STORAGE_FILE);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<std::vector<Property>> outProps = std::make_shared<std::vector<Property>>();
    context->property = 1;
    context->groupCode = 1;
    context->depth = 3;
    context->handle = 4;
    context->storageID = 1;

    int32_t result = mtpMediaLib_->GetObjectPropList(context, outProps);
    EXPECT_EQ(result, MTP_ERROR_SPECIFICATION_BY_DEPTH_UNSUPPORTED);
}
}// namespace Media
}// namespace OHOS