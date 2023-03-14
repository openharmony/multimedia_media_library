/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define MLOG_TAG "FileExtUnitTest"

#include "ability_context_impl.h"
#include "file_asset.h"
#include "media_file_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_object_test.h"
#include "medialibrary_object_utils.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MediaLibraryExtUnitTest::SetUpTestCase(void) {}

void MediaLibraryExtUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryExtUnitTest::SetUp() {}

void MediaLibraryExtUnitTest::TearDown(void) {}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CreateDirWithPath_test_001, TestSize.Level0)
{
    string dirPath = "";
    int32_t ret = MediaLibraryObjectUtils::CreateDirWithPath(dirPath);
    EXPECT_EQ(ret, E_INVALID_PATH);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    dirPath = "CreateDirWithPath/storage/media/local/data";
    ret = MediaLibraryObjectUtils::CreateDirWithPath(dirPath);
    EXPECT_EQ(ret, E_INVALID_PATH);
    dirPath = "CreateDirWithPath.exe";
    ret = MediaLibraryObjectUtils::CreateDirWithPath(dirPath);
    EXPECT_EQ(ret, E_INVALID_PATH);
    dirPath = "/storage/media/local/files/medialib_CreateDirWithPath_test_001";
    ret = MediaLibraryObjectUtils::CreateDirWithPath(dirPath);
    EXPECT_GT(ret, 0);
    ret = MediaFileUtils::DeleteFile(dirPath);
    EXPECT_EQ(ret, true);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetDirAsset_test_001, TestSize.Level0)
{
    string path = "";
    NativeAlbumAsset dirAsset;
    dirAsset = MediaLibraryObjectUtils::GetDirAsset(path);
    EXPECT_EQ(dirAsset.GetAlbumId(), E_INVALID_PATH);
    path = "medialib_GetDirAsset/";
    dirAsset = MediaLibraryObjectUtils::GetDirAsset(path);
    EXPECT_EQ(dirAsset.GetAlbumId(), E_HAS_DB_ERROR);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    dirAsset = MediaLibraryObjectUtils::GetDirAsset(path);
    EXPECT_EQ(dirAsset.GetAlbumId(), E_INVALID_PATH);
    path = "//data/app/el1";
    dirAsset = MediaLibraryObjectUtils::GetDirAsset(path);
    EXPECT_EQ(dirAsset.GetAlbumId(), E_FAIL);
    path = "/storage/media/local/files/medialib_GetDirAsset_test_001";
    dirAsset = MediaLibraryObjectUtils::GetDirAsset(path);
    EXPECT_GT(dirAsset.GetAlbumId(), 0);
    bool ret = MediaFileUtils::DeleteFile(path);
    EXPECT_EQ(ret, true);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CreateFileObj_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    int32_t ret = MediaLibraryObjectUtils::CreateFileObj(cmd);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    cmd.SetTableName(MEDIALIBRARY_TABLE);
    NativeRdb::ValuesBucket values;
    string name = "medialib_CreateFileObj_test_001";
    values.PutString(MEDIA_DATA_DB_NAME, name);
    cmd.SetValueBucket(values);
    ret = MediaLibraryObjectUtils::CreateFileObj(cmd);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_TYPE_FILE);
    cmd.SetValueBucket(values);
    string path = "//storage/media/local/files/CreateFileObj_test_001";
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, path);
    cmd.SetValueBucket(values);
    ret = MediaLibraryObjectUtils::CreateFileObj(cmd);
    EXPECT_EQ(ret, E_CHECK_EXTENSION_FAIL);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CreateDirObj_test_001, TestSize.Level0)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    int64_t rowId = 0;
    int32_t ret = MediaLibraryObjectUtils::CreateDirObj(cmd, rowId);
    EXPECT_EQ(ret, E_INVALID_PATH);
    cmd.SetTableName(MEDIALIBRARY_TABLE);
    NativeRdb::ValuesBucket values;
    string path = "/storage/media/local/files/medialib_CreateDirObj_test_001";
    values.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    cmd.SetValueBucket(values);
    ret = MediaLibraryObjectUtils::CreateDirObj(cmd, rowId);
    EXPECT_LT(ret, 0);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_RenameFileObj_test_001, TestSize.Level0)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    string srcFilePath = "";
    string dstFilePath = "";
    int32_t ret = MediaLibraryObjectUtils::RenameFileObj(cmd, srcFilePath, dstFilePath);
    EXPECT_EQ(ret, E_INVALID_PATH);
    srcFilePath = "/storage/media/local/files";
    dstFilePath = "/storage/media/local/files";
    ret = MediaLibraryObjectUtils::RenameFileObj(cmd, srcFilePath, dstFilePath);
    EXPECT_EQ(ret, E_SUCCESS);
    dstFilePath = "RenameFileObj.test/media";
    cmd.SetTableName(MEDIALIBRARY_TABLE);
    NativeRdb::ValuesBucket values;
    string name = "RenameFileObj_test_001.nofile";
    string path = "/storage/media";
    values.PutString(MEDIA_DATA_DB_NAME, name);
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, path);
    cmd.SetValueBucket(values);
    ret = MediaLibraryObjectUtils::RenameFileObj(cmd, srcFilePath, dstFilePath);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_RenameDirObj_test_001, TestSize.Level0)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    string srcFilePath = "";
    string dstFilePath = "";
    int32_t ret = MediaLibraryObjectUtils::RenameDirObj(cmd, srcFilePath, dstFilePath);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    ret = MediaLibraryObjectUtils::RenameDirObj(cmd, srcFilePath, dstFilePath);
    EXPECT_EQ(ret, E_INVALID_PATH);
    srcFilePath = "/storage/media/local/files/medialib_GetDirAsset_test_001";
    dstFilePath = "/storage/media/local/files";
    ret = MediaLibraryObjectUtils::RenameDirObj(cmd, srcFilePath, dstFilePath);
    EXPECT_EQ(ret, E_HAS_FS_ERROR);
    srcFilePath = "//data/test";
    dstFilePath = "//data/test";
    ret = MediaLibraryObjectUtils::RenameDirObj(cmd, srcFilePath, dstFilePath);
    EXPECT_EQ(ret, E_INVALID_FILEID);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_OpenFile_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    string mode = "rw";
    Uri uri("datashare:///media/local/files");
    MediaLibraryCommand cmd(uri);
    int32_t ret = MediaLibraryObjectUtils::OpenFile(cmd, mode);
    EXPECT_EQ(ret, E_INVALID_URI);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CloseFile_test_001, TestSize.Level0)
{
    Uri uri("//data/test");
    MediaLibraryCommand cmd(uri, OperationType::CLOSE);
    cmd.SetOprnAssetId("//data/test");
    int ret = MediaLibraryObjectUtils::CloseFile(cmd);
    EXPECT_EQ(ret, E_INVALID_FILEID);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    cmd.SetOprnAssetId("medialib_CloseFile_test_001");
    ret = MediaLibraryObjectUtils::CloseFile(cmd);
    EXPECT_EQ(ret, E_INVALID_FILEID);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}


HWTEST_F(MediaLibraryExtUnitTest, medialib_UpdateDateModified_test_001, TestSize.Level0)
{
    string uriStr = "";
    int32_t ret = MediaLibraryObjectUtils::UpdateDateModified(uriStr);
    EXPECT_EQ(ret, E_INVALID_PATH);
    uriStr = "medialib_UpdateDateModified_test_001";
    ret = MediaLibraryObjectUtils::UpdateDateModified(uriStr);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    ret = MediaLibraryObjectUtils::UpdateDateModified(uriStr);
    EXPECT_EQ(ret, E_SUCCESS);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetIdByPathFromDb_test_001, TestSize.Level0)
{
    string path = "";
    int32_t ret = MediaLibraryObjectUtils::GetIdByPathFromDb(path);
    EXPECT_EQ(ret, E_INVALID_PATH);
    path = "medialib_GetIdByPathFromDb_test_001";
    ret = MediaLibraryObjectUtils::GetIdByPathFromDb(path);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    string dirPath = "/storage/media/local/files/medialib_GetIdByPathFromDb_test_001.jpg";
    ret = MediaLibraryObjectUtils::CreateDirWithPath(dirPath);
    EXPECT_GT(ret, 0);
    ret = MediaLibraryObjectUtils::GetIdByPathFromDb(dirPath);
    EXPECT_GT(ret, 0);
    ret = MediaFileUtils::DeleteFile(dirPath);
    EXPECT_EQ(ret, true);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetParentIdByIdFromDb_test_001, TestSize.Level0)
{
    string fileId = "";
    int32_t ret = MediaLibraryObjectUtils::GetParentIdByIdFromDb(fileId);
    EXPECT_EQ(ret, E_INVALID_FILEID);
    fileId = "medialib_GetParentIdByIdFromDb_test_001";
    ret = MediaLibraryObjectUtils::GetParentIdByIdFromDb(fileId);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    ret = MediaLibraryObjectUtils::GetParentIdByIdFromDb(fileId);
    EXPECT_EQ(ret, -1);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_InsertInDb_test_001, TestSize.Level0)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    int32_t ret = MediaLibraryObjectUtils::InsertInDb(cmd);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    ret = MediaLibraryObjectUtils::InsertInDb(cmd);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    NativeRdb::ValuesBucket values;
    string name = "";
    values.PutString(MEDIA_DATA_DB_NAME, name);
    cmd.SetValueBucket(values);
    ret = MediaLibraryObjectUtils::InsertInDb(cmd);
    EXPECT_NE(ret, E_SUCCESS);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_ModifyInfoByIdInDb_test_001, TestSize.Level0)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    string fileId = "";
    int32_t ret = MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, fileId);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    ret = MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, fileId);
    EXPECT_EQ(ret, E_INVALID_FILEID);
    fileId = "medialib_ModifyInfoByIdInDb_test_001";
    cmd.GetAbsRdbPredicates()->SetWhereClause("1 <> 0");
    ret = MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, fileId);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_QueryWithCondition_test_001, TestSize.Level0)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    vector<string> columns;
    string conditionColumn = "";
    auto resultSetPtr = MediaLibraryObjectUtils::QueryWithCondition(cmd, columns, conditionColumn);
    EXPECT_EQ(resultSetPtr, nullptr);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    string condition = "medialib_QueryWithCondition_test_001";
    resultSetPtr = MediaLibraryObjectUtils::QueryWithCondition(cmd, columns, condition);
    EXPECT_EQ(resultSetPtr, nullptr);
    resultSetPtr = MediaLibraryObjectUtils::QueryWithCondition(cmd, columns, conditionColumn);
    EXPECT_NE(resultSetPtr, nullptr);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_IsColumnValueExist_test_001, TestSize.Level0)
{
    string value = "";
    string column = "";
    bool ret = MediaLibraryObjectUtils::IsColumnValueExist(value, column);
    EXPECT_EQ(ret, false);
    value = "medialib_IsColumnValueExist_test_001";
    column = "medialib_IsColumnValueExist_test_001";
    ret = MediaLibraryObjectUtils::IsColumnValueExist(value, column);
    EXPECT_EQ(ret, false);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    ret = MediaLibraryObjectUtils::IsColumnValueExist(value, column);
    EXPECT_EQ(ret, false);
    column = MEDIA_DATA_DB_PARENT_ID;
    ret = MediaLibraryObjectUtils::IsColumnValueExist(value, column);
    EXPECT_EQ(ret, false);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteInfoByIdInDb_test_001, TestSize.Level0)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::CREATE);
    string fileId = "";
    int32_t ret = MediaLibraryObjectUtils::DeleteInfoByIdInDb(cmd, fileId);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    ret = MediaLibraryObjectUtils::DeleteInfoByIdInDb(cmd, fileId);
    EXPECT_EQ(ret, E_INVALID_FILEID);
    cmd.GetAbsRdbPredicates()->SetWhereClause("1 <> 0");
    ret = MediaLibraryObjectUtils::DeleteInfoByIdInDb(cmd, fileId);
    EXPECT_GT(ret, 0);
    fileId = "0";
    vector<std::string> whereArgs{"medialib_GetDirAsset"};
    cmd.SetTableName(MEDIALIBRARY_TABLE);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(whereArgs);
    cmd.GetAbsRdbPredicates()->SetWhereClause("medialib_GetDirAsset");
    ret = MediaLibraryObjectUtils::DeleteInfoByIdInDb(cmd, fileId);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_IsFileExistInDb_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    string dirPath = "/storage/media/local/files/medialib_IsFileExistInDb_test_001";
    int32_t ret = MediaLibraryObjectUtils::CreateDirWithPath(dirPath);
    EXPECT_GT(ret, 0);
    string path = "";
    ret = MediaLibraryObjectUtils::IsFileExistInDb(path);
    EXPECT_EQ(ret, false);
    path = "medialib_IsFileExistInDb";
    ret = MediaLibraryObjectUtils::IsFileExistInDb(path);
    EXPECT_EQ(ret, false);
    ret = MediaLibraryObjectUtils::IsFileExistInDb(dirPath);
    EXPECT_EQ(ret, true);
    ret = MediaFileUtils::DeleteFile(dirPath);
    EXPECT_EQ(ret, true);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CopyAsset_test_001, TestSize.Level0)
{
    shared_ptr<FileAsset> srcFileAsset = nullptr;
    string relativePath = "";
    int32_t ret = MediaLibraryObjectUtils::CopyAsset(srcFileAsset, relativePath);
    EXPECT_EQ(ret, E_INVALID_URI);
    relativePath = "medialib_CopyAsset_test_001";
    shared_ptr<FileAsset> srcFileAssetPtr = MediaLibraryObjectUtils::GetFileAssetFromUri(relativePath);
    ret = MediaLibraryObjectUtils::CopyAsset(srcFileAssetPtr, relativePath);
    EXPECT_TRUE(ret < 0);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CopyDir_test_001, TestSize.Level0)
{
    shared_ptr<FileAsset> srcDirAsset = nullptr;
    string relativePath = "";
    int32_t id = 1;
    int32_t ret = MediaLibraryObjectUtils::CopyDir(srcDirAsset, relativePath);
    EXPECT_EQ(ret, E_INVALID_URI);
    relativePath = "medialib_CopyDir_test_001";
    shared_ptr<FileAsset> srcDirAssetPtr = make_shared<FileAsset>();
    srcDirAssetPtr->SetDisplayName(MEDIA_NO_FILE);
    srcDirAssetPtr->SetId(id);
    relativePath = "/storage/media/local/files/";
    ret = MediaLibraryObjectUtils::CopyDir(srcDirAssetPtr, relativePath);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_IsSmartAlbumExistInDb_test_001, TestSize.Level0)
{
    int32_t id = 0;
    bool ret = MediaLibraryObjectUtils::IsSmartAlbumExistInDb(id);
    EXPECT_EQ(ret, false);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    id = 1;
    ret = MediaLibraryObjectUtils::IsSmartAlbumExistInDb(id);
    EXPECT_EQ(ret, true);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_IsParentSmartAlbum_test_001, TestSize.Level0)
{
    int32_t id = 0;
    bool isInclude = false;
    bool ret = MediaLibraryObjectUtils::IsParentSmartAlbum(id, isInclude);
    EXPECT_EQ(ret, false);
    isInclude = true;
    ret = MediaLibraryObjectUtils::IsParentSmartAlbum(id, isInclude);
    EXPECT_EQ(ret, false);
    id = 1;
    ret = MediaLibraryObjectUtils::IsParentSmartAlbum(id, isInclude);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteFileObj_test_001, TestSize.Level0)
{
    string dirPath = "";
    std::shared_ptr<FileAsset> fileAsset = make_shared<FileAsset>();
    fileAsset->SetPath(dirPath);
    fileAsset->SetId(0);
    int32_t ret = MediaLibraryObjectUtils::DeleteFileObj(fileAsset);
    EXPECT_EQ(ret, E_HAS_FS_ERROR);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_DeleteMisc_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    string path = "/storage/media/local/files/medialib_DeleteMisc_test_001";
    int32_t fileId = 1;
    int32_t parentId = 1;
    int32_t ret = MediaLibraryObjectUtils::DeleteMisc(fileId, path, parentId);
    EXPECT_EQ(ret, E_SUCCESS);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CheckDirExtension_test_001, TestSize.Level0)
{
    string relativePath = "";
    string displayName = "";
    int32_t ret = MediaLibraryObjectUtils::CheckDirExtension(relativePath, displayName);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
    displayName = MEDIA_NO_FILE;
    relativePath = "medialib_CheckDirExtension_test_001";
    ret = MediaLibraryObjectUtils::CheckDirExtension(relativePath, displayName);
    EXPECT_EQ(ret, E_SUCCESS);
    displayName = "medialib_CheckDirExtension_test_001";
    relativePath = "/storage/media/local/files/medialib_CheckDirExtension_test_001";
    ret = MediaLibraryObjectUtils::CheckDirExtension(relativePath, displayName);
    EXPECT_EQ(ret, E_CHECK_EXTENSION_FAIL);
    string name(256, 'a');
    ret = MediaLibraryObjectUtils::CheckDirExtension(relativePath, name);
    EXPECT_EQ(ret, E_FILE_NAME_INVALID);
}

} // namespace Media
} // namespace OHOS