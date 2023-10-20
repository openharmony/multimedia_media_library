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

#include "medialibrary_smartalbum_map_operations_test.h"
#include "medialibrary_uripermission_operations.h"
#include "medialibrary_unistore_manager.h"
#include "ability_context_impl.h"
#include "uri.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
HWTEST_F(MediaLibrarySmartalbumMapOperationTest, medialibrary_HandleUriPermOperations_test_001, TestSize.Level0)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::INSERT_PERMISSION);
    int32_t ret = UriPermissionOperations::HandleUriPermOperations(cmd);
    EXPECT_EQ(ret, E_INVALID_VALUES);
    
    MediaLibraryCommand cmd1(OperationObject::FILESYSTEM_ASSET, OperationType::UNKNOWN_TYPE);
    ret = UriPermissionOperations::HandleUriPermOperations(cmd1);
    EXPECT_EQ(ret, E_FAIL);
}

HWTEST_F(MediaLibrarySmartalbumMapOperationTest, medialibrary_HandleUriPermOperations_test_002, TestSize.Level0)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    Uri uri(queryUri);
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::INSERT_PERMISSION);
    int32_t ret = UriPermissionOperations::HandleUriPermOperations(cmd);
    EXPECT_EQ(ret, E_INVALID_VALUES);
    
    MediaLibraryCommand cmd1(OperationObject::FILESYSTEM_ASSET, OperationType::UNKNOWN_TYPE);
    ret = UriPermissionOperations::HandleUriPermOperations(cmd1);
    EXPECT_EQ(ret, E_FAIL);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibrarySmartalbumMapOperationTest, medialibrary_HandleUriPermInsert_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);

    string queryUri = MEDIALIBRARY_DATA_URI;
    Uri uri(queryUri);
    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    int32_t ret = UriPermissionOperations::HandleUriPermInsert(cmd);
    EXPECT_EQ(ret, E_INVALID_VALUES);

    queryUri = MEDIA_FILEOPRN;
    Uri uri1(queryUri);
    MediaLibraryCommand cmd1(uri1, OperationType::QUERY);
    ret = UriPermissionOperations::HandleUriPermInsert(cmd1);
    EXPECT_EQ(ret, E_INVALID_VALUES);
    
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibrarySmartalbumMapOperationTest, medialibrary_InsertBundlePermission_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);

    string bundleName = "inserBundTestCase";
    string mode = "rw";
    string tableName = "Audios";
    int32_t ret = UriPermissionOperations::InsertBundlePermission(0, bundleName, mode,
            tableName);
    EXPECT_EQ(ret, E_OK);

    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibrarySmartalbumMapOperationTest, medialibrary_GetUriPermissionMode_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    string fileId = "-1";
    string bundleName = "uriPerissionTestCase";
    int32_t tableType = 1;
    string permissionMode = "w";
    int32_t ret = UriPermissionOperations::GetUriPermissionMode(fileId, bundleName, tableType, permissionMode);
    EXPECT_EQ(ret, E_PERMISSION_DENIED);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibrarySmartalbumMapOperationTest, medialibrary_CheckUriPermission_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    string queryUri = MEDIALIBRARY_DATA_URI;
    string permissionMode = "w";
    int32_t ret = UriPermissionOperations::CheckUriPermission(queryUri, permissionMode);
    EXPECT_EQ(ret, E_PERMISSION_DENIED);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

HWTEST_F(MediaLibrarySmartalbumMapOperationTest, medialibrary_DeleteBundlePermission_test_001, TestSize.Level0)
{
    auto context = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    string queryUri = MEDIALIBRARY_DATA_URI;
    Uri uri(queryUri);
    string fileId = "-1";
    string bundleName = "delBundTestCase";
    string tableName = "tableName";
    int32_t ret = UriPermissionOperations::DeleteBundlePermission(fileId, bundleName, tableName);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

}
}