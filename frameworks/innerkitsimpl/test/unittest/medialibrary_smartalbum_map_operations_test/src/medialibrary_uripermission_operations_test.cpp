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
#include "userfilemgr_uri.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
HWTEST_F(MediaLibrarySmartalbumMapOperationsTest, medialibrary_InsertBundlePermission_test_001, TestSize.Level0)
{
    string bundleName = "inserBundTestCase";
    string mode = "rw";
    string tableName = "Audios";
    int32_t ret = UriPermissionOperations::InsertBundlePermission(0, bundleName, mode,
            tableName);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibrarySmartalbumMapOperationsTest, medialibrary_GetUriPermissionMode_test_001, TestSize.Level0)
{
    string fileId = "-1";
    string bundleName = "uriPerissionTestCase";
    int32_t tableType = 1;
    string permissionMode = "w";
    int32_t ret = UriPermissionOperations::GetUriPermissionMode(fileId, bundleName, tableType, permissionMode);
    EXPECT_EQ(ret, E_PERMISSION_DENIED);
}

HWTEST_F(MediaLibrarySmartalbumMapOperationsTest, medialibrary_CheckUriPermission_test_001, TestSize.Level0)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    string permissionMode = "w";
    int32_t ret = UriPermissionOperations::CheckUriPermission(queryUri, permissionMode);
    EXPECT_EQ(ret, E_PERMISSION_DENIED);
}

HWTEST_F(MediaLibrarySmartalbumMapOperationsTest, medialibrary_DeleteBundlePermission_test_001, TestSize.Level0)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    Uri uri(queryUri);
    string fileId = "-1";
    string bundleName = "delBundTestCase";
    string tableName = "tableName";
    int32_t ret = UriPermissionOperations::DeleteBundlePermission(fileId, bundleName, tableName);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
}

}
}