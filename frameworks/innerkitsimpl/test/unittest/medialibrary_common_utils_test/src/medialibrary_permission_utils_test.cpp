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
#include "medialibrary_common_utils_test.h"
#include "thumbnail_utils.h"
#define private public
#include "permission_utils.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(MediaLibraryExtUnitTest, medialib_CheckCallerPermission_test_001, TestSize.Level0)
{
    string permission = "";
    bool ret = PermissionUtils::CheckCallerPermission(permission);
    EXPECT_EQ(ret, false);
    string permissions = PERM_WRITE_IMAGEVIDEO;
    ret = PermissionUtils::CheckCallerPermission(permissions);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_CheckCallerPermission_test_002, TestSize.Level0)
{
    array<string, PERM_GRP_SIZE> perms;
    uint32_t permMask = 0;
    bool ret = PermissionUtils::CheckCallerPermission(perms, permMask);
    EXPECT_EQ(ret, false);
    array<string, PERM_GRP_SIZE> permsTest = {PERM_WRITE_IMAGEVIDEO, PERM_WRITE_AUDIO};
    ret = PermissionUtils::CheckCallerPermission(permsTest, 1);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetClientBundle_test_001, TestSize.Level0)
{
    int uid = 0;
    string bundleName = "GetClientBundle";
    bool isSystemApp = false;
    PermissionUtils::GetClientBundle(uid, bundleName, isSystemApp);
    EXPECT_EQ(isSystemApp, true);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_SystemApiCheck_test_001, TestSize.Level0)
{
    string uri = "SystemApiCheck";
    bool ret = PermissionUtils::SystemApiCheck(uri);
    EXPECT_EQ(ret, true);
    string tempNetworkId = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    string uriOne = MEDIALIBRARY_DATA_ABILITY_PREFIX + tempNetworkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    ret = PermissionUtils::SystemApiCheck(uriOne);
    EXPECT_EQ(ret, false);
    string uriTwo = URI_CREATE_PHOTO_ALBUM;
    ret = PermissionUtils::SystemApiCheck(uriTwo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryExtUnitTest, medialib_GetSysBundleManager_test_001, TestSize.Level0)
{
    auto ret = PermissionUtils::GetSysBundleManager();
    EXPECT_NE(ret, nullptr);
}
} // namespace Media
} // namespace OHOS