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
HWTEST_F(MediaLibraryCommonUtilsTest, medialib_CheckCallerPermission_test_001, TestSize.Level0)
{
    string permission = "";
    bool ret = PermissionUtils::CheckCallerPermission(permission);
    EXPECT_EQ(ret, false);
    string permissions = PERM_WRITE_IMAGEVIDEO;
    ret = PermissionUtils::CheckCallerPermission(permissions);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSysBundleManager_test_001, TestSize.Level0)
{
    auto ret = PermissionUtils::GetSysBundleManager();
    EXPECT_NE(ret, nullptr);
}
} // namespace Media
} // namespace OHOS
