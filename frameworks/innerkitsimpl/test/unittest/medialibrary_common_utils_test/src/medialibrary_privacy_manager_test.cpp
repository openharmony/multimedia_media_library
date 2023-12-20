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
#include "medialibrary_errno.h"
#define private public
#include "media_privacy_manager.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_001, TestSize.Level0)
{
    string path = "";
    string mode = "";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_002, TestSize.Level0)
{
    string path = ".Open";
    string mode = "Z";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_003, TestSize.Level0)
{
    string path = ".jpeg";
    string mode = "";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, -ENOMEM);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_004, TestSize.Level0)
{
    string path = ".Open";
    string mode = "w";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_005, TestSize.Level0)
{
    string path(4096, 'a');
    string mode = "w";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_006, TestSize.Level0)
{
    string path = "data:image/;base64,Open.jpeg";
    string mode = "a";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, -ENOMEM);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_007, TestSize.Level0)
{
    string path = "data:image/;base64,Open.jpeg";
    string mode = "rwrwrw";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_008, TestSize.Level0)
{
    string path = "/storage/cloud/files/open.jpeg";
    string mode = "w";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_009, TestSize.Level0)
{
    string path = "";
    string mode = "w";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_Open_test_010, TestSize.Level0)
{
    string path = "/storage/cloud/files/";
    string mode = "w";
    MediaPrivacyManager mediaPrivacyManager(path, mode);
    int32_t ret = mediaPrivacyManager.Open();
    EXPECT_EQ(ret, E_ERR);
}
} // namespace Media
} // namespace OHOS