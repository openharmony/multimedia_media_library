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

#include "medialibrary_helper_test.h"

#include "media_column.h"
#include "medialibrary_db_const.h"
#include "photo_album_asset.h"
#include "userfile_manager_types.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check set get function
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, PhotoAlbumAsset_SetGet_Test_001, TestSize.Level0)
{
    PhotoAlbumAsset photoAlbumAsset;

    const int32_t TEST_ALBUM_ID = 1;
    photoAlbumAsset.SetAlbumId(TEST_ALBUM_ID);
    EXPECT_EQ(photoAlbumAsset.GetAlbumId(), TEST_ALBUM_ID);

    photoAlbumAsset.SetPhotoAlbumType(USER);
    EXPECT_EQ(photoAlbumAsset.GetPhotoAlbumType(), USER);

    photoAlbumAsset.SetPhotoAlbumSubType(USER_GENERIC);
    EXPECT_EQ(photoAlbumAsset.GetPhotoAlbumSubType(), USER_GENERIC);

    const string TEST_URI = "file://media/album/1";
    photoAlbumAsset.SetAlbumUri(TEST_URI);
    EXPECT_EQ(photoAlbumAsset.GetAlbumUri(), TEST_URI);

    const string TEST_ALBUM_NAME = "test";
    photoAlbumAsset.SetAlbumName(TEST_ALBUM_NAME);
    EXPECT_EQ(photoAlbumAsset.GetAlbumName(), TEST_ALBUM_NAME);

    const string TEST_COVERURI = TEST_URI;
    photoAlbumAsset.SetCoverUri(TEST_COVERURI);
    EXPECT_EQ(photoAlbumAsset.GetCoverUri(), TEST_COVERURI);

    const int32_t TEST_COUNT = 1;
    photoAlbumAsset.SetCount(TEST_COUNT);
    EXPECT_EQ(photoAlbumAsset.GetCount(), TEST_COUNT);

    const string TEST_RELATIVE_PATH = "Camera";
    photoAlbumAsset.SetRelativePath(TEST_RELATIVE_PATH);
    EXPECT_EQ(photoAlbumAsset.GetRelativePath(), TEST_RELATIVE_PATH);

    const string TEST_TYPE_MASK = "000";
    photoAlbumAsset.SetTypeMask(TEST_TYPE_MASK);
    EXPECT_EQ(photoAlbumAsset.GetTypeMask(), TEST_TYPE_MASK);

    photoAlbumAsset.SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
    EXPECT_EQ(photoAlbumAsset.GetResultNapiType(), ResultNapiType::TYPE_USERFILE_MGR);
}
} // namespace Media
} // namespace OHOS