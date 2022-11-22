/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "album_asset.h"
#include "medialibrary_db_const.h"
#include "medialibrary_type_const.h"

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
HWTEST_F(MediaLibraryHelperUnitTest, AlbumAsset_SetGet_Test_001, TestSize.Level0)
{
    AlbumAsset albumAsset;

    const int32_t TEST_ALBUM_ID = -1;
    albumAsset.SetAlbumId(TEST_ALBUM_ID);
    EXPECT_EQ(albumAsset.GetAlbumId(), TEST_ALBUM_ID);

    string albumName = DEFAULT_ALBUM_NAME;
    albumAsset.SetAlbumName(albumName);
    EXPECT_EQ(albumAsset.GetAlbumName(), albumName);

    string albumUri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_FILE_URI;
    albumAsset.SetAlbumUri(albumUri);
    EXPECT_EQ(albumAsset.GetAlbumUri(), albumUri);

    const int64_t TEST_ALBUM_DATE_MODIFIED = -1;
    albumAsset.SetAlbumDateModified(TEST_ALBUM_DATE_MODIFIED);
    EXPECT_EQ(albumAsset.GetAlbumDateModified(), TEST_ALBUM_DATE_MODIFIED);

    const int32_t TEST_COUNT = -1;
    albumAsset.SetCount(TEST_COUNT);
    EXPECT_EQ(albumAsset.GetCount(), TEST_COUNT);

    string albumRelativePath = PIC_DIR_VALUES;
    albumAsset.SetAlbumRelativePath(albumRelativePath);
    EXPECT_EQ(albumAsset.GetAlbumRelativePath(), albumRelativePath);

    const int32_t TEST_FILE_ID = 1;
    string coverUri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_IMAGE_URI + "/" + to_string(TEST_FILE_ID);
    albumAsset.SetCoverUri(coverUri);
    EXPECT_EQ(albumAsset.GetCoverUri(), coverUri);

    string albumPath = PIC_DIR_VALUES + albumName;
    albumAsset.SetAlbumPath(albumPath);
    EXPECT_EQ(albumAsset.GetAlbumPath(), albumPath);

    bool albumVirtual = true;
    albumAsset.SetAlbumVirtual(albumVirtual);
    EXPECT_EQ(albumAsset.GetAlbumVirtual(), albumVirtual);

    const string TEST_TYPE_MASK = "000";
    albumAsset.SetAlbumTypeMask(TEST_TYPE_MASK);
    EXPECT_EQ(albumAsset.GetAlbumTypeMask(), TEST_TYPE_MASK);

    ResultNapiType resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    albumAsset.SetResultNapiType(resultNapiType);
    EXPECT_EQ(albumAsset.GetResultNapiType(), resultNapiType);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check createalbumasset
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, AlbumAsset_CreateAlbumAsset_Test_001, TestSize.Level0)
{
    AlbumAsset albumAsset;
    const string albumPath = "/data/test/CreateAlbumAsset_001";
    albumAsset.SetAlbumPath(albumPath);
    EXPECT_EQ(albumAsset.CreateAlbumAsset(), true);
    EXPECT_EQ(albumAsset.CreateAlbumAsset(), false);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check deletealbumasset
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, AlbumAsset_DeleteAlbumAsset_Test_001, TestSize.Level0)
{
    AlbumAsset albumAsset;
    const string albumPath = "/data/test/DeleteAlbumAsset_001";
    albumAsset.SetAlbumPath(albumPath);
    albumAsset.CreateAlbumAsset();
    EXPECT_EQ(albumAsset.DeleteAlbumAsset(albumPath), true);
}

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check modifyalbumasset
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, AlbumAsset_ModifyAlbumAsset_Test_001, TestSize.Level0)
{
    AlbumAsset albumAsset;
    const string albumPath = "/data/test/ModifyAlbumAsset_001";
    const string newAlbumName = "ModifyAlbumAsset_001_modified";
    albumAsset.SetAlbumPath(albumPath);
    albumAsset.CreateAlbumAsset();
    albumAsset.SetAlbumName(newAlbumName);
    EXPECT_EQ(albumAsset.ModifyAlbumAsset(albumPath), true);
    EXPECT_EQ(albumAsset.ModifyAlbumAsset(newAlbumName), false);
}
} // namespace Media
} // namespace OHOS