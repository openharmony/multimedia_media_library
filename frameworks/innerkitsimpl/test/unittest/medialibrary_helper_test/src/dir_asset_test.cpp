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

#include "dir_asset.h"
#include "media_container_types.h"
#include "medialibrary_type_const.h"
#include "userfile_manager_types.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const std::string DIR_ALL_IMAGE_CONTAINER_TYPE = "." + IMAGE_CONTAINER_TYPE_BMP + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_BM + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_GIF + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_JPG + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_JPEG + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_JPE + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_PNG + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_WEBP + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_RAW + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_SVG + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_HEIF + "?";

/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check set get function
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, DirAsset_SetGet_Test_001, TestSize.Level1)
{
    DirAsset dirAsset;

    int32_t dirType = DEFAULT_DIR_TYPE;
    dirAsset.SetDirType(dirType);
    EXPECT_EQ(dirAsset.GetDirType(), dirType);

    string mediaTypes = to_string(MEDIA_TYPE_IMAGE);
    dirAsset.SetMediaTypes(mediaTypes);
    EXPECT_EQ(dirAsset.GetMediaTypes(), mediaTypes);

    string directory = PIC_DIR_VALUES;
    dirAsset.SetDirectory(directory);
    EXPECT_EQ(dirAsset.GetDirectory(), directory);

    string extensions = DIR_ALL_IMAGE_CONTAINER_TYPE;
    dirAsset.SetExtensions(extensions);
    EXPECT_EQ(dirAsset.GetExtensions(), extensions);
}
} // namespace Media
} // namespace OHOS