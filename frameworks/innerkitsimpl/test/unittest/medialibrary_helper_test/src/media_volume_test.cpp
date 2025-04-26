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

#include "medialibrary_errno.h"
#include "userfile_manager_types.h"
#define private public
#include "media_volume.h"
#undef private

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const int FILE_DATA_SIZE = 4;

HWTEST_F(MediaLibraryHelperUnitTest, MediaVolum_GetAudiosSize_Test_001, TestSize.Level1)
{
    MediaVolume mediaVolume;
    int64_t ret = mediaVolume.GetAudiosSize();
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaVolum_GetFilesSize_Test_001, TestSize.Level1)
{
    MediaVolume mediaVolume;
    int64_t ret = mediaVolume.GetFilesSize();
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaVolum_GetImagesSize_Test_001, TestSize.Level1)
{
    MediaVolume mediaVolume;
    int64_t ret = mediaVolume.GetImagesSize();
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaVolum_GetVideosSize_Test_001, TestSize.Level1)
{
    MediaVolume mediaVolume;
    int64_t ret = mediaVolume.GetVideosSize();
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaVolum_SetSize_Test_001, TestSize.Level1)
{
    MediaVolume mediaVolume;
    int mediaType = MEDIA_TYPE_AUDIO;
    int size = 0;
    mediaVolume.SetSize(mediaType, size);
    EXPECT_EQ(mediaVolume.mediaVolumeMap_.size(), FILE_DATA_SIZE);
}
}
}