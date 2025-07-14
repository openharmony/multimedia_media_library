/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "medialibrary_album_helper_test.h"

#include "medialibrary_album_helper.h"
#include "media_column.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void MediaLibraryAlbumHelperUnitTest::SetUpTestCase(void) {}
void MediaLibraryAlbumHelperUnitTest::TearDownTestCase(void) {}
void MediaLibraryAlbumHelperUnitTest::SetUp(void) {}
void MediaLibraryAlbumHelperUnitTest::TearDown(void) {}

HWTEST_F(MediaLibraryAlbumHelperUnitTest, GetAnalysisAlbumPredicates_Test_001, TestSize.Level1)
{
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    EXPECT_EQ(MediaLibraryAlbumHelper::GetAnalysisAlbumPredicates(1, PhotoAlbumSubType::PORTRAIT, "1",
        predicates, false), true);
    predicates.Clear();
    EXPECT_EQ(MediaLibraryAlbumHelper::GetAnalysisAlbumPredicates(1, PhotoAlbumSubType::SHOOTING_MODE,
        "1", predicates, false), true);
    predicates.Clear();
    EXPECT_EQ(MediaLibraryAlbumHelper::GetAnalysisAlbumPredicates(1, PhotoAlbumSubType::CLASSIFY, "1",
        predicates, false), true);
}
} // namespace Media
} // namespace OHOS