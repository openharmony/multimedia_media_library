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

#include "photo_album_column_test.h"
#include "photo_album_column.h"
#include "media_column.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void PhotoAlbumColumnTest::SetUpTestCase(void) {}
void PhotoAlbumColumnTest::TearDownTestCase(void) {}
void PhotoAlbumColumnTest::SetUp(void) {}
void PhotoAlbumColumnTest::TearDown(void) {}

/*
 * Feature : PhotoAlbumColumnTest
 * Function : GetSystemAlbumPredicates
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(PhotoAlbumColumnTest, PhotoAlbumColumn_Test_001, TestSize.Level0)
{
    PhotoAlbumSubType subtype = PhotoAlbumSubType::ANALYSIS_START;
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    bool hiddenState = false;
    PhotoAlbumColumns::GetSystemAlbumPredicates(subtype, predicates, hiddenState);

    std::string res = PhotoAlbumColumns::CheckUploadPhotoAlbumColumns();
    EXPECT_NE(res, "");
}
} // namespace Media
} // namespace OHOS