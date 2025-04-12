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

#include "medialibrary_kvstore_utils_test.h"
#include "medialibrary_kvstore_utils.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MediaLibraryKvstoreUtilsTest::SetUpTestCase(void) {}
void MediaLibraryKvstoreUtilsTest::TearDownTestCase(void) {}
void MediaLibraryKvstoreUtilsTest::SetUp(void) {}
void MediaLibraryKvstoreUtilsTest::TearDown(void) {}

/*
 * Feature : MediaLibraryKvstoreUtilsTest
 * Function : GetSystemAlbumPredicates
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryKvstoreUtilsTest, MediaLibraryKvstoreUtils_Test_001, TestSize.Level1)
{
    KvStoreValueType type = KvStoreValueType::MONTH_ASTC;
    std::string oldKey = "adc";
    std::string newKey = "def";
    MediaLibraryKvStoreUtils::CopyAstcDataToKvStoreByType(type, oldKey, newKey);

    type = KvStoreValueType::YEAR_ASTC;
    MediaLibraryKvStoreUtils::CopyAstcDataToKvStoreByType(type, oldKey, newKey);

    type = KvStoreValueType::MONTH_ASTC_OLD_VERSION;
    int32_t res = MediaLibraryKvStoreUtils::CopyAstcDataToKvStoreByType(type, oldKey, newKey);
    EXPECT_EQ(res, E_ERR);
}
} // namespace Media
} // namespace OHOS