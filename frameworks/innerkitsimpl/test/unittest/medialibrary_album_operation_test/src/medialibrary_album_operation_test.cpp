/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaLibraryAlbumOperationTest"

#include "medialibrary_album_operation_test.h"
#include "datashare_result_set.h"
#include "photo_album_column.h"
#include "get_self_permissions.h"
#include "location_column.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "uri.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

constexpr int32_t UNFAVORITE_PAGE = 0;
void ClearAnalysisAlbum()
{
    auto rdbStore = MediaLibraryDataManager::GetInstance()->rdbStore_;
    NativeRdb::AbsRdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.NotEqualTo(ALBUM_SUBTYPE, PhotoAlbumSubType::SHOOTING_MODE);
    int32_t deletedRows = -1;
    auto ret = rdbStore->Delete(deletedRows, predicates);
    MEDIA_INFO_LOG("ClearAnalysisAlbum Delete retVal: %{public}d, deletedRows: %{public}d", ret, deletedRows);
}

void MediaLibraryAlbumOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Vision_Test::Start");
    MediaLibraryUnitTestUtils::Init();
    vector<string> perms = { "ohos.permission.MEDIA_LOCATION" };
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryAlbumOperationTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    ClearAnalysisAlbum();
}

void MediaLibraryAlbumOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("Vision_Test::End");
}

void MediaLibraryAlbumOperationTest::SetUp(void)
{
    MEDIA_INFO_LOG("SetUp");
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::CleanBundlePermission();
    MediaLibraryUnitTestUtils::InitRootDirs();
    MediaLibraryUnitTestUtils::Init();
}

void MediaLibraryAlbumOperationTest::TearDown(void) {}

HWTEST_F(MediaLibraryAlbumOperationTest, portrait_set_display_level_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("portrait_set_display_level_001::Start");
    Uri uri(PAH_PORTRAIT_DISPLAY_LEVLE);
    MediaLibraryCommand queryCmd(uri);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(USER_DISPLAY_LEVEL, UNFAVORITE_PAGE);
    int result = MediaLibraryDataManager::GetInstance()->Update(queryCmd, valuesBucket, predicates);
    EXPECT_EQ(result, E_INVALID_VALUES);
    MEDIA_INFO_LOG("portrait_set_display_level_001 End, result:%{public}d", result);
}
} // namespace Media
} // namespace OHOS