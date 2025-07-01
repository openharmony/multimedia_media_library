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

#define MLOG_TAG "MediaLibraryTriggerUtilsTest"

#include "medialibrary_trigger_utils_test.h"
#include "medialibrary_trigger_utils.h"
#include "medialibrary_trigger_test_utils.h"
#include "photo_asset_change_info.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "photo_album_column.h"

using namespace testing::ext;

namespace OHOS {

namespace Media {
static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void MediaLibraryTriggerUtilsTest::SetUpTestCase()
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    MediaLibraryTriggerTestUtils::SetRdbStore(g_rdbStore);
    MediaLibraryTriggerTestUtils::SetTables();
}

void MediaLibraryTriggerUtilsTest::TearDownTestCase()
{
    MediaLibraryTriggerTestUtils::ClearTables();
    MediaLibraryTriggerTestUtils::SetRdbStore(nullptr);
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("MediaLibraryTriggerUtilsTest TearDownTestCase is finish");
}

void MediaLibraryTriggerUtilsTest::SetUp()
{
    MediaLibraryTriggerTestUtils::PrepareData();
}

void MediaLibraryTriggerUtilsTest::TearDown()
{
    MediaLibraryTriggerTestUtils::RemoveData();
}

HWTEST_F(MediaLibraryTriggerUtilsTest, MediaLibraryTriggerUtilsTest_BracketVec_000, TestSize.Level2)
{
    std::vector<AccurateRefresh::PhotoAssetChangeData> values;
    std::string wrapper = "'";
    std::string expected = "()";
    EXPECT_EQ(MediaLibraryTriggerUtils::BracketVec(values, wrapper), expected);
}

HWTEST_F(MediaLibraryTriggerUtilsTest, MediaLibraryTriggerUtilsTest_BracketVec_001, TestSize.Level2)
{
    std::vector<AccurateRefresh::PhotoAssetChangeData> values;
    AccurateRefresh::PhotoAssetChangeData data;
    values.push_back(data);

    std::string wrapper = "'";
    std::string expected = "('" + data.ToString() + "')";
    EXPECT_EQ(MediaLibraryTriggerUtils::BracketVec(values, wrapper), expected);
}

HWTEST_F(MediaLibraryTriggerUtilsTest, MediaLibraryTriggerUtilsTest_BracketVec_002, TestSize.Level2)
{
    std::vector<AccurateRefresh::PhotoAssetChangeData> values;
    AccurateRefresh::PhotoAssetChangeData data1;
    data1.infoAfterChange_.packageName_ = "data1PackageName";
    values.push_back(data1);

    AccurateRefresh::PhotoAssetChangeData data2;
    data2.infoAfterChange_.packageName_ = "data2PackageName";
    values.push_back(data2);

    std::string wrapper = "'";
    std::string expected = "('" + data1.ToString() + "', '" + data2.ToString() + "')";
    EXPECT_EQ(MediaLibraryTriggerUtils::BracketVec(values, wrapper), expected);
}

HWTEST_F(MediaLibraryTriggerUtilsTest, MediaLibraryTriggerUtilsTest_BracketVec_003, TestSize.Level2)
{
    std::vector<std::string> values = {"data1", "data2"};
    std::string wrapper = "'";
    std::string expected = "('data1', 'data2')";
    EXPECT_EQ(MediaLibraryTriggerUtils::BracketVec(values, wrapper), expected);
}

HWTEST_F(MediaLibraryTriggerUtilsTest, MediaLibraryTriggerUtilsTest_WrapQuotation_000, TestSize.Level2)
{
    std::string expected = "'1'";
    EXPECT_EQ(MediaLibraryTriggerUtils::WrapQuotation("1"), expected);
}

HWTEST_F(MediaLibraryTriggerUtilsTest, MediaLibraryTriggerUtilsTest_CheckResultSet_000, TestSize.Level2)
{
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    EXPECT_FALSE(MediaLibraryTriggerUtils::CheckResultSet(resultSet));
}

HWTEST_F(MediaLibraryTriggerUtilsTest, MediaLibraryTriggerUtilsTest_CheckResultSet_001, TestSize.Level2)
{
    NativeRdb::RdbPredicates predicate(PhotoAlbumColumns::TABLE);
    predicate.EqualTo(PhotoAlbumColumns::ALBUM_LPATH, "111");
    auto resultSet = g_rdbStore->Query(predicate, {PhotoAlbumColumns::ALBUM_ID});
    EXPECT_EQ(MediaLibraryTriggerUtils::CheckResultSet(resultSet), false);
}

HWTEST_F(MediaLibraryTriggerUtilsTest, MediaLibraryTriggerUtilsTest_CheckResultSet_002, TestSize.Level2)
{
    NativeRdb::RdbPredicates predicate(PhotoAlbumColumns::TABLE);
    predicate.EqualTo(PhotoAlbumColumns::ALBUM_LPATH,
        MediaLibraryTriggerTestUtils::SOURCE_ALBUM_INFO.lpath_);
    auto resultSet = g_rdbStore->Query(predicate, {PhotoAlbumColumns::ALBUM_ID});
    EXPECT_EQ(MediaLibraryTriggerUtils::CheckResultSet(resultSet), true);
}
} // namespace Media
} // namespace OHOS