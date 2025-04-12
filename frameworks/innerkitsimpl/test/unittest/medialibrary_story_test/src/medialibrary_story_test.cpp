/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaLibraryStoryTest"

#include "medialibrary_story_test.h"

#include <thread>
#include "datashare_result_set.h"
#include "get_self_permissions.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "userfilemgr_uri.h"
#include "story_album_column.h"
#include "story_cover_info_column.h"
#include "story_play_info_column.h"
#include "user_photography_info_column.h"
#include "vision_album_column.h"
#include "uri.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void ClearStoryData()
{
    DataShare::DataSharePredicates predicates;
    Uri storyAlbumUri(URI_HIGHLIGHT_ALBUM);
    MediaLibraryCommand storyAlbumCmd(storyAlbumUri);
    Uri storyCoverUri(URI_HIGHLIGHT_COVER_INFO);
    MediaLibraryCommand storyCoverCmd(storyCoverUri);
    Uri storyPlayUri(URI_HIGHLIGHT_PLAY_INFO);
    MediaLibraryCommand storyPlayCmd(storyPlayUri);
    Uri userPhotoGraphyUri(URI_USER_PHOTOGRAPHY_INFO);
    MediaLibraryCommand userPhotoGraphyCmd(userPhotoGraphyUri);
    MediaLibraryDataManager::GetInstance()->Delete(storyAlbumCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(storyCoverCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(storyPlayCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(userPhotoGraphyCmd, predicates);
}

void MediaLibraryStoryTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Story_Test::Start");
    MediaLibraryUnitTestUtils::Init();
}

void MediaLibraryStoryTest::TearDownTestCase(void)
{
    ClearStoryData();
    MEDIA_INFO_LOG("Story_Test::End");
}

void MediaLibraryStoryTest::SetUp(void)
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::CleanBundlePermission();
    MediaLibraryUnitTestUtils::InitRootDirs();
    MediaLibraryUnitTestUtils::Init();
    ClearStoryData();
}

void MediaLibraryStoryTest::TearDown(void) {}

HWTEST_F(MediaLibraryStoryTest, Story_InsertAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_InsertAlbum_Test_001::Start");
    Uri storyAlbumUri(URI_HIGHLIGHT_ALBUM);
    MediaLibraryCommand cmd(storyAlbumUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 1);
    valuesBucket.Put(AI_ALBUM_ID, 1);
    valuesBucket.Put(SUB_TITLE, "2024.03.20 ~ 03.21");
    valuesBucket.Put(CLUSTER_TYPE, "2");
    valuesBucket.Put(CLUSTER_SUB_TYPE, "3");
    valuesBucket.Put(CLUSTER_CONDITION, "地点");
    valuesBucket.Put(MIN_DATE_ADDED, 1432973383179);
    valuesBucket.Put(MAX_DATE_ADDED, 1432973383180);
    valuesBucket.Put(GENERATE_TIME, 1432973383181);
    valuesBucket.Put(HIGHLIGHT_VERSION, 1);
    valuesBucket.Put(REMARKS, "2");
    valuesBucket.Put(HIGHLIGHT_STATUS, 1);
    valuesBucket.Put(HIGHLIGHT_INSERT_PIC_COUNT, 3);
    valuesBucket.Put(HIGHLIGHT_REMOVE_PIC_COUNT, 3);
    valuesBucket.Put(HIGHLIGHT_SHARE_SCREENSHOT_COUNT, 5);
    valuesBucket.Put(HIGHLIGHT_SHARE_COVER_COUNT, 6);
    valuesBucket.Put(HIGHLIGHT_RENAME_COUNT, 7);
    valuesBucket.Put(HIGHLIGHT_CHANGE_COVER_COUNT, 7);
    valuesBucket.Put(HIGHLIGHT_RENDER_VIEWED_TIMES, 5);
    valuesBucket.Put(HIGHLIGHT_RENDER_VIEWED_DURATION, 5);
    valuesBucket.Put(HIGHLIGHT_ART_LAYOUT_VIEWED_TIMES, 6);
    valuesBucket.Put(HIGHLIGHT_ART_LAYOUT_VIEWED_DURATION, 6);
    valuesBucket.Put(HIGHLIGHT_MUSIC_EDIT_COUNT, 3);
    valuesBucket.Put(HIGHLIGHT_FILTER_EDIT_COUNT, 4);
    valuesBucket.Put(HIGHLIGHT_IS_MUTED, false);
    valuesBucket.Put(HIGHLIGHT_IS_FAVORITE, true);
    valuesBucket.Put(HIGHLIGHT_THEME, "生日");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Story_InsertAlbum_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryStoryTest, Story_UpdateAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_UpdateAlbum_Test_001::Start");
    Uri storyAlbumUri(URI_HIGHLIGHT_ALBUM);
    MediaLibraryCommand cmd(storyAlbumUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 2);
    valuesBucket.Put(AI_ALBUM_ID, 2);
    valuesBucket.Put(SUB_TITLE, "2024.03.20 ~ 03.21");
    valuesBucket.Put(CLUSTER_TYPE, "2");
    valuesBucket.Put(CLUSTER_SUB_TYPE, "7");
    valuesBucket.Put(CLUSTER_CONDITION, "地点");
    valuesBucket.Put(MIN_DATE_ADDED, 1432973383179);
    valuesBucket.Put(MAX_DATE_ADDED, 1432973383184);
    valuesBucket.Put(GENERATE_TIME, 1432973383181);
    valuesBucket.Put(HIGHLIGHT_VERSION, 1);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(CLUSTER_SUB_TYPE, "4");
    updateValues.Put(CLUSTER_CONDITION, "美食");
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_ID, to_string(2));
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    vector<string> columns;
    columns.push_back(CLUSTER_CONDITION);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    string condition;
    resultSet->GetString(0, condition);
    MEDIA_INFO_LOG("Story_UpdateAlbum_Test_001::condition = %{public}s. End",
        condition.c_str());
}

HWTEST_F(MediaLibraryStoryTest, Story_DeleteAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_DeleteAlbum_Test_001::Start");
    Uri storyAlbumUri(URI_HIGHLIGHT_ALBUM);
    MediaLibraryCommand cmd(storyAlbumUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 3);
    valuesBucket.Put(AI_ALBUM_ID, 3);
    valuesBucket.Put(SUB_TITLE, "2024.03.20 ~ 03.21");
    valuesBucket.Put(CLUSTER_TYPE, "2");
    valuesBucket.Put(CLUSTER_SUB_TYPE, "5");
    valuesBucket.Put(CLUSTER_CONDITION, "地点");
    valuesBucket.Put(MIN_DATE_ADDED, 1432973383179);
    valuesBucket.Put(MAX_DATE_ADDED, 1432973383150);
    valuesBucket.Put(GENERATE_TIME, 1432973383181);
    valuesBucket.Put(HIGHLIGHT_VERSION, 2);
    valuesBucket.Put(HIGHLIGHT_MUSIC_EDIT_COUNT, 3);
    valuesBucket.Put(HIGHLIGHT_FILTER_EDIT_COUNT, 4);
    valuesBucket.Put(HIGHLIGHT_IS_MUTED, false);
    valuesBucket.Put(HIGHLIGHT_IS_FAVORITE, true);
    valuesBucket.Put(HIGHLIGHT_THEME, "生日");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_ID, to_string(3));
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Story_DeleteAlbum_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryStoryTest, Story_InsertCoverInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_InsertCoverInfo_Test_001::Start");
    Uri storyCoverUri(URI_HIGHLIGHT_COVER_INFO);
    MediaLibraryCommand cmd(storyCoverUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 1);
    valuesBucket.Put(RATIO, "2:1");
    valuesBucket.Put(BACKGROUND, "file://media/Photo/1/1/1.jpg");
    valuesBucket.Put(FOREGROUND, "file://media/Photo/1/1/2.jpg");
    valuesBucket.Put(WORDART, "file://media/Photo/1/1/3.jpg");
    valuesBucket.Put(IS_COVERED, 0);
    valuesBucket.Put(COLOR, "black");
    valuesBucket.Put(RADIUS, 1);
    valuesBucket.Put(SATURATION, 6.5);
    valuesBucket.Put(BRIGHTNESS, 6.5);
    valuesBucket.Put(TITLE_SCALE_X, 5.5);
    valuesBucket.Put(TITLE_SCALE_Y, 5.5);
    valuesBucket.Put(TITLE_RECT_HEIGHT, 50.0);
    valuesBucket.Put(TITLE_RECT_HEIGHT, 60.5);
    valuesBucket.Put(BACKGROUND_SCALE_X, 6.5);
    valuesBucket.Put(BACKGROUND_SCALE_Y, 6.5);
    valuesBucket.Put(BACKGROUND_RECT_HEIGHT, 6.5);
    valuesBucket.Put(BACKGROUND_RECT_WIDTH, 6.5);
    valuesBucket.Put(COVER_ALGO_VERSION, 2);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Story_InsertCoverInfo_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryStoryTest, Story_UpdateCoverInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_UpdateCoverInfo_Test_001::Start");
    Uri storyCoverUri(URI_HIGHLIGHT_COVER_INFO);
    MediaLibraryCommand cmd(storyCoverUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 1);
    valuesBucket.Put(RATIO, "2:1");
    valuesBucket.Put(BACKGROUND, "file://media/Photo/1/2/1.jpg");
    valuesBucket.Put(FOREGROUND, "file://media/Photo/1/2/2.jpg");
    valuesBucket.Put(WORDART, "file://media/Photo/1/2/3.jpg");
    valuesBucket.Put(COLOR, "black");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(COLOR, "blue");
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_ID, to_string(1));
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    vector<string> columns;
    columns.push_back(COLOR);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    string color;
    resultSet->GetString(0, color);
    MEDIA_INFO_LOG("Story_UpdateCoverInfo_Test_001::color = %{public}s. End", color.c_str());
}

HWTEST_F(MediaLibraryStoryTest, Story_DeleteCoverInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_DeleteCoverInfo_Test_001::Start");
    Uri storyCoverUri(URI_HIGHLIGHT_COVER_INFO);
    MediaLibraryCommand cmd(storyCoverUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 1);
    valuesBucket.Put(RATIO, "3:1");
    valuesBucket.Put(BACKGROUND, "file://media/Photo/1/1/1.jpg");
    valuesBucket.Put(FOREGROUND, "file://media/Photo/1/1/2.jpg");
    valuesBucket.Put(WORDART, "file://media/Photo/1/1/3.jpg");
    valuesBucket.Put(COLOR, "black");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_ID, to_string(1));
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Story_DeleteCoverInfo_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryStoryTest, Story_InsertPlayInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_InsertPlayInfo_Test_001::Start");
    Uri storyPlayUri(URI_HIGHLIGHT_PLAY_INFO);
    MediaLibraryCommand cmd(storyPlayUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 1);
    valuesBucket.Put(MUSIC, "11");
    valuesBucket.Put(FILTER, 1);
    valuesBucket.Put(HIGHLIGHT_PLAY_INFO, "file://media/Photo/1/1/2.jpg");
    valuesBucket.Put(IS_CHOSEN, 1);
    valuesBucket.Put(PLAY_INFO_VERSION, 2);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Story_InsertPlayInfo_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryStoryTest, Story_UpdatePlayInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_UpdatePlayInfo_Test_001::Start");
    Uri storyPlayUri(URI_HIGHLIGHT_PLAY_INFO);
    MediaLibraryCommand cmd(storyPlayUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 2);
    valuesBucket.Put(MUSIC, "11");
    valuesBucket.Put(FILTER, 2);
    valuesBucket.Put(HIGHLIGHT_PLAY_INFO, "file://media/Photo/1/1/2.jpg");
    valuesBucket.Put(IS_CHOSEN, 1);
    valuesBucket.Put(PLAY_INFO_VERSION, 2);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(MUSIC, "22");
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_ID, to_string(2));
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    vector<string> columns;
    columns.push_back(MUSIC);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    string music;
    resultSet->GetString(0, music);
    MEDIA_INFO_LOG("Story_UpdatePlayInfo_Test_001::color = %{public}s. End", music.c_str());
}

HWTEST_F(MediaLibraryStoryTest, Story_DeletePlayInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_DeletePlayInfo_Test_001::Start");
    Uri storyPlayUri(URI_HIGHLIGHT_PLAY_INFO);
    MediaLibraryCommand cmd(storyPlayUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_ID, 3);
    valuesBucket.Put(MUSIC, "11");
    valuesBucket.Put(FILTER, 2);
    valuesBucket.Put(HIGHLIGHT_PLAY_INFO, "file://media/Photo/1/1/2.jpg");
    valuesBucket.Put(IS_CHOSEN, 0);
    valuesBucket.Put(PLAY_INFO_VERSION, 3);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_ID, to_string(3));
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Story_DeletePlayInfo_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryStoryTest, Story_InsertUserGraphyInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_InsertUserGraphyInfo_Test_001::Start");
    Uri userPhotoGraphyUri(URI_USER_PHOTOGRAPHY_INFO);
    MediaLibraryCommand cmd(userPhotoGraphyUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(AVERAGE_AESTHETICS_SCORE, 5);
    valuesBucket.Put(CAPTURE_AESTHETICS_SCORE, 6);
    valuesBucket.Put(AVERAGE_AESTHETICS_COUNT, 7);
    valuesBucket.Put(CAPTURE_AESTHETICS_COUNT, 7);
    valuesBucket.Put(CALCULATE_TIME_START, 1432973383181);
    valuesBucket.Put(CALCULATE_TIME_END, 1432973383181);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Story_InsertUserGraphyInfo_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryStoryTest, Story_UpdateUserGraphyInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_UpdateUserGraphyInfo_Test_001::Start");
    Uri userPhotoGraphyUri(URI_USER_PHOTOGRAPHY_INFO);
    MediaLibraryCommand cmd(userPhotoGraphyUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(AVERAGE_AESTHETICS_SCORE, 5);
    valuesBucket.Put(CAPTURE_AESTHETICS_SCORE, 6);
    valuesBucket.Put(AVERAGE_AESTHETICS_COUNT, 8);
    valuesBucket.Put(CAPTURE_AESTHETICS_COUNT, 8);
    valuesBucket.Put(CALCULATE_TIME_START, 1432973383181);
    valuesBucket.Put(CALCULATE_TIME_END, 1432973383181);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(CAPTURE_AESTHETICS_COUNT, 10);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(AVERAGE_AESTHETICS_SCORE, to_string(5));
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    vector<string> columns;
    columns.push_back(CAPTURE_AESTHETICS_COUNT);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    resultSet->GetInt(0, count);
    MEDIA_INFO_LOG("Story_UpdateUserGraphyInfo_Test_001::color = %{public}d. End", count);
}

HWTEST_F(MediaLibraryStoryTest, Story_DeleteUserGraphyInfo_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Story_DeleteUserGraphyInfo_Test_001::Start");
    Uri userPhotoGraphyUri(URI_USER_PHOTOGRAPHY_INFO);
    MediaLibraryCommand cmd(userPhotoGraphyUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(AVERAGE_AESTHETICS_SCORE, 5);
    valuesBucket.Put(CAPTURE_AESTHETICS_SCORE, 6);
    valuesBucket.Put(AVERAGE_AESTHETICS_COUNT, 10);
    valuesBucket.Put(CAPTURE_AESTHETICS_COUNT, 10);
    valuesBucket.Put(CALCULATE_TIME_START, 1432973383181);
    valuesBucket.Put(CALCULATE_TIME_END, 1432973383181);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(AVERAGE_AESTHETICS_SCORE, to_string(5));
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Story_DeleteUserGraphyInfo_Test_001::retVal = %{public}d. End", retVal);
}
} // namespace OHOS
} // namespace Media