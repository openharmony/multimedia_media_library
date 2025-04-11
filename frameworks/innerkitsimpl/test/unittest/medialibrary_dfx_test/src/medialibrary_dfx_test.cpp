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

#include "medialibrary_dfx_test.h"

#include <string>
#include <unordered_set>

#include "dfx_cloud_manager.h"
#include "dfx_collector.h"
#include "dfx_const.h"
#include "dfx_database_utils.h"
#include "dfx_manager.h"
#include "dfx_reporter.h"
#include "dfx_utils.h"
#include "hisysevent.h"
#include "medialibrary_astc_stat.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_rdbstore.h"
#include "media_file_utils.h"
#include "photo_album_column.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "parameters.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";

void MediaLibraryDfxTest::SetUpTestCase(void)
{
    DfxManager::GetInstance();
}
void MediaLibraryDfxTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

// SetUp:Execute before each test case
void MediaLibraryDfxTest::SetUp()
{
    DfxManager::GetInstance()->isInitSuccess_ = true;
}

void MediaLibraryDfxTest::TearDown(void) {}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_common_image_test, TestSize.Level0)
{
    std::string path = "common.jpg";
    int32_t width = 256;
    int32_t height = 256;
    int32_t mediaType = 1;
    int32_t result = DfxManager::GetInstance()->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, COMMON_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_common_image_test_002, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    std::string path = "common.jpg";
    int32_t width = 256;
    int32_t height = 256;
    int32_t mediaType = 1;
    dfxManager->isInitSuccess_ = false;
    int32_t result = dfxManager->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, NOT_INIT);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_png_test, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    std::string path = "other.png";
    int32_t width = 256;
    int32_t height = 256;
    int32_t mediaType = 1;
    int32_t result = dfxManager->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, OTHER_FORMAT_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_big_image_test, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    std::string path = "big_image.jpg";
    int32_t width = 10000;
    int32_t height = 10000;
    int32_t mediaType = 1;
    int32_t result = dfxManager->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, BIG_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_common_video_test, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    std::string path = "common.mp4";
    int32_t width = 256;
    int32_t height = 256;
    int32_t mediaType = 2;
    int32_t result = dfxManager->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, COMMON_VIDEO);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_8K_video_test, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    std::string path = "8K.mp4";
    int32_t width = 7680;
    int32_t height = 7680;
    int32_t mediaType = 2;
    int32_t result = dfxManager->HandleHighMemoryThumbnail(path, mediaType, width, height);
    EXPECT_EQ(result, BIG_VIDEO);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_timeout_operation_test_001, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    string bundleName = "bundleName";
    int32_t type = 1;
    int32_t object = 0;
    int32_t time = 0;
    dfxManager->HandleTimeOutOperation(bundleName, type, object, time);
    EXPECT_EQ(dfxManager->isInitSuccess_, true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_timeout_operation_test_002, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    string bundleName = "bundleName";
    int32_t type = 1;
    int32_t object = 0;
    int32_t time = 0;
    dfxManager->isInitSuccess_ = false;
    dfxManager->HandleTimeOutOperation(bundleName, type, object, time);
    EXPECT_EQ(dfxManager->isInitSuccess_, false);
}


HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_error_test_001, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    std::string path = "";
    int32_t method = 1;
    int32_t errorCode = 1;
    dfxManager->HandleThumbnailError(path, method, errorCode);
    EXPECT_EQ(dfxManager->isInitSuccess_, true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_error_test_002, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    std::string path = "";
    int32_t method = 1;
    int32_t errorCode = 1;
    dfxManager->isInitSuccess_ = false;
    dfxManager->HandleThumbnailError(path, method, errorCode);
    EXPECT_EQ(dfxManager->isInitSuccess_, false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_generation_test_001, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    ThumbnailData::GenerateStats stats;
    dfxManager->HandleThumbnailGeneration(stats);
    EXPECT_EQ(dfxManager->isInitSuccess_, true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_thumbnail_generation_test_002, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    ThumbnailData::GenerateStats stats;
    dfxManager->isInitSuccess_ = false;
    dfxManager->HandleThumbnailGeneration(stats);
    EXPECT_EQ(dfxManager->isInitSuccess_, false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_common_behavior_test_001, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    string bundleName = "bundleName";
    int32_t type = 1;
    dfxManager->HandleCommonBehavior(bundleName, type);
    EXPECT_EQ(dfxManager->isInitSuccess_, true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_common_behavior_test_002, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    string bundleName = "bundleName";
    int32_t type = 1;
    dfxManager->isInitSuccess_ = false;
    dfxManager->HandleCommonBehavior(bundleName, type);
    EXPECT_EQ(dfxManager->isInitSuccess_, false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_half_day_missions_test_001, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    dfxManager->HandleHalfDayMissions();
    EXPECT_EQ(dfxManager->isInitSuccess_, true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_half_day_missions_test_002, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    dfxManager->isInitSuccess_ = false;
    dfxManager->HandleHalfDayMissions();
    EXPECT_EQ(dfxManager->isInitSuccess_, false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_half_day_missions_test_003, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    dfxManager->dfxWorker_ = nullptr;
    dfxManager->HandleHalfDayMissions();
    EXPECT_EQ(dfxManager->dfxWorker_, nullptr);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_directory_exist_test_001, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    string dirName = "/storage/cloud/files/test";
    dfxManager->IsDirectoryExist(dirName);
    struct stat statInfo {};
    EXPECT_NE(stat(dirName.c_str(), &statInfo), E_SUCCESS);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_five_minute_task_test_001, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    dfxManager->isInitSuccess_ = false;
    dfxManager->HandleFiveMinuteTask();
    EXPECT_EQ(dfxManager->isInitSuccess_, false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_five_minute_task_test_002, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    dfxManager->isInitSuccess_ = false;
    int64_t result = MediaFileUtils::UTCTimeSeconds();
    EXPECT_EQ(dfxManager->HandleMiddleReport(), result);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_one_day_report_test_001, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    dfxManager->isInitSuccess_ = false;
    int64_t result = MediaFileUtils::UTCTimeSeconds();
    EXPECT_EQ(dfxManager->HandleOneDayReport(), result);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_one_day_report_test_002, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    string appName = "appName";
    bool adapted = true;
    dfxManager->isInitSuccess_ = false;
    dfxManager->HandleAdaptationToMovingPhoto(appName, adapted);
    EXPECT_EQ(dfxManager->isInitSuccess_, false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_one_day_report_test_003, TestSize.Level0)
{
    auto dfxManager = DfxManager::GetInstance();
    string appName = "appName";
    bool adapted = true;
    dfxManager->HandleAdaptationToMovingPhoto(appName, adapted);
    EXPECT_EQ(dfxManager->isInitSuccess_, true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_sync_state_test_001, TestSize.Level0)
{
    CloudSyncDfxManager* cloudSyncDfxManager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::BEGIN)));
    cloudSyncDfxManager->InitSyncState();
    EXPECT_EQ(cloudSyncDfxManager->syncState_, SyncState::INIT_STATE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_sync_state_test_002, TestSize.Level0)
{
    CloudSyncDfxManager* cloudSyncDfxManager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::FIRST_FIVE_HUNDRED)));
    cloudSyncDfxManager->InitSyncState();
    EXPECT_EQ(cloudSyncDfxManager->syncState_, SyncState::START_STATE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_sync_state_test_003, TestSize.Level0)
{
    CloudSyncDfxManager* cloudSyncDfxManager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::INCREMENT_DOWNLOAD)));
    cloudSyncDfxManager->InitSyncState();
    EXPECT_EQ(cloudSyncDfxManager->syncState_, SyncState::START_STATE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_sync_state_test_004, TestSize.Level0)
{
    CloudSyncDfxManager* cloudSyncDfxManager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::TOTAL_DOWNLOAD)));
    cloudSyncDfxManager->InitSyncState();
    EXPECT_EQ(cloudSyncDfxManager->syncState_, SyncState::START_STATE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_sync_state_test_005, TestSize.Level0)
{
    CloudSyncDfxManager* cloudSyncDfxManager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::TOTAL_DOWNLOAD_FINISH)));
    cloudSyncDfxManager->InitSyncState();
    EXPECT_EQ(cloudSyncDfxManager->syncState_, SyncState::END_STATE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_sync_state_test_006, TestSize.Level0)
{
    CloudSyncDfxManager* cloudSyncDfxManager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::SYNC_SWITCHED_OFF)));
    cloudSyncDfxManager->InitSyncState();
    EXPECT_EQ(cloudSyncDfxManager->syncState_, SyncState::INIT_STATE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_state_switch_test_001, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::FIRST_FIVE_HUNDRED)));
    EXPECT_EQ(InitState::StateSwitch(*manager), true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_state_switch_test_002, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::TOTAL_DOWNLOAD_FINISH)));
    EXPECT_EQ(InitState::StateSwitch(*manager), true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_init_state_switch_test_003, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::SYNC_SWITCHED_OFF)));
    EXPECT_EQ(InitState::StateSwitch(*manager), false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_start_state_switch_test_001, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::FIRST_FIVE_HUNDRED)));
    EXPECT_EQ(StartState::StateSwitch(*manager), false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_start_state_switch_test_002, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::TOTAL_DOWNLOAD_FINISH)));
    EXPECT_EQ(StartState::StateSwitch(*manager), true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_start_state_switch_test_003, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::SYNC_SWITCHED_OFF)));
    EXPECT_EQ(StartState::StateSwitch(*manager), true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_end_state_switch_test_001, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::FIRST_FIVE_HUNDRED)));
    EXPECT_EQ(EndState::StateSwitch(*manager), false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_end_state_switch_test_002, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::TOTAL_DOWNLOAD_FINISH)));
    EXPECT_EQ(EndState::StateSwitch(*manager), true);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_end_state_switch_test_003, TestSize.Level0)
{
    CloudSyncDfxManager* manager = &CloudSyncDfxManager::GetInstance();
    system::SetParameter(CLOUDSYNC_STATUS_KEY,
        std::to_string(static_cast<int>(CloudSyncStatus::SYNC_SWITCHED_OFF)));
    EXPECT_EQ(EndState::StateSwitch(*manager), true);
    EndState::Process(*manager);
    EXPECT_NE(manager->timerId_, 0);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_safe_path_test, TestSize.Level0)
{
    std::string path = "/storage/cloud/files/DCIM/123";
    std::string safePath = DfxUtils::GetSafePath(path);
    ASSERT_TRUE(safePath == "*DCIM");
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_join_strings_test, TestSize.Level0)
{
    unordered_set<string> set {"string1", "string2"};

    EXPECT_EQ(DfxUtils::JoinStrings(set, ';'), "string2;string1");
    EXPECT_EQ(DfxUtils::JoinStrings(set, '!'), "string2!string1");
    EXPECT_EQ(DfxUtils::JoinStrings({"string1"}, ';'), "string1");
    EXPECT_EQ(DfxUtils::JoinStrings({}, ';'), "");
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_split_test, TestSize.Level0)
{
    vector<string> result = {};
    string input = "";
    string pattern = "pattern";
    EXPECT_EQ(DfxUtils::Split(input, pattern), result);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_get_safeuri_test, TestSize.Level0)
{
    string safeUri = "";
    string uri = "";
    EXPECT_EQ(DfxUtils::GetSafeUri(uri), safeUri);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_get_safealbumname_test_001, TestSize.Level0)
{
    string albumName = ";";
    uint32_t length = albumName.size();
    string safeAlbumName = GARBLE + albumName.substr(length - GARBLE_LAST_ONE);
    EXPECT_EQ(DfxUtils::GetSafeAlbumName(albumName), safeAlbumName);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_get_safealbumname_test_002, TestSize.Level0)
{
    string albumName = "test";
    uint32_t length = albumName.size();
    string safeAlbumName = GARBLE + albumName.substr(length - GARBLE_LAST_TWO);
    EXPECT_EQ(DfxUtils::GetSafeAlbumName(albumName), safeAlbumName);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_split_string_test, TestSize.Level0)
{
    unordered_set<string> set {"string1", "string2"};

    EXPECT_EQ(DfxUtils::SplitString("string1;string2", ';'), set);
    EXPECT_EQ(DfxUtils::SplitString("string1!string2", '!'), set);
    EXPECT_EQ(DfxUtils::SplitString("string1", ';'), unordered_set<string>{"string1"});
    EXPECT_EQ(DfxUtils::SplitString("", ';'), unordered_set<string>{});
}

HWTEST_F(MediaLibraryDfxTest, medialib_cloud_manager_test, TestSize.Level0)
{
    CloudSyncDfxManager::GetInstance().RunDfx();
    int32_t downloadedThumb = 0;
    int32_t generatedThumb = 0;
    int32_t totalDownload = 0;
    DfxDatabaseUtils::QueryDownloadedAndGeneratedThumb(downloadedThumb, generatedThumb);
    DfxDatabaseUtils::QueryTotalCloudThumb(totalDownload);

    EXPECT_EQ(downloadedThumb, 0);
    EXPECT_EQ(generatedThumb, 0);
    EXPECT_EQ(totalDownload, 0);

    InitState::StateSwitch(CloudSyncDfxManager::GetInstance());
    InitState::Process(CloudSyncDfxManager::GetInstance());
    StartState::StateSwitch(CloudSyncDfxManager::GetInstance());
    StartState::Process(CloudSyncDfxManager::GetInstance());
    EndState::StateSwitch(CloudSyncDfxManager::GetInstance());
    EndState::Process(CloudSyncDfxManager::GetInstance());

    CloudSyncDfxManager::GetInstance().ShutDownTimer();
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_one_day_report_test, TestSize.Level0)
{
    int64_t result = DfxManager::GetInstance()->HandleOneDayReport();
    EXPECT_GT(result, 0);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportTimeOutOperation_test, TestSize.Level0)
{
    std::string bundleName = "bundleName";
    int32_t type = 1;
    int32_t object = 0;
    int32_t time = 0;
    DfxReporter dfxReporter;
    dfxReporter.ReportTimeOutOperation(bundleName, type, object, time);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_TIMEOUT_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "BUNDLE_NAME", bundleName,
        "OPERATION_TYPE", type,
        "OPERATION_OBJECT", object,
        "TIME", time);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportHighMemoryImageThumbnail_test_001, TestSize.Level0)
{
    std::string path = "";
    std::string suffix = "jpg";
    int32_t width = 4096;
    int32_t height = 4096;
    DfxReporter dfxReporter;
    EXPECT_EQ(dfxReporter.ReportHighMemoryImageThumbnail(path,
        suffix, width, height), COMMON_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportHighMemoryImageThumbnail_test_002, TestSize.Level0)
{
    std::string path = "";
    std::string suffix = "png";
    int32_t width = 1;
    int32_t height = 1;
    DfxReporter dfxReporter;
    EXPECT_EQ(dfxReporter.ReportHighMemoryImageThumbnail(path,
        suffix, width, height), OTHER_FORMAT_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportHighMemoryImageThumbnail_test_003, TestSize.Level0)
{
    std::string path = "";
    std::string suffix = "jpg";
    int32_t width = 4097;
    int32_t height = 4097;
    DfxReporter dfxReporter;
    EXPECT_EQ(dfxReporter.ReportHighMemoryImageThumbnail(path,
        suffix, width, height), BIG_IMAGE);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportHighMemoryVideoThumbnail_test_001, TestSize.Level0)
{
    std::string path = "";
    std::string suffix = "mp4";
    int32_t width = 7680;
    int32_t height = 7680;
    DfxReporter dfxReporter;
    EXPECT_EQ(dfxReporter.ReportHighMemoryVideoThumbnail(path,
        suffix, width, height), BIG_VIDEO);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportHighMemoryVideoThumbnail_test_002, TestSize.Level0)
{
    std::string path = "";
    std::string suffix = "mp4";
    int32_t width = 4096;
    int32_t height = 4096;
    DfxReporter dfxReporter;
    EXPECT_EQ(dfxReporter.ReportHighMemoryVideoThumbnail(path,
        suffix, width, height), COMMON_VIDEO);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportDeleteBehavior_test_001, TestSize.Level0)
{
    string bundleName = "";
    int32_t type = 1;
    std::string path = "";
    DfxReporter dfxReporter;
    dfxReporter.ReportDeleteBehavior(bundleName, type, path);
    EXPECT_EQ(bundleName, "");
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportDeleteBehavior_test_002, TestSize.Level0)
{
    string bundleName = "bundleName";
    int32_t type = 1;
    std::string path = "/data";
    DfxReporter dfxReporter;
    dfxReporter.ReportDeleteBehavior(bundleName, type, path);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DELETE_BEHAVIOR",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "BUNDLE_NAME", bundleName,
        "TYPE", type,
        "PATH", path);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportPhotoInfo_test_001, TestSize.Level0)
{
    PhotoStatistics stats = {};
    DfxReporter dfxReporter;
    dfxReporter.ReportPhotoInfo(stats);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_PHOTO_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "LOCAL_IMAGE_COUNT", stats.localImageCount,
        "LOCAL_VIDEO_COUNT", stats.localVideoCount,
        "CLOUD_IMAGE_COUNT", stats.cloudImageCount,
        "CLOUD_VIDEO_COUNT", stats.cloudVideoCount,
        "SHARED_IMAGE_COUNT", stats.sharedImageCount,
        "SHARED_VIDEO_COUNT", stats.sharedVideoCount);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportAstcInfo_test_001, TestSize.Level0)
{
    LcdAndAstcCount count = {};
    DfxReporter dfxReporter;
    dfxReporter.ReportAstcInfo(count);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_ASTC_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "LOCAL_LCD_COUNT", count.localLcdCount,
        "LOCAL_ASTC_COUNT", count.localAstcCount,
        "CLOUD_LCD_COUNT", count.cloudLcdCount,
        "CLOUD_ASTC_COUNT", count.cloudAstcCount,
        "PHASE_DETAIL", MediaLibraryAstcStat::GetInstance().GetJson());
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportAlbumInfo_test_001, TestSize.Level0)
{
    std::string albumName = "albumName";
    int32_t albumImageCount = 1;
    int32_t albumVideoCount = 1;
    bool isLocal = true;
    DfxReporter dfxReporter;
    dfxReporter.ReportAlbumInfo(albumName, albumImageCount, albumVideoCount, isLocal);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_ALBUM_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "ALBUM_NAME", albumName,
        "ALBUM_IMAGE_COUNT", albumImageCount,
        "ALBUM_VIDEO_COUNT", albumVideoCount,
        "IS_LOCAL", isLocal);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportDirtyCloudPhoto_test_001, TestSize.Level0)
{
    std::string data = "data";
    int32_t dirty = 1;
    int32_t cloudVersion = 1;
    DfxReporter dfxReporter;
    dfxReporter.ReportDirtyCloudPhoto(data, dirty, cloudVersion);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DIRTY_CLOUD_PHOTO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "PATH", data,
        "DIRTY", dirty,
        "CLOUD_VERSION", cloudVersion);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportCommonVersion_test_001, TestSize.Level0)
{
    int32_t dbVersion = 1;
    DfxReporter dfxReporter;
    dfxReporter.ReportCommonVersion(dbVersion);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_COMMON_VERSION",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "DB_VERSION", dbVersion,
        "THUMBNAIL_VERSION", THUMBNAIL_VERSION);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportAnalysisVersion_test_001, TestSize.Level0)
{
    std::string analysisName = "analysisName";
    int32_t version = 1;
    DfxReporter dfxReporter;
    dfxReporter.ReportAnalysisVersion(analysisName, version);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_ANALYSIS_VERSION",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "NAME", analysisName,
        "VERSION", version);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportStartResult_test_001, TestSize.Level0)
{
    int32_t scene = 1;
    int32_t error = 0;
    int32_t start = 1;
    int32_t cost = static_cast<int32_t>(MediaFileUtils::UTCTimeMilliSeconds() - start);
    DfxReporter dfxReporter;
    dfxReporter.ReportStartResult(scene, error, start);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_START_RESULT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "SCENE", scene,
        "ERROR", error,
        "TIME", cost);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportCloudSyncThumbGenerationStatus_test_001, TestSize.Level0)
{
    int32_t downloadedThumb = 1;
    int32_t generatedThumb = 1;
    int32_t totalDownload = 0;
    DfxReporter dfxReporter;
    int32_t result = dfxReporter.ReportCloudSyncThumbGenerationStatus(downloadedThumb,
        generatedThumb, totalDownload);
    EXPECT_EQ(result, 0);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportCloudSyncThumbGenerationStatus_test_002, TestSize.Level0)
{
    int32_t downloadedThumb = 1;
    int32_t generatedThumb = 1;
    int32_t totalDownload = 1;
    DfxReporter dfxReporter;
    int32_t result = dfxReporter.ReportCloudSyncThumbGenerationStatus(downloadedThumb,
        generatedThumb, totalDownload);
    EXPECT_EQ(result, 0);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportMedialibraryAPI_test_001, TestSize.Level0)
{
    string callerPackage = "";
    string saveUri = "saveUri";
    DfxReporter dfxReporter;
    int32_t result = dfxReporter.ReportMedialibraryAPI(callerPackage, saveUri);
    EXPECT_EQ(result, E_SUCCESS);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_ReportCustomRestoreFusion_test_001, TestSize.Level0)
{
    CustomRestoreDfxDataPoint dfxDataPoint;
    dfxDataPoint.customRestorePackageName = "customRestorePackageName";
    dfxDataPoint.albumLPath = "albumLPath";
    dfxDataPoint.keyPath = "keyPath";
    dfxDataPoint.totalNum = 11;
    dfxDataPoint.successNum = 12;
    dfxDataPoint.failedNum = 13;
    dfxDataPoint.sameNum = 14;
    dfxDataPoint.cancelNum = 16;
    dfxDataPoint.totalTime = 102221;
    DfxReporter dfxReporter;
    int32_t result = dfxReporter.ReportCustomRestoreFusion(dfxDataPoint);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_QueryFromPhotos_test_001, TestSize.Level0)
{
    int32_t mediaType = 1;
    int32_t position = 1;
    DfxDatabaseUtils dfxDatabaseUtils;
    int32_t result = dfxDatabaseUtils.QueryFromPhotos(mediaType, position);
    EXPECT_EQ(result, E_SUCCESS);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_QueryAlbumInfoBySubtype_test_001, TestSize.Level0)
{
    int32_t albumSubtype = 1;
    DfxDatabaseUtils dfxDatabaseUtils;
    EXPECT_EQ(dfxDatabaseUtils.QueryAlbumInfoBySubtype(albumSubtype).count, 0);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_QueryDirtyCloudPhoto_test_001, TestSize.Level0)
{
    vector<PhotoInfo> photoInfoList;
    DfxDatabaseUtils dfxDatabaseUtils;
    dfxDatabaseUtils.QueryDirtyCloudPhoto();
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, 1);
    predicates.NotEqualTo(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t> (DirtyType::TYPE_SYNCED));
    predicates.Limit(DIRTY_PHOTO_COUNT);
    std::vector<std::string> columns = { MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_DIRTY,
        PhotoColumn::PHOTO_CLOUD_ID };
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(predicates, columns);
    EXPECT_EQ(resultSet, nullptr);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_QueryAnalysisVersion_test_001, TestSize.Level0)
{
    std::string table = "";
    std::string column = "";
    DfxDatabaseUtils dfxDatabaseUtils;
    int32_t result = dfxDatabaseUtils.QueryAnalysisVersion(table, column);
    EXPECT_EQ(result, E_SUCCESS);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_QueryDouble_test_001, TestSize.Level0)
{
    NativeRdb::AbsRdbPredicates dirAbsPred(PhotoColumn::PHOTOS_TABLE);
    dirAbsPred.EqualTo(MEDIA_DATA_DB_ID, to_string(0));
    vector<string> columns = {};
    std::string queryColumn = "queryColumn";
    double value = 1;
    DfxDatabaseUtils dfxDatabaseUtils;
    int32_t result = dfxDatabaseUtils.QueryDouble(dirAbsPred, columns, queryColumn, value);
    EXPECT_EQ(result, E_DB_FAIL);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_QueryLCDThumb_test_001, TestSize.Level0)
{
    DfxDatabaseUtils dfxDatabaseUtils;
    int32_t result_1 = dfxDatabaseUtils.QueryLCDThumb(true);
    EXPECT_EQ(result_1, 0);
    int32_t result_2 = dfxDatabaseUtils.QueryLCDThumb(true);
    EXPECT_EQ(result_2, 0);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_AddCommonBahavior_test_001, TestSize.Level0)
{
    int32_t type = 1;
    string bundleName = "test";
    DfxCollector dfxCollector;
    dfxCollector.AddCommonBahavior(bundleName, type);
    dfxCollector.AddCommonBahavior(bundleName, type);
    EXPECT_EQ(dfxCollector.commonBehaviorMap_[bundleName].times, 2);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_CollectDeleteBehavior_test_001, TestSize.Level0)
{
    string bundleName = "medialib_dfx";
    int32_t type = DfxType::TRASH_PHOTO;
    int32_t size = 10;
    DfxCollector dfxCollector;
    dfxCollector.CollectDeleteBehavior(bundleName, type, size);
    EXPECT_EQ(dfxCollector.deleteToTrashMap_[bundleName], 1);
    type = DfxType::ALBUM_DELETE_ASSETS;
    dfxCollector.CollectDeleteBehavior(bundleName, type, size);
    EXPECT_EQ(dfxCollector.deleteToTrashMap_[bundleName], 1);
    type = DfxType::ALBUM_REMOVE_PHOTOS;
    dfxCollector.CollectDeleteBehavior(bundleName, type, size);
    EXPECT_EQ(dfxCollector.deleteToTrashMap_[bundleName], 1);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_CollectAdaptationToMovingPhotoInfo_test_001, TestSize.Level0)
{
    string appName = "appName";
    DfxCollector dfxCollector;
    dfxCollector.CollectAdaptationToMovingPhotoInfo(appName, true);
    auto result = dfxCollector.adaptationToMovingPhotoInfo_.adaptedAppPackages;
    EXPECT_NE(result.find(appName), result.end());
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_CollectAdaptationToMovingPhotoInfo_test_002, TestSize.Level0)
{
    string appName = "medialib";
    DfxCollector dfxCollector;
    dfxCollector.CollectAdaptationToMovingPhotoInfo(appName, false);
    auto result = dfxCollector.adaptationToMovingPhotoInfo_.unadaptedAppPackages;
    EXPECT_NE(result.find(appName), result.end());
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_FlushCommonBehavior_test_001, TestSize.Level0)
{
    string bundleName = "medialib_dfx";
    std::unordered_map<string, CommonBehavior> commonBehaviorMap;
    CommonBehavior commonBehavior = { 0 };
    commonBehaviorMap[bundleName] = commonBehavior;
    DfxAnalyzer dfxAnalyzer;
    dfxAnalyzer.FlushCommonBehavior(commonBehaviorMap);
    EXPECT_EQ(commonBehaviorMap.empty(), false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_FlushCommonBehavior_test_002, TestSize.Level0)
{
    string bundleName = "";
    std::unordered_map<string, CommonBehavior> commonBehaviorMap;
    CommonBehavior commonBehavior = { 0 };
    commonBehaviorMap[bundleName] = commonBehavior;
    DfxAnalyzer dfxAnalyzer;
    dfxAnalyzer.FlushCommonBehavior(commonBehaviorMap);
    EXPECT_EQ(commonBehaviorMap.empty(), false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_FlushDeleteBehavior_test_001, TestSize.Level0)
{
    string bundleName = "medialib_dfx";
    std::unordered_map<string, int32_t> deleteBehaviorMap;
    deleteBehaviorMap[bundleName] = 0;
    int32_t type = 1;
    DfxAnalyzer dfxAnalyzer;
    dfxAnalyzer.FlushDeleteBehavior(deleteBehaviorMap, type);
    EXPECT_EQ(deleteBehaviorMap.empty(), false);
}

HWTEST_F(MediaLibraryDfxTest, medialib_dfx_FlushAdaptationToMovingPhoto_test_001, TestSize.Level0)
{
    string bundleName = "medialib_dfx";
    AdaptationToMovingPhotoInfo newAdaptationInfo;
    newAdaptationInfo.unadaptedAppPackages.emplace(bundleName);
    DfxAnalyzer dfxAnalyzer;
    dfxAnalyzer.FlushAdaptationToMovingPhoto(newAdaptationInfo);
    EXPECT_EQ(newAdaptationInfo.unadaptedAppPackages.empty(), false);
}
} // namespace Media
} // namespace OHOS