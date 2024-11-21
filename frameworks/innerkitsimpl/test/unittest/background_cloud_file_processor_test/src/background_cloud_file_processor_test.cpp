/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "BackgroundCloudFileProcessorTest"

#include "background_cloud_file_processor_test.h"

#include <chrono>
#include <thread>

#define private public
#include "background_cloud_file_processor.h"
#undef private

#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

static shared_ptr<MediaLibraryRdbStore> rdbStore;
static std::atomic<int> num{ 0 };

int32_t ExecSqls(const vector<string> &sqls)
{
    EXPECT_NE((rdbStore == nullptr), true);
    int32_t err = E_OK;
    for (const auto &sql : sqls) {
        err = rdbStore->ExecuteSql(sql);
        MEDIA_INFO_LOG("exec sql: %{public}s result: %{public}d", sql.c_str(), err);
        EXPECT_EQ(err, E_OK);
    }
    return E_OK;
}

void ClearTables()
{
    string clearPhoto = "DELETE FROM " + PhotoColumn::PHOTOS_TABLE;
    vector<string> executeSqls = { clearPhoto };
    MEDIA_INFO_LOG("start clear data");
    ExecSqls(executeSqls);
    num = 0;
}

inline void IncrementNum()
{
    ++num;
}

int64_t GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    IncrementNum();
    return seconds.count() + num.load();
}

string GetTitle(int64_t &timestamp)
{
    IncrementNum();
    return "IMG_" + to_string(timestamp) + "_" + to_string(num.load());
}

string InsertPhoto(const MediaType &mediaType)
{
    EXPECT_NE((rdbStore == nullptr), true);
    int64_t fileId = -1;
    int64_t timestamp = GetTimestamp();
    string title = GetTitle(timestamp);
    string displayName = mediaType == MEDIA_TYPE_VIDEO ? (title + ".mp4") : (title + ".jpg");
    string path = "/storage/cloud/files/photo/1/" + displayName;
    int32_t position = 2;
    int64_t videoSize = 1 * 1000 * 1000 * 1000;
    int64_t imageSize = 10 * 1000 * 1000;
    int32_t videoDuration = 0;
    int32_t imageDuration = 2560;
    int32_t videoWidth = 3072;
    int32_t imageWidth = 1920;
    int32_t videoHeight = 4096;
    int32_t imageHeight = 1080;
    string videoMimeType = "video/mp4";
    string imageMimeType = "image/jpeg";
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, mediaType);
    valuesBucket.PutInt(PhotoColumn::PHOTO_POSITION, position);
    valuesBucket.PutLong(MediaColumn::MEDIA_SIZE, mediaType == MEDIA_TYPE_VIDEO ? videoSize : imageSize);
    valuesBucket.PutInt(MediaColumn::MEDIA_DURATION, mediaType == MEDIA_TYPE_VIDEO ? videoDuration : imageDuration);
    valuesBucket.PutInt(PhotoColumn::PHOTO_WIDTH, mediaType == MEDIA_TYPE_VIDEO ? videoWidth : imageWidth);
    valuesBucket.PutInt(PhotoColumn::PHOTO_HEIGHT, mediaType == MEDIA_TYPE_VIDEO ? videoHeight : imageHeight);
    valuesBucket.PutString(MediaColumn::MEDIA_MIME_TYPE, mediaType == MEDIA_TYPE_VIDEO ? videoMimeType : imageMimeType);
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, path);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_ADDED, timestamp);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, timestamp);
    valuesBucket.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_HIDDEN, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_TIME_PENDING, 0);
    int32_t ret = rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertPhoto fileId is %{public}s", to_string(fileId).c_str());
    return path;
}

vector<string> PreparePhotos(const int count, const MediaType &mediaType)
{
    vector<string> photos;
    for (size_t index = 0; index < count; ++index) {
        string path = InsertPhoto(mediaType);
        photos.push_back(path);
    }
    return photos;
}

int32_t PrepareAbnormalPhotos(const string &column)
{
    EXPECT_NE((rdbStore == nullptr), true);
    string updateSql;
    if (column == MediaColumn::MEDIA_MIME_TYPE) {
        updateSql = "update " + PhotoColumn::PHOTOS_TABLE + " set " + column + " = '' ";
    } else {
        updateSql = "update " + PhotoColumn::PHOTOS_TABLE + " set " + column + " = 0 ";
    }
    vector<string> executeSqls = {updateSql};
    int32_t ret = ExecSqls(executeSqls);
    EXPECT_EQ(ret, E_OK);
    return ret;
}

int32_t QueryPhotosCount()
{
    EXPECT_NE((rdbStore == nullptr), true);

    const string sql = "SELECT COUNT( * ) AS count FROM " + PhotoColumn::PHOTOS_TABLE;
    shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(sql);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);

    int32_t count = GetInt32Val("count", resultSet);
    EXPECT_GE(count, 0);

    MEDIA_INFO_LOG("Photos Count is %{public}d", count);
    return count;
}

std::vector<std::string> QueryCurDownloadFiles()
{
    std::vector<std::string> curDownloadFiles;
    auto resultSet = BackgroundCloudFileProcessor::QueryCloudFiles();
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query cloud files!");
        return curDownloadFiles;
    }

    BackgroundCloudFileProcessor::DownloadFiles downloadFiles;
    BackgroundCloudFileProcessor::ParseDownloadFiles(resultSet, downloadFiles);
    if (downloadFiles.paths.empty()) {
        MEDIA_INFO_LOG("No cloud files need to be downloaded");
        return curDownloadFiles;
    }
    return downloadFiles.paths;
}

void BackgroundCloudFileProcessorTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("BackgroundCloudFileProcessorTest SetUpTestCase");

    MediaLibraryUnitTestUtils::Init();
    rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(rdbStore, nullptr);
}

void BackgroundCloudFileProcessorTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("BackgroundCloudFileProcessorTest TearDownTestCase");
    ClearTables();
}

void BackgroundCloudFileProcessorTest::SetUp()
{
    MEDIA_INFO_LOG("BackgroundCloudFileProcessorTest SetUp");
    ClearTables();
}

void BackgroundCloudFileProcessorTest::TearDown()
{
    MEDIA_INFO_LOG("BackgroundCloudFileProcessorTest TearDown");
}

// Scenario2: Test Image download order
HWTEST_F(BackgroundCloudFileProcessorTest, background_cloud_file_processor_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("background_cloud_file_processor_test_002 Start");
    PreparePhotos(5, MEDIA_TYPE_IMAGE);
    PreparePhotos(10, MEDIA_TYPE_IMAGE);
    vector<string> lastBatch = PreparePhotos(2, MEDIA_TYPE_IMAGE);
    EXPECT_EQ(QueryPhotosCount(), 17);

    EXPECT_EQ(BackgroundCloudFileProcessor::processInterval_, 50);
    BackgroundCloudFileProcessor::StartTimer();

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    std::sort(BackgroundCloudFileProcessor::curDownloadPaths_.begin(),
        BackgroundCloudFileProcessor::curDownloadPaths_.end());
    std::sort(lastBatch.begin(), lastBatch.end());
    EXPECT_EQ(BackgroundCloudFileProcessor::curDownloadPaths_, lastBatch);

    BackgroundCloudFileProcessor::StopTimer();
    MEDIA_INFO_LOG("background_cloud_file_processor_test_002 End");
}

// Scenario3: Test Video download order
HWTEST_F(BackgroundCloudFileProcessorTest, background_cloud_file_processor_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("background_cloud_file_processor_test_003 Start");
    PreparePhotos(5, MEDIA_TYPE_VIDEO);
    PreparePhotos(10, MEDIA_TYPE_VIDEO);
    vector<string> latest = PreparePhotos(1, MEDIA_TYPE_VIDEO);
    EXPECT_EQ(QueryPhotosCount(), 16);

    EXPECT_EQ(BackgroundCloudFileProcessor::processInterval_, 50);
    BackgroundCloudFileProcessor::StartTimer();

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(BackgroundCloudFileProcessor::curDownloadPaths_, latest);

    BackgroundCloudFileProcessor::StopTimer();
    MEDIA_INFO_LOG("background_cloud_file_processor_test_003 End");
}

// Scenario4: Test the download order when the video is latest
HWTEST_F(BackgroundCloudFileProcessorTest, background_cloud_file_processor_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("background_cloud_file_processor_test_004 Start");
    PreparePhotos(5, MEDIA_TYPE_IMAGE);
    PreparePhotos(5, MEDIA_TYPE_VIDEO);
    PreparePhotos(5, MEDIA_TYPE_IMAGE);
    PreparePhotos(5, MEDIA_TYPE_VIDEO);
    vector<string> latest = PreparePhotos(1, MEDIA_TYPE_VIDEO);
    EXPECT_EQ(QueryPhotosCount(), 21);

    EXPECT_EQ(BackgroundCloudFileProcessor::processInterval_, 50);
    BackgroundCloudFileProcessor::StartTimer();

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(BackgroundCloudFileProcessor::curDownloadPaths_, latest);

    BackgroundCloudFileProcessor::StopTimer();
    MEDIA_INFO_LOG("background_cloud_file_processor_test_004 End");
}

// Scenario5: Test the download order when the video is earliest
HWTEST_F(BackgroundCloudFileProcessorTest, background_cloud_file_processor_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("background_cloud_file_processor_test_005 Start");
    vector<string> earliest = PreparePhotos(1, MEDIA_TYPE_VIDEO);
    PreparePhotos(10, MEDIA_TYPE_IMAGE);
    PreparePhotos(10, MEDIA_TYPE_IMAGE);
    EXPECT_EQ(QueryPhotosCount(), 21);

    EXPECT_EQ(BackgroundCloudFileProcessor::processInterval_, 50);
    BackgroundCloudFileProcessor::StartTimer();

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(BackgroundCloudFileProcessor::curDownloadPaths_, earliest);

    BackgroundCloudFileProcessor::StopTimer();
    MEDIA_INFO_LOG("background_cloud_file_processor_test_005 End");
}

// Scenario6: Test how many images can be downloaded in one minute
HWTEST_F(BackgroundCloudFileProcessorTest, background_cloud_file_processor_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("background_cloud_file_processor_test_006 Start");
    PreparePhotos(10, MEDIA_TYPE_IMAGE);
    EXPECT_EQ(QueryPhotosCount(), 10);

    EXPECT_EQ(BackgroundCloudFileProcessor::processInterval_, 50);
    BackgroundCloudFileProcessor::StartTimer();

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(BackgroundCloudFileProcessor::curDownloadPaths_.size(), 2);

    BackgroundCloudFileProcessor::StopTimer();
    MEDIA_INFO_LOG("background_cloud_file_processor_test_006 End");
}

// Scenario7: Test how many videos can be downloaded in one minute
HWTEST_F(BackgroundCloudFileProcessorTest, background_cloud_file_processor_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("background_cloud_file_processor_test_007 Start");
    PreparePhotos(10, MEDIA_TYPE_VIDEO);
    EXPECT_EQ(QueryPhotosCount(), 10);

    EXPECT_EQ(BackgroundCloudFileProcessor::processInterval_, 50);
    BackgroundCloudFileProcessor::StartTimer();

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(BackgroundCloudFileProcessor::curDownloadPaths_.size(), 1);

    BackgroundCloudFileProcessor::StopTimer();
    MEDIA_INFO_LOG("background_cloud_file_processor_test_007 End");
}

// Scenario8: Test how many image can be updated in one minute
HWTEST_F(BackgroundCloudFileProcessorTest, background_cloud_file_processor_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("background_cloud_file_processor_test_008 Start");
    PreparePhotos(10, MEDIA_TYPE_IMAGE);
    PrepareAbnormalPhotos(MediaColumn::MEDIA_SIZE);
    auto resultSet = BackgroundCloudFileProcessor::QueryUpdateData();
    int32_t rowCount;
    int32_t ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(rowCount, 1);
    MEDIA_INFO_LOG("background_cloud_file_processor_test_008 End");
}

// Scenario9: Test how many video can be updated in one minute
HWTEST_F(BackgroundCloudFileProcessorTest, background_cloud_file_processor_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("background_cloud_file_processor_test_009 Start");
    PreparePhotos(10, MEDIA_TYPE_VIDEO);
    PrepareAbnormalPhotos(MediaColumn::MEDIA_SIZE);
    auto resultSet = BackgroundCloudFileProcessor::QueryUpdateData();
    int32_t rowCount;
    int32_t ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(rowCount, 1);
    MEDIA_INFO_LOG("background_cloud_file_processor_test_009 End");
}
} // namespace Media
} // namespace OHOS