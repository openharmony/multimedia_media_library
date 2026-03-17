/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaCleanAllDirtyFilesTaskTest"

#include "media_clean_all_dirty_files_task_test.h"
#include "media_clean_all_dirty_files_task.h"

#include <chrono>
#include <thread>

#include "media_log.h"
#include "media_file_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_mock_tocken.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "media_column.h"
#include "download_resources_column.h"
#include "media_upgrade.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::Background;

static shared_ptr<MediaLibraryRdbStore> rdbStore;
static std::atomic<int> num{0};
static uint64_t g_shellToken = 0;
static MediaLibraryMockHapToken* mockToken = nullptr;

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

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

void CleanTestTables()
{
    vector<string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
        DownloadResourcesColumn::TABLE,
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        int32_t ret = rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

void ResetTables()
{
    vector<string> createTableSqlList = {
        PhotoUpgrade::CREATE_PHOTO_TABLE,
        DownloadResourcesColumn::CREATE_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

void ClearAndResetTable()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    ::system("rm -rf /storage/cloud/files/*");
    ::system("rm -rf /storage/cloud/files/.thumbs");
    ::system("rm -rf /storage/cloud/files/.editData");
    for (const auto &dir : TEST_ROOT_DIRS) {
        string ROOT_PATH = "/storage/cloud/100/files/";
        bool ret = MediaFileUtils::CreateDirectory(ROOT_PATH + dir + "/");
        CHECK_AND_PRINT_LOG(ret, "make %{public}s dir failed, ret=%{public}d", dir.c_str(), ret);
    }
    CleanTestTables();
    ResetTables();
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

string InsertPhoto(const MediaType &mediaType, int32_t position)
{
    EXPECT_NE((rdbStore == nullptr), true);

    int64_t fileId = -1;
    int64_t timestamp = GetTimestamp();
    int64_t timestampMilliSecond = timestamp * SEC_TO_MSEC;
    string title = GetTitle(timestamp);
    string displayName = mediaType == MEDIA_TYPE_VIDEO ? (title + ".mp4") : (title + ".jpg");
    string path = "/storage/cloud/files/photo/1/" + displayName;
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
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_ADDED, timestampMilliSecond);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, timestampMilliSecond);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TAKEN, timestampMilliSecond);
    valuesBucket.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_HIDDEN, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_TIME_PENDING, 0);
    int32_t ret = rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertPhoto fileId is %{public}s", to_string(fileId).c_str());
    return path;
}

vector<string> PreparePhotos(const int count, const MediaType &mediaType, int32_t position)
{
    vector<string> photos;
    for (size_t index = 0; index < count; ++index) {
        string path = InsertPhoto(mediaType, position);
        photos.push_back(path);
    }
    return photos;
}

void InsertBatchDownloadTask(int32_t fileId, std::string path, std::string displayName, int32_t status)
{
    EXPECT_NE((rdbStore == nullptr), true);
    int64_t rowId = -1;
    NativeRdb::ValuesBucket values;
    values.PutInt(DownloadResourcesColumn::MEDIA_ID, fileId);
    values.PutString(DownloadResourcesColumn::MEDIA_NAME, displayName);
    values.PutLong(DownloadResourcesColumn::MEDIA_SIZE, 3096); // 3096 size
    values.PutString(DownloadResourcesColumn::MEDIA_URI, path);
    values.PutLong(DownloadResourcesColumn::MEDIA_DATE_ADDED, 0);
    values.PutLong(DownloadResourcesColumn::MEDIA_DATE_FINISH, 0);
    values.PutInt(DownloadResourcesColumn::MEDIA_DOWNLOAD_STATUS, status);
    values.PutInt(DownloadResourcesColumn::MEDIA_PERCENT, -1);
    values.PutInt(DownloadResourcesColumn::MEDIA_AUTO_PAUSE_REASON, 1);
    values.PutInt(DownloadResourcesColumn::MEDIA_COVER_LEVEL, 1);
    values.PutInt(DownloadResourcesColumn::MEDIA_TASK_SEQ, 1);
    values.PutInt(DownloadResourcesColumn::MEDIA_NETWORK_POLICY, 1);
    int32_t ret = rdbStore->Insert(rowId, DownloadResourcesColumn::TABLE, values);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertBatchDownloadTask fileId is %{public}s", to_string(fileId).c_str());
}

vector<string> PrepareBatchDownloadTask(const int32_t count)
{
    vector<string> uris;
    for (int32_t index = 1; index <= count; ++index) {
        int64_t timestamp = GetTimestamp();
        string title = GetTitle(timestamp);
        string displayName = title + to_string(index) + ".jpg";
        string path = "file://media/Photo/" + to_string(index) + "/" + displayName;
        InsertBatchDownloadTask(index, path, displayName, 0);
        uris.push_back(path);
    }
    return uris;
}

void MediaCleanAllDirtyFilesTaskTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("MediaCleanAllDirtyFilesTaskTest SetUpTestCase");

    MediaLibraryUnitTestUtils::Init();
    g_shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(g_shellToken);
 
    vector<string> perms;
    perms.push_back("ohos.permission.GET_NETWORK_INFO");
    // mock  tokenID
    mockToken = new MediaLibraryMockHapToken("com.ohos.medialibrary.medialibrarydata", perms);
    for (auto &perm : perms) {
        MediaLibraryMockTokenUtils::GrantPermissionByTest(IPCSkeleton::GetSelfTokenID(), perm, 0);
    }
    rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(rdbStore, nullptr);
}

void MediaCleanAllDirtyFilesTaskTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("MediaCleanAllDirtyFilesTaskTest TearDownTestCase");
    ClearAndResetTable();
    if (mockToken != nullptr) {
    delete mockToken;
    mockToken = nullptr;
    }
 
    MediaLibraryMockTokenUtils::ResetToken();
    SetSelfTokenID(g_shellToken);
    EXPECT_EQ(g_shellToken, IPCSkeleton::GetSelfTokenID());
    std::this_thread::sleep_for(chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MediaCleanAllDirtyFilesTaskTest::SetUp()
{
    MEDIA_INFO_LOG("MediaCleanAllDirtyFilesTaskTest SetUp");
    ClearAndResetTable();
    PreparePhotos(10, MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::CLOUD)); // 10 count
}

void MediaCleanAllDirtyFilesTaskTest::TearDown()
{
    MEDIA_INFO_LOG("MediaCleanAllDirtyFilesTaskTest TearDown");
}

HWTEST_F(MediaCleanAllDirtyFilesTaskTest, Mcadft_SetBatchExecuteTime_01, TestSize.Level1)
{
    MEDIA_INFO_LOG("Mcadft_SetBatchExecuteTime_01 Start");
    MediaCleanAllDirtyFilesTask task;
    int64_t testTime = 1234567890;
    task.SetBatchExecuteTime();
    int64_t saveTime = task.GetBatchExecuteTime();
    EXPECT_NE(testTime, saveTime);
    MEDIA_INFO_LOG("Mcadft_SetBatchExecuteTime_01 End");
}
} // namespace Media
} // namespace OHOS