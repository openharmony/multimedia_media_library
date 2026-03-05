/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define MLOG_TAG "HeightWidthCorrectOperationTest"

#include "height_width_correct_operation_test.h"

#include <chrono>
#include <fstream>

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "photo_album_column.h"
#include "height_width_correct_operation.h"
#include "photo_file_utils.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "media_upgrade.h"
#include "preferences_helper.h"
#include "metadata.h"
#include "metadata_extractor.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

shared_ptr<MediaLibraryRdbStore> g_rdbStore;
std::atomic<int> g_num{0};

struct InsertPhotoParams {
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    int32_t position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    int32_t height = 1920;
    int32_t width = 1080;
    int32_t orientation = 0;
    int32_t exifRotate = 0;
    std::string lcdSize = "1080:1920";
};


const int32_t MILSEC_TO_MICSEC = 1000;

int32_t ExecSqls(const vector<string> &sqls)
{
    EXPECT_NE(g_rdbStore, nullptr);
    int32_t err = E_OK;
    for (const auto &sql : sqls) {
        err = g_rdbStore->ExecuteSql(sql);
        MEDIA_INFO_LOG("exec sql: %{public}s result: %{public}d", sql.c_str(), err);
        EXPECT_EQ(err, E_OK);
    }
    return E_OK;
}

void ClearTables()
{
    vector<string> createTableSqlList = {
        "DELETE FROM " + PhotoColumn::PHOTOS_TABLE,
        "DELETE FROM " + PhotoAlbumColumns::TABLE,
    };
    MEDIA_INFO_LOG("start clear data");
    ExecSqls(createTableSqlList);
}

inline void IncrementNum()
{
    ++g_num;
}

int64_t GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    IncrementNum();
    return seconds.count() + g_num.load();
}

string GetTitle(int64_t &timestamp)
{
    IncrementNum();
    return "IMG_" + to_string(timestamp) + "_" + to_string(g_num.load());
}

int64_t InsertPhoto(const InsertPhotoParams &params)
{
    EXPECT_NE(g_rdbStore, nullptr);
    int64_t timestamp = GetTimestamp();
    int64_t timestampMilliSecond = timestamp * SEC_TO_MSEC;
    string title = GetTitle(timestamp);
    string displayName = params.mediaType == MEDIA_TYPE_VIDEO ? (title + ".mp4") : (title + ".jpg");
    string path = "/storage/cloud/files/photo/16/" + displayName;
    int64_t size = params.mediaType == MEDIA_TYPE_VIDEO ? (1000 * 1000 * 1000) : (10 * 1000 * 1000);
    int32_t duration = params.mediaType == MEDIA_TYPE_VIDEO ? 2560 : 0;
    int32_t photoWidth = params.mediaType == MEDIA_TYPE_VIDEO ? 3072 : params.width;
    int32_t photoHeight = params.mediaType == MEDIA_TYPE_VIDEO ? 4096 : params.height;

    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, path);
    values.PutLong(MediaColumn::MEDIA_SIZE, size);
    values.PutString(MediaColumn::MEDIA_TITLE, title);
    values.PutString(MediaColumn::MEDIA_NAME, displayName);
    values.PutInt(MediaColumn::MEDIA_TYPE, params.mediaType);
    values.PutString(MediaColumn::MEDIA_MIME_TYPE, "image/jpeg");
    values.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, "com.ohos.photos");
    values.PutString(MediaColumn::MEDIA_OWNER_APPID, "100");
    values.PutLong(MediaColumn::MEDIA_DATE_ADDED, timestampMilliSecond);
    values.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, timestampMilliSecond);
    values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, timestampMilliSecond);
    values.PutInt(MediaColumn::MEDIA_DURATION, duration);
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, params.orientation);
    values.PutInt(PhotoColumn::PHOTO_HEIGHT, photoHeight);
    values.PutInt(PhotoColumn::PHOTO_WIDTH, photoWidth);
    values.PutInt(PhotoColumn::PHOTO_POSITION, params.position);
    values.PutString(PhotoColumn::PHOTO_LCD_SIZE, params.lcdSize);
    values.PutInt(PhotoColumn::PHOTO_EXIF_ROTATE, params.exifRotate);

    int64_t outRowId = 0;
    int32_t ret = g_rdbStore->Insert(outRowId, PhotoColumn::PHOTOS_TABLE, values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(outRowId, 0);
    return outRowId;
}


void HeightWidthCorrectOperationTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperationTest::SetUpTestCase");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(g_rdbStore, nullptr);
    ClearTables();
}

void HeightWidthCorrectOperationTest::TearDownTestCase()
{
    HeightWidthCorrectOperation::Stop();
    MEDIA_INFO_LOG("HeightWidthCorrectOperationTest::TearDownTestCase");
    ClearTables();
    MediaLibraryUnitTestUtils::StopUnistore();
    g_rdbStore.reset();
}

void HeightWidthCorrectOperationTest::SetUp()
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperationTest::SetUp");
}

void HeightWidthCorrectOperationTest::TearDown()
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperationTest::TearDown");
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_Stop_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_Stop_Test_001 start");
    HeightWidthCorrectOperation::Stop();
    EXPECT_TRUE(true);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_QueryNoCheckPhotoCount_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_QueryNoCheckPhotoCount_Test_002 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL)});
    int64_t fileId2 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL)});
    EXPECT_GT(fileId1, 0);
    EXPECT_GT(fileId2, 0);
    int32_t count = HeightWidthCorrectOperation::QueryNoCheckPhotoCount(0);
    EXPECT_EQ(count, 2);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_HandlePhotoInfos_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_HandlePhotoInfos_Test_001 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL)});
    EXPECT_GT(fileId1, 0);
    vector<CheckPhotoInfo> photoInfos;
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    photoInfos.push_back(photoInfo);
    int32_t curFileId = 0;
    unordered_set<int32_t> failedIds;
    int32_t count = 1;
    HeightWidthCorrectOperation::HandlePhotoInfos(photoInfos, curFileId, failedIds, count);
    EXPECT_EQ(count, 0);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_001 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1080, .width = 1920, .orientation = 90, .exifRotate = 0, .lcdSize = "1920:1080"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1080;
    photoInfo.width = 1920;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 90;
    photoInfo.lcdSize = "1920:1080";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_002 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1080, .width = 1920, .orientation = 270, .exifRotate = 0, .lcdSize = "1920:1080"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1080;
    photoInfo.width = 1920;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 270;
    photoInfo.lcdSize = "1920:1080";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_003 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 1, .lcdSize = "1080:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 1;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_004 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 3, .lcdSize = "1080:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 3;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_005 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 5, .lcdSize = "1080:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 5;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_006 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 6, .lcdSize = "1080:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 6;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_007 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 8, .lcdSize = "1080:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 8;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_008 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::CLOUD),
        .height = 0, .width = 0, .orientation = 0, .exifRotate = 0, .lcdSize = ""});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 0;
    photoInfo.width = 0;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_FALSE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_009 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 0, .lcdSize = ""});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_FALSE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_010 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 0, .lcdSize = "0:0"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "0:0";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_FALSE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_011, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_011 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 0, .lcdSize = "1920:1080"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1920:1080";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_012, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_012 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1080, .width = 1920, .orientation = 0, .exifRotate = 0, .lcdSize = "1920:1080"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1080;
    photoInfo.width = 1920;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1920:1080";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_013, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_013 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1920, .orientation = 0, .exifRotate = 0, .lcdSize = "1920:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1920;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1920:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_014, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_014 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 3840, .width = 2160, .orientation = 0, .exifRotate = 0, .lcdSize = "2160:3840"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 3840;
    photoInfo.width = 2160;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "2160:3840";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_015, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_015 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 2160, .width = 3840, .orientation = 0, .exifRotate = 0, .lcdSize = "3840:2160"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 2160;
    photoInfo.width = 3840;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "3840:2160";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_016, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_016 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 2, .lcdSize = "1080:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 2;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_017, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_017 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 4, .lcdSize = "1080:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 4;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_018, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_018 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 1920, .width = 1080, .orientation = 0, .exifRotate = 7, .lcdSize = "1080:1920"});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 1920;
    photoInfo.width = 1080;
    photoInfo.exifRotate = 7;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "1080:1920";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_TRUE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_019, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_019 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = -1, .width = -1, .orientation = 0, .exifRotate = 0, .lcdSize = ""});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = -1;
    photoInfo.width = -1;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_FALSE(result);
}

HWTEST_F(HeightWidthCorrectOperationTest, HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_020, TestSize.Level1)
{
    MEDIA_INFO_LOG("HeightWidthCorrectOperation_UpdatePhotoHeightWidth_Test_020 start");
    ClearTables();
    int64_t fileId1 = InsertPhoto({.mediaType = MEDIA_TYPE_IMAGE,
        .position = static_cast<int32_t>(PhotoPositionType::LOCAL),
        .height = 0, .width = 0, .orientation = 0, .exifRotate = 0, .lcdSize = ""});
    EXPECT_GT(fileId1, 0);
    CheckPhotoInfo photoInfo;
    photoInfo.fileId = static_cast<int32_t>(fileId1);
    photoInfo.height = 0;
    photoInfo.width = 0;
    photoInfo.exifRotate = 0;
    photoInfo.orientation = 0;
    photoInfo.lcdSize = "";
    photoInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    bool result = HeightWidthCorrectOperation::UpdatePhotoHeightWidth(photoInfo);
    EXPECT_FALSE(result);
}
}
}