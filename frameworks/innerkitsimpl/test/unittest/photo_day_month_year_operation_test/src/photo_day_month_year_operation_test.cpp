/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "PhotoDayMonthYearOperationTest"

#include "photo_day_month_year_operation_test.h"

#include <chrono>

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "photo_album_column.h"
#include "photo_day_month_year_operation.h"
#include "photo_file_utils.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "media_upgrade.h"
#include "preferences_helper.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

shared_ptr<MediaLibraryRdbStore> g_rdbStore;
std::atomic<int> g_num{0};

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

int64_t InsertPhoto(const MediaType &mediaType, int32_t position)
{
    EXPECT_NE(g_rdbStore, nullptr);
    int64_t timestamp = GetTimestamp();
    int64_t timestampMilliSecond = timestamp * SEC_TO_MSEC;
    string title = GetTitle(timestamp);
    string displayName = mediaType == MEDIA_TYPE_VIDEO ? (title + ".mp4") : (title + ".jpg");
    string path = "/storage/cloud/files/photo/16/" + displayName;
    int64_t videoSize = 1 * 1000 * 1000 * 1000;
    int64_t imageSize = 10 * 1000 * 1000;
    int32_t videoDuration = 2560;
    int32_t imageDuration = 0;
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
    string detailTime =
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, timestampMilliSecond);
    auto const [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    valuesBucket.Put(PhotoColumn::PHOTO_DETAIL_TIME, detailTime);
    valuesBucket.Put(PhotoColumn::PHOTO_DATE_YEAR, dateYear);
    valuesBucket.Put(PhotoColumn::PHOTO_DATE_MONTH, dateMonth);
    valuesBucket.Put(PhotoColumn::PHOTO_DATE_DAY, dateDay);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    valuesBucket.Put(PhotoColumn::PHOTO_ALL_EXIF, exif);
    int64_t fileId = -1;
    int32_t ret = g_rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    return fileId;
}

int64_t InsertPhotoWithDateTime(
    const int64_t dateTaken, const string &detailTime, const string &dateDay, const string &exif)
{
    EXPECT_NE(g_rdbStore, nullptr);

    int64_t timestamp = GetTimestamp();
    int64_t timestampMilliSecond = timestamp * SEC_TO_MSEC;
    string title = GetTitle(timestamp);
    string displayName = title + ".jpg";
    string path = "/storage/cloud/files/photo/16/" + displayName;
    int64_t imageSize = 10 * 1000 * 1000;
    int32_t imageWidth = 1920;
    int32_t imageHeight = 1080;
    string imageMimeType = "image/jpeg";
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, MEDIA_TYPE_IMAGE);
    valuesBucket.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    valuesBucket.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL));
    valuesBucket.PutLong(MediaColumn::MEDIA_SIZE, imageSize);
    valuesBucket.PutInt(PhotoColumn::PHOTO_WIDTH, imageWidth);
    valuesBucket.PutInt(PhotoColumn::PHOTO_HEIGHT, imageHeight);
    valuesBucket.PutString(MediaColumn::MEDIA_MIME_TYPE, imageMimeType);
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, path);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_ADDED, timestampMilliSecond);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, timestampMilliSecond);
    valuesBucket.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_HIDDEN, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_TIME_PENDING, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TAKEN, dateTaken);
    valuesBucket.Put(PhotoColumn::PHOTO_DETAIL_TIME, detailTime);
    auto const [detailYear, detailMonth, detailDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    valuesBucket.Put(PhotoColumn::PHOTO_DATE_YEAR, detailYear);
    valuesBucket.Put(PhotoColumn::PHOTO_DATE_MONTH, detailMonth);
    valuesBucket.Put(PhotoColumn::PHOTO_DATE_DAY, dateDay);
    valuesBucket.Put(PhotoColumn::PHOTO_ALL_EXIF, exif);
    int64_t fileId = -1;
    int32_t ret = g_rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    return fileId;
}

void PreparePhotos()
{
    int64_t fileId = InsertPhoto(MEDIA_TYPE_VIDEO, static_cast<int32_t>(PhotoPositionType::LOCAL));
    EXPECT_GT(fileId, 0);

    fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
    EXPECT_GT(fileId, 0);

    fileId = InsertPhoto(MEDIA_TYPE_VIDEO, static_cast<int32_t>(PhotoPositionType::CLOUD));
    EXPECT_GT(fileId, 0);

    fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::CLOUD));
    EXPECT_GT(fileId, 0);

    fileId = InsertPhoto(MEDIA_TYPE_VIDEO, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
    EXPECT_GT(fileId, 0);

    fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
    EXPECT_GT(fileId, 0);
}

void PrepareAbnormalPhotos()
{
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);

    int64_t fileId = InsertPhotoWithDateTime(0, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);

    fileId = InsertPhotoWithDateTime(-1, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);

    fileId = InsertPhotoWithDateTime(dateTaken * MILSEC_TO_MICSEC, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);

    fileId = InsertPhotoWithDateTime(dateTaken, "1970:01:01 08:00:00", dateDay, exif);
    EXPECT_GT(fileId, 0);

    fileId = InsertPhotoWithDateTime(dateTaken, detailTime, "19700101", exif);
    EXPECT_GT(fileId, 0);

    exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+08:00\","
           "\"SubsecTimeOriginal\":\"120000\",\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);

    exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"\","
           "\"SubsecTimeOriginal\":\"\",\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);

    exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
           "\"GPSDateStamp\":\"2020:08:08\",\"GPSTimeStamp\":\"00:08:53.12\"}";
    fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);

    exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
           "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
}

int32_t QueryAbnormalPhotosCount()
{
    EXPECT_NE(g_rdbStore, nullptr);

    const string sql = "SELECT"
                       "  COUNT( * ) AS count "
                       "FROM"
                       "  Photos "
                       "WHERE"
                       "  date_taken <= 0 "
                       "  OR date_day IS NULL "
                       "  OR date_day = '' "
                       "  OR date_day = '19700101' "
                       "  OR detail_time IS NULL "
                       "  OR detail_time = '' "
                       "  OR date_day != REPLACE ( SUBSTR( detail_time, 1, 10 ), ':', '' );";
    shared_ptr<NativeRdb::ResultSet> resultSet = g_rdbStore->QuerySql(sql);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);

    int32_t count = GetInt32Val("count", resultSet);
    MEDIA_INFO_LOG("Abnormal Photos Count is %{public}d", count);
    return count;
}

int64_t UpdatePhotosDateDay()
{
    EXPECT_NE(g_rdbStore, nullptr);

    const string sql = "UPDATE Photos "
                       "SET date_day = '19700101';";

    int64_t changeRows = 0;
    auto errCode = g_rdbStore->ExecuteForChangedRowCount(changeRows, sql);
    EXPECT_EQ(errCode, E_OK);

    return changeRows;
}

void SetTables()
{
    vector<string> createTableSqlList = {
        PhotoUpgrade::CREATE_PHOTO_TABLE,
        PhotoAlbumColumns::CREATE_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        ASSERT_NE(g_rdbStore, nullptr);

        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        ASSERT_EQ(ret, NativeRdb::E_OK);
        MEDIA_INFO_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

void PhotoDayMonthYearOperationTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("PhotoDayMonthYearOperationTest SetUpTestCase");

    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
    SetTables();
}

void PhotoDayMonthYearOperationTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("PhotoDayMonthYearOperationTest TearDownTestCase");
    ClearTables();
}

void PhotoDayMonthYearOperationTest::SetUp()
{
    MEDIA_INFO_LOG("PhotoDayMonthYearOperationTest SetUp");
    ClearTables();
    g_num = 0;
}

void PhotoDayMonthYearOperationTest::TearDown()
{
    MEDIA_INFO_LOG("PhotoDayMonthYearOperationTest TearDown");
}

HWTEST_F(PhotoDayMonthYearOperationTest, photo_day_month_year_operation_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("photo_day_month_year_operation_test_001 Start");
    PreparePhotos();
    PrepareAbnormalPhotos();

    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);

    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("photo_day_month_year_operation_test_001 End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, photo_day_month_year_operation_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("photo_day_month_year_operation_test_002 Start");
    PreparePhotos();
    PrepareAbnormalPhotos();

    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_GT(count, 0);

    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);

    count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);

    auto changeRows = UpdatePhotosDateDay();
    EXPECT_GT(changeRows, 0);

    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);

    count = QueryAbnormalPhotosCount();
    EXPECT_GT(count, 0);
    MEDIA_INFO_LOG("photo_day_month_year_operation_test_002 End");
}

static void MarkDateAddedDatesDataStatus(const shared_ptr<MediaLibraryRdbStore>& rdbStore)
{
    vector<string> columns = {"max(file_id)"};
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    auto resultSet = rdbStore->QueryByStep(predicates, columns);
    bool needUpdateDateAddedDatesData = true;
    CHECK_AND_RETURN_LOG(TryToGoToFirstRow(resultSet), "Query max file id failed");
    int32_t maxFileId = GetInt32Val("max(file_id)", resultSet);
    needUpdateDateAddedDatesData = (maxFileId > 0);

    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs != nullptr, "GetPreferences returned nullptr, errcode: %{public}d", errCode);
    const string isFinishedKeyName = "is_task_finished";
    const string maxFileIdKeyName = "max_file_id";
    prefs->PutInt(isFinishedKeyName, needUpdateDateAddedDatesData ? 0 : 1);
    prefs->PutInt(maxFileIdKeyName, maxFileId);
    prefs->FlushSync();
    MEDIA_INFO_LOG("Mark date added dates need update: %{public}d", needUpdateDateAddedDatesData ? 1 : 0);
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_test Start");
    MarkDateAddedDatesDataStatus(g_rdbStore);

    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string maxFileIdKeyName = "max_file_id";
    EXPECT_EQ(prefs->GetInt(maxFileIdKeyName, 0), 0);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDateAndIdx_nullptr_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_nullptr_test Start");
    shared_ptr<MediaLibraryRdbStore> nullStore = nullptr;
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(nullStore);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_nullptr_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDateAndIdx_normal_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_normal_test Start");
    PreparePhotos();
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_normal_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_normal_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_normal_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDate_normal_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_no_anomaly_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_no_anomaly_test Start");
    PreparePhotos();
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDate_no_anomaly_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_empty_db_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_empty_db_test Start");
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_empty_db_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_normal_photos_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_normal_photos_test Start");
    PreparePhotos();
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_normal_photos_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_zero_date_taken_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_zero_date_taken_test Start");
    int64_t dateTaken = 0;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_zero_date_taken_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_negative_date_taken_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_negative_date_taken_test Start");
    int64_t dateTaken = -1;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_negative_date_taken_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_19700101_date_day_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_19700101_date_day_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    string dateDay = "19700101";
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_19700101_date_day_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_exif_offset_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_exif_offset_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+08:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_exif_offset_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_gps_exif_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_gps_exif_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"2020:08:08\",\"GPSTimeStamp\":\"00:08:53\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_gps_exif_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_invalid_exif_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_invalid_exif_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_invalid_exif_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_empty_db_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_empty_db_test Start");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    prefs->PutInt(isFinishedKeyName, 0);
    prefs->FlushSync();
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 0);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_empty_db_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_already_finished_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_already_finished_test Start");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    prefs->PutInt(isFinishedKeyName, 1);
    prefs->FlushSync();
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_already_finished_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_photos_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_photos_test Start");
    PreparePhotos();
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_photos_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_multiple_anomalies_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_multiple_anomalies_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_multiple_anomalies_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_large_timestamp_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_large_timestamp_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds() * MILSEC_TO_MICSEC;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_large_timestamp_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_subsecond_exif_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_exif_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"456\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_exif_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_negative_offset_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_negative_offset_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"-05:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_negative_offset_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_max_offset_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_max_offset_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+14:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_max_offset_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_min_offset_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_min_offset_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"-12:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_min_offset_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDateAndIdx_multiple_times_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_multiple_times_test Start");
    PreparePhotos();
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_multiple_times_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_zero_detail_time_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_zero_detail_time_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    string detailTime = "0000:00:00 00:00:00";
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_zero_detail_time_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_empty_detail_time_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_empty_detail_time_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    string detailTime = "";
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_empty_detail_time_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_mismatch_detail_time_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_mismatch_detail_time_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    string mismatchDetailTime = "2020:01:01 00:00:00";
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, mismatchDetailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_mismatch_detail_time_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_with_batch_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_with_batch_test Start");
    PrepareAbnormalPhotos();
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("UpdatePhotosDate_with_batch_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_concurrent_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_concurrent_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_concurrent_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_concurrent_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_concurrent_test Start");
    PreparePhotos();
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_concurrent_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_dirty_synced_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_dirty_synced_test Start");
    int64_t dateTaken = 0;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET dirty = 0 WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_dirty_synced_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_min_timestamp_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_min_timestamp_test Start");
    int64_t dateTaken = 500;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_min_timestamp_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_max_timestamp_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_max_timestamp_test Start");
    int64_t dateTaken = 11991456000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_max_timestamp_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_invalid_offset_format_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_invalid_offset_format_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+8:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_invalid_offset_format_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_invalid_offset_sign_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_invalid_offset_sign_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"*08:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_invalid_offset_sign_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_gps_date_only_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_gps_date_only_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"2020:08:08\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_gps_date_only_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_gps_time_only_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_gps_time_only_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"00:08:53\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_gps_time_only_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_added_fallback_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_added_fallback_test Start");
    int64_t dateTaken = 0;
    int64_t dateAdded = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateAdded);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET date_added = " + to_string(dateAdded) +
                      " WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_added_fallback_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_modified_fallback_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_modified_fallback_test Start");
    int64_t dateTaken = 0;
    int64_t dateModified = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateModified);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET date_added = 0, date_modified = " +
                      to_string(dateModified) + " WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_modified_fallback_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_all_zero_dates_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_all_zero_dates_test Start");
    int64_t dateTaken = 0;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET date_added = 0, date_modified = 0 WHERE file_id = " +
                       to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_all_zero_dates_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_null_dates_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_null_dates_test Start");
    int64_t timestamp = GetTimestamp();
    int64_t timestampMilliSecond = timestamp * SEC_TO_MSEC;
    string title = GetTitle(timestamp);
    string displayName = title + ".jpg";
    string path = "/storage/cloud/files/photo/16/" + displayName;
    int64_t imageSize = 10 * 1000 * 1000;
    string imageMimeType = "image/jpeg";
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, MEDIA_TYPE_IMAGE);
    valuesBucket.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    valuesBucket.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL));
    valuesBucket.PutLong(MediaColumn::MEDIA_SIZE, imageSize);
    valuesBucket.PutInt(PhotoColumn::PHOTO_WIDTH, 1920);
    valuesBucket.PutInt(PhotoColumn::PHOTO_HEIGHT, 1080);
    valuesBucket.PutString(MediaColumn::MEDIA_MIME_TYPE, imageMimeType);
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, path);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, title);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_ADDED, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, timestampMilliSecond);
    valuesBucket.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TRASHED, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_HIDDEN, 0);
    valuesBucket.PutInt(MediaColumn::MEDIA_TIME_PENDING, 0);
    valuesBucket.PutLong(MediaColumn::MEDIA_DATE_TAKEN, timestampMilliSecond);
    int64_t fileId = -1;
    int32_t ret = g_rdbStore->Insert(fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(fileId, 0);
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_null_dates_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_boundary_timestamp_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_boundary_timestamp_test Start");
    int64_t dateTaken = 1000;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_boundary_timestamp_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_sync_status_off_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_sync_status_off_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_sync_status_off_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_progress_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_progress_test Start");
    for (int i = 0; i < 10; i++) {
        int64_t fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
        EXPECT_GT(fileId, 0);
    }
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_progress_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_hours_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_hours_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+10:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_hours_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_minutes_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_minutes_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:30\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_minutes_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_combined_offset_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_combined_offset_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+05:30\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_combined_offset_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_with_empty_result_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_with_empty_result_test Start");
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDate_with_empty_result_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_null_date_day_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_null_date_day_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, "", exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET date_day = NULL WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_null_date_day_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_empty_date_day_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_empty_date_day_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, "", exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET date_day = '' WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_empty_date_day_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDateAndIdx_null_store_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_null_store_test Start");
    shared_ptr<MediaLibraryRdbStore> nullStore = nullptr;
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(nullStore);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_null_store_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_subsecond_overflow_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_overflow_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"999999\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_overflow_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_subsecond_zero_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_zero_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"000\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_zero_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_gps_invalid_format_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_gps_invalid_format_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"2020/08/08\",\"GPSTimeStamp\":\"00:08:53\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_gps_invalid_format_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_large_dataset_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_large_dataset_test Start");
    for (int i = 0; i < 100; i++) {
        int64_t fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
        EXPECT_GT(fileId, 0);
    }
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_large_dataset_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_dirty_mdirty_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_dirty_mdirty_test Start");
    int64_t dateTaken = 0;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET dirty = 1 WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_dirty_mdirty_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_year_mismatch_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_year_mismatch_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET date_year = '2020' WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_year_mismatch_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_month_mismatch_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_month_mismatch_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET date_month = '202008' WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_month_mismatch_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_exif_only_original_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_exif_only_original_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"\","
                   "\"SubsecTimeOriginal\":\"\",\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_exif_only_original_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_with_single_photo_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_with_single_photo_test Start");
    int64_t dateTaken = 0;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("UpdatePhotosDate_with_single_photo_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_very_large_timestamp_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_very_large_timestamp_test Start");
    int64_t dateTaken = 99999999999999LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_very_large_timestamp_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_very_small_timestamp_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_very_small_timestamp_test Start");
    int64_t dateTaken = -99999999999999LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_very_small_timestamp_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_zero_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_zero_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_zero_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_mixed_photos_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_mixed_photos_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_mixed_photos_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_within_range_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_within_range_test Start");
    int64_t dateTaken = 16094592000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_within_range_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_null_exif_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_null_exif_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_null_exif_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_malformed_exif_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_malformed_exif_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{invalid json}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_malformed_exif_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_normalization_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_normalization_test Start");
    int64_t dateTaken = 500;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_normalization_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_zero_file_id_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_zero_file_id_test Start");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string maxFileIdKeyName = "max_file_id";
    prefs->PutInt(maxFileIdKeyName, 0);
    prefs->FlushSync();
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(maxFileIdKeyName, 0), 0);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_zero_file_id_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_out_of_range_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_out_of_range_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+24:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_out_of_range_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_negative_offset_minutes_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_negative_offset_minutes_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"-00:60\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_negative_offset_minutes_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_with_normal_data_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_with_normal_data_test Start");
    PreparePhotos();
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDate_with_normal_data_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_max_valid_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_max_valid_test Start");
    int64_t dateTaken = 11991456000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_max_valid_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_subsecond_partial_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_partial_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"12\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_partial_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_subsecond_single_digit_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_single_digit_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"5\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_single_digit_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_batch_processing_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_batch_processing_test Start");
    for (int i = 0; i < 250; i++) {
        int64_t fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
        EXPECT_GT(fileId, 0);
    }
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_batch_processing_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_exact_min_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_exact_min_test Start");
    int64_t dateTaken = 1000;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_exact_min_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_exact_max_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_exact_max_test Start");
    int64_t dateTaken = 11991456000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_exact_max_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_with_empty_anomalies_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_with_empty_anomalies_test Start");
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDate_with_empty_anomalies_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_boundary_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_boundary_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+13:59\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_boundary_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_below_min_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_below_min_test Start");
    int64_t dateTaken = 999;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_below_min_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_above_max_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_above_max_test Start");
    int64_t dateTaken = 11991456001000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_above_max_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_progress_persistence_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_progress_persistence_test Start");
    for (int i = 0; i < 50; i++) {
        int64_t fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
        EXPECT_GT(fileId, 0);
    }
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_progress_persistence_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_sync_status_check_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_sync_status_check_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_sync_status_check_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_with_null_result_set_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_with_null_result_set_test Start");
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDate_with_null_result_set_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_exif_priority_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_exif_priority_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"120\",\"GPSDateStamp\":\"2020:08:08\","
                   "\"GPSTimeStamp\":\"00:08:53\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_exif_priority_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_multiple_repair_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_multiple_repair_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_multiple_repair_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_no_progress_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_no_progress_test Start");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string maxFileIdKeyName = "max_file_id";
    prefs->PutInt(maxFileIdKeyName, -1);
    prefs->FlushSync();
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(maxFileIdKeyName, 0), -1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_no_progress_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_overflow_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_overflow_test Start");
    int64_t dateTaken = 100000000000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, EOK);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_overflow_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_negative_max_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_negative_max_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"-14:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_negative_max_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_underflow_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_underflow_test Start");
    int64_t dateTaken = -100000000000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_underflow_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_large_max_file_id_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_large_max_file_id_test Start");
    for (int i = 0; i < 10; i++) {
        int64_t fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
        EXPECT_GT(fileId, 0);
    }
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string maxFileIdKeyName = "max_file_id";
    prefs->PutInt(maxFileIdKeyName, 999999);
    prefs->FlushSync();
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(maxFileIdKeyName, 0), 999999);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_large_max_file_id_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_subsecond_max_value_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_max_value_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"999\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_subsecond_max_value_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_minutes_boundary_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_minutes_boundary_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:59\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_minutes_boundary_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_with_batch_processing_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_with_batch_processing_test Start");
    for (int i = 0; i < 250; i++) {
        int64_t dateTaken = 0;
        auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
            PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
        string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
        auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
        int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
        EXPECT_GT(fileId, 0);
    }
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, EOK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("UpdatePhotosDate_with_batch_processing_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_empty_gps_fields_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_empty_gps_fields_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_empty_gps_fields_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_hours_boundary_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_hours_boundary_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+23:59\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_hours_boundary_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDateAndIdx_with_empty_db_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_with_empty_db_test Start");
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("UpdatePhotosDateAndIdx_with_empty_db_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_all_null_fields_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_all_null_fields_test Start");
    int64_t dateTaken = 0;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    string updateSql = "UPDATE Photos SET date_added = 0, date_modified = 0, date_day = NULL, "
                      "detail_time = NULL WHERE file_id = " + to_string(fileId);
    int32_t ret = g_rdbStore->ExecuteSql(updateSql);
    EXPECT_EQ(ret, E_OK);
    ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_all_null_fields_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_batch_boundary_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_batch_boundary_test Start");
    for (int i = 0; i < 200; i++) {
        int64_t fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
        EXPECT_GT(fileId, 0);
    }
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    prefs->FlushSync();
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_batch_boundary_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_normalization_edge_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_normalization_edge_test Start");
    int64_t dateTaken = 1001;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_normalization_edge_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_exif_subsecond_truncation_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_exif_subsecond_truncation_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"+00:00\","
                   "\"SubsecTimeOriginal\":\"123456789\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_exif_subsecond_truncation_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotosDate_with_large_batch_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotosDate_with_large_batch_test Start");
    for (int i = 0; i < 300; i++) {
        int64_t dateTaken = 0;
        auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
            PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
        string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
        auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
        int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
        EXPECT_GT(fileId, 0);
    }
    int32_t ret = PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(g_rdbStore);
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("UpdatePhotosDate_with_large_batch_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_zero_boundary_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_zero_boundary_test Start");
    int64_t dateTaken = 0;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_zero_boundary_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_negative_max_file_id_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_negative_max_file_id_test Start");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string maxFileIdKeyName = "max_file_id";
    prefs->PutInt(maxFileIdKeyName, -1);
    prefs->FlushSync();
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(maxFileIdKeyName, 0), -1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_negative_max_file_id_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_offset_sign_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_offset_sign_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"2020:08:08 00:08:53\",\"OffsetTimeOriginal\":\"-08:00\","
                   "\"SubsecTimeOriginal\":\"120\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_offset_sign_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_negative_boundary_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_negative_boundary_test Start");
    int64_t dateTaken = -1;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_negative_boundary_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_zero_progress_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_zero_progress_test Start");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string maxFileIdKeyName = "max_file_id";
    prefs->PutInt(maxFileIdKeyName, 0);
    prefs->FlushSync();
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(maxFileIdKeyName, 0), 0);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_zero_progress_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_exif_empty_original_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_exif_empty_original_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"\",\"OffsetTimeOriginal\":\"\",\"SubsecTimeOriginal\":\"\","
                   "\"GPSDateStamp\":\"\",\"GPSTimeStamp\":\"\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_exif_empty_original_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_small_positive_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_small_positive_test Start");
    int64_t dateTaken = 100;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_small_positive_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_single_photo_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_single_photo_test Start");
    int64_t fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
    EXPECT_GT(fileId, 0);
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_single_photo_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_exact_zero_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_exact_zero_test Start");
    int64_t dateTaken = 0;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_exact_zero_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_min_boundary_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_min_boundary_test Start");
    int64_t dateTaken = 999;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_min_boundary_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_max_boundary_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_max_boundary_test Start");
    int64_t dateTaken = 11991456001000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_max_boundary_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_small_negative_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_small_negative_test Start");
    int64_t dateTaken = -100;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_small_negative_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_very_small_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_very_small_test Start");
    int64_t dateTaken = -999999999;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_very_small_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_very_large_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_very_large_test Start");
    int64_t dateTaken = 9999999999999LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_very_large_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_batch_size_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_batch_size_test Start");
    for (int i = 0; i < 199; i++) {
        int64_t fileId = InsertPhoto(MEDIA_TYPE_IMAGE, static_cast<int32_t>(PhotoPositionType::LOCAL));
        EXPECT_GT(fileId, 0);
    }
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_batch_size_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_edge_case_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_edge_case_test Start");
    int64_t dateTaken = 11991456000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_edge_case_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_concurrent_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_concurrent_test Start");
    PreparePhotos();
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_concurrent_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_normal_case_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_normal_case_test Start");
    int64_t dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_normal_case_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_validation_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_validation_test Start");
    int64_t dateTaken = 5000;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_validation_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_validation_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_validation_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_validation_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_range_check_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_range_check_test Start");
    int64_t dateTaken = 10000000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_range_check_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_boundary_check_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_boundary_check_test Start");
    int64_t dateTaken = 11991456000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_boundary_check_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_completion_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_completion_test Start");
    PreparePhotos();
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_completion_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_edge_validation_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_edge_validation_test Start");
    int64_t dateTaken = 999;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_edge_validation_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_comprehensive_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_comprehensive_test Start");
    int64_t dateTaken = 10000000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_comprehensive_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_comprehensive_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_comprehensive_test Start");
    PreparePhotos();
    PrepareAbnormalPhotos();
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_comprehensive_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_final_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_final_test Start");
    int64_t dateTaken = 11991456000000LL;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_final_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, RepairDateTime_with_date_taken_ultimate_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_ultimate_test Start");
    int64_t dateTaken = 1000;
    auto detailTime = MediaFileUtils::StrCreateTimeByMilliseconds(
        PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, MediaFileUtils::UTCTimeMilliSeconds());
    string exif = "{\"DateTimeOriginal\":\"" + detailTime + "\"}";
    auto [dateYear, dateMonth, dateDay] = PhotoFileUtils::ExtractYearMonthDay(detailTime);
    int64_t fileId = InsertPhotoWithDateTime(dateTaken, detailTime, dateDay, exif);
    EXPECT_GT(fileId, 0);
    int32_t ret = PhotoDayMonthYearOperation::RepairDateTime();
    EXPECT_EQ(ret, E_OK);
    int32_t count = QueryAbnormalPhotosCount();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("RepairDateTime_with_date_taken_ultimate_test End");
}

HWTEST_F(PhotoDayMonthYearOperationTest, UpdatePhotoDateAddedDateInfo_with_ultimate_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_ultimate_test Start");
    PreparePhotos();
    MarkDateAddedDatesDataStatus(g_rdbStore);
    PhotoDayMonthYearOperation::UpdatePhotoDateAddedDateInfo();
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(
            PhotoDayMonthYearOperation::DATE_ADDED_DATE_UPGRADE_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    const string isFinishedKeyName = "is_task_finished";
    EXPECT_EQ(prefs->GetInt(isFinishedKeyName, 0), 1);
    MEDIA_INFO_LOG("UpdatePhotoDateAddedDateInfo_with_ultimate_test End");
}

} // namespace Media
} // namespace OHOS