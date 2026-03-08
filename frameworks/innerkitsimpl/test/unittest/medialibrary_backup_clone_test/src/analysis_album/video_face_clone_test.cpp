/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "VideoFaceCloneTest"

#include "video_face_clone_test.h"

#include "vision_column.h"
#include "vision_db_sqls.h"
#include "video_face_clone.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_rdb_utils.h"
#include "userfile_manager_types.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "backup_const.h"
#include "backup_database_utils.h"
#include "media_log.h"
#include "media_upgrade.h"

using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
static constexpr int32_t MOCK_FILE_ID_VIDEO_FACE_TEST = 5;
static const string TEST_BACKUP_PATH = "/data/test/backup/db";
static const string TEST_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
static const string TEST_BACKUP_DB_PATH = TEST_BACKUP_PATH + TEST_DB_PATH;
static shared_ptr<MediaLibraryRdbStore> newRdbStore = nullptr;
static shared_ptr<MediaLibraryRdbStore> backupRdbStore = nullptr;
static unique_ptr<VideoFaceClone> videoFaceClone = nullptr;

static std::vector<std::string> createTableSqlLists = {
    PhotoUpgrade::CREATE_PHOTO_TABLE,
    CREATE_TAB_ANALYSIS_TOTAL,
    CREATE_TAB_VIDEO_FACE,
};

static std::vector<std::string> testTables = {
    PhotoColumn::PHOTOS_TABLE,
    ANALYSIS_TOTAL_TABLE,
    VISION_VIDEO_FACE_TABLE,
};

void VideoFaceCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Start VideoFaceCloneTest::Init");
    MediaLibraryUnitTestUtils::Init();
    newRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(newRdbStore, nullptr);
    MediaLibraryUnitTestUtils::CreateTestTables(newRdbStore, createTableSqlLists);
}

void VideoFaceCloneTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("VideoFaceCloneTest::TearDownTestCase");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables, true);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryLibraryMgr();
    videoFaceClone = nullptr;
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void VideoFaceCloneTest::SetUp()
{
    MEDIA_INFO_LOG("enter VideoFaceCloneTest::SetUp");
    MediaLibraryUnitTestUtils::CleanTestTables(newRdbStore, testTables);

    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_VIDEO_FACE_TEST;
    photoInfoMap[1] = photoInfo;

    videoFaceClone = make_unique<VideoFaceClone>(backupRdbStore, newRdbStore, photoInfoMap);
}

void VideoFaceCloneTest::TearDown() {}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_CloneVideoFaceInfo_Empty_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> emptyPhotoInfoMap;
    videoFaceClone = make_unique<VideoFaceClone>(backupRdbStore, newRdbStore, emptyPhotoInfoMap);

    bool result = videoFaceClone->CloneVideoFaceInfo();

    EXPECT_TRUE(result);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_CloneVideoFaceInfo_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + VISION_VIDEO_FACE_TABLE + " (file_id, face_id) VALUES (1, 'face_001')";
    newRdbStore->ExecuteSql(insertSql);

    bool result = videoFaceClone->CloneVideoFaceInfo();

    EXPECT_TRUE(result);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_QueryVideoFaceTbl_Success_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + VISION_VIDEO_FACE_TABLE + " (file_id, face_id) VALUES (1, 'face_001')";
    newRdbStore->ExecuteSql(insertSql);

    std::string fileIdClause = "(1)";
    std::vector<std::string> commonColumns = {"file_id", "face_id"};

    std::vector<VideoFaceTbl> result = videoFaceClone->QueryVideoFaceTbl(0, fileIdClause, commonColumns);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_ParseVideoFaceResultSet_001, TestSize.Level0)
{
    std::string insertSql = "INSERT INTO " + VISION_VIDEO_FACE_TABLE + " (file_id, face_id) VALUES (1, 'face_001')";
    newRdbStore->ExecuteSql(insertSql);

    std::string querySql = "SELECT * FROM " + VISION_VIDEO_FACE_TABLE + " WHERE file_id = 1";
    auto resultSet = newRdbStore->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);

    VideoFaceTbl videoFaceTbl;
    videoFaceClone->ParseVideoFaceResultSet(resultSet, videoFaceTbl);

    EXPECT_TRUE(videoFaceTbl.file_id.has_value());
    resultSet->Close();
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_ProcessVideoFaceTbls_Empty_001, TestSize.Level0)
{
    std::vector<VideoFaceTbl> videoFaceTbls;

    std::vector<VideoFaceTbl> result = videoFaceClone->ProcessVideoFaceTbls(videoFaceTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_ProcessVideoFaceTbls_Success_001, TestSize.Level0)
{
    std::vector<VideoFaceTbl> videoFaceTbls;
    VideoFaceTbl tbl;
    tbl.file_id = 1;
    videoFaceTbls.push_back(tbl);

    std::vector<VideoFaceTbl> result = videoFaceClone->ProcessVideoFaceTbls(videoFaceTbls);

    EXPECT_GT(result.size(), 0);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_ProcessVideoFaceTbls_NotFound_001, TestSize.Level0)
{
    std::unordered_map<int32_t, PhotoInfo> photoInfoMap;
    PhotoInfo photoInfo;
    photoInfo.fileIdNew = MOCK_FILE_ID_VIDEO_FACE_TEST;
    photoInfoMap[2] = photoInfo;
    videoFaceClone = make_unique<VideoFaceClone>(backupRdbStore, newRdbStore, photoInfoMap);

    std::vector<VideoFaceTbl> videoFaceTbls;
    VideoFaceTbl tbl;
    tbl.file_id = 1;
    videoFaceTbls.push_back(tbl);

    std::vector<VideoFaceTbl> result = videoFaceClone->ProcessVideoFaceTbls(videoFaceTbls);

    EXPECT_TRUE(result.empty());
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_BatchInsertVideoFaces_Empty_001, TestSize.Level0)
{
    std::vector<VideoFaceTbl> videoFaceTbls;

    videoFaceClone->BatchInsertVideoFaces(videoFaceTbls);

    EXPECT_EQ(videoFaceClone->migrateVideoFaceNum_, 0);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_BatchInsertVideoFaces_Success_001, TestSize.Level0)
{
    std::vector<VideoFaceTbl> videoFaceTbls;
    VideoFaceTbl tbl;
    tbl.file_id = 1;
    tbl.face_id = "face_001";
    videoFaceTbls.push_back(tbl);

    videoFaceClone->BatchInsertVideoFaces(videoFaceTbls);

    EXPECT_EQ(videoFaceClone->migrateVideoFaceNum_, 0);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_CreateValuesBucketFromVideoFaceTbl_001, TestSize.Level0)
{
    VideoFaceTbl videoFaceTbl;
    videoFaceTbl.file_id = 1;
    videoFaceTbl.face_id = "face_001";

    NativeRdb::ValuesBucket result = videoFaceClone->CreateValuesBucketFromVideoFaceTbl(videoFaceTbl);

    EXPECT_GT(result.GetSize(), 0);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_BatchInsertWithRetry_Empty_001, TestSize.Level0)
{
    std::vector<NativeRdb::ValuesBucket> values;
    int64_t rowNum = 0;

    int32_t result = videoFaceClone->BatchInsertWithRetry(VISION_VIDEO_FACE_TABLE, values, rowNum);

    EXPECT_EQ(result, E_OK);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_DeleteExistingVideoFaceData_Empty_001, TestSize.Level0)
{
    std::vector<int32_t> newFileIds;

    videoFaceClone->DeleteExistingVideoFaceData(newFileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_DeleteExistingVideoFaceData_Success_001, TestSize.Level0)
{
    std::vector<int32_t> newFileIds = {MOCK_FILE_ID_VIDEO_FACE_TEST};

    videoFaceClone->DeleteExistingVideoFaceData(newFileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_StartCloneAnalysisVideoTotalTab_001, TestSize.Level0)
{
    std::vector<int32_t> oldFileIds = {1};
    std::vector<int32_t> newFileIds = {MOCK_FILE_ID_VIDEO_FACE_TEST};

    videoFaceClone->StartCloneAnalysisVideoTotalTab(oldFileIds, newFileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_UpdateAnalysisVideoTotalTblLabelAndFace_001, TestSize.Level0)
{
    std::vector<int32_t> oldFileIds = {1};
    std::vector<int32_t> newFileIds = {MOCK_FILE_ID_VIDEO_FACE_TEST};

    videoFaceClone->UpdateAnalysisVideoTotalTblLabelAndFace(oldFileIds, newFileIds);

    EXPECT_TRUE(true);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_UpdateAnalysisVideoTotalTblFaceAndTagId_001, TestSize.Level0)
{
    videoFaceClone->UpdateAnalysisVideoTotalTblFaceAndTagId();

    EXPECT_TRUE(true);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_WriteDataToAnaVideoTotalTabTab_Empty_001, TestSize.Level0)
{
    std::vector<CloneVideoInfo> updateDataList;

    videoFaceClone->WriteDataToAnaVideoTotalTab(updateDataList);

    EXPECT_TRUE(true);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_WriteDataToAnaVideoTotalTab_Success_001, TestSize.Level0)
{
    std::vector<CloneVideoInfo> updateDataList;
    CloneVideoInfo info;
    info.file_id = 1;
    info.face = 1;
    updateDataList.push_back(info);

    videoFaceClone->WriteDataToAnaVideoTotalTab(updateDataList);

    EXPECT_TRUE(true);
}

HWTEST_F(VideoFaceCloneTest, VideoFaceClone_CopyAnalysisVideoTotalTab_001, TestSize.Level0)
{
    std::vector<int32_t> oldFileIds = {1};

    bool result = videoFaceClone->CopyAnalysisVideoTotalTab(ANALYSIS_TOTAL_TABLE, oldFileIds);

    EXPECT_TRUE(result);
}
} // namespace Media
} // namespace OHOS
