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

#define MLOG_TAG "BackupCloneTest"

#include "medialibrary_backup_clone_test.h"

#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "clone_source.h"
#include "media_column.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "backup_restore_service.h"
#include "base_restore.h"
#include "clone_restore.h"
#include "clone_restore_analysis_data.h"
#include "clone_restore_geo.h"
#include "clone_restore_classify.h"
#include "clone_restore_portrait_album.h"
#include "video_face_clone.h"
#include "beauty_score_clone.h"
#include "search_index_clone.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_data_manager.h"
#include "others_clone_restore.h"
#include "tab_old_albums_clone.h"
#include "photos_dao.h"
#include "photos_data_handler.h"
#include "burst_key_generator.h"
#include "vision_db_sqls.h"
#include "vision_db_sqls_more.h"
#include "story_db_sqls.h"
#include "classify_restore.h"
#include "values_bucket.h"
#include "classify_aggregate_types.h"
#include <random>
#include "parameters.h"
#include "media_config_info_column.h"
#include "values_bucket.h"
#include "group_photo_album_restore.h"
#include "media_audio_column.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
/*
 * Test interface: BackupRestoreService::ShouldRestoreFromCloud
 * Test content: Test checking if restore should be performed from cloud
 * Covered branches: Default cloud restore status check
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_should_restore_from_cloud_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_should_restore_from_cloud_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->CheckTableColumnStatus(restoreService->mediaRdb_, CLONE_TABLE_LISTS_PHOTO);
    bool result = restoreService->ShouldRestoreFromCloud();
    EXPECT_EQ(result, false);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::GetCloneConfigInfoFromOriginDB
 * Test content: Test getting clone configuration info from origin database
 * Covered branches: Valid config info retrieval
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_clone_config_info_from_origin_db_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_clone_config_info_from_origin_db_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    CloneRestoreConfigInfo configInfo = restoreService->GetCloneConfigInfoFromOriginDB();
    EXPECT_EQ(configInfo.isValid, true);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::CheckSrcDstSwitchStatusMatch
 * Test content: Test checking if source and destination switch status match (both CLOUD)
 * Covered branches: Valid config info, matching CLOUD switch status
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_src_dst_switch_status_match_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_src_dst_switch_status_match_test_001 start");
    restoreService->srcCloneRestoreConfigInfo_.isValid = true;
    restoreService->dstCloneRestoreConfigInfo_.isValid = true;
    restoreService->srcCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOUD;
    restoreService->dstCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOUD;
    restoreService->CheckSrcDstSwitchStatusMatch();
    EXPECT_EQ(restoreService->isSrcDstSwitchStatusMatch_, true);
}

/*
 * Test interface: BackupRestoreService::CheckSrcDstSwitchStatusMatch
 * Test content: Test checking if source and destination switch status match (invalid source)
 * Covered branches: Invalid source config info, switch status mismatch
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_src_dst_switch_status_match_test_002,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_src_dst_switch_status_match_test_002 start");
    restoreService->srcCloneRestoreConfigInfo_.isValid = false;
    restoreService->dstCloneRestoreConfigInfo_.isValid = true;
    restoreService->CheckSrcDstSwitchStatusMatch();
    EXPECT_EQ(restoreService->isSrcDstSwitchStatusMatch_, false);
}

/*
 * Test interface: BackupRestoreService::IsCloudRestoreSatisfied
 * Test content: Test checking if cloud restore conditions are satisfied
 * Covered branches: Valid account and matching switch status
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_cloud_restore_satisfied_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_cloud_restore_satisfied_test_001 start");
    restoreService->isAccountValid_ = true;
    restoreService->isSrcDstSwitchStatusMatch_ = true;
    bool result = restoreService->IsCloudRestoreSatisfied();
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::IsCloudRestoreSatisfied
 * Test content: Test checking if cloud restore conditions are satisfied (invalid account)
 * Covered branches: Invalid account, cloud restore not satisfied
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_cloud_restore_satisfied_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_cloud_restore_satisfied_test_002 start");
    restoreService->isAccountValid_ = false;
    restoreService->isSrcDstSwitchStatusMatch_ = true;
    bool result = restoreService->IsCloudRestoreSatisfied();
    EXPECT_EQ(result, false);
}

/*
 * Test interface: BackupRestoreService::ParseDstDeviceBackupInfo
 * Test content: Test parsing destination device backup info with hdcEnabled false
 * Covered branches: Compatibility info parsing, hdcEnabled flag
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_parse_dst_device_backup_info_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_parse_dst_device_backup_info_test_002 start");
    restoreService->restoreInfo_ = R"([{"type":"compatibility_info","detail":"{\"hdcEnabled\":false}"}])";
    restoreService->ParseDstDeviceBackupInfo();
    EXPECT_EQ(restoreService->dstDeviceBackupInfo_.hdcEnabled, false);
}

/*
 * Test interface: BackupRestoreService::GetHighlightCloudMediaCnt
 * Test content: Test getting highlight cloud media count
 * Covered branches: Cloud media count query
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_highlight_cloud_media_cnt_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_highlight_cloud_media_cnt_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    int32_t count = restoreService->GetHighlightCloudMediaCnt();
    EXPECT_GE(count, 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::CheckDestDbHasRiskStatusColumn
 * Test content: Test checking if destination database has risk status column
 * Covered branches: Risk status column existence check
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_dest_db_has_risk_status_column_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_dest_db_has_risk_status_column_test_001 start");
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    bool result = restoreService->CheckDestDbHasRiskStatusColumn();
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::CheckSrcDbHasRiskStatusColumn
 * Test content: Test checking if source database has risk status column
 * Covered branches: Risk status column existence check in source DB
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_src_db_has_risk_status_column_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_src_db_has_risk_status_column_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    bool result = restoreService->CheckSrcDbHasRiskStatusColumn();
    EXPECT_EQ(result, true);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::AddToPhotosFailedOffsets
 * Test content: Test adding failed offset to photos failed offsets list
 * Covered branches: Failed offset addition
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_add_to_photos_failed_offsets_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_add_to_photos_failed_offsets_test_001 start");
    restoreService->needReportFailed_ = false;
    restoreService->AddToPhotosFailedOffsets(100);
    EXPECT_EQ(restoreService->photosFailedOffsets_.size(), 1);
    EXPECT_EQ(restoreService->photosFailedOffsets_[0], 100);
}

/*
 * Test interface: BackupRestoreService::GetThumbnailLocalPath
 * Test content: Test getting thumbnail local path from cloud path
 * Covered branches: Valid cloud path, thumbnail path generation
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_local_path_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_thumbnail_local_path_test_001 start");
    string cloudPath = "/storage/cloud/files/test.jpg";
    string result = restoreService->GetThumbnailLocalPath(cloudPath);
    EXPECT_FALSE(result.empty());
    EXPECT_TRUE(result.find(".thumbs") != string::npos);
}

/*
 * Test interface: BackupRestoreService::GetThumbnailLocalPath
 * Test content: Test getting thumbnail local path with invalid path
 * Covered branches: Invalid cloud path, empty result
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_local_path_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_thumbnail_local_path_test_002 start");
    string cloudPath = "/invalid/path/test.jpg";
    string result = restoreService->GetThumbnailLocalPath(cloudPath);
    EXPECT_TRUE(result.empty());
}

/*
 * Test interface: BackupRestoreService::HasColumn
 * Test content: Test checking if column exists in column info map
 * Covered branches: Column exists in map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_column_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_column_test_001 start");
    unordered_map<string, string> columnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" }
    };
    bool result = restoreService->HasColumn(columnInfoMap, "file_id");
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::HasColumn
 * Test content: Test checking if column exists in column info map (non-existent)
 * Covered branches: Column does not exist in map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_column_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_column_test_002 start");
    unordered_map<string, string> columnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" }
    };
    bool result = restoreService->HasColumn(columnInfoMap, "non_existent_column");
    EXPECT_EQ(result, false);
}

/*
 * Test interface: BackupRestoreService::IsReadyForRestore
 * Test content: Test checking if table is ready for restore (ready)
 * Covered branches: Table column status is true
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_ready_for_restore_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_ready_for_restore_test_001 start");
    restoreService->tableColumnStatusMap_["Photos"] = true;
    bool result = restoreService->IsReadyForRestore("Photos");
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::IsReadyForRestore
 * Test content: Test checking if table is ready for restore (not ready)
 * Covered branches: Table column status is false
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_ready_for_restore_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_ready_for_restore_test_002 start");
    restoreService->tableColumnStatusMap_["Photos"] = false;
    bool result = restoreService->IsReadyForRestore("Photos");
    EXPECT_EQ(result, false);
}

/*
 * Test interface: BackupRestoreService::HasColumns
 * Test content: Test checking if multiple columns exist in column info map
 * Covered branches: All columns exist in map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_columns_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_columns_test_001 start");
    unordered_map<string, string> columnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" },
        { "size", "BIGINT" }
    };
    unordered_set<string> columnSet = { "file_id", "display_name" };
    bool result = restoreService->HasColumns(columnInfoMap, columnSet);
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::HasColumns
 * Test content: Test checking if multiple columns exist in column info map (one missing)
 * Covered branches: Not all columns exist in map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_columns_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_columns_test_002 start");
    unordered_map<string, string> columnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" }
    };
    unordered_set<string> columnSet = { "file_id", "non_existent_column" };
    bool result = restoreService->HasColumns(columnInfoMap, columnSet);
    EXPECT_EQ(result, false);
}

/*
 * Test interface: BackupRestoreService::GetInsertValue
 * Test content: Test getting insert values for map info
 * Covered branches: Map info to values bucket conversion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_insert_value_map_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_insert_value_map_info_test_001 start");
    MapInfo mapInfo;
    mapInfo.fileId = 100;
    mapInfo.albumId = 200;
    auto values = restoreService->GetInsertValue(mapInfo);
    EXPECT_EQ(values.values_.size(), 2);
}

/*
 * Test interface: BackupRestoreService::CorrectTimestamp
 * Test content: Test correcting timestamp (milliseconds, no correction needed)
 * Covered branches: Timestamp in milliseconds range, no correction
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_correct_timestamp_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_correct_timestamp_test_001 start");
    int64_t originalTime = 1700000000000;
    int64_t result = restoreService->CorrectTimestamp(originalTime);
    EXPECT_EQ(result, originalTime);
}

/*
 * Test interface: BackupRestoreService::CorrectTimestamp
 * Test content: Test correcting timestamp (seconds, needs correction)
 * Covered branches: Timestamp in seconds range, convert to milliseconds
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_correct_timestamp_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_correct_timestamp_test_002 start");
    int64_t originalTime = 1700000000;
    int64_t result = restoreService->CorrectTimestamp(originalTime);
    EXPECT_GT(result, originalTime);
}

/*
 * Test interface: BackupRestoreService::IsInvalidLocalFile
 * Test content: Test checking if local file is invalid (LOCAL_AND_CLOUD position)
 * Covered branches: LOCAL_AND_CLOUD position, file not found error
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_invalid_local_file_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_invalid_local_file_test_001 start");
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD);
    fileInfo.uniqueId = "test_unique_id";
    bool result = restoreService->IsInvalidLocalFile(E_NO_SUCH_FILE, fileInfo);
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::IsInvalidLocalFile
 * Test content: Test checking if local file is invalid (LOCAL position)
 * Covered branches: LOCAL position, file not considered invalid
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_is_invalid_local_file_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_is_invalid_local_file_test_002 start");
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    fileInfo.uniqueId = "test_unique_id";
    bool result = restoreService->IsInvalidLocalFile(E_NO_SUCH_FILE, fileInfo);
    EXPECT_EQ(result, false);
}

/*
 * Test interface: BackupRestoreService::AddInvalidLocalFiles
 * Test content: Test adding invalid local files to tracking map
 * Covered branches: Invalid file addition
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_add_invalid_local_files_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_add_invalid_local_files_test_001 start");
    FileInfo fileInfo;
    fileInfo.fileIdOld = 100;
    fileInfo.cloudPath = "/test/path.jpg";
    restoreService->AddInvalidLocalFiles(fileInfo);
    EXPECT_EQ(restoreService->invalidLocalFiles_.size(), 1);
    EXPECT_EQ(restoreService->invalidLocalFiles_[100].fileIdOld, 100);
}

/*
 * Test interface: BackupRestoreService::RemoveInvalidLocalFiles
 * Test content: Test removing invalid local files from tracking map
 * Covered branches: Invalid file removal
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_remove_invalid_local_files_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_remove_invalid_local_files_test_001 start");
    FileInfo fileInfo;
    fileInfo.fileIdOld = 100;
    restoreService->invalidLocalFiles_[100] = fileInfo;
    restoreService->RemoveInvalidLocalFiles(fileInfo);
    EXPECT_EQ(restoreService->invalidLocalFiles_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::CheckThumbReady
 * Test content: Test checking if thumbnail is ready (all files exist)
 * Covered branches: All thumbnail files exist, ready status
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_ready_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_ready_test_001 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isThmExist = true;
    existFlag.isDayAstcExist = true;
    existFlag.isYearAstcExist = true;
    int32_t result = restoreService->CheckThumbReady(fileInfo, existFlag);
    EXPECT_EQ(result, RESTORE_THUMBNAIL_READY_ALL_SUCCESS);
}

/*
 * Test interface: BackupRestoreService::CheckThumbReady
 * Test content: Test checking if thumbnail is ready (thm missing)
 * Covered branches: Thumbnail file missing, fail status
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_ready_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_ready_test_002 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isThmExist = false;
    existFlag.isDayAstcExist = true;
    existFlag.isYearAstcExist = true;
    int32_t result = restoreService->CheckThumbReady(fileInfo, existFlag);
    EXPECT_EQ(result, RESTORE_THUMBNAIL_READY_FAIL);
}

/*
 * Test interface: BackupRestoreService::CheckLcdVisitTime
 * Test content: Test checking LCD visit time (LCD exists)
 * Covered branches: LCD file exists, success status
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_lcd_visit_time_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_lcd_visit_time_test_001 start");
    CloudPhotoFileExistFlag existFlag;
    existFlag.isLcdExist = true;
    int32_t result = restoreService->CheckLcdVisitTime(existFlag);
    EXPECT_EQ(result, RESTORE_LCD_VISIT_TIME_SUCCESS);
}

/*
 * Test interface: BackupRestoreService::CheckLcdVisitTime
 * Test content: Test checking LCD visit time (LCD missing)
 * Covered branches: LCD file missing, no LCD status
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_lcd_visit_time_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_lcd_visit_time_test_002 start");
    CloudPhotoFileExistFlag existFlag;
    existFlag.isLcdExist = false;
    int32_t result = restoreService->CheckLcdVisitTime(existFlag);
    EXPECT_EQ(result, RESTORE_LCD_VISIT_TIME_NO_LCD);
}

/*
 * Test interface: BackupRestoreService::GetNoNeedMigrateCount
 * Test content: Test getting count of files that don't need migration
 * Covered branches: No need migrate count retrieval
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_no_need_migrate_count_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_no_need_migrate_count_test_001 start");
    int32_t result = restoreService->GetNoNeedMigrateCount();
    EXPECT_GE(result, 0);
}

/*
 * Test interface: BackupRestoreService::SetRestoreFailedAndErrorCount
 * Test content: Test setting restore failed and error count
 * Covered branches: Failed and error count calculation
 */
HWTEST_F(MediaLibraryBackupCloneTest,
    medialibrary_backup_clone_set_restore_failed_and_error_count_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_set_restore_failed_and_error_count_test_001 start");
    restoreService->totalNumber_ = 100;
    restoreService->migrateFileNumber_ = 80;
    restoreService->migratePhotoDuplicateNumber_ = 5;
    restoreService->notFoundNumber_ = 2;
    uint64_t failed = 0;
    uint64_t error = 0;
    restoreService->SetRestoreFailedAndErrorCount(failed, error);
    EXPECT_GE(failed, 0);
    EXPECT_GE(error, 0);
}

/*
 * Test interface: BackupRestoreService::HasExThumbnail
 * Test content: Test checking if file has extended thumbnail (LOCAL image with rotation)
 * Covered branches: LOCAL position, image type, non-zero orientation
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_ex_thumbnail_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_ex_thumbnail_test_001 start");
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::LOCAL);
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.orientation = 90;
    bool result = restoreService->HasExThumbnail(fileInfo);
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::HasExThumbnail
 * Test content: Test checking if file has extended thumbnail (CLOUD image with rotation)
 * Covered branches: CLOUD position, image type, non-zero orientation
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_ex_thumbnail_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_ex_thumbnail_test_002 start");
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.orientation = 90;
    bool result = restoreService->HasExThumbnail(fileInfo);
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::HasExThumbnail
 * Test content: Test checking if file has extended thumbnail (CLOUD video no rotation)
 * Covered branches: CLOUD position, video type, zero orientation
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_ex_thumbnail_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_ex_thumbnail_test_003 start");
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    fileInfo.fileType = MediaType::MEDIA_TYPE_VIDEO;
    fileInfo.orientation = 0;
    bool result = restoreService->HasExThumbnail(fileInfo);
    EXPECT_EQ(result, false);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (extended thumbnails exist)
 * Covered branches: Extended thumbnail files exist
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_009, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_009 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isExThmExist = true;
    existFlag.isExLcdExist = true;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_NE(result, RESTORE_THUMBNAIL_STATUS_ALL);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (extended LCD missing)
 * Covered branches: Extended thumbnail exists, LCD missing
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_010, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_010 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isExThmExist = true;
    existFlag.isExLcdExist = false;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_NE(result, RESTORE_THUMBNAIL_STATUS_NOT_LCD);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (extended thumbnail missing)
 * Covered branches: Extended thumbnail missing, LCD exists
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_011, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_011 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isExThmExist = false;
    existFlag.isExLcdExist = true;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_NE(result, RESTORE_THUMBNAIL_STATUS_NOT_THUMB);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (all thumbnails exist)
 * Covered branches: All thumbnail files exist
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_012, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_012 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isThmExist = true;
    existFlag.isLcdExist = true;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_EQ(result, RESTORE_THUMBNAIL_STATUS_ALL);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (all thumbnails missing)
 * Covered branches: All thumbnail files missing
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_013, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_013 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isThmExist = false;
    existFlag.isLcdExist = false;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_EQ(result, RESTORE_THUMBNAIL_STATUS_NOT_ALL);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (extended LCD missing)
 * Covered branches: Extended thumbnail exists, LCD missing
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_014, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_014 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isExThmExist = true;
    existFlag.isExLcdExist = false;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_NE(result, RESTORE_THUMBNAIL_STATUS_NOT_LCD);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (extended thumbnail missing)
 * Covered branches: Extended thumbnail missing, LCD exists
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_015, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_015 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isExThmExist = false;
    existFlag.isExLcdExist = true;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_NE(result, RESTORE_THUMBNAIL_STATUS_NOT_THUMB);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (all thumbnails exist)
 * Covered branches: All thumbnail files exist
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_016, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_016 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isThmExist = true;
    existFlag.isLcdExist = true;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_EQ(result, RESTORE_THUMBNAIL_STATUS_ALL);
}

/*
 * Test interface: BackupRestoreService::CheckThumbStatus
 * Test content: Test checking thumbnail status (all thumbnails missing)
 * Covered branches: All thumbnail files missing
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_thumb_status_test_017, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_thumb_status_test_017 start");
    FileInfo fileInfo;
    CloudPhotoFileExistFlag existFlag;
    existFlag.isThmExist = false;
    existFlag.isLcdExist = false;
    int32_t result = restoreService->CheckThumbStatus(fileInfo, existFlag);
    EXPECT_EQ(result, RESTORE_THUMBNAIL_STATUS_NOT_ALL);
}

/*
 * Test interface: BackupRestoreService::CheckAlbumNameUnique
 * Test content: Test checking if album name is unique (empty repeated list)
 * Covered branches: Empty repeated album name list
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_album_name_unique_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_album_name_unique_test_001 start");
    string albumName = "TestAlbum";
    vector<string> repeatedAlbumName = {};
    bool result = restoreService->CheckAlbumNameUnique(albumName, repeatedAlbumName);
    EXPECT_EQ(result, true);
}

/*
 * Test interface: CheckAlbumNameUnique
 * Test content: Test checking if album name is unique (with repeated list)
 * Covered branches: Non-empty repeated album name list
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_check_album_name_unique_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_check_album_name_unique_test_002 start");
    string albumName = "TestAlbum";
    vector<string> repeatedAlbumName = { "testalbum" };
    bool result = restoreService->CheckAlbumNameUnique(albumName, repeatedAlbumName);
    EXPECT_NE(result, false);
}

/*
 * Test interface: BackupRestoreService::GetQueryWhereClauseByTable
 * Test content: Test getting query where clause by table name
 * Covered branches: Table exists in query where clause map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_query_where_clause_by_table_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_query_where_clause_by_table_test_001 start");
    restoreService->tableQueryWhereClauseMap_["Photos"] = "position = 1";
    restoreService->tableExtraQueryWhereClauseMap_["Photos"] = "sync_status = 0";
    string result = restoreService->GetQueryWhereClauseByTable("Photos");
    EXPECT_FALSE(result.empty());
}

/*
 * Test interface: BackupRestoreService::GetQueryWhereClauseByTable
 * Test content: Test getting query where clause by table name (non-existent)
 * Covered branches: Table does not exist in query where clause map
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_query_where_clause_by_table_test_002,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_query_where_clause_by_table_test_002 start");
    string result = restoreService->GetQueryWhereClauseByTable("NonExistentTable");
    EXPECT_TRUE(result.empty());
}

/*
 * Test interface: BackupRestoreService::UpdateExistNewAddColumnSet
 * Test content: Test updating exist new add column set
 * Covered branches: Column info map processing
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_update_exist_new_add_column_set_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_update_exist_new_add_column_set_test_001 start");
    unordered_map<string, string> srcColumnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" }
    };
    restoreService->UpdateExistNewAddColumnSet(srcColumnInfoMap);
    EXPECT_NE(restoreService->existNewAddColumnSet_.size(), 1);
}

/*
 * Test interface: BackupRestoreService::UpdateExistNewAddColumnSet
 * Test content: Test updating exist new add column set with new column
 * Covered branches: New column detection and addition
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_update_exist_new_add_column_set_test_002,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_update_exist_new_add_column_set_test_002 start");
    unordered_map<string, string> srcColumnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" },
        { "exif_rotate", "INTEGER" }
    };
    restoreService->UpdateExistNewAddColumnSet(srcColumnInfoMap);
    EXPECT_NE(restoreService->existNewAddColumnSet_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::HasSameColumn
 * Test content: Test checking if column has same name and type
 * Covered branches: Column exists with matching type
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_same_column_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_same_column_test_001 start");
    unordered_map<string, string> columnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" }
    };
    bool result = restoreService->HasSameColumn(columnInfoMap, "file_id", "INTEGER");
    EXPECT_EQ(result, true);
}

/*
 * Test interface: BackupRestoreService::HasSameColumn
 * Test content: Test checking if column has same name and type (type mismatch)
 * Covered branches: Column exists with different type
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_same_column_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_same_column_test_002 start");
    unordered_map<string, string> columnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" }
    };
    bool result = restoreService->HasSameColumn(columnInfoMap, "file_id", "TEXT");
    EXPECT_EQ(result, false);
}

/*
 * Test interface: BackupRestoreService::HasSameColumn
 * Test content: Test checking if column has same name and type (non-existent)
 * Covered branches: Column does not exist
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_has_same_column_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_has_same_column_test_003 start");
    unordered_map<string, string> columnInfoMap = {
        { "file_id", "INTEGER" },
        { "display_name", "TEXT" }
    };
    bool result = restoreService->HasSameColumn(columnInfoMap, "non_existent", "INTEGER");
    EXPECT_EQ(result, false);
}

/*
 * Test interface: BackupRestoreService::SetFileIdReference
 * Test content: Test setting file ID reference map
 * Covered branches: File ID reference mapping
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_set_file_id_reference_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_set_file_id_reference_test_001 start");
    vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileIdOld = 100;
    fileInfo.fileIdNew = 200;
    fileInfos.push_back(fileInfo);
    string selection;
    unordered_map<int32_t, int32_t> fileIdMap;
    restoreService->SetFileIdReference(fileInfos, selection, fileIdMap);
    EXPECT_EQ(fileIdMap.size(), 1);
    EXPECT_EQ(fileIdMap[100], 200);
}

/*
 * Test interface: BackupRestoreService::SetFileIdReference
 * Test content: Test setting file ID reference map (with zero old ID)
 * Covered branches: File ID reference mapping with zero old ID
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_set_file_id_reference_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_set_file_id_reference_test_002 start");
    vector<FileInfo> fileInfos;
    FileInfo fileInfo1;
    fileInfo1.fileIdOld = 100;
    fileInfo1.fileIdNew = 200;
    fileInfos.push_back(fileInfo1);
    FileInfo fileInfo2;
    fileInfo2.fileIdOld = 0;
    fileInfo2.fileIdNew = 300;
    fileInfos.push_back(fileInfo2);
    string selection;
    unordered_map<int32_t, int32_t> fileIdMap;
    restoreService->SetFileIdReference(fileInfos, selection, fileIdMap);
    EXPECT_EQ(fileIdMap.size(), 1);
}

/*
 * Test interface: BackupRestoreService::QueryTotalNumber
 * Test content: Test querying total number of records in table
 * Covered branches: Total number query
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_query_total_number_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_query_total_number_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    int32_t result = restoreService->QueryTotalNumber(PhotoColumn::PHOTOS_TABLE);
    EXPECT_GE(result, 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::ParseAlbumResultSet
 * Test content: Test parsing album result set from query
 * Covered branches: Album result set parsing
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_parse_album_result_set_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_parse_album_result_set_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoAlbumColumns::TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    
    string insertSql = "INSERT INTO PhotoAlbum (album_type, album_subtype, album_name) VALUES (?, ?, ?)";
    vector<NativeRdb::ValueObject> params = {1024, 0, "TestAlbum"};
    cloneSource.cloneStorePtr_->ExecuteSql(insertSql, params);
    
    string querySql = "SELECT * FROM PhotoAlbum WHERE album_name = 'TestAlbum'";
    auto resultSet = cloneSource.cloneStorePtr_->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    
    AlbumInfo albumInfo;
    bool result = restoreService->ParseAlbumResultSet(PhotoAlbumColumns::TABLE, resultSet, albumInfo);
    EXPECT_EQ(result, true);
    EXPECT_EQ(albumInfo.albumName, "TestAlbum");
    resultSet->Close();
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::GetInsertValue
 * Test content: Test getting insert values for album info (USER type)
 * Covered branches: USER album type insert values
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_insert_value_album_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_insert_value_album_info_test_001 start");
    AlbumInfo albumInfo;
    albumInfo.albumType = PhotoAlbumType::USER;
    albumInfo.albumSubType = PhotoAlbumSubType::USER_GENERIC;
    albumInfo.albumName = "TestAlbum";
    auto values = restoreService->GetInsertValue(albumInfo, PhotoAlbumColumns::TABLE);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::GetInsertValue
 * Test content: Test getting insert values for album info (SOURCE type)
 * Covered branches: SOURCE album type insert values
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_insert_value_album_info_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_insert_value_album_info_test_002 start");
    AlbumInfo albumInfo;
    albumInfo.albumType = PhotoAlbumType::SOURCE;
    albumInfo.albumSubType = PhotoAlbumSubType::SOURCE_GENERIC;
    albumInfo.albumName = "SourceAlbum";
    auto values = restoreService->GetInsertValue(albumInfo, PhotoAlbumColumns::TABLE);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::GetInsertValues
 * Test content: Test getting insert values for album info vector
 * Covered branches: Album info vector to values bucket conversion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_insert_values_vector_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_insert_values_vector_test_001 start");
    vector<AlbumInfo> albumInfos;
    AlbumInfo albumInfo;
    albumInfo.albumType = PhotoAlbumType::USER;
    albumInfo.albumSubType = PhotoAlbumSubType::USER_GENERIC;
    albumInfo.albumName = "TestAlbum";
    albumInfos.push_back(albumInfo);
    vector<string> albumIds;
    vector<NativeRdb::ValuesBucket> values = restoreService->GetInsertValues(albumInfos, albumIds,
        PhotoAlbumColumns::TABLE);
    EXPECT_NE(values.size(), 1);
}

/*
 * Test interface: BackupRestoreService::GetInsertValues
 * Test content: Test getting insert values for file info vector
 * Covered branches: File info vector to values bucket conversion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_insert_values_file_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_insert_values_file_info_test_001 start");
    vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = "test.jpg";
    fileInfo.cloudPath = "/test/path.jpg";
    fileInfos.push_back(fileInfo);
    vector<NativeRdb::ValuesBucket> values = restoreService->GetInsertValues(CLONE_RESTORE_ID, fileInfos,
        SourceType::PHOTOS);
    EXPECT_NE(values.size(), 1);
}

/*
 * Test interface: BackupRestoreService::GetCloudInsertValues
 * Test content: Test getting cloud insert values for file info vector
 * Covered branches: Cloud insert values generation
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_cloud_insert_values_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_cloud_insert_values_test_001 start");
    vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = "test.jpg";
    fileInfo.cloudPath = "/test/path.jpg";
    fileInfos.push_back(fileInfo);
    vector<NativeRdb::ValuesBucket> values = restoreService->GetCloudInsertValues(CLONE_RESTORE_ID,
        fileInfos, SourceType::PHOTOS);
    EXPECT_EQ(values.size(), 1);
}

/*
 * Test interface: BackupRestoreService::GetInsertValue
 * Test content: Test getting insert values for file info
 * Covered branches: File info to values bucket conversion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_insert_value_file_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_insert_value_file_info_test_001 start");
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = "test.jpg";
    fileInfo.cloudPath = "/test/path.jpg";
    fileInfo.fileSize = 1024;
    fileInfo.dateAdded = 1700000000000;
    fileInfo.dateModified = 1700000000000;
    fileInfo.dateTaken = 1700000000000;
    fileInfo.orientation = 0;
    fileInfo.subtype = 0;
    auto values = restoreService->GetInsertValue(fileInfo, fileInfo.cloudPath, SourceType::PHOTOS);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::GetCloudInsertValue
 * Test content: Test getting cloud insert values for file info
 * Covered branches: Cloud insert values generation
 */
HWTEST_F(MediaLibraryBackupCloneTest,
    medialibrary_backup_clone_get_cloud_insert_value_file_info_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_cloud_insert_value_file_info_test_001 start");
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = "test.jpg";
    fileInfo.cloudPath = "/test/path.jpg";
    fileInfo.fileSize = 1024;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    auto values = restoreService->GetCloudInsertValue(fileInfo, fileInfo.cloudPath, SourceType::PHOTOS);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::GetThumbnailInsertValue
 * Test content: Test getting thumbnail insert values with success status
 * Covered branches: Thumbnail ready and LCD visit time success
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_insert_value_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_thumbnail_insert_value_test_004 start");
    FileInfo fileInfo;
    fileInfo.lcdVisitTime = RESTORE_LCD_VISIT_TIME_SUCCESS;
    fileInfo.thumbnailReady = RESTORE_THUMBNAIL_READY_SUCCESS;
    NativeRdb::ValuesBucket values;
    restoreService->GetThumbnailInsertValue(fileInfo, values);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::GetThumbnailInsertValue
 * Test content: Test getting thumbnail insert values without clone thumbnail dir
 * Covered branches: No clone thumbnail directory
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_thumbnail_insert_value_test_006, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_thumbnail_insert_value_test_006 start");
    restoreService->hasCloneThumbnailDir_ = false;
    FileInfo fileInfo;
    NativeRdb::ValuesBucket values;
    restoreService->GetThumbnailInsertValue(fileInfo, values);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::GetCloudThumbnailInsertValue
 * Test content: Test getting cloud thumbnail insert values
 * Covered branches: Cloud thumbnail insert values generation
 */
HWTEST_F(MediaLibraryBackupCloneTest,
    medialibrary_backup_clone_get_cloud_thumbnail_insert_value_test_001,
    TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_cloud_thumbnail_insert_value_test_001 start");
    restoreService->dstCloneRestoreConfigInfo_.switchStatus = SwitchStatus::CLOUD;
    FileInfo fileInfo;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    fileInfo.cloudVersion = 1;
    NativeRdb::ValuesBucket values;
    restoreService->GetCloudThumbnailInsertValue(fileInfo, values);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::PrepareShootingModeVal
 * Test content: Test preparing shooting mode value
 * Covered branches: Shooting mode value preparation
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_shooting_mode_val_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_prepare_shooting_mode_val_test_001 start");
    FileInfo fileInfo;
    fileInfo.valMap[PhotoColumn::PHOTO_SHOOTING_MODE_TAG] = string("portrait");
    NativeRdb::ValuesBucket values;
    restoreService->PrepareShootingModeVal(fileInfo, values);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::PrepareShootingModeVal
 * Test content: Test preparing shooting mode value (empty)
 * Covered branches: Empty shooting mode value
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_shooting_mode_val_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_prepare_shooting_mode_val_test_002 start");
    FileInfo fileInfo;
    NativeRdb::ValuesBucket values;
    restoreService->PrepareShootingModeVal(fileInfo, values);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::SetTimeInfo
 * Test content: Test setting time info with detail time
 * Covered branches: Time info with detail time
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_set_time_info_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_set_time_info_test_001 start");
    FileInfo fileInfo;
    fileInfo.dateAdded = 1700000000000;
    fileInfo.dateModified = 1700000000000;
    fileInfo.dateTaken = 1700000000000;
    fileInfo.detailTime = "2024-01-01 00:00:00";
    NativeRdb::ValuesBucket values;
    restoreService->SetTimeInfo(fileInfo, values);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::SetTimeInfo
 * Test content: Test setting time info without detail time
 * Covered branches: Time info without detail time
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_set_time_info_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_set_time_info_test_002 start");
    FileInfo fileInfo;
    fileInfo.dateAdded = 1700000000;
    fileInfo.dateModified = 1700000000;
    fileInfo.dateTaken = 1700000000;
    NativeRdb::ValuesBucket values;
    restoreService->SetTimeInfo(fileInfo, values);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::SetTimeInfo
 * Test content: Test setting time info with empty detail time
 * Covered branches: Empty detail time
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_set_time_info_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_set_time_info_test_003 start");
    FileInfo fileInfo;
    fileInfo.dateAdded = 1700000000000;
    fileInfo.dateModified = 1700000000000;
    fileInfo.dateTaken = 1700000000000;
    fileInfo.detailTime = "";
    NativeRdb::ValuesBucket values;
    restoreService->SetTimeInfo(fileInfo, values);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::PrepareCommonColumnVal
 * Test content: Test preparing common column value (INTEGER)
 * Covered branches: INTEGER type column value
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_common_column_val_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_prepare_common_column_val_test_001 start");
    unordered_map<string, string> commonColumnInfoMap = {
        { "test_column", "INTEGER" }
    };
    variant<int32_t, int64_t, double, string> columnVal = 100;
    NativeRdb::ValuesBucket values;
    restoreService->PrepareCommonColumnVal(values, "test_column", columnVal, commonColumnInfoMap);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::PrepareCommonColumnVal
 * Test content: Test preparing common column value (TEXT)
 * Covered branches: TEXT type column value
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_common_column_val_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_prepare_common_column_val_test_002 start");
    unordered_map<string, string> commonColumnInfoMap = {
        { "test_column", "TEXT" }
    };
    variant<int32_t, int64_t, double, string> columnVal = string("test_value");
    NativeRdb::ValuesBucket values;
    restoreService->PrepareCommonColumnVal(values, "test_column", columnVal, commonColumnInfoMap);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::PrepareCommonColumnVal
 * Test content: Test preparing common column value (BIGINT)
 * Covered branches: BIGINT type column value
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_common_column_val_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_prepare_common_column_val_test_003 start");
    unordered_map<string, string> commonColumnInfoMap = {
        { "test_column", "BIGINT" }
    };
    variant<int32_t, int64_t, double, string> columnVal = int64_t(1000000);
    NativeRdb::ValuesBucket values;
    restoreService->PrepareCommonColumnVal(values, "test_column", columnVal, commonColumnInfoMap);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::PrepareCommonColumnVal
 * Test content: Test preparing common column value (DOUBLE)
 * Covered branches: DOUBLE type column value
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_common_column_val_test_004, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_prepare_common_column_val_test_004 start");
    unordered_map<string, string> commonColumnInfoMap = {
        { "test_column", "DOUBLE" }
    };
    variant<int32_t, int64_t, double, string> columnVal = 3.14;
    NativeRdb::ValuesBucket values;
    restoreService->PrepareCommonColumnVal(values, "test_column", columnVal, commonColumnInfoMap);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::GetValFromResultSet
 * Test content: Test getting values from result set
 * Covered branches: Result set value extraction
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_val_from_result_set_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_val_from_result_set_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    
    string insertSql = "INSERT INTO Photos (file_id, display_name, size) VALUES (?, ?, ?)";
    vector<NativeRdb::ValueObject> params = {1, "test.jpg", 1024};
    cloneSource.cloneStorePtr_->ExecuteSql(insertSql, params);
    
    string querySql = "SELECT file_id, display_name, size FROM Photos WHERE file_id = 1";
    auto resultSet = cloneSource.cloneStorePtr_->QuerySql(querySql);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    
    unordered_map<string, variant<int32_t, int64_t, double, string>> valMap;
    restoreService->GetValFromResultSet(resultSet, valMap, "file_id", "INTEGER");
    restoreService->GetValFromResultSet(resultSet, valMap, "display_name", "TEXT");
    restoreService->GetValFromResultSet(resultSet, valMap, "size", "BIGINT");
    EXPECT_EQ(valMap.size(), 3);
    resultSet->Close();
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::PrepareEditTimeVal
 * Test content: Test preparing edit time value
 * Covered branches: Edit time value preparation
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_prepare_edit_time_val_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_prepare_edit_time_val_test_001 start");
    FileInfo fileInfo;
    fileInfo.relativePath = "/test/path.jpg";
    fileInfo.dateModified = 1700000000000;
    unordered_map<string, string> commonColumnInfoMap = {
        { "edit_time", "BIGINT" }
    };
    NativeRdb::ValuesBucket values;
    restoreService->PrepareEditTimeVal(values, 1700000000000, fileInfo, commonColumnInfoMap);
    EXPECT_GT(values.values_.size(), 0);
}

/*
 * Test interface: BackupRestoreService::QueryFileInfos
 * Test content: Test querying file infos
 * Covered branches: File info query
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_query_file_infos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_query_file_infos_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    vector<FileInfo> result = restoreService->QueryFileInfos(0, 0);
    EXPECT_GE(result.size(), 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::QueryCloudFileInfos
 * Test content: Test querying cloud file infos
 * Covered branches: Cloud file info query
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_query_cloud_file_infos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_query_cloud_file_infos_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    vector<FileInfo> result = restoreService->QueryCloudFileInfos(0, 0);
    EXPECT_GE(result.size(), 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::QueryAlbumInfos
 * Test content: Test querying album infos
 * Covered branches: Album info query
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_query_album_infos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_query_album_infos_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoAlbumColumns::TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    vector<AlbumInfo> result = restoreService->QueryAlbumInfos(PhotoAlbumColumns::TABLE, 0);
    EXPECT_GE(result.size(), 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::GetInsertValues
 * Test content: Test getting insert values for map info vector
 * Covered branches: Map info vector to values bucket conversion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_get_insert_values_map_infos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_get_insert_values_map_infos_test_001 start");
    vector<MapInfo> mapInfos;
    MapInfo mapInfo;
    mapInfo.fileId = 100;
    mapInfo.albumId = 200;
    mapInfos.push_back(mapInfo);
    vector<NativeRdb::ValuesBucket> values = restoreService->GetInsertValues(mapInfos);
    EXPECT_EQ(values.size(), 1);
}

/*
 * Test interface: BackupRestoreService::InsertPhoto
 * Test content: Test inserting photo with file info
 * Covered branches: Photo insertion with valid file info
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_photo_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_insert_photo_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = "test.jpg";
    fileInfo.cloudPath = "/test/path.jpg";
    fileInfo.fileSize = 1024;
    fileInfo.isNew = true;
    fileInfos.push_back(fileInfo);
    int32_t result = restoreService->InsertPhoto(fileInfos);
    EXPECT_EQ(result, E_OK);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::InsertPhoto
 * Test content: Test inserting photo with empty file info vector
 * Covered branches: Empty file info vector
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_photo_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_insert_photo_test_002 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    vector<FileInfo> fileInfos;
    int32_t result = restoreService->InsertPhoto(fileInfos);
    EXPECT_EQ(result, E_OK);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::InsertCloudPhoto
 * Test content: Test inserting cloud photo with file info
 * Covered branches: Cloud photo insertion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_cloud_photo_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_insert_cloud_photo_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_IMAGE;
    fileInfo.displayName = "test.jpg";
    fileInfo.cloudPath = "/test/path.jpg";
    fileInfo.fileSize = 1024;
    fileInfo.position = static_cast<int32_t>(PhotoPositionType::CLOUD);
    fileInfos.push_back(fileInfo);
    int32_t result = restoreService->InsertCloudPhoto(CLONE_RESTORE_ID, fileInfos, SourceType::PHOTOS);
    EXPECT_EQ(result, E_OK);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::InsertAudio
 * Test content: Test inserting audio file info
 * Covered branches: Audio file insertion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_audio_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_insert_audio_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { AudioColumn::AUDIOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileType = MediaType::MEDIA_TYPE_AUDIO;
    fileInfo.displayName = "test.mp3";
    fileInfo.filePath = "/test/path.mp3";
    fileInfo.fileSize = 1024;
    fileInfos.push_back(fileInfo);
    restoreService->InsertAudio(fileInfos);
    EXPECT_GE(restoreService->migrateAudioFileNumber_, 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::InsertAlbum
 * Test content: Test inserting album info
 * Covered branches: Album insertion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_album_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_insert_album_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoAlbumColumns::TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    vector<AlbumInfo> albumInfos;
    AlbumInfo albumInfo;
    albumInfo.albumType = PhotoAlbumType::USER;
    albumInfo.albumSubType = PhotoAlbumSubType::USER_GENERIC;
    albumInfo.albumName = "TestAlbum";
    albumInfos.push_back(albumInfo);
    restoreService->InsertAlbum(albumInfos, PhotoAlbumColumns::TABLE);
    EXPECT_GE(restoreService->migrateDatabaseAlbumNumber_, 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::BatchQueryPhoto
 * Test content: Test batch querying photos
 * Covered branches: Batch photo query
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_batch_query_photo_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_batch_query_photo_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    
    string insertSql = "INSERT INTO Photos (file_id, display_name, size, data) VALUES (?, ?, ?, ?)";
    vector<NativeRdb::ValueObject> params = {1, "test.jpg", 1024, "/test/path.jpg"};
    g_rdbStore->GetRaw()->ExecuteSql(insertSql, params);
    
    vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.cloudPath = "/test/path.jpg";
    fileInfos.push_back(fileInfo);
    restoreService->BatchQueryPhoto(fileInfos);
    EXPECT_EQ(fileInfos[0].fileIdNew, 1);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::BatchInsertMap
 * Test content: Test batch inserting map info
 * Covered branches: Batch map insertion
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_batch_insert_map_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_batch_insert_map_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    
    string insertAlbumSql = "INSERT INTO PhotoAlbum (album_id, album_type, album_subtype, album_name) " \
        "VALUES (?, ?, ?, ?)";
    vector<NativeRdb::ValueObject> albumParams = {100, 1, 0, "TestAlbum"};
    g_rdbStore->GetRaw()->ExecuteSql(insertAlbumSql, albumParams);
    
    string insertPhotoSql = "INSERT INTO Photos (file_id, display_name, size, data) VALUES (?, ?, ?, ?)";
    vector<NativeRdb::ValueObject> photoParams = {200, "test.jpg", 1024, "/test/path.jpg"};
    g_rdbStore->GetRaw()->ExecuteSql(insertPhotoSql, photoParams);
    
    restoreService->tableAlbumIdMap_[PhotoAlbumColumns::TABLE][100] = 100;
    
    vector<FileInfo> fileInfos;
    FileInfo fileInfo;
    fileInfo.fileIdOld = 200;
    fileInfo.fileIdNew = 200;
    fileInfos.push_back(fileInfo);
    
    int64_t totalRowNum = 0;
    restoreService->BatchInsertMap(fileInfos, totalRowNum);
    EXPECT_GE(totalRowNum, 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::QueryMapTotalNumber
 * Test content: Test querying map total number
 * Covered branches: Map total number query
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_query_map_total_number_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_query_map_total_number_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    string baseQuerySql = "SELECT * FROM PhotoMap";
    int32_t result = restoreService->QueryMapTotalNumber(baseQuerySql);
    EXPECT_GE(result, 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::QueryMapInfos
 * Test content: Test querying map infos
 * Covered branches: Map info query
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_query_map_infos_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_query_map_infos_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    string baseQuerySql = "SELECT * FROM PhotoMap";
    unordered_map<int32_t, int32_t> fileIdMap;
    unordered_map<int32_t, int32_t> albumIdMap;
    vector<MapInfo> result = restoreService->QueryMapInfos(PhotoMap::TABLE, baseQuerySql, 0, fileIdMap, albumIdMap);
    EXPECT_GE(result.size(), 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}

/*
 * Test interface: BackupRestoreService::InsertMapByTable
 * Test content: Test inserting map info by table
 * Covered branches: Map insertion by table
 */
HWTEST_F(MediaLibraryBackupCloneTest, medialibrary_backup_clone_insert_map_by_table_test_001, TestSize.Level2)
{
    MEDIA_INFO_LOG("medialibrary_backup_clone_insert_map_by_table_test_001 start");
    CloneSource cloneSource;
    vector<string> tableList = { PhotoColumn::PHOTOS_TABLE, PhotoAlbumColumns::TABLE, PhotoMap::TABLE };
    Init(cloneSource, TEST_BACKUP_DB_PATH, tableList);
    restoreService->mediaRdb_ = cloneSource.cloneStorePtr_;
    restoreService->mediaLibraryRdb_ = g_rdbStore->GetRaw();
    vector<MapInfo> mapInfos;
    MapInfo mapInfo;
    mapInfo.fileId = 100;
    mapInfo.albumId = 200;
    mapInfos.push_back(mapInfo);
    unordered_set<int32_t> albumSet;
    int64_t result = restoreService->InsertMapByTable(PhotoMap::TABLE, mapInfos, albumSet);
    EXPECT_GE(result, 0);
    EXPECT_GE(albumSet.size(), 0);
    ClearCloneSource(cloneSource, TEST_BACKUP_DB_PATH);
}
} // namespace Media
} // namespace OHOS
