/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryCloneRestore"

#include "clone_restore.h"
#include "backup_const_column.h"

#include "application_context.h"
#include "backup_dfx_utils.h"
#include "backup_file_utils.h"
#include "backup_log_utils.h"
#include "clone_restore_classify.h"
#include "clone_restore_cv_analysis.h"
#include "clone_restore_highlight.h"
#include "clone_restore_geo.h"
#include "cloud_sync_utils.h"
#include "database_report.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_library_db_upgrade.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_type_const.h"
#include "ohos_account_kits.h"
#include "photos_dao.h"
#include "rdb_store.h"
#include "result_set_utils.h"
#include "upgrade_restore_task_report.h"
#include "userfile_manager_types.h"
#include "ohos_account_kits.h"

#ifdef CLOUD_SYNC_MANAGER
#include "cloud_sync_manager.h"
#endif

using namespace std;
namespace OHOS {
namespace Media {
const int32_t CLONE_QUERY_COUNT = 200;
const string MEDIA_DB_PATH = "/data/storage/el2/database/rdb/media_library.db";
const std::string THM_SAVE_WITHOUT_ROTATE_PATH = "/THM_EX";
constexpr int64_t SECONDS_LEVEL_LIMIT = 1e10;
const int32_t ORIETATION_ZERO = 0;
const int32_t MIGRATE_CLOUD_THM_TYPE = 0;
const int32_t MIGRATE_CLOUD_LCD_TYPE = 1;
const int32_t MIGRATE_CLOUD_ASTC_TYPE = 2;
const int32_t RELEATED_TO_PHOTO_MAP = 1;
const unordered_map<string, unordered_set<string>> NEEDED_COLUMNS_MAP = {
    { PhotoColumn::PHOTOS_TABLE,
        {
            MediaColumn::MEDIA_ID,
            MediaColumn::MEDIA_FILE_PATH,
            MediaColumn::MEDIA_SIZE,
            MediaColumn::MEDIA_TYPE,
            MediaColumn::MEDIA_NAME,
            MediaColumn::MEDIA_DATE_ADDED,
            MediaColumn::MEDIA_DATE_MODIFIED,
            PhotoColumn::PHOTO_ORIENTATION,
            PhotoColumn::PHOTO_SUBTYPE,
            MediaColumn::MEDIA_DATE_TRASHED,
            MediaColumn::MEDIA_HIDDEN,
        }},
    { PhotoAlbumColumns::TABLE,
        {
            PhotoAlbumColumns::ALBUM_ID,
            PhotoAlbumColumns::ALBUM_TYPE,
            PhotoAlbumColumns::ALBUM_SUBTYPE,
            PhotoAlbumColumns::ALBUM_NAME,
            PhotoAlbumColumns::ALBUM_BUNDLE_NAME,
        }},
    { PhotoMap::TABLE,
        {
            PhotoMap::ALBUM_ID,
            PhotoMap::ASSET_ID,
        }},
    { ANALYSIS_ALBUM_TABLE,
        {
            PhotoAlbumColumns::ALBUM_ID,
            PhotoAlbumColumns::ALBUM_TYPE,
            PhotoAlbumColumns::ALBUM_SUBTYPE,
            PhotoAlbumColumns::ALBUM_NAME,
        }},
    { ANALYSIS_PHOTO_MAP_TABLE,
        {
            PhotoMap::ALBUM_ID,
            PhotoMap::ASSET_ID,
        }},
    { AudioColumn::AUDIOS_TABLE,
        {
            MediaColumn::MEDIA_ID,
            MediaColumn::MEDIA_FILE_PATH,
            MediaColumn::MEDIA_SIZE,
            MediaColumn::MEDIA_TYPE,
            MediaColumn::MEDIA_NAME,
            MediaColumn::MEDIA_DATE_ADDED,
            MediaColumn::MEDIA_DATE_MODIFIED,
        }},
};
const unordered_map<string, unordered_set<string>> NEEDED_COLUMNS_EXCEPTION_MAP = {
    { PhotoAlbumColumns::TABLE,
        {
            PhotoAlbumColumns::ALBUM_BUNDLE_NAME,
        }},
};
const unordered_map<string, unordered_set<string>> EXCLUDED_COLUMNS_MAP = {
    { PhotoColumn::PHOTOS_TABLE,
        {
            PhotoColumn::PHOTO_CLOUD_ID, PhotoColumn::PHOTO_DIRTY,
            PhotoColumn::PHOTO_SYNC_STATUS, PhotoColumn::PHOTO_CLOUD_VERSION, PhotoColumn::PHOTO_POSITION,
            PhotoColumn::PHOTO_THUMB_STATUS, PhotoColumn::PHOTO_CLEAN_FLAG, // cloud related
            PhotoColumn::PHOTO_THUMBNAIL_READY, PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, // thumbnail related
            PhotoColumn::PHOTO_LCD_VISIT_TIME, // lcd related
            PhotoColumn::PHOTO_CE_AVAILABLE, PhotoColumn::PHOTO_CE_STATUS_CODE, // cloud enhancement
            PhotoColumn::PHOTO_THUMBNAIL_VISIBLE,
            PhotoColumn::PHOTO_METADATA_FLAGS, // meta recovery related
        }},
    { PhotoAlbumColumns::TABLE,
        {
            PhotoAlbumColumns::ALBUM_COVER_URI, PhotoAlbumColumns::ALBUM_COUNT, PhotoAlbumColumns::CONTAINS_HIDDEN,
            PhotoAlbumColumns::HIDDEN_COUNT, PhotoAlbumColumns::HIDDEN_COVER, PhotoAlbumColumns::ALBUM_IMAGE_COUNT,
            PhotoAlbumColumns::ALBUM_VIDEO_COUNT, // updated by album udpate
            PhotoAlbumColumns::ALBUM_DIRTY, PhotoAlbumColumns::ALBUM_CLOUD_ID, // cloud related
            PhotoAlbumColumns::ALBUM_ORDER, // created by trigger
        }},
    { ANALYSIS_ALBUM_TABLE,
        {
            PhotoAlbumColumns::ALBUM_COVER_URI,
            PhotoAlbumColumns::ALBUM_COUNT,
        }},
};
const unordered_map<string, unordered_map<string, string>> TABLE_QUERY_WHERE_CLAUSE_MAP = {
    { PhotoColumn::PHOTOS_TABLE,
        {
            { PhotoColumn::PHOTO_POSITION, PhotoColumn::PHOTO_POSITION + " IN (1, 3) "},
            { PhotoColumn::PHOTO_SYNC_STATUS, PhotoColumn::PHOTO_SYNC_STATUS + " = " +
                to_string(static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE)) },
            { PhotoColumn::PHOTO_CLEAN_FLAG, PhotoColumn::PHOTO_CLEAN_FLAG + " = " +
                to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN)) },
            { MediaColumn::MEDIA_TIME_PENDING, MediaColumn::MEDIA_TIME_PENDING + " = 0" },
            { PhotoColumn::PHOTO_IS_TEMP, PhotoColumn::PHOTO_IS_TEMP + " = 0" },
        }},
    { PhotoAlbumColumns::TABLE,
        {
            { PhotoAlbumColumns::ALBUM_NAME, PhotoAlbumColumns::ALBUM_NAME + " IS NOT NULL" },
            { PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumColumns::ALBUM_TYPE + " != " +
                to_string(PhotoAlbumType::SYSTEM)},
        }},
    { ANALYSIS_ALBUM_TABLE,
        {
            { PhotoAlbumColumns::ALBUM_NAME, PhotoAlbumColumns::ALBUM_NAME + " IS NOT NULL" },
            { PhotoAlbumColumns::ALBUM_SUBTYPE, PhotoAlbumColumns::ALBUM_SUBTYPE + " IN (" +
                to_string(PhotoAlbumSubType::SHOOTING_MODE) + ", " +
                to_string(PhotoAlbumSubType::GEOGRAPHY_CITY) + ", " +
                to_string(PhotoAlbumSubType::CLASSIFY) + ")" },
        }},
};
const unordered_map<string, unordered_map<string, string>> TABLE_QUERY_WHERE_CLAUSE_MAP_WITH_CLOUD = {
    { PhotoColumn::PHOTOS_TABLE,
        {
            { PhotoColumn::PHOTO_POSITION, PhotoColumn::PHOTO_POSITION + " IN (1, 2, 3) "},
            { PhotoColumn::PHOTO_SYNC_STATUS, PhotoColumn::PHOTO_SYNC_STATUS + " = " +
                to_string(static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE)) },
            { PhotoColumn::PHOTO_CLEAN_FLAG, PhotoColumn::PHOTO_CLEAN_FLAG + " = " +
                to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN)) },
            { MediaColumn::MEDIA_TIME_PENDING, MediaColumn::MEDIA_TIME_PENDING + " = 0" },
            { PhotoColumn::PHOTO_IS_TEMP, PhotoColumn::PHOTO_IS_TEMP + " = 0" },
        }},
    { PhotoAlbumColumns::TABLE,
        {
            { PhotoAlbumColumns::ALBUM_NAME, PhotoAlbumColumns::ALBUM_NAME + " IS NOT NULL" },
            { PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumColumns::ALBUM_TYPE + " != " +
                to_string(PhotoAlbumType::SYSTEM)},
        }},
    { ANALYSIS_ALBUM_TABLE,
        {
            { PhotoAlbumColumns::ALBUM_NAME, PhotoAlbumColumns::ALBUM_NAME + " IS NOT NULL" },
            { PhotoAlbumColumns::ALBUM_SUBTYPE, PhotoAlbumColumns::ALBUM_SUBTYPE + " IN (" +
                to_string(PhotoAlbumSubType::SHOOTING_MODE) + ", " +
                to_string(PhotoAlbumSubType::GEOGRAPHY_CITY) + ", " +
                to_string(PhotoAlbumSubType::CLASSIFY) + ")" },
        }},
};
const vector<string> CLONE_ALBUMS = { PhotoAlbumColumns::TABLE, ANALYSIS_ALBUM_TABLE };
const unordered_map<string, string> CLONE_ALBUM_MAP = {
    { PhotoAlbumColumns::TABLE, PhotoMap::TABLE },
    { ANALYSIS_ALBUM_TABLE, ANALYSIS_PHOTO_MAP_TABLE },
};
const unordered_map<string, ResultSetDataType> COLUMN_TYPE_MAP = {
    { "INT", ResultSetDataType::TYPE_INT32 },
    { "INTEGER", ResultSetDataType::TYPE_INT32 },
    { "BIGINT", ResultSetDataType::TYPE_INT64 },
    { "DOUBLE", ResultSetDataType::TYPE_DOUBLE },
    { "REAL", ResultSetDataType::TYPE_DOUBLE },
    { "TEXT", ResultSetDataType::TYPE_STRING },
    { "BLOB", ResultSetDataType::TYPE_BLOB },
};
const unordered_map<string, string> ALBUM_URI_PREFIX_MAP = {
    { PhotoAlbumColumns::TABLE, PhotoAlbumColumns::ALBUM_URI_PREFIX },
    { ANALYSIS_ALBUM_TABLE, PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX },
};

template<typename Key, typename Value>
Value GetValueFromMap(const unordered_map<Key, Value> &map, const Key &key, const Value &defaultValue = Value())
{
    auto it = map.find(key);
    CHECK_AND_RETURN_RET(it != map.end(), defaultValue);
    return it->second;
}

CloneRestore::CloneRestore()
{
    sceneCode_ = CLONE_RESTORE_ID;
    ffrt_disable_worker_escape();
    MEDIA_INFO_LOG("Set ffrt_disable_worker_escape");
}

void CloneRestore::StartRestore(const string &backupRestoreDir, const string &upgradePath)
{
    MEDIA_INFO_LOG("Start clone restore");
    SetParameterForClone();
    GetAccountValid();
    GetSyncSwitchOn();
    MEDIA_INFO_LOG("the isAccountValid_ is %{public}d, the isSyncSwitchOn_ is %{public}d", isAccountValid_,
        isSyncSwitchOn_);
#ifdef CLOUD_SYNC_MANAGER
    FileManagement::CloudSync::CloudSyncManager::GetInstance().StopSync("com.ohos.medialibrary.medialibrarydata");
#endif
    backupRestoreDir_ = backupRestoreDir;
    garbagePath_ = backupRestoreDir_ + "/storage/media/local/files";
    int32_t errorCode = Init(backupRestoreDir, upgradePath, true);
    if (errorCode == E_OK) {
        RestoreGallery();
        RestoreMusic();
        UpdateDatabase();
        (void)NativeRdb::RdbHelper::DeleteRdbStore(dbPath_);
    } else {
        SetErrorCode(RestoreError::INIT_FAILED);
        ErrorInfo errorInfo(RestoreError::INIT_FAILED, 0, errorCode);
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
    }
    HandleRestData();
    StopParameterForClone();
    CloseAllKvStore();
    MEDIA_INFO_LOG("End clone restore");
}

void CloneRestore::InitThumbnailStatus()
{
    std::string cloneThumbnailDir = backupRestoreDir_ + RESTORE_FILES_LOCAL_DIR + ".thumbs";
    if (!MediaFileUtils::IsFileExists(cloneThumbnailDir)) {
        MEDIA_WARN_LOG("Uncloned thumbnail dir, no need to clone thumbnail");
        return;
    }
    hasCloneThumbnailDir_ = true;
    isInitKvstoreSuccess_ = InitAllKvStore();
}

int32_t CloneRestore::Init(const string &backupRestoreDir, const string &upgradePath, bool isUpgrade)
{
    dbPath_ = backupRestoreDir_ + MEDIA_DB_PATH;
    filePath_ = backupRestoreDir_ + "/storage/media/local/files";
    if (!MediaFileUtils::IsFileExists(dbPath_)) {
        MEDIA_ERR_LOG("Media db is not exist.");
        return E_FAIL;
    }
    if (isUpgrade && BaseRestore::Init() != E_OK) {
        return E_FAIL;
    }

    auto context = AbilityRuntime::Context::GetApplicationContext();
    CHECK_AND_RETURN_RET_LOG(context != nullptr, E_FAIL, "Failed to get context");
    int32_t err = BackupDatabaseUtils::InitDb(mediaRdb_, MEDIA_DATA_ABILITY_DB_NAME, dbPath_, BUNDLE_NAME, true,
        context->GetArea());
    CHECK_AND_RETURN_RET_LOG(mediaRdb_ != nullptr, E_FAIL, "Init remote medialibrary rdb fail, err = %{public}d", err);

    BackupDatabaseUtils::CheckDbIntegrity(mediaRdb_, sceneCode_, "OLD_MEDIA_LIBRARY");
    InitThumbnailStatus();
    this->photoAlbumClone_.OnStart(this->mediaRdb_, this->mediaLibraryRdb_);
    this->photosClone_.OnStart(this->mediaLibraryRdb_, this->mediaRdb_);
    cloneRestoreGeoDictionary_.Init(this->sceneCode_, this->taskId_, this->mediaLibraryRdb_, this->mediaRdb_);
    MEDIA_INFO_LOG("Init db succ.");
    return E_OK;
}

void CloneRestore::RestorePhoto()
{
    MEDIA_INFO_LOG("Start clone restore: photos");
    CHECK_AND_RETURN_LOG(IsReadyForRestore(PhotoColumn::PHOTOS_TABLE),
        "Column status is not ready for restore photo, quit");
    unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_,
        PhotoColumn::PHOTOS_TABLE);
    unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_,
        PhotoColumn::PHOTOS_TABLE);
    if (!PrepareCommonColumnInfoMap(PhotoColumn::PHOTOS_TABLE, srcColumnInfoMap, dstColumnInfoMap)) {
        MEDIA_ERR_LOG("Prepare common column info failed");
        return;
    }
    // The begining of the restore process
    // Start clone restore
    this->photosClone_.LoadPhotoAlbums();
    // Scenario 1, clone photos from PhotoAlbum, PhotoMap and Photos.
    int totalNumberInPhotoMap = this->photosClone_.GetPhotosRowCountInPhotoMap();
    MEDIA_INFO_LOG("GetPhotosRowCountInPhotoMap, totalNumber = %{public}d", totalNumberInPhotoMap);
    totalNumber_ += static_cast<uint64_t>(totalNumberInPhotoMap);
    MEDIA_INFO_LOG("onProcess Update totalNumber_: %{public}lld", (long long)totalNumber_);
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_THREAD_NUM);
    for (int32_t offset = 0; offset < totalNumberInPhotoMap; offset += CLONE_QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestorePhotoBatch(offset, RELEATED_TO_PHOTO_MAP); }, {&offset}, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
    ProcessPhotosBatchFailedOffsets(RELEATED_TO_PHOTO_MAP);
    needReportFailed_ = false;
    // Scenario 2, clone photos from Photos only.
    int32_t totalNumber = this->photosClone_.GetPhotosRowCountNotInPhotoMap();
    MEDIA_INFO_LOG("QueryTotalNumberNot, totalNumber = %{public}d", totalNumber);
    totalNumber_ += static_cast<uint64_t>(totalNumber);
    MEDIA_INFO_LOG("onProcess Update totalNumber_: %{public}lld", (long long)totalNumber_);
    for (int32_t offset = 0; offset < totalNumber; offset += CLONE_QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestorePhotoBatch(offset); }, { &offset }, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
    ProcessPhotosBatchFailedOffsets();
    this->photosClone_.OnStop(otherTotalNumber_, otherProcessStatus_);
}

void CloneRestore::GetAccountValid()
{
    string oldId = "";
    string newId = "";
    nlohmann::json jsonArr = nlohmann::json::parse(restoreInfo_, nullptr, false);
    CHECK_AND_RETURN_LOG(!jsonArr.is_discarded(), "cloud account parse failed");
    for (const auto& item : jsonArr) {
        bool cond = (!item.contains("type") || !item.contains("detail") || item["type"] != "singleAccountId");
        CHECK_AND_CONTINUE(!cond);
        oldId = item["detail"];
        MEDIA_INFO_LOG("the old is %{public}s", oldId.c_str());
        break;
    }
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> ret =
        OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (ret.first) {
        OHOS::AccountSA::OhosAccountInfo& resultInfo = ret.second;
        newId = resultInfo.uid_;
    } else {
        MEDIA_ERR_LOG("new account logins failed");
        return;
    }
    MEDIA_INFO_LOG("clone the old id is %{public}s, new id is %{public}s",
        BackupFileUtils::GarbleFilePath(oldId, sceneCode_).c_str(),
        BackupFileUtils::GarbleFilePath(newId, sceneCode_).c_str());
    isAccountValid_ = (oldId != "" && oldId == newId);
}

void CloneRestore::AddToPhotosFailedOffsets(int32_t offset)
{
    std::lock_guard<ffrt::mutex> lock(photosFailedMutex_);
    photosFailedOffsets_.push_back(offset);
}

void CloneRestore::ProcessPhotosBatchFailedOffsets(int32_t isRelatedToPhotoMap)
{
    std::lock_guard<ffrt::mutex> lock(photosFailedMutex_);
    size_t vectorLen = photosFailedOffsets_.size();
    needReportFailed_ = true;
    for (size_t offset = 0; offset < vectorLen; offset++) {
        RestorePhotoBatch(photosFailedOffsets_[offset], isRelatedToPhotoMap);
    }
    photosFailedOffsets_.clear();
}

void CloneRestore::ProcessCloudPhotosFailedOffsets(int32_t isRelatedToPhotoMap)
{
    std::lock_guard<ffrt::mutex> lock(photosFailedMutex_);
    size_t vectorLen = photosFailedOffsets_.size();
    needReportFailed_ = true;
    for (size_t offset = 0; offset < vectorLen; offset++) {
        RestoreBatchForCloud(photosFailedOffsets_[offset], isRelatedToPhotoMap);
    }
    photosFailedOffsets_.clear();
}

void CloneRestore::RestorePhotoForCloud()
{
    MEDIA_INFO_LOG("singleClone start clone restore: photos");
    CHECK_AND_RETURN_LOG(IsReadyForRestore(PhotoColumn::PHOTOS_TABLE),
        "singleClone column status is not ready for restore photo, quit");
    unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_,
        PhotoColumn::PHOTOS_TABLE);
    unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_,
        PhotoColumn::PHOTOS_TABLE);
    CHECK_AND_RETURN_LOG(PrepareCommonColumnInfoMap(PhotoColumn::PHOTOS_TABLE, srcColumnInfoMap, dstColumnInfoMap),
        "singleClone Prepare common column info failed");

    this->photosClone_.LoadPhotoAlbums();
    int totalNumberInPhotoMap = this->photosClone_.GetCloudPhotosRowCountInPhotoMap();
    MEDIA_INFO_LOG("singleClone getPhotosRowCountInPhotoMap, totalNumber = %{public}d", totalNumberInPhotoMap);
    totalNumber_ += static_cast<uint64_t>(totalNumberInPhotoMap);
    MEDIA_INFO_LOG("singleClone onProcess Update totalNumber_: %{public}lld", (long long)totalNumber_);
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_THREAD_NUM);
    for (int32_t offset = 0; offset < totalNumberInPhotoMap; offset += CLONE_QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestoreBatchForCloud(offset, RELEATED_TO_PHOTO_MAP); }, {&offset}, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
    ProcessCloudPhotosFailedOffsets(RELEATED_TO_PHOTO_MAP);
    needReportFailed_ = false;
    int32_t totalNumber = this->photosClone_.GetCloudPhotosRowCountNotInPhotoMap();
    MEDIA_INFO_LOG("singleClone queryTotalNumberNot, totalNumber = %{public}d", totalNumber);
    totalNumber_ += static_cast<uint64_t>(totalNumber);
    MEDIA_INFO_LOG("singleClone onProcess Update totalNumber_: %{public}lld", (long long)totalNumber_);
    for (int32_t offset = 0; offset < totalNumber; offset += CLONE_QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestoreBatchForCloud(offset); }, { &offset }, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
    ProcessCloudPhotosFailedOffsets();
    this->photosClone_.OnStop(otherTotalNumber_, otherProcessStatus_);

    BackupDatabaseUtils::UpdateFaceAnalysisTblStatus(mediaLibraryRdb_);
    BackupDatabaseUtils::UpdateAnalysisPhotoMapStatus(mediaLibraryRdb_);
    ReportPortraitCloneStat(sceneCode_);
}

void CloneRestore::RestoreAlbum()
{
    MEDIA_INFO_LOG("Start clone restore: albums");
    maxSearchId_ = BackupDatabaseUtils::QueryMaxId(mediaLibraryRdb_,
        ANALYSIS_SEARCH_INDEX_TABLE, SEARCH_IDX_COL_ID);
    maxAnalysisAlbumId_ = BackupDatabaseUtils::QueryMaxId(mediaLibraryRdb_,
        ANALYSIS_ALBUM_TABLE, ANALYSIS_COL_ALBUM_ID);
    maxBeautyFileId_ = BackupDatabaseUtils::QueryMaxId(mediaLibraryRdb_,
        ANALYSIS_BEAUTY_SCORE_TABLE, BEAUTY_SCORE_COL_FILE_ID);

    for (const auto &tableName : CLONE_ALBUMS) {
        if (!IsReadyForRestore(tableName)) {
            MEDIA_ERR_LOG("Column status of %{public}s is not ready for restore album, quit",
                BackupDatabaseUtils::GarbleInfoName(tableName).c_str());
            continue;
        }
        unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_, tableName);
        unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_,
            tableName);
        if (!PrepareCommonColumnInfoMap(tableName, srcColumnInfoMap, dstColumnInfoMap)) {
            MEDIA_ERR_LOG("Prepare common column info failed");
            continue;
        }
        GetAlbumExtraQueryWhereClause(tableName);
        int32_t totalNumber = QueryTotalNumber(tableName);
        MEDIA_INFO_LOG(
            "QueryAlbumTotalNumber, tableName=%{public}s, totalNumber=%{public}d", tableName.c_str(), totalNumber);
        for (int32_t offset = 0; offset < totalNumber; offset += CLONE_QUERY_COUNT) {
            vector<AlbumInfo> albumInfos = QueryAlbumInfos(tableName, offset);
            this->photoAlbumClone_.TRACE_LOG(tableName, albumInfos);
            InsertAlbum(albumInfos, tableName);
        }
        UpdateSystemAlbumColumns(tableName);
    }

    RestoreFromGalleryPortraitAlbum();
    RestorePortraitClusteringInfo();
    cloneRestoreGeoDictionary_.RestoreAlbums();
}

int32_t CloneRestore::GetHighlightCloudMediaCnt()
{
    const std::string QUERY_SQL = "SELECT COUNT(1) AS count FROM AnalysisAlbum AS a "
        "INNER JOIN AnalysisPhotoMap AS m ON a.album_id = m.map_album "
        "INNER JOIN Photos AS p ON p.file_id = m.map_asset "
        "WHERE a.album_subtype IN (4104, 4105) AND p.position = 2";
    std::shared_ptr<NativeRdb::ResultSet> resultSet = BackupDatabaseUtils::QuerySql(this->mediaRdb_, QUERY_SQL, {});
    bool cond = (resultSet == nullptr);
    CHECK_AND_RETURN_RET_LOG(!cond, -1, "query count of highlight cloud media failed.");
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return -1;
    }
    int32_t cnt = GetInt32Val("count", resultSet);
    MEDIA_INFO_LOG("GetHighlightCloudMediaCnt is %{public}d", cnt);
    resultSet->Close();
    return cnt;
}

void CloneRestore::RestoreHighlightAlbums()
{
    int32_t highlightCloudMediaCnt = GetHighlightCloudMediaCnt();
    UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_)
        .Report("CLONE_RESTORE_HIGHLIGHT_CHECK", "",
            "highlightCloudMediaCnt: " + std::to_string(highlightCloudMediaCnt) +
            ", isCloudRestoreSatisfied: " + std::to_string(IsCloudRestoreSatisfied()));
    CHECK_AND_RETURN(highlightCloudMediaCnt == 0 || IsCloudRestoreSatisfied());

    CloneRestoreHighlight cloneRestoreHighlight;
    CloneRestoreHighlight::InitInfo initInfo = { sceneCode_, taskId_, mediaLibraryRdb_, mediaRdb_, backupRestoreDir_,
        photoInfoMap_ };
    cloneRestoreHighlight.Init(initInfo);
    cloneRestoreHighlight.Restore();

    CloneRestoreCVAnalysis cloneRestoreCVAnalysis;
    cloneRestoreCVAnalysis.Init(sceneCode_, taskId_, mediaLibraryRdb_, mediaRdb_, backupRestoreDir_);
    cloneRestoreCVAnalysis.RestoreAlbums(cloneRestoreHighlight);

    cloneRestoreHighlight.ReportCloneRestoreHighlightTask();
}

void CloneRestore::MoveMigrateFile(std::vector<FileInfo> &fileInfos, int64_t &fileMoveCount,
    int64_t &videoFileMoveCount)
{
    vector<std::string> moveFailedData;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        bool cond = (!MediaFileUtils::IsFileExists(fileInfos[i].filePath) ||
            fileInfos[i].cloudPath.empty() || !fileInfos[i].needMove);
        CHECK_AND_CONTINUE(!cond);
        int32_t errCode = MoveAsset(fileInfos[i]);
        if (errCode != E_OK) {
            fileInfos[i].needUpdate = false;
            fileInfos[i].needVisible = false;
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{public}s, error:%{public}s",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, CLONE_RESTORE_ID, garbagePath_).c_str(),
                strerror(errno));
            UpdateFailedFiles(fileInfos[i].fileType, fileInfos[i], RestoreError::MOVE_FAILED);
            ErrorInfo errorInfo(RestoreError::MOVE_FAILED, 1, std::to_string(errCode),
                BackupLogUtils::FileInfoToString(sceneCode_, fileInfos[i]));
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
            moveFailedData.push_back(fileInfos[i].cloudPath);
            continue;
        }
        fileMoveCount++;
        videoFileMoveCount += fileInfos[i].fileType == MediaType::MEDIA_TYPE_VIDEO;
    }
    DeleteMoveFailedData(moveFailedData);
    SetVisiblePhoto(fileInfos);
    migrateFileNumber_ += fileMoveCount;
    migrateVideoFileNumber_ += videoFileMoveCount;
}

static void UpdateThumbnailStatusToFailed(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, std::string id,
    bool isThumbnailStatusNeedUpdate, bool isLcdStatusNeedUpdate)
{
    bool cond = (rdbStore == nullptr || id.empty());
    CHECK_AND_RETURN_LOG(!cond, "singleClone rdb is nullptr or id is empty");

    NativeRdb::ValuesBucket values;
    int changedRows;
    if (isThumbnailStatusNeedUpdate) {
        values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, RESTORE_THUMBNAIL_READY_NO_THUMBNAIL);
        values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, RESTORE_THUMBNAIL_VISIBLE_FALSE);
    }
    if (isLcdStatusNeedUpdate) {
        values.PutInt(PhotoColumn::PHOTO_LCD_VISIT_TIME, RESTORE_LCD_VISIT_TIME_NO_LCD);
    }
    int32_t err = rdbStore->Update(changedRows, PhotoColumn::PHOTOS_TABLE,
        values, MEDIA_DATA_DB_ID + " = ?", vector<string> { id });
    CHECK_AND_PRINT_LOG(err == NativeRdb::E_OK, "singleClone rdbStore Update failed! %{public}d", err);
}

void CloneRestore::GetCloudPhotoFileExistFlag(const FileInfo &fileInfo, CloudPhotoFileExistFlag &resultExistFlag)
{
    std::string dirPath = GetThumbnailLocalPath(fileInfo.cloudPath);
    CHECK_AND_RETURN_LOG(MediaFileUtils::IsFileExists(dirPath),
        "GetCloudPhotoFileExistFlag %{public}s not exist!", fileInfo.cloudPath.c_str());
    
    std::string lcdPath = dirPath + "/LCD.jpg";
    resultExistFlag.isLcdExist = MediaFileUtils::IsFileExists(lcdPath) ? true : false;
    std::string thmPath = dirPath + "/THM.jpg";
    resultExistFlag.isThmExist = MediaFileUtils::IsFileExists(thmPath) ? true : false;
    std::string astcPath = dirPath + "/THM_ASTC.astc";
    resultExistFlag.isDayAstcExist = MediaFileUtils::IsFileExists(astcPath) ? true : false;

    if (fileInfo.orientation != 0) {
        std::string exLcdPath = dirPath + "/THM_EX/LCD.jpg";
        resultExistFlag.isExLcdExist = MediaFileUtils::IsFileExists(exLcdPath) ? true : false;
        std::string exThmPath = dirPath + "/THM_EX/THM.jpg";
        resultExistFlag.isExThmExist = MediaFileUtils::IsFileExists(exThmPath) ? true : false;
    }
    MEDIA_DEBUG_LOG("%{public}s, isexist lcd:%{public}d, thm:%{public}d, astc:%{public}d,"
        "yearastc:%{public}d, exlcd:%{public}d, exthm:%{public}d",
        dirPath.c_str(), resultExistFlag.isLcdExist, resultExistFlag.isThmExist,
        resultExistFlag.isDayAstcExist, resultExistFlag.isYearAstcExist,
        resultExistFlag.isExLcdExist, resultExistFlag.isExThmExist);
}

void CloneRestore::CloudPhotoFilesVerify(const std::vector<FileInfo> &fileInfos, std::vector<FileInfo> &LCDNotFound,
    std::vector<FileInfo> &THMNotFound, unordered_map<string, CloudPhotoFileExistFlag> &resultExistMap)
{
    for (size_t i = 0; i < fileInfos.size(); i++) {
        CloudPhotoFileExistFlag fileExistFlag;
        unordered_map<string, CloudPhotoFileExistFlag>::iterator iter = resultExistMap.find(fileInfos[i].cloudPath);
        CHECK_AND_EXECUTE(iter == resultExistMap.end(), fileExistFlag = iter->second);
        GetCloudPhotoFileExistFlag(fileInfos[i], fileExistFlag);
        resultExistMap[fileInfos[i].cloudPath] = fileExistFlag;
        if (fileInfos[i].orientation != 0) {
            CHECK_AND_EXECUTE(fileExistFlag.isExLcdExist, LCDNotFound.push_back(fileInfos[i]));
            CHECK_AND_EXECUTE(fileExistFlag.isExThmExist, THMNotFound.push_back(fileInfos[i]));
        } else {
            CHECK_AND_EXECUTE(fileExistFlag.isLcdExist, LCDNotFound.push_back(fileInfos[i]));
            CHECK_AND_EXECUTE(fileExistFlag.isThmExist, THMNotFound.push_back(fileInfos[i]));
        }
    }
}

void CloneRestore::MoveMigrateCloudFile(std::vector<FileInfo> &fileInfos, int32_t &fileMoveCount,
    int32_t &videoFileMoveCount, int32_t sceneCode)
{
    MEDIA_INFO_LOG("singleClone MoveMigrateCloudFile start");
    unordered_map<string, CloudPhotoFileExistFlag> resultExistMap;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        CHECK_AND_CONTINUE(fileInfos[i].needMove);
        MoveCloudThumbnailDir(fileInfos[i]);
        CHECK_AND_CONTINUE_ERR_LOG(isInitKvstoreSuccess_,
            "singleClone isInitKvstoreSuccess_ false, id:%{public}d, path:%{public}s",
            fileInfos[i].fileIdNew, MediaFileUtils::DesensitizePath(fileInfos[i].cloudPath).c_str());

        CHECK_AND_CONTINUE_ERR_LOG(fileInfos[i].thumbnailReady >= RESTORE_THUMBNAIL_READY_SUCCESS,
            "singleClone Astc does not exist, id:%{public}d, path:%{public}s",
                fileInfos[i].fileIdNew, MediaFileUtils::DesensitizePath(fileInfos[i].cloudPath).c_str());
        if (MoveAstc(fileInfos[i]) != E_OK) {
            UpdateThumbnailStatusToFailed(mediaLibraryRdb_, to_string(fileInfos[i].fileIdNew), true, false);
            MEDIA_ERR_LOG("Move astc failed, id:%{public}d, path:%{public}s",
                fileInfos[i].fileIdNew, MediaFileUtils::DesensitizePath(fileInfos[i].cloudPath).c_str());
        }
        CloudPhotoFileExistFlag tmpFlag;
        tmpFlag.isYearAstcExist = true;
        resultExistMap[fileInfos[i].cloudPath] = tmpFlag;
        videoFileMoveCount += fileInfos[i].fileType == MediaType::MEDIA_TYPE_VIDEO;
    }
    std::vector<FileInfo> LCDNotFound;
    std::vector<FileInfo> THMNotFound;
    CloudPhotoFilesVerify(fileInfos, LCDNotFound, THMNotFound, resultExistMap);
    MEDIA_INFO_LOG("singleClone LCDNotFound:%{public}zu, THMNotFound:%{public}zu",
        LCDNotFound.size(), THMNotFound.size());
    std::vector<std::string> dentryFailedLCD;
    std::vector<std::string> dentryFailedThumb;
    CHECK_AND_EXECUTE(BatchCreateDentryFile(LCDNotFound, dentryFailedLCD, DENTRY_INFO_LCD) != E_OK,
        HandleFailData(fileInfos, dentryFailedLCD, DENTRY_INFO_LCD));
    CHECK_AND_EXECUTE(BatchCreateDentryFile(THMNotFound, dentryFailedThumb, DENTRY_INFO_THM) != E_OK,
        HandleFailData(fileInfos, dentryFailedThumb, DENTRY_INFO_THM));

    BatchUpdateFileInfoData(fileInfos, resultExistMap);
    fileMoveCount = SetVisiblePhoto(fileInfos);
    successCloudMetaNumber_ += fileMoveCount;
    migrateFileNumber_ += fileMoveCount;
    migrateVideoFileNumber_ += videoFileMoveCount;
    MEDIA_INFO_LOG("singleClone MoveMigrateCloudFile end");
}

int CloneRestore::InsertPhoto(vector<FileInfo> &fileInfos)
{
    CHECK_AND_RETURN_RET_LOG(mediaLibraryRdb_ != nullptr, E_OK, "mediaLibraryRdb_ is null");
    CHECK_AND_RETURN_RET_LOG(!fileInfos.empty(), E_OK, "fileInfos are empty");
    int64_t startGenerate = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(CLONE_RESTORE_ID, fileInfos, SourceType::PHOTOS);
    int64_t startInsertPhoto = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t photoRowNum = 0;
    int32_t errCode = BatchInsertWithRetry(PhotoColumn::PHOTOS_TABLE, values, photoRowNum);
    if (errCode != E_OK) {
        if (needReportFailed_) {
            UpdateFailedFiles(fileInfos, RestoreError::INSERT_FAILED);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, static_cast<int32_t>(fileInfos.size()), errCode);
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        }
        return errCode;
    }
    migrateDatabaseNumber_ += photoRowNum;

    int64_t startInsertRelated = MediaFileUtils::UTCTimeMilliSeconds();
    InsertPhotoRelated(fileInfos, SourceType::PHOTOS);

    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t fileMoveCount = 0;
    int64_t videoFileMoveCount = 0;
    MoveMigrateFile(fileInfos, fileMoveCount, videoFileMoveCount);
    int64_t startUpdate = MediaFileUtils::UTCTimeMilliSeconds();
    UpdatePhotosByFileInfoMap(mediaLibraryRdb_, fileInfos);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("generate cost %{public}ld, insert %{public}ld assets cost %{public}ld, insert photo related cost "
        "%{public}ld, and move %{public}ld files (%{public}ld + %{public}ld) cost %{public}ld. update cost %{public}ld",
        (long)(startInsertPhoto - startGenerate), (long)photoRowNum, (long)(startInsertRelated - startInsertPhoto),
        (long)(startMove - startInsertRelated), (long)fileMoveCount, (long)(fileMoveCount - videoFileMoveCount),
        (long)videoFileMoveCount, (long)(startUpdate - startMove), (long)(end - startUpdate));
    return E_OK;
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(int32_t sceneCode, vector<FileInfo> &fileInfos,
    int32_t sourceType)
{
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        int32_t errCode = BackupFileUtils::IsFileValid(fileInfos[i].filePath, CLONE_RESTORE_ID);
        if (errCode != E_OK) {
            ErrorInfo errorInfo(RestoreError::FILE_INVALID, 1, std::to_string(errCode),
                BackupLogUtils::FileInfoToString(sceneCode, fileInfos[i]));
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
            continue;
        }
        CHECK_AND_CONTINUE(PrepareCloudPath(PhotoColumn::PHOTOS_TABLE, fileInfos[i]));
        if (fileInfos[i].isNew) {
            NativeRdb::ValuesBucket value = GetInsertValue(fileInfos[i], fileInfos[i].cloudPath, sourceType);
            values.emplace_back(value);
        }
    }
    return values;
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetCloudInsertValues(int32_t sceneCode, vector<FileInfo> &fileInfos,
    int32_t sourceType)
{
    MEDIA_INFO_LOG("singleClone GetCloudInsertValues: %{public}zu", fileInfos.size());
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        CHECK_AND_CONTINUE(PrepareCloudPath(PhotoColumn::PHOTOS_TABLE, fileInfos[i]));
        NativeRdb::ValuesBucket value = GetCloudInsertValue(fileInfos[i], fileInfos[i].cloudPath, sourceType);
        fileInfos[i].isNew = true;
        values.emplace_back(value);
    }
    return values;
}

void CloneRestore::HandleRestData(void)
{
    MEDIA_INFO_LOG("Start to handle rest data in native.");
}

vector<FileInfo> CloneRestore::QueryFileInfos(int32_t offset, int32_t isRelatedToPhotoMap)
{
    vector<FileInfo> result;
    result.reserve(CLONE_QUERY_COUNT);
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    if (isRelatedToPhotoMap == 1) {
        resultSet = this->photosClone_.GetPhotosInPhotoMap(offset, CLONE_QUERY_COUNT);
    } else {
        resultSet = this->photosClone_.GetPhotosNotInPhotoMap(offset, CLONE_QUERY_COUNT);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        fileInfo.isRelatedToPhotoMap = isRelatedToPhotoMap;
        CHECK_AND_EXECUTE(!ParseResultSet(resultSet, fileInfo), result.emplace_back(fileInfo));
    }
    return result;
}

vector<FileInfo> CloneRestore::QueryCloudFileInfos(int32_t offset, int32_t isRelatedToPhotoMap)
{
    MEDIA_INFO_LOG("singleClone QueryCloudFileInfos");
    vector<FileInfo> result;
    result.reserve(CLONE_QUERY_COUNT);
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    if (isRelatedToPhotoMap == 1) {
        resultSet = this->photosClone_.GetCloudPhotosInPhotoMap(offset, CLONE_QUERY_COUNT);
    } else {
        resultSet = this->photosClone_.GetCloudPhotosNotInPhotoMap(offset, CLONE_QUERY_COUNT);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "singleClone Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        fileInfo.isRelatedToPhotoMap = isRelatedToPhotoMap;
        CHECK_AND_EXECUTE(!ParseResultSet(resultSet, fileInfo), result.emplace_back(fileInfo));
    }
    return result;
}

bool CloneRestore::ParseResultSet(const shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &fileInfo,
    string dbName)
{
    return ParseResultSet(PhotoColumn::PHOTOS_TABLE, resultSet, fileInfo);
}

int32_t CloneRestore::QueryTotalNumber(const string &tableName)
{
    CHECK_AND_RETURN_RET(tableName != PhotoAlbumColumns::TABLE,
        this->photoAlbumClone_.GetPhotoAlbumCountInOriginalDb());
    CHECK_AND_RETURN_RET(tableName != PhotoColumn::PHOTOS_TABLE,
        this->photosClone_.GetPhotosRowCountNotInPhotoMap());
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName;
    string whereClause = GetQueryWhereClauseByTable(tableName);
    querySql += whereClause.empty() ? "" : " WHERE " + whereClause;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    if (resultSet == nullptr) {
        return 0;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return 0;
    }
    int32_t result = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    resultSet->Close();
    return result;
}

vector<AlbumInfo> CloneRestore::QueryAlbumInfos(const string &tableName, int32_t offset)
{
    vector<AlbumInfo> result;
    result.reserve(CLONE_QUERY_COUNT);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    if (tableName == PhotoAlbumColumns::TABLE) {
        resultSet = this->photoAlbumClone_.GetPhotoAlbumInOriginalDb(offset, CLONE_QUERY_COUNT);
    } else {
        string querySql = "SELECT * FROM " + tableName;
        string whereClause = GetQueryWhereClauseByTable(tableName);
        querySql += whereClause.empty() ? "" : " WHERE " + whereClause;
        querySql += " LIMIT " + to_string(offset) + ", " + to_string(CLONE_QUERY_COUNT);
        resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    }
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AlbumInfo albumInfo;
        if (ParseAlbumResultSet(tableName, resultSet, albumInfo)) {
            result.emplace_back(albumInfo);
        }
    }
    resultSet->Close();
    return result;
}

bool CloneRestore::ParseAlbumResultSet(const string &tableName, const shared_ptr<NativeRdb::ResultSet> &resultSet,
    AlbumInfo &albumInfo)
{
    albumInfo.albumIdOld = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    albumInfo.albumName = GetStringVal(PhotoAlbumColumns::ALBUM_NAME, resultSet);
    albumInfo.albumType = static_cast<PhotoAlbumType>(GetInt32Val(PhotoAlbumColumns::ALBUM_TYPE, resultSet));
    albumInfo.albumSubType = static_cast<PhotoAlbumSubType>(GetInt32Val(PhotoAlbumColumns::ALBUM_SUBTYPE, resultSet));
    albumInfo.lPath = GetStringVal(PhotoAlbumColumns::ALBUM_LPATH, resultSet);
    albumInfo.albumBundleName = GetStringVal(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, resultSet);
    albumInfo.dateModified = GetInt64Val(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, resultSet);

    auto commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, tableName);
    for (auto it = commonColumnInfoMap.begin(); it != commonColumnInfoMap.end(); ++it) {
        string columnName = it->first;
        string columnType = it->second;
        GetValFromResultSet(resultSet, albumInfo.valMap, columnName, columnType);
    }
    return true;
}

void CloneRestore::AnalyzeSource()
{
    MEDIA_INFO_LOG("analyze source later");
}

int32_t CloneRestore::MovePicture(FileInfo &fileInfo)
{
    bool deleteOriginalFile = fileInfo.isRelatedToPhotoMap == 1 ? false : true;
    string localPath = BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::LOCAL,
        fileInfo.cloudPath);
    int32_t opRet = E_FAIL;
    if (deleteOriginalFile) {
        opRet = this->MoveFile(fileInfo.filePath, localPath);
    } else {
        opRet = this->CopyFile(fileInfo.filePath, localPath);
    }
    CHECK_AND_RETURN_RET_LOG(opRet == E_OK, E_FAIL,
        "Move photo file failed, filePath = %{public}s, deleteOriginalFile = %{public}d",
        BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str(),
        deleteOriginalFile);
    return E_OK;
}

int32_t CloneRestore::MoveMovingPhotoVideo(FileInfo &fileInfo)
{
    CHECK_AND_RETURN_RET(fileInfo.subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO), E_OK);
    bool deleteOriginalFile = fileInfo.isRelatedToPhotoMap == 1 ? false : true;
    std::string localPath = BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::LOCAL,
        fileInfo.cloudPath);
    std::string srcLocalVideoPath = MediaFileUtils::GetMovingPhotoVideoPath(fileInfo.filePath);
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsFileExists(srcLocalVideoPath), E_OK,
        "video of moving photo does not exist: %{private}s", srcLocalVideoPath.c_str());
    std::string localVideoPath = MediaFileUtils::GetMovingPhotoVideoPath(localPath);
    int32_t opVideoRet = E_FAIL;
    if (deleteOriginalFile) {
        opVideoRet = this->MoveFile(srcLocalVideoPath, localVideoPath);
    } else {
        opVideoRet = this->CopyFile(srcLocalVideoPath, localVideoPath);
    }
    CHECK_AND_RETURN_RET_LOG(opVideoRet == E_OK, E_FAIL, "Move video of moving photo failed");
    BackupFileUtils::ModifyFile(localVideoPath, fileInfo.dateModified / MSEC_TO_SEC);
    return E_OK;
}

int32_t CloneRestore::MoveEditedData(FileInfo &fileInfo)
{
    bool deleteOriginalFile = fileInfo.isRelatedToPhotoMap == 1 ? false : true;
    string localPath =
        BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::LOCAL, fileInfo.cloudPath);
    string srcEditDataPath = this->backupRestoreDir_ +
        BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL_EDIT_DATA, fileInfo.relativePath);
    string dstEditDataPath = BackupFileUtils::GetReplacedPathByPrefixType(
        PrefixType::CLOUD, PrefixType::LOCAL_EDIT_DATA, fileInfo.cloudPath);
    bool cond = (this->IsFilePathExist(srcEditDataPath) &&
        this->MoveDirectory(srcEditDataPath, dstEditDataPath, deleteOriginalFile) != E_OK);
    CHECK_AND_RETURN_RET_LOG(!cond, E_FAIL, "Move editData file failed");
    return E_OK;
}

std::string CloneRestore::GetThumbnailLocalPath(const string path)
{
    size_t cloudDirLength = RESTORE_FILES_CLOUD_DIR.length();
    if (path.length() <= cloudDirLength || path.substr(0, cloudDirLength).compare(RESTORE_FILES_CLOUD_DIR) != 0) {
        return "";
    }

    std::string suffixStr = path.substr(cloudDirLength);
    return RESTORE_FILES_LOCAL_DIR + ".thumbs/" + suffixStr;
}

int32_t CloneRestore::MoveAstc(FileInfo &fileInfo)
{
    bool cond = (oldMonthKvStorePtr_ == nullptr || oldYearKvStorePtr_ == nullptr ||
        newMonthKvStorePtr_ == nullptr || newYearKvStorePtr_ == nullptr);
    CHECK_AND_RETURN_RET_LOG(!cond, E_FAIL, "Kvstore is nullptr");
    if (fileInfo.fileIdOld <= 0 || fileInfo.fileIdNew <= 0) {
        MEDIA_ERR_LOG("Old fileId:%{public}d or new fileId:%{public}d is invalid",
            fileInfo.fileIdOld, fileInfo.fileIdNew);
        return E_FAIL;
    }

    string oldKey;
    string newKey;
    if (!MediaFileUtils::GenerateKvStoreKey(to_string(fileInfo.fileIdOld), fileInfo.oldAstcDateKey, oldKey) ||
        !MediaFileUtils::GenerateKvStoreKey(to_string(fileInfo.fileIdNew), fileInfo.newAstcDateKey, newKey)) {
        return E_FAIL;
    }

    std::vector<uint8_t> monthValue;
    std::vector<uint8_t> yearValue;
    if (oldMonthKvStorePtr_->Query(oldKey, monthValue) != E_OK ||
        newMonthKvStorePtr_->Insert(newKey, monthValue) != E_OK) {
        MEDIA_ERR_LOG("MonthValue move failed, fileID %{public}s", newKey.c_str());
        return E_FAIL;
    }
    if (oldYearKvStorePtr_->Query(oldKey, yearValue) != E_OK ||
        newYearKvStorePtr_->Insert(newKey, yearValue) != E_OK) {
        MEDIA_ERR_LOG("YearValue move failed, fileID %{public}s", newKey.c_str());
        return E_FAIL;
    }
    if (fileInfo.isRelatedToPhotoMap != 1) {
        oldMonthKvStorePtr_->Delete(oldKey);
        oldYearKvStorePtr_->Delete(oldKey);
    }
    return E_OK;
}

int32_t CloneRestore::MoveThumbnailDir(FileInfo &fileInfo)
{
    string thumbnailOldDir = backupRestoreDir_ + RESTORE_FILES_LOCAL_DIR + ".thumbs" + fileInfo.relativePath;
    string thumbnailNewDir = GetThumbnailLocalPath(fileInfo.cloudPath);
    if (fileInfo.relativePath.empty() || thumbnailNewDir.empty()) {
        MEDIA_ERR_LOG("Old path:%{public}s or new path:%{public}s is invalid",
            fileInfo.relativePath.c_str(), MediaFileUtils::DesensitizePath(fileInfo.cloudPath).c_str());
        return E_FAIL;
    }
    if (!MediaFileUtils::IsDirectory(thumbnailOldDir)) {
        MEDIA_ERR_LOG("Old dir is not a direcrory or does not exist, errno:%{public}d, dir:%{public}s",
            errno, MediaFileUtils::DesensitizePath(thumbnailOldDir).c_str());
        return E_FAIL;
    }
    CHECK_AND_RETURN_RET_LOG(BackupFileUtils::PreparePath(thumbnailNewDir) == E_OK, E_FAIL,
        "Prepare thumbnail dir path failed");
    bool cond = (MediaFileUtils::IsFileExists(thumbnailNewDir) && !MediaFileUtils::DeleteDir(thumbnailNewDir));
    CHECK_AND_RETURN_RET_LOG(!cond, E_FAIL, "Delete thumbnail new dir failed, errno:%{public}d", errno);

    int32_t opRet = E_FAIL;
    if (fileInfo.isRelatedToPhotoMap != 1) {
        opRet = MediaFileUtils::ModifyAsset(thumbnailOldDir, thumbnailNewDir);
    } else {
        opRet = MediaFileUtils::CopyDirectory(thumbnailOldDir, thumbnailNewDir);
    }
    if (opRet != E_OK) {
        CHECK_AND_RETURN_RET(MediaFileUtils::IsFileExists(thumbnailNewDir), opRet);
        MEDIA_WARN_LOG("MoveThumbnailDir failed but thumbnailNewDir exists");
        CHECK_AND_PRINT_LOG(MediaFileUtils::DeleteDir(thumbnailNewDir),
            "Delete existential thumbnailNewDir failed, errno:%{public}d", errno);
        return opRet;
    }
    return E_OK;
}

int32_t CloneRestore::MoveCloudThumbnailDir(FileInfo &fileInfo)
{
    string thumbnailOldDir = backupRestoreDir_ + RESTORE_FILES_LOCAL_DIR + ".thumbs" + fileInfo.relativePath;
    string thumbnailNewDir = GetThumbnailLocalPath(fileInfo.cloudPath);
    bool cond = (fileInfo.relativePath.empty() || thumbnailNewDir.empty());
    CHECK_AND_RETURN_RET_LOG(!cond, E_FAIL, "singleCloud Old path:%{public}s or new path:%{public}s is invalid",
        fileInfo.relativePath.c_str(), MediaFileUtils::DesensitizePath(fileInfo.cloudPath).c_str());

    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsDirectory(thumbnailOldDir), E_FAIL,
        "singleCloud Old dir is not a direcrory or does not exist, errno:%{public}d, dir:%{public}s",
        errno, MediaFileUtils::DesensitizePath(thumbnailOldDir).c_str());

    CHECK_AND_RETURN_RET_LOG(BackupFileUtils::PreparePath(thumbnailNewDir) == E_OK, E_FAIL,
        "singleCloud Prepare thumbnail dir path failed");
    cond = (MediaFileUtils::IsFileExists(thumbnailNewDir) && !MediaFileUtils::DeleteDir(thumbnailNewDir));
    CHECK_AND_RETURN_RET_LOG(!cond, E_FAIL, "singleCloud Delete thumbnail new dir failed, errno:%{public}d", errno);

    int32_t opRet = E_FAIL;
    if (fileInfo.isRelatedToPhotoMap != 1) {
        opRet = MediaFileUtils::ModifyAsset(thumbnailOldDir, thumbnailNewDir);
    } else {
        opRet = MediaFileUtils::CopyDirectory(thumbnailOldDir, thumbnailNewDir);
    }
    if (opRet != E_OK) {
        CHECK_AND_RETURN_RET(MediaFileUtils::IsFileExists(thumbnailNewDir), opRet);
        MEDIA_WARN_LOG("singleCloud MoveThumbnailDir failed but thumbnailNewDir exists");
        return opRet;
    }
    return E_OK;
}

/**
 * The processing logic of the MoveThumbnail function must match the logic of the GetThumbnailInsertValue function.
 * If the status indicates that the thumbnail does not exist, the thumbnail does not need to be cloned and
 * the status of the thumbnail needs to be set to the initial status in the GetThumbnailInsertValue function.
 * If the status indicates that the thumbnail exists but the thumbnail fails to be transferred,
 * the thumbnail status needs to be set to the initial status.
*/
int32_t CloneRestore::MoveThumbnail(FileInfo &fileInfo)
{
    CHECK_AND_RETURN_RET(hasCloneThumbnailDir_, E_NO_SUCH_FILE);
    if (fileInfo.thumbnailReady < RESTORE_THUMBNAIL_READY_SUCCESS &&
        fileInfo.lcdVisitTime < RESTORE_LCD_VISIT_TIME_SUCCESS) {
        MEDIA_INFO_LOG("Thumbnail dose not exist, id:%{public}d, path:%{public}s",
            fileInfo.fileIdNew, MediaFileUtils::DesensitizePath(fileInfo.cloudPath).c_str());
        return E_NO_SUCH_FILE;
    }
    if (MoveThumbnailDir(fileInfo) != E_OK) {
        UpdateThumbnailStatusToFailed(mediaLibraryRdb_, to_string(fileInfo.fileIdNew), true, true);
        MEDIA_ERR_LOG("Move thumbnail failed, id:%{public}d, path:%{public}s",
            fileInfo.fileIdNew, MediaFileUtils::DesensitizePath(fileInfo.cloudPath).c_str());
        return E_FAIL;
    }

    CHECK_AND_RETURN_RET(isInitKvstoreSuccess_, E_NO_SUCH_FILE);
    CHECK_AND_RETURN_RET_LOG(fileInfo.thumbnailReady >= RESTORE_THUMBNAIL_READY_SUCCESS, E_NO_SUCH_FILE,
        "Astc does not exist, id:%{public}d, path:%{public}s",
        fileInfo.fileIdNew, MediaFileUtils::DesensitizePath(fileInfo.cloudPath).c_str());
    if (MoveAstc(fileInfo) != E_OK) {
        UpdateThumbnailStatusToFailed(mediaLibraryRdb_, to_string(fileInfo.fileIdNew), true, false);
        MEDIA_ERR_LOG("Move astc failed, id:%{public}d, path:%{public}s",
            fileInfo.fileIdNew, MediaFileUtils::DesensitizePath(fileInfo.cloudPath).c_str());
        return E_FAIL;
    }

    return E_OK;
}

int32_t CloneRestore::MoveAsset(FileInfo &fileInfo)
{
    // Picture files.
    int32_t optRet = this->MovePicture(fileInfo);
    CHECK_AND_RETURN_RET(optRet == E_OK, E_FAIL);
    // Video files of moving photo.
    optRet = this->MoveMovingPhotoVideo(fileInfo);
    CHECK_AND_RETURN_RET(optRet == E_OK, E_FAIL);
    // Edit Data.
    optRet = this->MoveEditedData(fileInfo);
    CHECK_AND_RETURN_RET(optRet == E_OK, E_FAIL);
    // Thumbnail of photos.
    this->MoveThumbnail(fileInfo);

    MediaLibraryPhotoOperations::StoreThumbnailAndEditSize(to_string(fileInfo.fileIdNew), fileInfo.cloudPath);
    return E_OK;
}

bool CloneRestore::IsFilePathExist(const string &filePath) const
{
    if (!MediaFileUtils::IsFileExists(filePath)) {
        MEDIA_DEBUG_LOG("%{private}s doesn't exist", filePath.c_str());
        return false;
    }
    bool cond = (MediaFileUtils::IsDirectory(filePath) && MediaFileUtils::IsDirEmpty(filePath));
    CHECK_AND_RETURN_RET_LOG(!cond, false, "%{private}s is an empty directory", filePath.c_str());
    return true;
}

void CloneRestore::GetThumbnailInsertValue(const FileInfo &fileInfo, NativeRdb::ValuesBucket &values)
{
    if (!hasCloneThumbnailDir_) {
        // If there is no thumbnail directory, all statuses of thumbnail are set to the initial status.
        values.PutInt(PhotoColumn::PHOTO_LCD_VISIT_TIME, RESTORE_LCD_VISIT_TIME_NO_LCD);
        values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, RESTORE_THUMBNAIL_READY_NO_THUMBNAIL);
        values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, RESTORE_THUMBNAIL_VISIBLE_FALSE);
        return;
    }

    // The LCD status is same as the origin status.
    values.PutInt(PhotoColumn::PHOTO_LCD_VISIT_TIME, fileInfo.lcdVisitTime);
    if (!isInitKvstoreSuccess_ || fileInfo.thumbnailReady < RESTORE_THUMBNAIL_READY_SUCCESS) {
        // The kvdb does not exist or the THM status indicates that there is no THM.
        // Therefore, the THM status needs to be set to the initial status.
        values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, RESTORE_THUMBNAIL_READY_NO_THUMBNAIL);
        values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, RESTORE_THUMBNAIL_VISIBLE_FALSE);
        return;
    }
    values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, fileInfo.thumbnailReady);
    values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, RESTORE_THUMBNAIL_VISIBLE_TRUE);
}

void CloneRestore::GetCloudThumbnailInsertValue(const FileInfo &fileInfo, NativeRdb::ValuesBucket &values)
{
    values.PutInt(PhotoColumn::PHOTO_POSITION, fileInfo.position);
    values.PutString(PhotoColumn::PHOTO_CLOUD_ID, fileInfo.cloudId);
    values.PutInt(PhotoColumn::PHOTO_CLOUD_VERSION, fileInfo.cloudVersion);
    values.PutInt(PhotoColumn::PHOTO_DIRTY, 0);
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, 0);
    values.PutInt(PhotoColumn::PHOTO_THUMB_STATUS, RESTORE_THUMBNAIL_STATUS_NOT_ALL);
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_BACKUP));
    values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, 0);
    values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, RESTORE_THUMBNAIL_VISIBLE_FALSE);
    values.PutInt(PhotoColumn::PHOTO_LCD_VISIT_TIME, 0);
}

void CloneRestore::PrepareShootingModeVal(const FileInfo &fileInfo, NativeRdb::ValuesBucket &values)
{
    values.Delete(PhotoColumn::PHOTO_SHOOTING_MODE);
    auto it = fileInfo.valMap.find(PhotoColumn::PHOTO_SHOOTING_MODE_TAG);
    if (it == fileInfo.valMap.end()) {
        values.PutString(PhotoColumn::PHOTO_SHOOTING_MODE, "");
        return;
    }
    string shootingModeTag = get<string>(it->second);
    values.PutString(PhotoColumn::PHOTO_SHOOTING_MODE,
        ShootingModeAlbum::MapShootingModeTagToShootingMode(shootingModeTag));
}

void CloneRestore::GetInsertValueFromValMap(const FileInfo &fileInfo, NativeRdb::ValuesBucket &values)
{
    unordered_map<string, string> commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_,
        PhotoColumn::PHOTOS_TABLE);
    for (auto it = fileInfo.valMap.begin(); it != fileInfo.valMap.end(); ++it) {
        string columnName = it->first;
        auto columnVal = it->second;
        if (columnName == PhotoColumn::PHOTO_EDIT_TIME) {
            PrepareEditTimeVal(values, get<int64_t>(columnVal), fileInfo, commonColumnInfoMap);
            continue;
        }
        if (columnName == PhotoColumn::MEDIA_DATE_TAKEN) {
            if (get<int64_t>(columnVal) > SECONDS_LEVEL_LIMIT) {
                values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, get<int64_t>(columnVal));
            } else {
                values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, get<int64_t>(columnVal) * MSEC_TO_SEC);
            }
            continue;
        }
        PrepareCommonColumnVal(values, columnName, columnVal, commonColumnInfoMap);
    }
    PrepareShootingModeVal(fileInfo, values);
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const FileInfo &fileInfo, const string &newPath,
    int32_t sourceType)
{
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
    values.PutLong(MediaColumn::MEDIA_SIZE, fileInfo.fileSize);
    values.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.fileType);
    values.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    values.PutString(PhotoColumn::PHOTO_MEDIA_SUFFIX, ScannerUtils::GetFileExtension(fileInfo.displayName));
    values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.dateAdded);
    values.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, fileInfo.dateModified);
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, fileInfo.orientation); // photos need orientation
    values.PutInt(PhotoColumn::PHOTO_SUBTYPE, fileInfo.subtype);
    // use owner_album_id to mark the album id which the photo is in.
    values.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, fileInfo.ownerAlbumId);
    // Only SOURCE album has package_name and owner_package.
    values.PutString(MediaColumn::MEDIA_PACKAGE_NAME, fileInfo.packageName);
    values.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, fileInfo.bundleName);
    if (fileInfo.packageName.empty() && fileInfo.bundleName.empty()) {
    // package_name and owner_package are empty, clear owner_appid
        values.PutString(MediaColumn::MEDIA_OWNER_APPID, "");
    }
    values.PutInt(PhotoColumn::PHOTO_QUALITY, fileInfo.photoQuality);
    values.PutInt(PhotoColumn::STAGE_VIDEO_TASK_STATUS, static_cast<int32_t>(StageVideoTaskStatus::NO_NEED_TO_STAGE));
    values.PutLong(MediaColumn::MEDIA_DATE_TRASHED, fileInfo.recycledTime);
    values.PutInt(MediaColumn::MEDIA_HIDDEN, fileInfo.hidden);
    values.PutString(PhotoColumn::PHOTO_SOURCE_PATH, fileInfo.sourcePath);
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_BACKUP));
    GetThumbnailInsertValue(fileInfo, values);
    GetInsertValueFromValMap(fileInfo, values);
    return values;
}

NativeRdb::ValuesBucket CloneRestore::GetCloudInsertValue(const FileInfo &fileInfo, const string &newPath,
    int32_t sourceType)
{
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
    values.PutLong(MediaColumn::MEDIA_SIZE, fileInfo.fileSize);
    values.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.fileType);
    values.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.dateAdded);
    values.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, fileInfo.dateModified);
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, fileInfo.orientation); // photos need orientation
    values.PutInt(PhotoColumn::PHOTO_SUBTYPE, fileInfo.subtype);
    // use owner_album_id to mark the album id which the photo is in.
    values.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, fileInfo.ownerAlbumId);
    // Only SOURCE album has package_name and owner_package.
    values.PutString(MediaColumn::MEDIA_PACKAGE_NAME, fileInfo.packageName);
    values.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, fileInfo.bundleName);

    bool cond = (fileInfo.packageName.empty() && fileInfo.bundleName.empty());
    // package_name and owner_package are empty, clear owner_appid
    CHECK_AND_EXECUTE(!cond, values.PutString(MediaColumn::MEDIA_OWNER_APPID, ""));
    values.PutInt(PhotoColumn::PHOTO_QUALITY, fileInfo.photoQuality);
    values.PutLong(MediaColumn::MEDIA_DATE_TRASHED, fileInfo.recycledTime);
    values.PutInt(MediaColumn::MEDIA_HIDDEN, fileInfo.hidden);
    values.PutString(PhotoColumn::PHOTO_SOURCE_PATH, fileInfo.sourcePath);
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_BACKUP));
    GetCloudThumbnailInsertValue(fileInfo, values);
    GetInsertValueFromValMap(fileInfo, values);
    return values;
}

bool CloneRestore::PrepareCommonColumnInfoMap(const string &tableName,
    const unordered_map<string, string> &srcColumnInfoMap, const unordered_map<string, string> &dstColumnInfoMap)
{
    auto neededColumns = GetValueFromMap(NEEDED_COLUMNS_MAP, tableName);
    auto neededColumnsException = GetValueFromMap(NEEDED_COLUMNS_EXCEPTION_MAP, tableName);
    auto excludedColumns = GetValueFromMap(EXCLUDED_COLUMNS_MAP, tableName);
    auto &commonColumnInfoMap = tableCommonColumnInfoMap_[tableName];
    CHECK_AND_RETURN_RET_LOG(HasColumns(dstColumnInfoMap, neededColumns), false, "Destination lack needed columns");
    for (auto it = dstColumnInfoMap.begin(); it != dstColumnInfoMap.end(); ++it) {
        if (!HasSameColumn(srcColumnInfoMap, it->first, it->second) || excludedColumns.count(it->first) > 0) {
            continue;
        }
        if (neededColumns.count(it->first) > 0 && (neededColumnsException.empty() ||
            neededColumnsException.count(it->first) == 0)) {
            continue;
        }
        commonColumnInfoMap[it->first] = it->second;
    }
    MEDIA_INFO_LOG("Table %{public}s has %{public}zu common columns",
        BackupDatabaseUtils::GarbleInfoName(tableName).c_str(), commonColumnInfoMap.size());
    return true;
}

bool CloneRestore::HasSameColumn(const unordered_map<string, string> &columnInfoMap, const string &columnName,
    const string &columnType)
{
    auto it = columnInfoMap.find(columnName);
    return it != columnInfoMap.end() && it->second == columnType;
}

void CloneRestore::GetValFromResultSet(const shared_ptr<NativeRdb::ResultSet> &resultSet,
    unordered_map<string, variant<int32_t, int64_t, double, string>> &valMap, const string &columnName,
    const string &columnType)
{
    int32_t columnIndex = 0;
    int32_t errCode = resultSet->GetColumnIndex(columnName, columnIndex);
    CHECK_AND_RETURN_LOG(errCode == 0, "Get column index errCode: %{public}d", errCode);
    bool isNull = false;
    errCode = resultSet->IsColumnNull(columnIndex, isNull);
    if (errCode || isNull) {
        return;
    }
    ResultSetDataType dataType = GetValueFromMap(COLUMN_TYPE_MAP, columnType, ResultSetDataType::TYPE_NULL);
    switch (dataType) {
        case ResultSetDataType::TYPE_INT32: {
            int32_t int32Val;
            if (resultSet->GetInt(columnIndex, int32Val) == E_OK) {
                valMap[columnName] = int32Val;
            }
            break;
        }
        case ResultSetDataType::TYPE_INT64: {
            int64_t int64Val;
            if (resultSet->GetLong(columnIndex, int64Val) == E_OK) {
                valMap[columnName] = int64Val;
            }
            break;
        }
        case ResultSetDataType::TYPE_DOUBLE: {
            double doubleVal;
            if (resultSet->GetDouble(columnIndex, doubleVal) == E_OK) {
                valMap[columnName] = doubleVal;
            }
            break;
        }
        case ResultSetDataType::TYPE_STRING: {
            string stringVal;
            if (resultSet->GetString(columnIndex, stringVal) == E_OK) {
                valMap[columnName] = stringVal;
            }
            break;
        }
        default:
            MEDIA_ERR_LOG("No such column type: %{public}s", columnType.c_str());
    }
}

void CloneRestore::PrepareCommonColumnVal(NativeRdb::ValuesBucket &values, const string &columnName,
    const variant<int32_t, int64_t, double, string> &columnVal,
    const unordered_map<string, string> &commonColumnInfoMap) const
{
    string columnType = GetValueFromMap(commonColumnInfoMap, columnName);
    CHECK_AND_RETURN_LOG(!columnType.empty(), "No such column %{public}s", columnName.c_str());
    ResultSetDataType dataType = GetValueFromMap(COLUMN_TYPE_MAP, columnType, ResultSetDataType::TYPE_NULL);
    switch (dataType) {
        case ResultSetDataType::TYPE_INT32: {
            values.PutInt(columnName, get<int32_t>(columnVal));
            break;
        }
        case ResultSetDataType::TYPE_INT64: {
            values.PutLong(columnName, get<int64_t>(columnVal));
            break;
        }
        case ResultSetDataType::TYPE_DOUBLE: {
            values.PutDouble(columnName, get<double>(columnVal));
            break;
        }
        case ResultSetDataType::TYPE_STRING: {
            values.PutString(columnName, get<string>(columnVal));
            break;
        }
        default:
            MEDIA_ERR_LOG("No such column type: %{public}s", columnType.c_str());
    }
}

void CloneRestore::GetQueryWhereClause(const string &tableName, const unordered_map<string, string> &columnInfoMap)
{
    unordered_map<string, string> queryWhereClauseMap;
    if (IsCloudRestoreSatisfied()) {
        queryWhereClauseMap = GetValueFromMap(TABLE_QUERY_WHERE_CLAUSE_MAP_WITH_CLOUD, tableName);
    } else {
        queryWhereClauseMap = GetValueFromMap(TABLE_QUERY_WHERE_CLAUSE_MAP, tableName);
    }
    
    if (queryWhereClauseMap.empty()) {
        return;
    }
    string &queryWhereClause = tableQueryWhereClauseMap_[tableName];
    queryWhereClause.clear();
    for (auto it = queryWhereClauseMap.begin(); it != queryWhereClauseMap.end(); ++it) {
        CHECK_AND_CONTINUE(columnInfoMap.count(it->first) != 0);
        if (!queryWhereClause.empty()) {
            queryWhereClause += " AND ";
        }
        queryWhereClause += it->second + " ";
    }
}

void CloneRestore::GetAlbumExtraQueryWhereClause(const string &tableName)
{
    string mapTableName = GetValueFromMap(CLONE_ALBUM_MAP, tableName);
    CHECK_AND_RETURN_LOG(!mapTableName.empty(), "Get map of table %{public}s failed",
        BackupDatabaseUtils::GarbleInfoName(tableName).c_str());
    string albumQueryWhereClause = "EXISTS (SELECT " + PhotoMap::ASSET_ID + " FROM " + mapTableName + " WHERE " +
        PhotoMap::ALBUM_ID + " = " + PhotoAlbumColumns::ALBUM_ID + " AND EXISTS (SELECT " + MediaColumn::MEDIA_ID +
        " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    string photoQueryWhereClause = GetValueFromMap(tableQueryWhereClauseMap_, PhotoColumn::PHOTOS_TABLE);
    if (!photoQueryWhereClause.empty()) {
        albumQueryWhereClause += " AND " + photoQueryWhereClause;
    }
    albumQueryWhereClause += "))";
    tableExtraQueryWhereClauseMap_[tableName] = albumQueryWhereClause;
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const AlbumInfo &albumInfo, const string &tableName) const
{
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, static_cast<int32_t>(albumInfo.albumType));
    values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, static_cast<int32_t>(albumInfo.albumSubType));
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, albumInfo.albumName);

    if (tableName == PhotoAlbumColumns::TABLE) {
        values.PutLong(PhotoAlbumColumns::ALBUM_DATE_MODIFIED,
            (albumInfo.dateModified ? albumInfo.dateModified : MediaFileUtils::UTCTimeMilliSeconds()));
    }

    unordered_map<string, string> commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, tableName);
    for (auto it = albumInfo.valMap.begin(); it != albumInfo.valMap.end(); ++it) {
        string columnName = it->first;
        auto columnVal = it->second;
        PrepareCommonColumnVal(values, columnName, columnVal, commonColumnInfoMap);
    }
    return values;
}

void CloneRestore::BatchQueryPhoto(vector<FileInfo> &fileInfos)
{
    string selection;
    unordered_map<string, size_t> fileIndexMap;
    for (size_t index = 0; index < fileInfos.size(); index++) {
        CHECK_AND_CONTINUE(!fileInfos[index].cloudPath.empty());
        BackupDatabaseUtils::UpdateSelection(selection, fileInfos[index].cloudPath, true);
        fileIndexMap[fileInfos[index].cloudPath] = index;
    }
    string querySql = "SELECT " + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + ", " +
        MediaColumn::MEDIA_DATE_TAKEN + " FROM " + PhotoColumn::PHOTOS_TABLE +
        " WHERE " + MediaColumn::MEDIA_FILE_PATH + " IN (" + selection + ")";
    querySql += " LIMIT " + to_string(fileIndexMap.size());
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        string cloudPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
        string dateTaken = GetStringVal(MediaColumn::MEDIA_DATE_TAKEN, resultSet);
        CHECK_AND_CONTINUE_ERR_LOG(fileId > 0, "Get fileId invalid: %{public}d", fileId);
        CHECK_AND_CONTINUE(fileIndexMap.count(cloudPath) != 0);
        size_t index = fileIndexMap.at(cloudPath);
        fileInfos[index].fileIdNew = fileId;
        fileInfos[index].newAstcDateKey = dateTaken;
    }
    resultSet->Close();
    BackupDatabaseUtils::UpdateAssociateFileId(mediaLibraryRdb_, fileInfos);
}

void CloneRestore::UpdateAlbumOrderColumns(const AlbumInfo &albumInfo, const string &tableName)
{
    CHECK_AND_RETURN(tableName == PhotoAlbumColumns::TABLE);
    CHECK_AND_RETURN_LOG(mediaLibraryRdb_ != nullptr, "rdbStore is null");

    std::unique_ptr<NativeRdb::AbsRdbPredicates> predicates =
        make_unique<NativeRdb::AbsRdbPredicates>(PhotoAlbumColumns::TABLE);
    predicates->EqualTo(PhotoAlbumColumns::ALBUM_ID, albumInfo.albumIdNew);

    NativeRdb::ValuesBucket values;
    unordered_map<string, string> commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, tableName);
    for (const auto &columns : PhotoAlbumColumns::ORDER_COLUMN_STYLE_MAP) {
        for (const auto &columnName : columns.second) {
            auto iter = albumInfo.valMap.find(columnName);
            CHECK_AND_EXECUTE(iter == albumInfo.valMap.end(),
                PrepareCommonColumnVal(values, columnName, iter->second, commonColumnInfoMap));
        }
    }

    int32_t changeRows = 0;
    int32_t ret = BackupDatabaseUtils::Update(mediaLibraryRdb_, changeRows, values, predicates);
    bool cond = (changeRows < 0 || ret < 0);
    CHECK_AND_RETURN_LOG(!cond,
        "Failed to update albumOrder columns, ret: %{public}d, updateRows: %{public}d", ret, changeRows);
}

void CloneRestore::UpdateSystemAlbumColumns(const string &tableName)
{
    CHECK_AND_RETURN(tableName == PhotoAlbumColumns::TABLE);
    CHECK_AND_RETURN_LOG(this->mediaRdb_ != nullptr, "original rdbStore is null");

    const std::string querySql =
        "SELECT PhotoAlbum.* FROM PhotoAlbum WHERE PhotoAlbum.album_type = 1024 ORDER BY PhotoAlbum.album_id";
    const vector<string> bindArgs = {};
    auto resultSet = this->mediaRdb_->QuerySql(querySql, bindArgs);
    CHECK_AND_RETURN_LOG(resultSet != nullptr,
        "Failed to query system album! querySql = %{public}s", querySql.c_str());
    
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AlbumInfo albumInfo;
        bool ret = ParseAlbumResultSet(tableName, resultSet, albumInfo);
        CHECK_AND_CONTINUE_INFO_LOG(ret == true, "Update system album columns failed");
        albumInfo.albumIdNew = albumInfo.albumIdOld;
        UpdateAlbumOrderColumns(albumInfo, tableName);
    }
    resultSet->Close();
}

void CloneRestore::InsertAlbum(vector<AlbumInfo> &albumInfos, const string &tableName)
{
    CHECK_AND_RETURN_LOG(mediaLibraryRdb_ != nullptr, "mediaLibraryRdb_ is null");
    CHECK_AND_RETURN_LOG(!albumInfos.empty(), "albumInfos are empty");
    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    vector<string> albumIds{};
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(albumInfos, albumIds, tableName);
    UpdatePhotoAlbumDateModified(albumIds, tableName);
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(tableName, values, rowNum);
    CHECK_AND_RETURN_LOG(errCode == E_OK, "Batc insert failed");
    migrateDatabaseAlbumNumber_ += rowNum;
    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    BatchQueryAlbum(albumInfos, tableName);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("insert %{public}ld albums cost %{public}ld, query cost %{public}ld.", (long)rowNum,
        (long)(startQuery - startInsert), (long)(end - startQuery));
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(vector<AlbumInfo> &albumInfos, vector<string> &albumIds,
    const string &tableName)
{
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < albumInfos.size(); i++) {
        if (HasSameAlbum(albumInfos[i], tableName)) {
            albumIds.emplace_back(to_string(albumInfos[i].albumIdNew));
            UpdateAlbumOrderColumns(albumInfos[i], tableName);
            MEDIA_WARN_LOG("Album (%{public}d, %{public}d, %{public}d, %{public}s) already exists.",
                albumInfos[i].albumIdOld, static_cast<int32_t>(albumInfos[i].albumType),
                static_cast<int32_t>(albumInfos[i].albumSubType), albumInfos[i].albumName.c_str());
            continue;
        }
        NativeRdb::ValuesBucket value = GetInsertValue(albumInfos[i], tableName);
        values.emplace_back(value);
    }
    return values;
}

bool CloneRestore::HasSameAlbum(AlbumInfo &albumInfo, const string &tableName)
{
    // check if the album already exists
    CHECK_AND_RETURN_RET(tableName != PhotoAlbumColumns::TABLE,
        this->photoAlbumClone_.HasSameAlbum(albumInfo.lPath, albumInfo.albumIdNew));
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName + " WHERE " +
        PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(albumInfo.albumType) + " AND " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(albumInfo.albumSubType) + " AND " +
        PhotoAlbumColumns::ALBUM_NAME + " = '" + albumInfo.albumName + "'";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
    bool cond = (resultSet == nullptr);
    CHECK_AND_RETURN_RET(!cond, false);
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return false;
    }
    int32_t count = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    resultSet->Close();
    return count > 0;
}

void CloneRestore::BatchQueryAlbum(vector<AlbumInfo> &albumInfos, const string &tableName)
{
    auto &albumIdMap = tableAlbumIdMap_[tableName];
    for (auto &albumInfo : albumInfos) {
        CHECK_AND_CONTINUE(albumInfo.albumIdOld > 0);
        string querySql = "SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + tableName + " WHERE " +
            PhotoAlbumColumns::ALBUM_TYPE + " = " + to_string(albumInfo.albumType) + " AND " +
            PhotoAlbumColumns::ALBUM_SUBTYPE + " = " + to_string(albumInfo.albumSubType) + " AND " +
            PhotoAlbumColumns::ALBUM_NAME + " = '" + albumInfo.albumName + "'";
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
        CHECK_AND_CONTINUE(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK);
        albumInfo.albumIdNew = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        CHECK_AND_CONTINUE(albumInfo.albumIdNew > 0);
        albumIdMap[albumInfo.albumIdOld] = albumInfo.albumIdNew;
        resultSet->Close();
    }
}

void CloneRestore::BatchInsertMap(const vector<FileInfo> &fileInfos, int64_t &totalRowNum)
{
    string selection;
    unordered_map<int32_t, int32_t> fileIdMap;
    SetFileIdReference(fileInfos, selection, fileIdMap);
    std::string tableName = ANALYSIS_ALBUM_TABLE;
    string garbledTableName = BackupDatabaseUtils::GarbleInfoName(tableName);
    string mapTableName = GetValueFromMap(CLONE_ALBUM_MAP, tableName);
    CHECK_AND_RETURN_LOG(!mapTableName.empty(),
        "Get map of table %{public}s failed", garbledTableName.c_str());
    auto albumIdMap = GetValueFromMap(tableAlbumIdMap_, tableName);
    CHECK_AND_RETURN_LOG(!albumIdMap.empty(),
        "Get album id map of table %{public}s empty, skip", garbledTableName.c_str());
    string albumSelection = GetValueFromMap(tableQueryWhereClauseMap_, tableName);
    unordered_set<int32_t> currentTableAlbumSet;
    string baseQuerySql = mapTableName + " INNER JOIN " + tableName + " ON " +
        mapTableName + "." + PhotoMap::ALBUM_ID + " = " + tableName + "." + PhotoAlbumColumns::ALBUM_ID +
        " WHERE " + mapTableName + "." + PhotoMap::ASSET_ID + " IN (" + selection + ")";
    baseQuerySql += albumSelection.empty() ? "" : " AND " + albumSelection;
    int32_t totalNumber = QueryMapTotalNumber(baseQuerySql);
    MEDIA_INFO_LOG("QueryMapTotalNumber of table %{public}s, totalNumber = %{public}d", garbledTableName.c_str(),
        totalNumber);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
        vector<MapInfo> mapInfos = QueryMapInfos(mapTableName, baseQuerySql, offset, fileIdMap, albumIdMap);
        int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
        int64_t rowNum = InsertMapByTable(mapTableName, mapInfos, currentTableAlbumSet);
        totalRowNum += rowNum;
        int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
        MEDIA_INFO_LOG("query %{public}zu map infos cost %{public}ld, insert %{public}ld maps cost %{public}ld",
            mapInfos.size(), (long)(startInsert - startQuery), (long)rowNum, (long)(end - startInsert));
    }
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const MapInfo &mapInfo) const
{
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoMap::ASSET_ID, mapInfo.fileId);
    values.PutInt(PhotoMap::ALBUM_ID, mapInfo.albumId);
    return values;
}

void CloneRestore::CheckTableColumnStatus(shared_ptr<NativeRdb::RdbStore> rdbStore,
    const vector<vector<string>> &cloneTableList)
{
    unordered_map<string, unordered_map<string, string>> tableColumnInfoMap;
    for (const auto &tableList : cloneTableList) {
        bool columnStatusGlobal = true;
        for (const auto &tableName : tableList) {
            auto &columnInfoMap = tableColumnInfoMap[tableName];
            columnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(rdbStore, tableName);
            auto neededColumns = GetValueFromMap(NEEDED_COLUMNS_MAP, tableName);
            columnStatusGlobal = columnStatusGlobal && HasColumns(columnInfoMap, neededColumns);
        }
        for (const auto &tableName : tableList) {
            tableColumnStatusMap_[tableName] = columnStatusGlobal;
        }
    }
    for (const auto &tableList : cloneTableList) {
        for (const auto &tableName : tableList) {
            if (!IsReadyForRestore(tableName)) {
                MEDIA_ERR_LOG("Column status is false");
                break;
            }
            auto columnInfoMap = GetValueFromMap(tableColumnInfoMap, tableName);
            GetQueryWhereClause(tableName, columnInfoMap);
        }
    }
}

bool CloneRestore::HasColumns(const unordered_map<string, string> &columnInfoMap,
    const unordered_set<string> &columnSet)
{
    for (const auto &columnName : columnSet) {
        if (!HasColumn(columnInfoMap, columnName)) {
            MEDIA_ERR_LOG("Lack of column %{public}s", columnName.c_str());
            return false;
        }
    }
    return true;
}

bool CloneRestore::HasColumn(const unordered_map<string, string> &columnInfoMap, const string &columnName)
{
    return columnInfoMap.count(columnName) > 0;
}

bool CloneRestore::IsReadyForRestore(const string &tableName)
{
    return GetValueFromMap(tableColumnStatusMap_, tableName, false);
}

void CloneRestore::PrepareEditTimeVal(NativeRdb::ValuesBucket &values, int64_t editTime, const FileInfo &fileInfo,
    const unordered_map<string, string> &commonColumnInfoMap) const
{
    string editDataPath = backupRestoreDir_ +
        BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL_EDIT_DATA, fileInfo.relativePath);
    int64_t newEditTime = editTime > 0 && IsFilePathExist(editDataPath) ? editTime : 0;
    PrepareCommonColumnVal(values, PhotoColumn::PHOTO_EDIT_TIME, newEditTime, commonColumnInfoMap);
}

void CloneRestore::RestoreGallery()
{
    CheckTableColumnStatus(mediaRdb_, CLONE_TABLE_LISTS_PHOTO);
    // Upgrade original MediaLibrary Database
    DataTransfer::MediaLibraryDbUpgrade medialibraryDbUpgrade;
    medialibraryDbUpgrade.OnUpgrade(*this->mediaRdb_);
    // Report the old db info.
    DatabaseReport()
        .SetSceneCode(this->sceneCode_)
        .SetTaskId(this->taskId_)
        .ReportMedia(this->mediaRdb_, DatabaseReport::PERIOD_OLD)
        .ReportMedia(this->mediaLibraryRdb_, DatabaseReport::PERIOD_BEFORE);
    UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_)
        .Report("RESTORE_CLOUD_STATUS", "",
            "isAccountValid_: " + std::to_string(isAccountValid_) +
            ", syncSwitchType_: " + std::to_string(syncSwitchType_) +
            ", isSyncSwitchOpen: " + std::to_string(isSyncSwitchOn_));
    // Restore the backup db info.
    RestoreAlbum();
    RestorePhoto();
    if (IsCloudRestoreSatisfied()) {
        MEDIA_INFO_LOG("singlCloud cloud clone");
        RestorePhotoForCloud();
    }
    MEDIA_INFO_LOG("singlCloud migrate database photo number: %{public}lld, file number: %{public}lld (%{public}lld + "
        "%{public}lld), duplicate number: %{public}lld + %{public}lld, album number: %{public}lld, map number: "
        "%{public}lld", (long long)migrateDatabaseNumber_, (long long)migrateFileNumber_,
        (long long)(migrateFileNumber_ - migrateVideoFileNumber_), (long long)migrateVideoFileNumber_,
        (long long)migratePhotoDuplicateNumber_, (long long)migrateVideoDuplicateNumber_,
        (long long)migrateDatabaseAlbumNumber_, (long long)migrateDatabaseMapNumber_);
    MEDIA_INFO_LOG("singlCloud Start update group tags");
    BackupDatabaseUtils::UpdateFaceGroupTagsUnion(mediaLibraryRdb_);
    BackupDatabaseUtils::UpdateFaceAnalysisTblStatus(mediaLibraryRdb_);
    BackupDatabaseUtils::UpdateAnalysisPhotoMapStatus(mediaLibraryRdb_);
    RestoreAnalysisClassify();
    RestoreAnalysisGeo();
    cloneRestoreGeoDictionary_.ReportGeoRestoreTask();
    RestoreAnalysisData();
    ReportPortraitCloneStat(sceneCode_);
    InheritManualCover();
}

void CloneRestore::RestoreAnalysisTablesData()
{
    cloneRestoreAnalysisData_.Init(this->sceneCode_, this->taskId_, mediaRdb_, mediaLibraryRdb_);
    std::unordered_set<std::string> excludedColumns = {"id", "file_id"};
    vector<std::string> analysisTables = {
        "tab_analysis_head",
        "tab_analysis_pose",
        "tab_analysis_composition",
        "tab_analysis_ocr",
        "tab_analysis_segmentation",
        "tab_analysis_object",
        "tab_analysis_saliency_detect",
        "tab_analysis_recommendation"
    };

    vector<std::string> totalTypes = {
        "head",
        "pose",
        "composition",
        "ocr",
        "segmentation",
        "object",
        "saliency",
        "recommendation"
    };

    for (size_t index = 0; index < analysisTables.size(); index++) {
        std::string table = analysisTables[index];
        std::string type = totalTypes[index];
        cloneRestoreAnalysisData_.CloneAnalysisData(table, type, photoInfoMap_, excludedColumns);
    }
}

void CloneRestore::RestoreAnalysisData()
{
    RestoreSearchIndexData();
    RestoreBeautyScoreData();
    RestoreVideoFaceData();
    RestoreAnalysisTablesData();
    RestoreHighlightAlbums();
}

void CloneRestore::RestoreSearchIndexData()
{
    SearchIndexClone searchIndexClone(mediaRdb_, mediaLibraryRdb_, photoInfoMap_, maxSearchId_);
    searchIndexClone.Clone();
}

void CloneRestore::RestoreBeautyScoreData()
{
    BeautyScoreClone beautyScoreClone(mediaRdb_, mediaLibraryRdb_, photoInfoMap_, maxBeautyFileId_);
    beautyScoreClone.CloneBeautyScoreInfo();
}

void CloneRestore::RestoreVideoFaceData()
{
    VideoFaceClone videoFaceClone(mediaRdb_, mediaLibraryRdb_, photoInfoMap_);
    videoFaceClone.CloneVideoFaceInfo();
}

bool CloneRestore::PrepareCloudPath(const string &tableName, FileInfo &fileInfo)
{
    fileInfo.cloudPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::CLOUD, fileInfo.relativePath);
    CHECK_AND_RETURN_RET_LOG(!fileInfo.cloudPath.empty(), false, "Get cloudPath empty");
    if (IsSameFileForClone(tableName, fileInfo)) {
        // should not delete the file, if the FileInfo is came from PhotoMap.
        if (fileInfo.isRelatedToPhotoMap != 1) {
            MEDIA_INFO_LOG("File (%{public}s) already exists. delete it.",
                BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str());
            (void)MediaFileUtils::DeleteFile(fileInfo.filePath);
        }
        UpdateDuplicateNumber(fileInfo.fileType);
        return false;
    }
    // If the device originally has dentry file in the cloud path, no need to generate new cloud path.
    if (fileInfo.isNew && (MediaFileUtils::IsFileExists(fileInfo.cloudPath) || fileInfo.isRelatedToPhotoMap == 1)) {
        int32_t uniqueId = GetUniqueId(fileInfo.fileType);
        int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileInfo.fileType,
            MediaFileUtils::GetExtensionFromPath(fileInfo.displayName), fileInfo.cloudPath);
        if (errCode != E_OK) {
            ErrorInfo errorInfo(RestoreError::CREATE_PATH_FAILED, 1, std::to_string(errCode),
                BackupLogUtils::FileInfoToString(sceneCode_, fileInfo));
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
            fileInfo.cloudPath.clear();
            return false;
        }
    }
    int32_t errCode = BackupFileUtils::PreparePath(
        BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::LOCAL, fileInfo.cloudPath));
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Prepare cloudPath failed, path: %{public}s, cloudPath: %{public}s",
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str(),
            BackupFileUtils::GarbleFilePath(fileInfo.cloudPath, DEFAULT_RESTORE_ID, garbagePath_).c_str());
        ErrorInfo errorInfo(RestoreError::PREPARE_PATH_FAILED, 1, std::to_string(errCode),
            BackupLogUtils::FileInfoToString(sceneCode_, fileInfo));
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        fileInfo.cloudPath.clear();
        return false;
    }
    return true;
}

void CloneRestore::RestoreMusic()
{
    CheckTableColumnStatus(mediaRdb_, CLONE_TABLE_LISTS_AUDIO);
    RestoreAudio();
    MEDIA_INFO_LOG("migrate database audio number: %{public}lld, file number: %{public}lld, duplicate number: "
        "%{public}lld", (long long)migrateAudioDatabaseNumber_, (long long)migrateAudioFileNumber_,
        (long long)migrateAudioDuplicateNumber_);
}

void CloneRestore::RestoreAudio(void)
{
    MEDIA_INFO_LOG("Start clone restore: audio");
    CHECK_AND_RETURN_LOG(IsReadyForRestore(AudioColumn::AUDIOS_TABLE),
        "Column status is not ready for restore audio, quit");
    unordered_map<string, string> srcColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaRdb_,
        AudioColumn::AUDIOS_TABLE);
    unordered_map<string, string> dstColumnInfoMap = BackupDatabaseUtils::GetColumnInfoMap(mediaLibraryRdb_,
        AudioColumn::AUDIOS_TABLE);
    CHECK_AND_RETURN_LOG(PrepareCommonColumnInfoMap(AudioColumn::AUDIOS_TABLE, srcColumnInfoMap,
        dstColumnInfoMap), "Prepare common column info failed");
    int32_t totalNumber = QueryTotalNumber(AudioColumn::AUDIOS_TABLE);
    MEDIA_INFO_LOG("QueryAudioTotalNumber, totalNumber = %{public}d", totalNumber);
    CHECK_AND_RETURN(totalNumber > 0);

    audioTotalNumber_ += static_cast<uint64_t>(totalNumber);
    MEDIA_INFO_LOG("onProcess Update audioTotalNumber_: %{public}lld", (long long)audioTotalNumber_);
    if (!MediaFileUtils::IsFileExists(RESTORE_MUSIC_LOCAL_DIR)) {
        MEDIA_INFO_LOG("music dir is not exists!!!");
        MediaFileUtils::CreateDirectory(RESTORE_MUSIC_LOCAL_DIR);
    }
    for (int32_t offset = 0; offset < totalNumber; offset += CLONE_QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestoreAudioBatch(offset); }, { &offset }, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
}

vector<FileInfo> CloneRestore::QueryFileInfos(const string &tableName, int32_t offset)
{
    vector<FileInfo> result;
    result.reserve(CLONE_QUERY_COUNT);
    string querySql = "SELECT * FROM " + tableName;
    string whereClause = GetQueryWhereClauseByTable(tableName);
    querySql += whereClause.empty() ? "" : " WHERE " + whereClause;
    querySql += " LIMIT " + to_string(offset) + ", " + to_string(CLONE_QUERY_COUNT);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        if (ParseResultSet(tableName, resultSet, fileInfo)) {
            result.emplace_back(fileInfo);
        }
    }
    resultSet->Close();
    return result;
}

bool CloneRestore::ParseResultSet(const string &tableName, const shared_ptr<NativeRdb::ResultSet> &resultSet,
    FileInfo &fileInfo)
{
    fileInfo.fileType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
    fileInfo.fileIdOld = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    fileInfo.displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    fileInfo.oldPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (!ConvertPathToRealPath(fileInfo.oldPath, filePath_, fileInfo.filePath, fileInfo.relativePath)) {
        ErrorInfo errorInfo(RestoreError::PATH_INVALID, 1, "", BackupLogUtils::FileInfoToString(sceneCode_, fileInfo));
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return false;
    }
    fileInfo.fileSize = GetInt64Val(MediaColumn::MEDIA_SIZE, resultSet);
    if (fileInfo.fileSize <= 0) {
        ErrorInfo errorInfo(RestoreError::SIZE_INVALID, 1, "Db size <= 0",
            BackupLogUtils::FileInfoToString(sceneCode_, fileInfo));
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return false;
    }

    fileInfo.dateAdded = GetInt64Val(MediaColumn::MEDIA_DATE_ADDED, resultSet);
    fileInfo.dateModified = GetInt64Val(MediaColumn::MEDIA_DATE_MODIFIED, resultSet);
    fileInfo.dateTaken = GetInt64Val(MediaColumn::MEDIA_DATE_TAKEN, resultSet);
    fileInfo.thumbnailReady = GetInt64Val(PhotoColumn::PHOTO_THUMBNAIL_READY, resultSet);
    fileInfo.lcdVisitTime = GetInt32Val(PhotoColumn::PHOTO_LCD_VISIT_TIME, resultSet);
    fileInfo.position = GetInt32Val(PhotoColumn::PHOTO_POSITION, resultSet);
    fileInfo.cloudVersion = GetInt32Val(PhotoColumn::PHOTO_CLOUD_VERSION, resultSet);
    fileInfo.cloudId = GetStringVal(PhotoColumn::PHOTO_CLOUD_ID, resultSet);
    fileInfo.oldAstcDateKey = to_string(fileInfo.dateTaken);
    SetSpecialAttributes(tableName, resultSet, fileInfo);

    auto commonColumnInfoMap = GetValueFromMap(tableCommonColumnInfoMap_, tableName);
    for (auto it = commonColumnInfoMap.begin(); it != commonColumnInfoMap.end(); ++it) {
        string columnName = it->first;
        string columnType = it->second;
        GetValFromResultSet(resultSet, fileInfo.valMap, columnName, columnType);
    }
    return true;
}

bool CloneRestore::ParseResultSetForAudio(const shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &fileInfo)
{
    return ParseResultSet(AudioColumn::AUDIOS_TABLE, resultSet, fileInfo);
}

void CloneRestore::InsertAudio(vector<FileInfo> &fileInfos)
{
    CHECK_AND_RETURN_LOG(mediaLibraryRdb_ != nullptr, "mediaLibraryRdb_ is null");
    CHECK_AND_RETURN_LOG(!fileInfos.empty(), "fileInfos are empty");
    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t fileMoveCount = 0;
    for (auto& fileInfo : fileInfos) {
        CHECK_AND_CONTINUE_ERR_LOG(BackupFileUtils::IsFileValid(fileInfo.filePath, CLONE_RESTORE_ID) == E_OK,
            "File is invalid: size: %{public}lld, name: %{public}s, filePath: %{public}s",
            (long long)fileInfo.fileSize, BackupFileUtils::GarbleFileName(fileInfo.displayName).c_str(),
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str());
        CHECK_AND_CONTINUE(PrepareCloudPath(AudioColumn::AUDIOS_TABLE, fileInfo));
        string localPath = RESTORE_MUSIC_LOCAL_DIR + fileInfo.displayName;
        if (MediaFileUtils::IsFileExists(localPath)) {
            MEDIA_INFO_LOG("localPath %{public}s already exists.",
                BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str());
            UpdateDuplicateNumber(fileInfo.fileType);
            continue;
        }

        int32_t moveErrCode = MoveFile(fileInfo.filePath, localPath);
        if (moveErrCode != E_OK) {
            MEDIA_ERR_LOG("MoveFile failed, filePath: %{public}s, errCode: %{public}d, errno: %{public}d",
                BackupFileUtils::GarbleFilePath(fileInfo.filePath, CLONE_RESTORE_ID, garbagePath_).c_str(), moveErrCode,
                errno);
            UpdateFailedFiles(fileInfo.fileType, fileInfo, RestoreError::MOVE_FAILED);
            continue;
        }
        BackupFileUtils::ModifyFile(localPath, fileInfo.dateModified / MSEC_TO_SEC);
        fileMoveCount++;
    }
    migrateAudioFileNumber_ += fileMoveCount;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("move %{public}ld files cost %{public}ld.", (long)fileMoveCount, (long)(end - startMove));
}

size_t CloneRestore::StatClonetotalSize(std::shared_ptr<NativeRdb::RdbStore> mediaRdb)
{
    CHECK_AND_RETURN_RET_LOG(mediaRdb != nullptr, 0, "rdbStore is nullptr");

    string thumbSizeSql {};
    thumbSizeSql = "SELECT SUM(CAST(" + PhotoExtColumn::THUMBNAIL_SIZE + " AS BIGINT)) AS " + MEDIA_DATA_DB_SIZE +
                          ", -1 AS " + MediaColumn::MEDIA_TYPE +
                          " FROM " + PhotoExtColumn::PHOTOS_EXT_TABLE;

    string mediaVolumeQuery = PhotoColumn::QUERY_MEDIA_VOLUME + " UNION ALL " +
                              AudioColumn::QUERY_MEDIA_VOLUME + " UNION ALL " +
                              thumbSizeSql;

    auto resultSet = mediaRdb->QuerySql(mediaVolumeQuery);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, 0, "Failed to execute media volume query");

    int64_t totalVolume = 0;
    MEDIA_INFO_LOG("Initial totalVolume: %{public}" PRId64, totalVolume);

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int64_t mediaSize = GetInt64Val(MediaColumn::MEDIA_SIZE, resultSet);
        int32_t mediatype = GetInt32Val(MediaColumn::MEDIA_TYPE, resultSet);
        MEDIA_INFO_LOG("mediatype is %{public}d, current media asset size is: %{public}" PRId64, mediatype, mediaSize);
        if (mediaSize < 0) {
            MEDIA_ERR_LOG("ill mediaSize: %{public}" PRId64 " for mediatype: %{public}d", mediaSize, mediatype);
        }

        totalVolume += mediaSize;
        MEDIA_INFO_LOG("current totalVolume: %{public}" PRId64, totalVolume);
    }
    resultSet->Close();
    MEDIA_INFO_LOG("media db media asset size is: %{public}" PRId64, totalVolume);

    if (totalVolume < 0) {
        MEDIA_ERR_LOG("totalVolume is negative: %{public}" PRId64 ". Returning 0.", totalVolume);
        return 0;
    }

    size_t totalAssetSize = static_cast<size_t>(totalVolume);
    // other meta data dir size
    size_t editDataTotalSize {0};
    size_t rdbTotalSize {0};
    size_t kvdbTotalSize {0};
    size_t highlightTotalSize {0};
    MediaFileUtils::StatDirSize(CLONE_STAT_EDIT_DATA_DIR, editDataTotalSize);
    MediaFileUtils::StatDirSize(CLONE_STAT_RDB_DIR, rdbTotalSize);
    MediaFileUtils::StatDirSize(CLONE_STAT_KVDB_DIR, kvdbTotalSize);
    MediaFileUtils::StatDirSize(CLONE_STAT_HIGHLIGHT_DIR, highlightTotalSize);
    size_t totalSize = totalAssetSize + editDataTotalSize + rdbTotalSize + kvdbTotalSize + highlightTotalSize;
    return totalSize;
}

string CloneRestore::GetBackupInfo()
{
    CHECK_AND_RETURN_RET_LOG(BaseRestore::Init() == E_OK, "", "GetBackupInfo init failed");
    CHECK_AND_RETURN_RET_LOG(mediaLibraryRdb_ != nullptr, "", "GetBackupInfo Rdbstore is null");

    CheckTableColumnStatus(mediaLibraryRdb_, CLONE_TABLE_LISTS_OLD_DEVICE);
    int32_t photoCount = QueryTotalNumberByMediaType(mediaLibraryRdb_, PhotoColumn::PHOTOS_TABLE,
        MediaType::MEDIA_TYPE_IMAGE);
    int32_t videoCount = QueryTotalNumberByMediaType(mediaLibraryRdb_, PhotoColumn::PHOTOS_TABLE,
        MediaType::MEDIA_TYPE_VIDEO);
    int32_t audioCount = QueryTotalNumberByMediaType(mediaLibraryRdb_, AudioColumn::AUDIOS_TABLE,
        MediaType::MEDIA_TYPE_AUDIO);

    size_t totalSize = StatClonetotalSize(mediaLibraryRdb_);
    MEDIA_INFO_LOG("QueryTotalNumber, photo: %{public}d, video: %{public}d, audio: %{public}d, totalSize: "
        "%{public}lld bytes", photoCount, videoCount, audioCount, static_cast<long long>(totalSize));

    return GetBackupInfoByCount(photoCount, videoCount, audioCount, totalSize);
}

int32_t CloneRestore::QueryTotalNumberByMediaType(shared_ptr<NativeRdb::RdbStore> rdbStore, const string &tableName,
    MediaType mediaType)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + tableName + " WHERE " + MediaColumn::MEDIA_TYPE +
        " = " + to_string(static_cast<int32_t>(mediaType));
    string whereClause = GetQueryWhereClauseByTable(tableName);
    querySql += whereClause.empty() ? "" : " AND " + whereClause;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(rdbStore, querySql);
    bool cond = (resultSet == nullptr);
    CHECK_AND_RETURN_RET(!cond, 0);
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return 0;
    }
    int32_t result = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    resultSet->Close();
    return result;
}

string CloneRestore::GetBackupInfoByCount(int32_t photoCount, int32_t videoCount, int32_t audioCount, size_t totalSize)
{
    nlohmann::json jsonObject = {
        {
            { STAT_KEY_BACKUP_INFO, STAT_TYPE_PHOTO },
            { STAT_KEY_NUMBER, photoCount }
        },
        {
            { STAT_KEY_BACKUP_INFO, STAT_TYPE_VIDEO },
            { STAT_KEY_NUMBER, videoCount }
        },
        {
            { STAT_KEY_BACKUP_INFO, STAT_TYPE_AUDIO },
            { STAT_KEY_NUMBER, audioCount }
        },
        {
            { STAT_KEY_BACKUP_INFO, STAT_TYPE_TOTAL_SIZE },
            { STAT_KEY_NUMBER, totalSize }
        }
    };
    return jsonObject.dump();
}

void CloneRestore::RestorePhotoBatch(int32_t offset, int32_t isRelatedToPhotoMap)
{
    MEDIA_INFO_LOG(
        "start restore photo, offset: %{public}d, isRelatedToPhotoMap: %{public}d", offset, isRelatedToPhotoMap);
    vector<FileInfo> fileInfos = QueryFileInfos(offset, isRelatedToPhotoMap);
    CHECK_AND_EXECUTE(InsertPhoto(fileInfos) == E_OK, AddToPhotosFailedOffsets(offset));
    RestoreImageFaceInfo(fileInfos);

    auto fileIdPairs = BackupDatabaseUtils::CollectFileIdPairs(fileInfos);
    BackupDatabaseUtils::UpdateAnalysisTotalTblNoFaceStatus(mediaLibraryRdb_, mediaRdb_, fileIdPairs);
    BackupDatabaseUtils::UpdateAnalysisTotalTblStatus(mediaLibraryRdb_, fileIdPairs);
    MEDIA_INFO_LOG("end restore photo, offset: %{public}d", offset);
}

void CloneRestore::RestoreBatchForCloud(int32_t offset, int32_t isRelatedToPhotoMap)
{
    MEDIA_INFO_LOG(
        "singlCloud restore photo, offset: %{public}d, isRelated: %{public}d", offset, isRelatedToPhotoMap);
    vector<FileInfo> fileInfos = QueryCloudFileInfos(offset, isRelatedToPhotoMap);
    CHECK_AND_EXECUTE(InsertCloudPhoto(sceneCode_, fileInfos, SourceType::PHOTOS) == E_OK,
        AddToPhotosFailedOffsets(offset));
    RestoreImageFaceInfo(fileInfos);

    auto fileIdPairs = BackupDatabaseUtils::CollectFileIdPairs(fileInfos);
    BackupDatabaseUtils::UpdateAnalysisTotalTblNoFaceStatus(mediaLibraryRdb_, mediaRdb_, fileIdPairs);
    BackupDatabaseUtils::UpdateAnalysisTotalTblStatus(mediaLibraryRdb_, fileIdPairs);
    MEDIA_INFO_LOG("singleCloud end restore photo, offset: %{public}d", offset);
}

int CloneRestore::InsertCloudPhoto(int32_t sceneCode, std::vector<FileInfo> &fileInfos, int32_t sourceType)
{
    MEDIA_INFO_LOG("singleCloud start insert cloud %{public}zu photos", fileInfos.size());
    CHECK_AND_RETURN_RET_LOG(mediaLibraryRdb_ != nullptr, E_OK,
        "singleCloud mediaLibraryRdb_ iS null in cloud clone");
    CHECK_AND_RETURN_RET_LOG(!fileInfos.empty(), E_OK, "singleCloud fileInfos are empty in cloud clone");
    int64_t startGenerate = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetCloudInsertValues(sceneCode, fileInfos, sourceType);
    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(PhotoColumn::PHOTOS_TABLE, values, rowNum);
    MEDIA_INFO_LOG("singleCloud insertCloudPhoto is %{public}d, the rowNum is %{public}" PRId64, errCode, rowNum);
    migrateCloudSuccessNumber_ += rowNum;
    if (errCode != E_OK) {
        if (needReportFailed_) {
            UpdateFailedFiles(fileInfos, RestoreError::INSERT_FAILED);
            ErrorInfo errorInfo(RestoreError::INSERT_FAILED, static_cast<int32_t>(fileInfos.size()), errCode);
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        }
        return errCode;
    }

    int64_t startInsertRelated = MediaFileUtils::UTCTimeMilliSeconds();
    InsertPhotoRelated(fileInfos, SourceType::PHOTOS);

    // create dentry file for cloud origin, save failed cloud id
    std::vector<std::string> dentryFailedOrigin;
    CHECK_AND_EXECUTE(BatchCreateDentryFile(fileInfos, dentryFailedOrigin, DENTRY_INFO_ORIGIN) != E_OK,
        HandleFailData(fileInfos, dentryFailedOrigin, DENTRY_INFO_ORIGIN));

    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    migrateDatabaseNumber_ += rowNum;
    int32_t fileMoveCount = 0;
    int32_t videoFileMoveCount = 0;
    MoveMigrateCloudFile(fileInfos, fileMoveCount, videoFileMoveCount, sceneCode);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("singleCloud generate values cost %{public}ld, insert %{public}ld assets cost %{public}ld, insert"
        " photo related cost %{public}ld, and move %{public}ld files (%{public}ld + %{public}ld) cost %{public}ld.",
        (long)(startInsert - startGenerate), (long)rowNum, (long)(startInsertRelated - startInsert),
        (long)(startMove - startInsertRelated), (long)fileMoveCount, (long)(fileMoveCount - videoFileMoveCount),
        (long)videoFileMoveCount, (long)(end - startMove));
    MEDIA_INFO_LOG("singleCLoud  insert cloud end");
    return E_OK;
}

void CloneRestore::RestoreAudioBatch(int32_t offset)
{
    MEDIA_INFO_LOG("start restore audio, offset: %{public}d", offset);
    vector<FileInfo> fileInfos = QueryFileInfos(AudioColumn::AUDIOS_TABLE, offset);
    InsertAudio(fileInfos);
    MEDIA_INFO_LOG("end restore audio, offset: %{public}d", offset);
}

void CloneRestore::AddToPhotoInfoMaps(std::vector<FileInfo> &fileInfos)
{
    std::lock_guard<ffrt::mutex> lock(photosInfoMutex_);
    for (auto fileInfo: fileInfos) {
        PhotoInfo photoInfo;
        photoInfo.fileIdNew = fileInfo.fileIdNew;
        photoInfo.fileType = fileInfo.fileType;
        photoInfo.displayName = fileInfo.displayName;
        photoInfo.cloudPath = fileInfo.cloudPath;
        photoInfoMap_.insert(std::make_pair(fileInfo.fileIdOld, photoInfo));
    }
}

void CloneRestore::InsertPhotoRelated(vector<FileInfo> &fileInfos, int32_t sourceType)
{
    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    BatchQueryPhoto(fileInfos);
    AddToPhotoInfoMaps(fileInfos);
    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t mapRowNum = 0;
    BatchInsertMap(fileInfos, mapRowNum);
    migrateDatabaseMapNumber_ += mapRowNum;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("query new file_id cost %{public}ld, insert %{public}ld maps cost %{public}ld",
        (long)(startInsert - startQuery), (long)mapRowNum, (long)(end - startInsert));
}

void CloneRestore::SetFileIdReference(const vector<FileInfo> &fileInfos, string &selection,
    unordered_map<int32_t, int32_t> &fileIdMap)
{
    for (const auto &fileInfo : fileInfos) {
        if (fileInfo.fileIdOld <= 0 || fileInfo.fileIdNew <= 0) {
            continue;
        }
        BackupDatabaseUtils::UpdateSelection(selection, to_string(fileInfo.fileIdOld), false);
        fileIdMap[fileInfo.fileIdOld] = fileInfo.fileIdNew;
    }
}

int32_t CloneRestore::QueryMapTotalNumber(const string &baseQuerySql)
{
    string querySql = "SELECT count(1) as count FROM " + baseQuerySql;
    return BackupDatabaseUtils::QueryInt(mediaRdb_, querySql, CUSTOM_COUNT);
}

vector<MapInfo> CloneRestore::QueryMapInfos(const string &tableName, const string &baseQuerySql, int32_t offset,
    const unordered_map<int32_t, int32_t> &fileIdMap, const unordered_map<int32_t, int32_t> &albumIdMap)
{
    vector<MapInfo> mapInfos;
    mapInfos.reserve(CLONE_QUERY_COUNT);
    string columnMapAlbum = tableName + "." + PhotoMap::ALBUM_ID;
    string columnMapAsset = tableName + "." + PhotoMap::ASSET_ID;
    string querySql = "SELECT " + columnMapAlbum + ", " + columnMapAsset + " FROM " + baseQuerySql;
    querySql += " LIMIT " + to_string(offset) + ", " + to_string(CLONE_QUERY_COUNT);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, mapInfos, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t albumIdOld = GetInt32Val(columnMapAlbum, resultSet);
        int32_t fileIdOld = GetInt32Val(columnMapAsset, resultSet);
        if (albumIdOld <= 0 || albumIdMap.count(albumIdOld) == 0 || fileIdOld <= 0 || fileIdMap.count(fileIdOld) <= 0) {
            continue;
        }
        MapInfo mapInfo;
        mapInfo.albumId = albumIdMap.at(albumIdOld);
        mapInfo.fileId = fileIdMap.at(fileIdOld);
        mapInfos.emplace_back(mapInfo);
    }
    resultSet->Close();
    return mapInfos;
}

int64_t CloneRestore::InsertMapByTable(const string &tableName, const vector<MapInfo> &mapInfos,
    unordered_set<int32_t> &albumSet)
{
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(mapInfos);
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(tableName, values, rowNum);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, 0,
        "Batch insert map failed, errCode: %{public}d", errCode);
    for (const auto &mapInfo : mapInfos) {
        albumSet.insert(mapInfo.albumId);
    }
    return rowNum;
}

vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(const vector<MapInfo> &mapInfos)
{
    vector<NativeRdb::ValuesBucket> values;
    for (const auto &mapInfo : mapInfos) {
        NativeRdb::ValuesBucket value = GetInsertValue(mapInfo);
        values.emplace_back(value);
    }
    return values;
}

string CloneRestore::GetQueryWhereClauseByTable(const string &tableName)
{
    string whereClause;
    if (tableQueryWhereClauseMap_.count(tableName)) {
        whereClause += tableQueryWhereClauseMap_.at(tableName);
    }
    if (tableExtraQueryWhereClauseMap_.count(tableName)) {
        whereClause += whereClause.empty() ? "" : " AND " + tableExtraQueryWhereClauseMap_.at(tableName);
    }
    return whereClause;
}

void CloneRestore::SetSpecialAttributes(const string &tableName, const shared_ptr<NativeRdb::ResultSet> &resultSet,
    FileInfo &fileInfo)
{
    if (tableName != PhotoColumn::PHOTOS_TABLE) {
        return;
    }
    fileInfo.lPath = GetStringVal(PhotoAlbumColumns::ALBUM_LPATH, resultSet);
    fileInfo.sourcePath = GetStringVal(PhotoColumn::PHOTO_SOURCE_PATH, resultSet);
    fileInfo.orientation = GetInt32Val(PhotoColumn::PHOTO_ORIENTATION, resultSet);
    fileInfo.subtype = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
    fileInfo.associateFileId = GetInt32Val(PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, resultSet);
    fileInfo.photoQuality = GetInt32Val(PhotoColumn::PHOTO_QUALITY, resultSet);
    fileInfo.recycledTime = GetInt64Val(MediaColumn::MEDIA_DATE_TRASHED, resultSet);
    fileInfo.hidden = GetInt32Val(MediaColumn::MEDIA_HIDDEN, resultSet);
    // find PhotoAlbum info in target database. PackageName and BundleName should be fixed after clone.
    fileInfo.lPath = this->photosClone_.FindlPath(fileInfo);
    fileInfo.ownerAlbumId = this->photosClone_.FindAlbumId(fileInfo);
    fileInfo.packageName = this->photosClone_.FindPackageName(fileInfo);
    fileInfo.bundleName = this->photosClone_.FindBundleName(fileInfo);
    fileInfo.photoQuality = this->photosClone_.FindPhotoQuality(fileInfo);
    fileInfo.sourcePath = this->photosClone_.FindSourcePath(fileInfo);
    fileInfo.latitude = GetDoubleVal("latitude", resultSet);
    fileInfo.longitude = GetDoubleVal("longitude", resultSet);
}

bool CloneRestore::IsSameFileForClone(const string &tableName, FileInfo &fileInfo)
{
    CHECK_AND_RETURN_RET(tableName == PhotoColumn::PHOTOS_TABLE,
        IsSameAudioFile(mediaLibraryRdb_, tableName, fileInfo));
    PhotosDao::PhotosRowData rowData = this->photosClone_.FindSameFile(fileInfo);
    int32_t fileId = rowData.fileId;
    std::string cloudPath = rowData.data;
    bool cond = (fileId <= 0 || cloudPath.empty());
    CHECK_AND_RETURN_RET(!cond, false);
    // Meed extra check to determine whether or not to drop the duplicate file.
    return ExtraCheckForCloneSameFile(fileInfo, rowData);
}

void CloneRestore::RestoreFromGalleryPortraitAlbum()
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    RecordOldPortraitAlbumDfx();

    std::string querySql =   "SELECT count(1) AS count FROM " + ANALYSIS_ALBUM_TABLE + " WHERE ";
    std::string whereClause = "(" + SMARTALBUM_DB_ALBUM_TYPE + " = " + std::to_string(SMART) + " AND " +
        "album_subtype" + " = " + std::to_string(PORTRAIT) + ")";
    AppendExtraWhereClause(whereClause, ANALYSIS_ALBUM_TABLE);
    querySql += whereClause;

    int32_t totalNumber = BackupDatabaseUtils::QueryInt(mediaRdb_, querySql, CUSTOM_COUNT);
    MEDIA_INFO_LOG("QueryPortraitAlbum totalNumber = %{public}d", totalNumber);

    std::vector<std::string> commonColumn = BackupDatabaseUtils::GetCommonColumnInfos(mediaRdb_, mediaLibraryRdb_,
        ANALYSIS_ALBUM_TABLE);
    std::vector<std::string> commonColumns = BackupDatabaseUtils::filterColumns(commonColumn,
        EXCLUDED_PORTRAIT_COLUMNS);

    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        std::vector<AnalysisAlbumTbl> analysisAlbumTbl = QueryPortraitAlbumTbl(offset, commonColumns);
        for (const auto& album : analysisAlbumTbl) {
            if (album.tagId.has_value() && album.coverUri.has_value()) {
                coverUriInfo_.emplace_back(album.tagId.value(),
                    std::make_pair(album.coverUri.value(),
                    album.isCoverSatisfied.value_or(INVALID_COVER_SATISFIED_STATUS)));
            }
        }

        InsertPortraitAlbum(analysisAlbumTbl, maxAnalysisAlbumId_);
    }

    LogPortraitCloneDfx();
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    migratePortraitTotalTimeCost_ += end - start;
}

vector<AnalysisAlbumTbl> CloneRestore::QueryPortraitAlbumTbl(int32_t offset,
    const std::vector<std::string>& commonColumns)
{
    vector<AnalysisAlbumTbl> result;
    result.reserve(QUERY_COUNT);

    std::string inClause = BackupDatabaseUtils::JoinValues<string>(commonColumns, ", ");
    std::string querySql =
        "SELECT " + inClause +
        " FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE ";
    std::string whereClause = "(" +
        SMARTALBUM_DB_ALBUM_TYPE + " = " + std::to_string(SMART) + " AND " +
        "album_subtype" + " = " + std::to_string(PORTRAIT) + ")";
    AppendExtraWhereClause(whereClause, ANALYSIS_ALBUM_TABLE);
    querySql += whereClause;
    querySql += " LIMIT " + std::to_string(offset) + ", " + std::to_string(QUERY_COUNT);

    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AnalysisAlbumTbl analysisAlbumTbl;
        ParsePortraitAlbumResultSet(resultSet, analysisAlbumTbl);
        result.emplace_back(analysisAlbumTbl);
    }
    resultSet->Close();
    return result;
}

void CloneRestore::ParsePortraitAlbumResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    AnalysisAlbumTbl &analysisAlbumTbl)
{
    analysisAlbumTbl.albumType = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, ANALYSIS_COL_ALBUM_TYPE);
    analysisAlbumTbl.albumSubtype = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        ANALYSIS_COL_ALBUM_SUBTYPE);
    analysisAlbumTbl.albumName = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_COL_ALBUM_NAME);
    analysisAlbumTbl.coverUri = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_COL_COVER_URI);
    analysisAlbumTbl.tagId = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_COL_TAG_ID);
    analysisAlbumTbl.userOperation = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        ANALYSIS_COL_USER_OPERATION);
    analysisAlbumTbl.groupTag = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_COL_GROUP_TAG);
    analysisAlbumTbl.userDisplayLevel = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        ANALYSIS_COL_USER_DISPLAY_LEVEL);
    analysisAlbumTbl.isMe = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, ANALYSIS_COL_IS_ME);
    analysisAlbumTbl.isRemoved = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, ANALYSIS_COL_IS_REMOVED);
    analysisAlbumTbl.renameOperation = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        ANALYSIS_COL_RENAME_OPERATION);
    analysisAlbumTbl.isLocal = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, ANALYSIS_COL_IS_LOCAL);
    analysisAlbumTbl.isCoverSatisfied = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        ANALYSIS_COL_IS_COVER_SATISFIED);
}

void CloneRestore::ParseFaceTagResultSet(const std::shared_ptr<NativeRdb::ResultSet>& resultSet, FaceTagTbl& faceTagTbl)
{
    faceTagTbl.tagId = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FACE_TAG_COL_TAG_ID);
    faceTagTbl.tagName = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FACE_TAG_COL_TAG_NAME);
    faceTagTbl.groupTag = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FACE_TAG_COL_GROUP_TAG);
    faceTagTbl.centerFeatures = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        FACE_TAG_COL_CENTER_FEATURES);
    faceTagTbl.tagVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, FACE_TAG_COL_TAG_VERSION);
    faceTagTbl.analysisVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        FACE_TAG_COL_ANALYSIS_VERSION);
}

void CloneRestore::InsertPortraitAlbum(std::vector<AnalysisAlbumTbl> &analysisAlbumTbl, int64_t maxAlbumId)
{
    CHECK_AND_RETURN_LOG(mediaLibraryRdb_ != nullptr, "mediaLibraryRdb_ is null");
    CHECK_AND_RETURN_LOG(!analysisAlbumTbl.empty(), "analysisAlbumTbl are empty");

    std::vector<std::string> albumNames;
    std::vector<std::string> tagIds;

    for (const auto &album : analysisAlbumTbl) {
        CHECK_AND_EXECUTE(!album.albumName.has_value(), albumNames.emplace_back(album.albumName.value()));
        CHECK_AND_EXECUTE(!album.tagId.has_value(), tagIds.emplace_back(album.tagId.value()));
    }
    MEDIA_INFO_LOG("Total albums: %{public}zu, Albums with names: %{public}zu, Albums with tagIds: %{public}zu",
                   analysisAlbumTbl.size(), albumNames.size(), tagIds.size());

    CHECK_AND_RETURN_LOG(BackupDatabaseUtils::DeleteDuplicatePortraitAlbum(maxAlbumId, albumNames,
        tagIds, mediaLibraryRdb_), "Batch delete failed.");

    int32_t albumRowNum = InsertPortraitAlbumByTable(analysisAlbumTbl);
    CHECK_AND_PRINT_LOG(albumRowNum != E_ERR, "Failed to insert album");

    migratePortraitAlbumNumber_ += static_cast<uint64_t>(albumRowNum);
    return;
}

int32_t CloneRestore::InsertPortraitAlbumByTable(std::vector<AnalysisAlbumTbl> &analysisAlbumTbl)
{
    std::vector<NativeRdb::ValuesBucket> valuesBuckets = GetInsertValues(analysisAlbumTbl);

    int64_t rowNum = 0;
    int32_t ret = BatchInsertWithRetry(ANALYSIS_ALBUM_TABLE, valuesBuckets, rowNum);
    CHECK_AND_RETURN_RET(ret == E_OK, E_ERR);
    return rowNum;
}

std::vector<NativeRdb::ValuesBucket> CloneRestore::GetInsertValues(std::vector<AnalysisAlbumTbl> &analysisAlbumTbl)
{
    std::vector<NativeRdb::ValuesBucket> values;
    for (auto &portraitAlbumInfo : analysisAlbumTbl) {
        NativeRdb::ValuesBucket value = GetInsertValue(portraitAlbumInfo);
        values.emplace_back(value);
    }
    return values;
}

NativeRdb::ValuesBucket CloneRestore::GetInsertValue(const AnalysisAlbumTbl &portraitAlbumInfo)
{
    NativeRdb::ValuesBucket values;

    PutIfPresent(values, ANALYSIS_COL_ALBUM_TYPE, portraitAlbumInfo.albumType);
    PutIfPresent(values, ANALYSIS_COL_ALBUM_SUBTYPE, portraitAlbumInfo.albumSubtype);
    PutIfPresent(values, ANALYSIS_COL_ALBUM_NAME, portraitAlbumInfo.albumName);
    PutIfPresent(values, ANALYSIS_COL_TAG_ID, portraitAlbumInfo.tagId);
    PutIfPresent(values, ANALYSIS_COL_USER_OPERATION, portraitAlbumInfo.userOperation);
    PutIfPresent(values, ANALYSIS_COL_GROUP_TAG, portraitAlbumInfo.groupTag);
    PutIfPresent(values, ANALYSIS_COL_USER_DISPLAY_LEVEL, portraitAlbumInfo.userDisplayLevel);
    PutIfPresent(values, ANALYSIS_COL_IS_ME, portraitAlbumInfo.isMe);
    PutIfPresent(values, ANALYSIS_COL_IS_REMOVED, portraitAlbumInfo.isRemoved);
    PutIfPresent(values, ANALYSIS_COL_RENAME_OPERATION, portraitAlbumInfo.renameOperation);
    PutIfPresent(values, ANALYSIS_COL_IS_LOCAL, portraitAlbumInfo.isLocal);

    return values;
}

NativeRdb::ValuesBucket CloneRestore::CreateValuesBucketFromFaceTagTbl(const FaceTagTbl& faceTagTbl)
{
    NativeRdb::ValuesBucket values;

    PutIfPresent(values, FACE_TAG_COL_TAG_ID, faceTagTbl.tagId);
    PutIfPresent(values, FACE_TAG_COL_TAG_NAME, faceTagTbl.tagName);
    PutIfPresent(values, FACE_TAG_COL_CENTER_FEATURES, faceTagTbl.centerFeatures);
    PutIfPresent(values, FACE_TAG_COL_TAG_VERSION, faceTagTbl.tagVersion);
    PutIfPresent(values, FACE_TAG_COL_ANALYSIS_VERSION, faceTagTbl.analysisVersion);

    return values;
}

std::vector<PortraitAlbumDfx> CloneRestore::QueryAllPortraitAlbum(int32_t& offset, int32_t& rowCount)
{
    std::vector<PortraitAlbumDfx> result;
    result.reserve(QUERY_COUNT);

    const std::string querySql = "SELECT album_name, cover_uri, tag_id, count "
        "FROM AnalysisAlbum "
        "WHERE album_type = ? "
        "AND album_subtype = ? "
        "LIMIT ?, ?";

    std::vector<NativeRdb::ValueObject> bindArgs = { SMART, PORTRAIT, offset, QUERY_COUNT };
    CHECK_AND_RETURN_RET_LOG(this->mediaRdb_ != nullptr, result, "Media_Restore: mediaRdb_ is null.");
    auto resultSet = mediaRdb_->QuerySql(querySql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PortraitAlbumDfx dfxInfo;
        dfxInfo.albumName = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_COL_ALBUM_NAME);
        dfxInfo.coverUri = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_COL_COVER_URI);
        dfxInfo.tagId = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_COL_TAG_ID);
        dfxInfo.count = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, ANALYSIS_COL_COUNT);

        result.push_back(dfxInfo);
    }
    resultSet->GetRowCount(rowCount);
    return result;
}

void CloneRestore::RecordOldPortraitAlbumDfx()
{
    int32_t offset {0};
    int32_t rowCount {0};
    std::vector<PortraitAlbumDfx> albums;

    do {
        auto batchResults =  QueryAllPortraitAlbum(offset, rowCount);
        if (!batchResults.empty()) {
            albums.insert(albums.end(), batchResults.begin(), batchResults.end());
        }

        offset += QUERY_COUNT;
    } while (rowCount > 0);

    for (const auto& album : albums) {
        PortraitAlbumDfx dfxInfo;
        if (album.albumName.has_value()) {
            dfxInfo.albumName = album.albumName.value();
        }
        if (album.coverUri.has_value()) {
            auto uriParts = BackupDatabaseUtils::SplitString(album.coverUri.value(), '/');
            if (uriParts.size() >= COVER_URI_NUM) {
                std::string fileName = uriParts[uriParts.size() - 1];
                dfxInfo.coverUri = BackupFileUtils::GarbleFileName(fileName);
            }
        }
        if (album.tagId.has_value()) {
            dfxInfo.tagId = album.tagId.value();
        }
        if (album.count.has_value()) {
            dfxInfo.count = album.count.value();
        }

        portraitAlbumDfx_.push_back(dfxInfo);
    }
}

std::unordered_set<std::string> CloneRestore::QueryAllPortraitAlbum()
{
    std::unordered_set<std::string> result;
    std::vector<std::string> tagIds;
    for (const auto& oldAlbum : portraitAlbumDfx_) {
        if (oldAlbum.tagId.has_value()) {
            tagIds.push_back(oldAlbum.tagId.value());
        }
    }

    CHECK_AND_RETURN_RET_LOG(!tagIds.empty(), result, "No valid tag_ids found in old albums");

    std::string querySql = "SELECT tag_id FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE tag_id IN (" + BackupDatabaseUtils::JoinSQLValues<string>(tagIds, ", ") + ")";

    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");

    std::string dfxInfo;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        dfxInfo =
            BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, ANALYSIS_COL_TAG_ID).value_or("");
        result.insert(dfxInfo);
    }

    resultSet->Close();
    return result;
}

void CloneRestore::LogPortraitCloneDfx()
{
    std::vector<std::string> failedAlbums;
    std::unordered_set<std::string> existingTagIds = QueryAllPortraitAlbum();

    for (const auto& oldAlbum : portraitAlbumDfx_) {
        if (!oldAlbum.tagId.has_value()) {
            continue;
        }

        if (existingTagIds.find(oldAlbum.tagId.value()) == existingTagIds.end()) {
            std::string albumInfo = "Album: " + oldAlbum.albumName.value_or("Unknown") +
                ", TagId: " + oldAlbum.tagId.value() +
                ", Cover: " + oldAlbum.coverUri.value_or("Unknown") +
                ", Count: " + std::to_string(oldAlbum.count.value_or(0));
            failedAlbums.push_back(albumInfo);
        }
    }

    if (!failedAlbums.empty()) {
        MEDIA_ERR_LOG("Following portrait albums failed to clone completely:");
        for (const auto& failedAlbum : failedAlbums) {
            MEDIA_ERR_LOG("%{public}s", failedAlbum.c_str());
        }
    } else {
        MEDIA_INFO_LOG("All portrait albums cloned successfully");
    }

    MEDIA_INFO_LOG("Stat: Total albums: %{public}zu, Failed albums count: %{public}zu",
        portraitAlbumDfx_.size(), failedAlbums.size());
}

void CloneRestore::RestorePortraitClusteringInfo()
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t totalNumber = BackupDatabaseUtils::QueryInt(mediaRdb_, QUERY_FACE_TAG_COUNT, CUSTOM_COUNT);
    MEDIA_INFO_LOG("QueryPortraitClustering totalNumber = %{public}d", totalNumber);

    std::vector<std::string> commonColumn = BackupDatabaseUtils::GetCommonColumnInfos(mediaRdb_, mediaLibraryRdb_,
        VISION_FACE_TAG_TABLE);
    std::vector<std::string> commonColumns = BackupDatabaseUtils::filterColumns(commonColumn,
        EXCLUDED_FACE_TAG_COLUMNS);
    BackupDatabaseUtils::LeftJoinValues<string>(commonColumns, "vft.");
    std::string inClause = BackupDatabaseUtils::JoinValues<string>(commonColumns, ", ");
    BackupDatabaseUtils::ExecuteSQL(mediaRdb_, CREATE_FACE_TAG_INDEX);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        vector<FaceTagTbl> faceTagTbls = QueryFaceTagTbl(offset, inClause);
        BatchInsertFaceTags(faceTagTbls);
        if (static_cast<std::int32_t>(faceTagTbls.size()) < QUERY_COUNT) {
            break;
        }
    }
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    migratePortraitTotalTimeCost_ += end - start;
}

std::vector<FaceTagTbl> CloneRestore::QueryFaceTagTbl(int32_t offset, const std::string &inClause)
{
    std::vector<FaceTagTbl> result;

    std::string querySql = "SELECT DISTINCT " + inClause +
        " FROM " + VISION_FACE_TAG_TABLE + " vft" +
        " LEFT JOIN AnalysisAlbum aa ON aa.tag_id = vft.tag_id" +
        " LEFT JOIN AnalysisPhotoMap apm ON aa.album_id = apm.map_album" +
        " LEFT JOIN Photos ph ON ph.file_id = apm.map_asset" +
        " WHERE " +
        (IsCloudRestoreSatisfied() ? "ph.position IN (1, 2, 3)" : "ph.position IN (1, 3)");

    querySql += " LIMIT " + std::to_string(offset) + ", " + std::to_string(QUERY_COUNT);

    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSet is null.");
    int resultRowCount = 0;
    resultSet->GetRowCount(resultRowCount);
    result.reserve(resultRowCount);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FaceTagTbl faceTagTbl;
        ParseFaceTagResultSet(resultSet, faceTagTbl);
        result.emplace_back(faceTagTbl);
    }

    resultSet->Close();
    return result;
}

void CloneRestore::BatchInsertFaceTags(const std::vector<FaceTagTbl>& faceTagTbls)
{
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (const auto& faceTagTbl : faceTagTbls) {
        valuesBuckets.push_back(CreateValuesBucketFromFaceTagTbl(faceTagTbl));
    }

    int64_t rowNum = 0;
    int32_t ret = BatchInsertWithRetry(VISION_FACE_TAG_TABLE, valuesBuckets, rowNum);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to batch insert face tags");
}

void CloneRestore::RestoreImageFaceInfo(std::vector<FileInfo> &fileInfos)
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    auto uniqueFileIdPairs = BackupDatabaseUtils::CollectFileIdPairs(fileInfos);
    auto [oldFileIds, newFileIds] = BackupDatabaseUtils::UnzipFileIdPairs(uniqueFileIdPairs);

    std::string fileIdOldInClause = "(" + BackupDatabaseUtils::JoinValues<int>(oldFileIds, ", ") + ")";

    std::string querySql = QUERY_IMAGE_FACE_COUNT;
    querySql += " WHERE " + IMAGE_FACE_COL_FILE_ID + " IN " + fileIdOldInClause;
    int32_t totalNumber = BackupDatabaseUtils::QueryInt(mediaRdb_, querySql, CUSTOM_COUNT);
    MEDIA_INFO_LOG("QueryImageFaceTotalNumber, totalNumber = %{public}d", totalNumber);
    if (totalNumber == 0) {
        int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
        migratePortraitTotalTimeCost_ += end - start;
        return;
    }

    std::vector<std::string> commonColumn = BackupDatabaseUtils::GetCommonColumnInfos(mediaRdb_, mediaLibraryRdb_,
        VISION_IMAGE_FACE_TABLE);
    std::vector<std::string> commonColumns = BackupDatabaseUtils::filterColumns(commonColumn,
        EXCLUDED_IMAGE_FACE_COLUMNS);

    BackupDatabaseUtils::DeleteExistingImageFaceData(mediaLibraryRdb_, uniqueFileIdPairs);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        std::vector<ImageFaceTbl> imageFaceTbls = QueryImageFaceTbl(offset, fileIdOldInClause, commonColumns);
        auto imageFaces = ProcessImageFaceTbls(imageFaceTbls, uniqueFileIdPairs);
        BatchInsertImageFaces(imageFaces);
    }

    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    migratePortraitTotalTimeCost_ += end - start;

    GenNewCoverUris(coverUriInfo_, fileInfos);
}

std::vector<ImageFaceTbl> CloneRestore::QueryImageFaceTbl(int32_t offset, std::string &fileIdClause,
    const std::vector<std::string> &commonColumns)
{
    std::vector<ImageFaceTbl> result;
    result.reserve(QUERY_COUNT);

    std::string inClause = BackupDatabaseUtils::JoinValues<string>(commonColumns, ", ");
    std::string querySql =
        "SELECT " + inClause +
        " FROM " + VISION_IMAGE_FACE_TABLE;
    querySql += " WHERE " + IMAGE_FACE_COL_FILE_ID + " IN " + fileIdClause;
    querySql += " LIMIT " + std::to_string(offset) + ", " + std::to_string(QUERY_COUNT);

    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSet is null.");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        ImageFaceTbl imageFaceTbl;
        ParseImageFaceResultSet(resultSet, imageFaceTbl);
        result.emplace_back(imageFaceTbl);
    }

    resultSet->Close();
    return result;
}

bool CloneRestore::GetFileInfoByFileId(int32_t fileId, const std::vector<FileInfo>& fileInfos, FileInfo& outFileInfo)
{
    auto it = std::find_if(fileInfos.begin(), fileInfos.end(),
        [fileId](const FileInfo& info) { return info.fileIdNew == fileId; });
    if (it != fileInfos.end()) {
        outFileInfo = *it;
        return true;
    }

    return false;
}

void CloneRestore::GenNewCoverUris(const std::vector<CloneRestore::CoverUriInfo>& coverUriInfo,
    std::vector<FileInfo> &fileInfos)
{
    bool cond = (coverUriInfo.empty() && fileInfos.empty());
    CHECK_AND_RETURN_LOG(!cond, "Empty coverUriInfo or fileIdPairs, skipping.");

    std::unordered_map<std::string, std::pair<std::string, int32_t>> tagIdToCoverInfo;
    for (const auto& [tagId, coverInfo] : coverUriInfo) {
        tagIdToCoverInfo[tagId] = coverInfo;
    }

    auto fileIdPairs = BackupDatabaseUtils::CollectFileIdPairs(fileInfos);
    std::unordered_map<std::string, int32_t> oldToNewFileId;
    for (const auto& [oldId, newId] : fileIdPairs) {
        oldToNewFileId[std::to_string(oldId)] = newId;
    }

    std::vector<std::string> tagIds;
    std::string updateSql = GenCoverUriUpdateSql(tagIdToCoverInfo, oldToNewFileId, fileInfos, tagIds);
    if (updateSql.empty()) {
        return;
    }

    BackupDatabaseUtils::ExecuteSQL(mediaLibraryRdb_, updateSql);
}

std::string CloneRestore::GenCoverUriUpdateSql(const std::unordered_map<std::string, std::pair<std::string, int32_t>>&
    tagIdToCoverInfo, const std::unordered_map<std::string, int32_t>& oldToNewFileId,
    const std::vector<FileInfo>& fileInfos, std::vector<std::string>& tagIds)
{
    std::unordered_map<std::string, std::string> coverUriUpdates;
    std::unordered_map<std::string, int32_t> isCoverSatisfiedUpdates;

    for (const auto& [tagId, coverInfo] : tagIdToCoverInfo) {
        const auto& [oldCoverUri, isCoverSatisfied] = coverInfo;
        std::string newUri = ProcessUriAndGenNew(tagId, oldCoverUri, oldToNewFileId, fileInfos);
        if (!newUri.empty()) {
            coverUriUpdates[tagId] = newUri;
            isCoverSatisfiedUpdates[tagId] = isCoverSatisfied;
            tagIds.push_back(tagId);
        }
    }

    bool cond = (coverUriUpdates.empty() || isCoverSatisfiedUpdates.empty());
    CHECK_AND_RETURN_RET(!cond, "");

    std::string updateSql = "UPDATE AnalysisAlbum SET ";

    updateSql += "cover_uri = CASE ";
    for (const auto& [tagId, newUri] : coverUriUpdates) {
        updateSql += "WHEN tag_id = '" + tagId + "' THEN '" + newUri + "' ";
    }
    updateSql += "ELSE cover_uri END";

    bool hasValidIsCoverSatisfied = false;
    std::string isCoverSatisfiedSql = ", is_cover_satisfied = CASE ";
    for (const auto& [tagId, isCoverSatisfied] : isCoverSatisfiedUpdates) {
        if (isCoverSatisfied != INVALID_COVER_SATISFIED_STATUS) {
            hasValidIsCoverSatisfied = true;
            isCoverSatisfiedSql += "WHEN tag_id = '" + tagId + "' THEN " + std::to_string(isCoverSatisfied) + " ";
        }
    }

    isCoverSatisfiedSql += "ELSE is_cover_satisfied END ";
    CHECK_AND_EXECUTE(!hasValidIsCoverSatisfied, updateSql += isCoverSatisfiedSql);

    updateSql += "WHERE tag_id IN ('" +
        BackupDatabaseUtils::JoinValues(tagIds, "','") + "')";

    return updateSql;
}

std::string CloneRestore::ProcessUriAndGenNew(const std::string& tagId, const std::string& oldCoverUri,
    const std::unordered_map<std::string, int32_t>& oldToNewFileId, const std::vector<FileInfo>& fileInfos)
{
    auto uriParts = BackupDatabaseUtils::SplitString(oldCoverUri, '/');
    if (uriParts.size() >= COVER_URI_NUM) {
        std::string fileIdOld = uriParts[uriParts.size() - 3];
        auto it = oldToNewFileId.find(fileIdOld);
        if (it != oldToNewFileId.end()) {
            int32_t fileIdNew = it->second;
            FileInfo fileInfo {};
            if (GetFileInfoByFileId(fileIdNew, fileInfos, fileInfo)) {
                std::string extraUri = MediaFileUtils::GetExtraUri(fileInfo.displayName, fileInfo.cloudPath);
                return MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX,
                    std::to_string(fileIdNew), extraUri);
            }
        }
    }
    return "";
}

std::vector<ImageFaceTbl> CloneRestore::ProcessImageFaceTbls(const std::vector<ImageFaceTbl>& imageFaceTbls,
    const std::vector<FileIdPair>& fileIdPairs)
{
    CHECK_AND_RETURN_RET_LOG(!imageFaceTbls.empty(), {}, "image faces tbl empty");

    std::vector<ImageFaceTbl> imageFaceNewTbls;
    imageFaceNewTbls.reserve(imageFaceTbls.size());

    for (const auto& imageFaceTbl : imageFaceTbls) {
        if (imageFaceTbl.fileId.has_value()) {
            int32_t oldFileId = imageFaceTbl.fileId.value();
            auto it = std::find_if(fileIdPairs.begin(), fileIdPairs.end(),
                [oldFileId](const FileIdPair& pair) { return pair.first == oldFileId; });
            if (it != fileIdPairs.end()) {
                ImageFaceTbl updatedFace = imageFaceTbl;
                updatedFace.fileId = it->second;
                imageFaceNewTbls.push_back(std::move(updatedFace));
            }
        }
    }

    return imageFaceNewTbls;
}

void CloneRestore::BatchInsertImageFaces(const std::vector<ImageFaceTbl>& imageFaceTbls)
{
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    std::unordered_set<int32_t> fileIdSet;
    for (const auto& imageFaceTbl : imageFaceTbls) {
        valuesBuckets.push_back(CreateValuesBucketFromImageFaceTbl(imageFaceTbl));
    }

    int64_t rowNum = 0;
    int32_t ret = BatchInsertWithRetry(VISION_IMAGE_FACE_TABLE, valuesBuckets, rowNum);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to batch insert image faces");

    for (const auto& imageFaceTbl : imageFaceTbls) {
        if (imageFaceTbl.fileId.has_value()) {
            fileIdSet.insert(imageFaceTbl.fileId.value());
        }
    }

    migratePortraitFaceNumber_ += rowNum;
    migratePortraitPhotoNumber_ += fileIdSet.size();
}

NativeRdb::ValuesBucket CloneRestore::CreateValuesBucketFromImageFaceTbl(const ImageFaceTbl& imageFaceTbl)
{
    NativeRdb::ValuesBucket values;

    PutIfPresent(values, IMAGE_FACE_COL_FILE_ID, imageFaceTbl.fileId);
    PutIfPresent(values, IMAGE_FACE_COL_FACE_ID, imageFaceTbl.faceId);
    PutIfPresent(values, IMAGE_FACE_COL_TAG_ID, imageFaceTbl.tagId);
    PutIfPresent(values, IMAGE_FACE_COL_SCALE_X, imageFaceTbl.scaleX);
    PutIfPresent(values, IMAGE_FACE_COL_SCALE_Y, imageFaceTbl.scaleY);
    PutIfPresent(values, IMAGE_FACE_COL_SCALE_WIDTH, imageFaceTbl.scaleWidth);
    PutIfPresent(values, IMAGE_FACE_COL_SCALE_HEIGHT, imageFaceTbl.scaleHeight);
    PutIfPresent(values, IMAGE_FACE_COL_LANDMARKS, imageFaceTbl.landmarks);
    PutIfPresent(values, IMAGE_FACE_COL_PITCH, imageFaceTbl.pitch);
    PutIfPresent(values, IMAGE_FACE_COL_YAW, imageFaceTbl.yaw);
    PutIfPresent(values, IMAGE_FACE_COL_ROLL, imageFaceTbl.roll);
    PutIfPresent(values, IMAGE_FACE_COL_PROB, imageFaceTbl.prob);
    PutIfPresent(values, IMAGE_FACE_COL_TOTAL_FACES, imageFaceTbl.totalFaces);
    PutIfPresent(values, IMAGE_FACE_COL_FACE_VERSION, imageFaceTbl.faceVersion);
    PutIfPresent(values, IMAGE_FACE_COL_FEATURES_VERSION, imageFaceTbl.featuresVersion);
    PutIfPresent(values, IMAGE_FACE_COL_FEATURES, imageFaceTbl.features);
    PutIfPresent(values, IMAGE_FACE_COL_FACE_OCCLUSION, imageFaceTbl.faceOcclusion);
    PutIfPresent(values, IMAGE_FACE_COL_ANALYSIS_VERSION, imageFaceTbl.analysisVersion);
    PutIfPresent(values, IMAGE_FACE_COL_BEAUTY_BOUNDER_X, imageFaceTbl.beautyBounderX);
    PutIfPresent(values, IMAGE_FACE_COL_BEAUTY_BOUNDER_Y, imageFaceTbl.beautyBounderY);
    PutIfPresent(values, IMAGE_FACE_COL_BEAUTY_BOUNDER_WIDTH, imageFaceTbl.beautyBounderWidth);
    PutIfPresent(values, IMAGE_FACE_COL_BEAUTY_BOUNDER_HEIGHT, imageFaceTbl.beautyBounderHeight);
    PutIfPresent(values, IMAGE_FACE_COL_AESTHETICS_SCORE, imageFaceTbl.aestheticsScore);
    PutIfPresent(values, IMAGE_FACE_COL_BEAUTY_BOUNDER_VERSION, imageFaceTbl.beautyBounderVersion);
    PutWithDefault<int>(values, IMAGE_FACE_COL_IS_EXCLUDED, imageFaceTbl.isExcluded, 0);
    PutIfPresent(values, IMAGE_FACE_COL_FACE_CLARITY, imageFaceTbl.faceClarity);
    PutIfPresent(values, IMAGE_FACE_COL_FACE_LUMINANCE, imageFaceTbl.faceLuminance);
    PutIfPresent(values, IMAGE_FACE_COL_FACE_SATURATION, imageFaceTbl.faceSaturation);
    PutIfPresent(values, IMAGE_FACE_COL_FACE_EYE_CLOSE, imageFaceTbl.faceEyeClose);
    PutIfPresent(values, IMAGE_FACE_COL_FACE_EXPRESSION, imageFaceTbl.faceExpression);
    PutIfPresent(values, IMAGE_FACE_COL_PREFERRED_GRADE, imageFaceTbl.preferredGrade);
    PutIfPresent(values, IMAGE_FACE_COL_JOINT_BEAUTY_BOUNDER_X, imageFaceTbl.jointBeautyBounderX);
    PutIfPresent(values, IMAGE_FACE_COL_JOINT_BEAUTY_BOUNDER_Y, imageFaceTbl.jointBeautyBounderY);
    PutIfPresent(values, IMAGE_FACE_COL_JOINT_BEAUTY_BOUNDER_WIDTH, imageFaceTbl.jointBeautyBounderWidth);
    PutIfPresent(values, IMAGE_FACE_COL_JOINT_BEAUTY_BOUNDER_HEIGHT, imageFaceTbl.jointBeautyBounderHeight);
    PutIfPresent(values, IMAGE_FACE_COL_GROUP_VERSION, imageFaceTbl.groupVersion);
    return values;
}

void ParseImageFaceResultSet1(const std::shared_ptr<NativeRdb::ResultSet>& resultSet, ImageFaceTbl& imageFaceTbl)
{
    imageFaceTbl.preferredGrade = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        IMAGE_FACE_COL_PREFERRED_GRADE);
    imageFaceTbl.jointBeautyBounderX = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_JOINT_BEAUTY_BOUNDER_X);
    imageFaceTbl.jointBeautyBounderY = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_JOINT_BEAUTY_BOUNDER_Y);
    imageFaceTbl.jointBeautyBounderWidth = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_JOINT_BEAUTY_BOUNDER_WIDTH);
    imageFaceTbl.jointBeautyBounderHeight = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_JOINT_BEAUTY_BOUNDER_HEIGHT);
    imageFaceTbl.groupVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        IMAGE_FACE_COL_GROUP_VERSION);
}

void CloneRestore::ParseImageFaceResultSet(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    ImageFaceTbl& imageFaceTbl)
{
    imageFaceTbl.fileId = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, IMAGE_FACE_COL_FILE_ID);
    imageFaceTbl.faceId = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, IMAGE_FACE_COL_FACE_ID);
    imageFaceTbl.tagId = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, IMAGE_FACE_COL_TAG_ID);
    imageFaceTbl.scaleX = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_SCALE_X);
    imageFaceTbl.scaleY = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_SCALE_Y);
    imageFaceTbl.scaleWidth = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_SCALE_WIDTH);
    imageFaceTbl.scaleHeight = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_SCALE_HEIGHT);
    imageFaceTbl.landmarks = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet, IMAGE_FACE_COL_LANDMARKS);
    imageFaceTbl.pitch = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_PITCH);
    imageFaceTbl.yaw = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_YAW);
    imageFaceTbl.roll = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_ROLL);
    imageFaceTbl.prob = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_PROB);
    imageFaceTbl.totalFaces = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, IMAGE_FACE_COL_TOTAL_FACES);
    imageFaceTbl.faceVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        IMAGE_FACE_COL_FACE_VERSION);
    imageFaceTbl.featuresVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        IMAGE_FACE_COL_FEATURES_VERSION);
    imageFaceTbl.features = BackupDatabaseUtils::GetOptionalValue<std::vector<uint8_t>>(resultSet,
        IMAGE_FACE_COL_FEATURES);
    imageFaceTbl.faceOcclusion = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        IMAGE_FACE_COL_FACE_OCCLUSION);
    imageFaceTbl.analysisVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        IMAGE_FACE_COL_ANALYSIS_VERSION);
    imageFaceTbl.beautyBounderX = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_BEAUTY_BOUNDER_X);
    imageFaceTbl.beautyBounderY = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_BEAUTY_BOUNDER_Y);
    imageFaceTbl.beautyBounderWidth = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_BEAUTY_BOUNDER_WIDTH);
    imageFaceTbl.beautyBounderHeight = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_BEAUTY_BOUNDER_HEIGHT);
    imageFaceTbl.aestheticsScore = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_AESTHETICS_SCORE);
    imageFaceTbl.beautyBounderVersion = BackupDatabaseUtils::GetOptionalValue<std::string>(resultSet,
        IMAGE_FACE_COL_BEAUTY_BOUNDER_VERSION);
    imageFaceTbl.isExcluded = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet, IMAGE_FACE_COL_IS_EXCLUDED);
    imageFaceTbl.faceClarity = BackupDatabaseUtils::GetOptionalValue<double>(resultSet, IMAGE_FACE_COL_FACE_CLARITY);
    imageFaceTbl.faceLuminance = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_FACE_LUMINANCE);
    imageFaceTbl.faceSaturation = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_FACE_SATURATION);
    imageFaceTbl.faceEyeClose = BackupDatabaseUtils::GetOptionalValue<int32_t>(resultSet,
        IMAGE_FACE_COL_FACE_EYE_CLOSE);
    imageFaceTbl.faceExpression = BackupDatabaseUtils::GetOptionalValue<double>(resultSet,
        IMAGE_FACE_COL_FACE_EXPRESSION);
    ParseImageFaceResultSet1(resultSet, imageFaceTbl);
}

void CloneRestore::ReportPortraitCloneStat(int32_t sceneCode)
{
    CHECK_AND_RETURN_LOG(sceneCode == CLONE_RESTORE_ID, "err scenecode %{public}d", sceneCode);

    MEDIA_INFO_LOG("PortraitStat: album %{public}lld, photo %{public}lld, face %{public}lld, cost %{public}lld",
        (long long)migratePortraitAlbumNumber_, (long long)migratePortraitPhotoNumber_,
        (long long)migratePortraitFaceNumber_, (long long)migratePortraitTotalTimeCost_);

    BackupDfxUtils::PostPortraitStat(static_cast<uint32_t>(migratePortraitAlbumNumber_), migratePortraitPhotoNumber_,
        migratePortraitFaceNumber_, migratePortraitTotalTimeCost_);
}

void CloneRestore::AppendExtraWhereClause(std::string& whereClause, const std::string& tableName)
{
    auto it = tableExtraQueryWhereClauseMap_.find(tableName);
    if (it != tableExtraQueryWhereClauseMap_.end()) {
        whereClause += whereClause.empty() ? "" : " AND ";
        whereClause += it->second;
    }
}

bool CloneRestore::InitAllKvStore()
{
    std::string oldBaseDir = backupRestoreDir_ + CLONE_KVDB_BACKUP_DIR;
    std::string newBaseDir = MEDIA_KVDB_DIR;
    oldMonthKvStorePtr_ = MediaLibraryKvStoreManager::GetInstance()
        .GetSingleKvStore(KvStoreRoleType::OWNER, CLONE_KVSTORE_MONTH_STOREID, oldBaseDir);
    oldYearKvStorePtr_ = MediaLibraryKvStoreManager::GetInstance()
        .GetSingleKvStore(KvStoreRoleType::OWNER, CLONE_KVSTORE_YEAR_STOREID, oldBaseDir);
    newMonthKvStorePtr_ = MediaLibraryKvStoreManager::GetInstance()
        .GetSingleKvStore(KvStoreRoleType::OWNER, MEDIA_KVSTORE_MONTH_STOREID, newBaseDir);
    newYearKvStorePtr_ = MediaLibraryKvStoreManager::GetInstance()
        .GetSingleKvStore(KvStoreRoleType::OWNER, MEDIA_KVSTORE_YEAR_STOREID, newBaseDir);

    bool cond = (oldMonthKvStorePtr_ == nullptr || oldYearKvStorePtr_ == nullptr ||
        newMonthKvStorePtr_ == nullptr || newYearKvStorePtr_ == nullptr);
    CHECK_AND_RETURN_RET_LOG(!cond, false, "Init all kvstore failed");
    return true;
}

void CloneRestore::CloseAllKvStore()
{
    oldMonthKvStorePtr_ != nullptr && oldMonthKvStorePtr_->Close();
    oldYearKvStorePtr_ != nullptr && oldYearKvStorePtr_->Close();
    newMonthKvStorePtr_ != nullptr && newMonthKvStorePtr_->Close();
    newYearKvStorePtr_ != nullptr && newYearKvStorePtr_->Close();
}

void CloneRestore::StartBackup()
{
    MEDIA_INFO_LOG("Start clone backup");
    bool cond = (!BackupKvStore() && !MediaFileUtils::DeleteDir(CLONE_KVDB_BACKUP_DIR));
    CHECK_AND_PRINT_LOG(!cond, "BackupKvStore failed and delete old backup kvdb failed, errno:%{public}d", errno);
    MEDIA_INFO_LOG("End clone backup");
}

void CloneRestore::InheritManualCover()
{
    std::string querySql = "SELECT album_id, cover_uri, cover_uri_source, cover_cloud_id"
        " FROM PhotoAlbum WHERE cover_uri_source > 0";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaRdb_, querySql);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Query resultSql is null.");

    vector<AlbumCoverInfo> albumCoverinfos;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AlbumCoverInfo albumCoverInfo;
        int32_t albumIdOld = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        string coverUriOld = GetStringVal(PhotoAlbumColumns::ALBUM_COVER_URI, resultSet);
        int32_t fileIdOld = atoi(MediaLibraryDataManagerUtils::GetFileIdFromPhotoUri(coverUriOld).c_str());
        int32_t coverUriSourceOld = GetInt32Val(PhotoAlbumColumns::COVER_URI_SOURCE, resultSet);
        string coverCloudIdOld = GetStringVal(PhotoAlbumColumns::COVER_CLOUD_ID, resultSet);

        int32_t albumIdNew = tableAlbumIdMap_[PhotoAlbumColumns::TABLE][albumIdOld];
        auto photoInfo = photoInfoMap_[fileIdOld];
        int32_t fileIdNew = photoInfo.fileIdNew;
        string coverUriNew = MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileIdNew),
            MediaFileUtils::GetExtraUri(photoInfo.displayName, photoInfo.cloudPath));
        albumCoverInfo.albumId = albumIdNew;
        albumCoverInfo.coverUri = coverUriNew;
        albumCoverInfo.coverUriSource = coverUriSourceOld;
        albumCoverInfo.coverCloudId = coverCloudIdOld;
        albumCoverinfos.emplace_back(albumCoverInfo);
    }
    resultSet->Close();

    UpdatePhotoAlbumCoverUri(albumCoverinfos);
}

bool CloneRestore::BackupKvStore()
{
    MEDIA_INFO_LOG("Start BackupKvstore");
    // Delete only redundant data and do not need to be returned.
    CHECK_AND_EXECUTE(!MediaFileUtils::IsFileExists(CLONE_KVDB_BACKUP_DIR),
        MediaFileUtils::DeleteDir(CLONE_KVDB_BACKUP_DIR));
    std::string backupKvdbPath = CLONE_KVDB_BACKUP_DIR + "/kvdb";
    CHECK_AND_RETURN_RET_LOG(BackupFileUtils::PreparePath(backupKvdbPath) == E_OK,
        false, "Prepare backup dir failed");

    int32_t status = MediaLibraryKvStoreManager::GetInstance().CloneKvStore(
        MEDIA_KVSTORE_MONTH_STOREID, MEDIA_KVDB_DIR, CLONE_KVSTORE_MONTH_STOREID, CLONE_KVDB_BACKUP_DIR);
    CHECK_AND_RETURN_RET(status == E_OK, false);
    status = MediaLibraryKvStoreManager::GetInstance().CloneKvStore(
        MEDIA_KVSTORE_YEAR_STOREID, MEDIA_KVDB_DIR, CLONE_KVSTORE_YEAR_STOREID, CLONE_KVDB_BACKUP_DIR);
    CHECK_AND_RETURN_RET(status == E_OK, false);
    MEDIA_INFO_LOG("End BackupKvstore");
    return true;
}

void CloneRestore::BatchUpdateFileInfoData(std::vector<FileInfo> &fileInfos,
    unordered_map<string, CloudPhotoFileExistFlag> &resultExistMap)
{
    for (size_t i = 0; i < fileInfos.size(); i++) {
        CloudPhotoFileExistFlag fileExistFlag;
        unordered_map<string, CloudPhotoFileExistFlag>::iterator iter =
            resultExistMap.find(fileInfos[i].cloudPath);
        CHECK_AND_CONTINUE(iter != resultExistMap.end());
        fileExistFlag = iter->second;
        int32_t thumbReady = CheckThumbReady(fileInfos[i], fileExistFlag);
        int32_t thumbStatus = CheckThumbStatus(fileInfos[i], fileExistFlag);
        int32_t lcdVisitTime = CheckLcdVisitTime(fileExistFlag);

        std::unique_ptr<NativeRdb::AbsRdbPredicates> predicates =
            std::make_unique<NativeRdb::AbsRdbPredicates>(PhotoColumn::PHOTOS_TABLE);
        std::string whereClause = "data = '" + fileInfos[i].cloudPath + "'";
        predicates->SetWhereClause(whereClause);

        int32_t updatedRows = 0;
        NativeRdb::ValuesBucket updateBucket;
        updateBucket.PutInt(PhotoColumn::PHOTO_THUMB_STATUS, thumbStatus);
        updateBucket.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY,
            thumbReady == 0 ? 0 : fileInfos[i].thumbnailReady);
        updateBucket.PutInt(PhotoColumn::PHOTO_LCD_VISIT_TIME, lcdVisitTime);
        updateBucket.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE,
            thumbReady == 0 ? 0 : RESTORE_THUMBNAIL_VISIBLE_TRUE);

        int32_t ret = BackupDatabaseUtils::Update(mediaLibraryRdb_, updatedRows, updateBucket, predicates);
        bool cond = (updatedRows < 0 || ret < 0);
        CHECK_AND_PRINT_LOG(!cond, "BatchInsertFileInfoData Failed to update column: %s",
            fileInfos[i].cloudPath.c_str());
        MediaLibraryPhotoOperations::StoreThumbnailSize(to_string(fileInfos[i].fileIdNew),
            fileInfos[i].cloudPath);
    }
}

int32_t CloneRestore::CheckThumbReady(const FileInfo &fileInfo,
    const CloudPhotoFileExistFlag &cloudPhotoFileExistFlag)
{
    if (fileInfo.orientation == ORIETATION_ZERO) {
        bool cond = (cloudPhotoFileExistFlag.isThmExist &&
            cloudPhotoFileExistFlag.isDayAstcExist &&
            cloudPhotoFileExistFlag.isYearAstcExist);
        CHECK_AND_RETURN_RET(!cond, RESTORE_THUMBNAIL_READY_ALL_SUCCESS);
    } else {
        bool cond = (cloudPhotoFileExistFlag.isExThmExist &&
            cloudPhotoFileExistFlag.isDayAstcExist &&
            cloudPhotoFileExistFlag.isYearAstcExist);
        CHECK_AND_RETURN_RET(!cond, RESTORE_THUMBNAIL_READY_ALL_SUCCESS);
    }
    return RESTORE_THUMBNAIL_READY_FAIL;
}

int32_t CloneRestore::CheckThumbStatus(const FileInfo &fileInfo,
    const CloudPhotoFileExistFlag &cloudPhotoFileExistFlag)
{
    if (fileInfo.orientation == ORIETATION_ZERO) {
        if (cloudPhotoFileExistFlag.isThmExist &&
            cloudPhotoFileExistFlag.isLcdExist) {
                return RESTORE_THUMBNAIL_STATUS_ALL;
        } else if (cloudPhotoFileExistFlag.isThmExist &&
            !cloudPhotoFileExistFlag.isLcdExist) {
                return RESTORE_THUMBNAIL_STATUS_NOT_LCD;
        } else if (!cloudPhotoFileExistFlag.isThmExist &&
            cloudPhotoFileExistFlag.isLcdExist) {
                return RESTORE_THUMBNAIL_STATUS_NOT_THUMB;
        } else {
            return RESTORE_THUMBNAIL_STATUS_NOT_ALL;
        }
    }
    if (cloudPhotoFileExistFlag.isExThmExist &&
        cloudPhotoFileExistFlag.isExLcdExist) {
            return RESTORE_THUMBNAIL_STATUS_ALL;
    } else if (cloudPhotoFileExistFlag.isExThmExist &&
        !cloudPhotoFileExistFlag.isExLcdExist) {
            return RESTORE_THUMBNAIL_STATUS_NOT_LCD;
    } else if (!cloudPhotoFileExistFlag.isExThmExist &&
        cloudPhotoFileExistFlag.isExLcdExist) {
            return RESTORE_THUMBNAIL_STATUS_NOT_THUMB;
    }
    return RESTORE_THUMBNAIL_STATUS_NOT_ALL;
}

int32_t CloneRestore::CheckLcdVisitTime(const CloudPhotoFileExistFlag &cloudPhotoFileExistFlag)
{
    CHECK_AND_RETURN_RET(!cloudPhotoFileExistFlag.isLcdExist, RESTORE_LCD_VISIT_TIME_SUCCESS);
    return RESTORE_LCD_VISIT_TIME_NO_LCD;
}


int32_t CloneRestore::GetNoNeedMigrateCount()
{
    return this->photosClone_.GetNoNeedMigrateCount();
}

void CloneRestore::RestoreAnalysisClassify()
{
    CloneRestoreClassify cloneRestoreClassify;
    cloneRestoreClassify.Init(sceneCode_, taskId_, mediaLibraryRdb_, mediaRdb_);
    cloneRestoreClassify.Restore(photoInfoMap_);
}

void CloneRestore::RestoreAnalysisGeo()
{
    CloneRestoreGeo cloneRestoreGeo;
    cloneRestoreGeo.Init(sceneCode_, taskId_, mediaLibraryRdb_, mediaRdb_);
    cloneRestoreGeo.Restore(photoInfoMap_);
}

void CloneRestore::UpdatePhotoAlbumCoverUri(vector<AlbumCoverInfo>& albumCoverInfos)
{
    for (auto& albumCoverInfo : albumCoverInfos) {
        int32_t changeRows = 0;
        std::unique_ptr<NativeRdb::AbsRdbPredicates> predicates =
            make_unique<NativeRdb::AbsRdbPredicates>(PhotoAlbumColumns::TABLE);
        predicates->EqualTo(PhotoAlbumColumns::ALBUM_ID, albumCoverInfo.albumId);
        NativeRdb::ValuesBucket updateBucket;
        updateBucket.PutInt(PhotoAlbumColumns::COVER_URI_SOURCE, albumCoverInfo.coverUriSource);
        updateBucket.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, albumCoverInfo.coverUri);
        updateBucket.PutString(PhotoAlbumColumns::COVER_CLOUD_ID, albumCoverInfo.coverCloudId);
        BackupDatabaseUtils::Update(mediaLibraryRdb_, changeRows, updateBucket, predicates);
        if (changeRows != 1) {
            MEDIA_ERR_LOG("UpdatePhotoAlbumCoverUri failed, expected count 1, but got %{public}d", changeRows);
        }
    }
}
} // namespace Media
} // namespace OHOS
