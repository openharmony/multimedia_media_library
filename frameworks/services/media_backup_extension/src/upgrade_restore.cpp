/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryUpgradeRestore"

#include "upgrade_restore.h"

#include "backup_const_column.h"
#include "backup_const_map.h"
#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "backup_log_utils.h"
#include "database_report.h"
#include "cloud_sync_helper.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "gallery_db_upgrade.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdb_transaction.h"
#include "photo_album_restore.h"
#include "photos_dao.h"
#include "photos_restore.h"
#include "result_set_utils.h"
#include "upgrade_restore_task_report.h"
#include "userfile_manager_types.h"
#include "vision_album_column.h"
#include "vision_column.h"
#include "vision_face_tag_column.h"
#include "vision_image_face_column.h"
#include "vision_photo_map_column.h"

#ifdef CLOUD_SYNC_MANAGER
#include "cloud_sync_manager.h"
#endif

namespace OHOS {
namespace Media {
constexpr int32_t PHOTOS_TABLE_ALBUM_ID = -1;
constexpr int32_t BASE_TEN_NUMBER = 10;
constexpr int32_t SEVEN_NUMBER = 7;
constexpr int32_t SD_PREFIX_LEVEL = 3;
constexpr int32_t RESTORE_CLOUD_QUERY_COUNT = 200;
const std::string DB_INTEGRITY_CHECK = "ok";

UpgradeRestore::UpgradeRestore(const std::string &galleryAppName, const std::string &mediaAppName, int32_t sceneCode)
{
    galleryAppName_ = galleryAppName;
    mediaAppName_ = mediaAppName;
    sceneCode_ = sceneCode;
    audioAppName_ = "Audio";
    ffrt_disable_worker_escape();
    MEDIA_INFO_LOG("Set ffrt_disable_worker_escape");
}

UpgradeRestore::UpgradeRestore(const std::string &galleryAppName, const std::string &mediaAppName, int32_t sceneCode,
    const std::string &dualDirName)
{
    galleryAppName_ = galleryAppName;
    mediaAppName_ = mediaAppName;
    sceneCode_ = sceneCode;
    dualDirName_ = dualDirName;
    ffrt_disable_worker_escape();
    MEDIA_INFO_LOG("Set ffrt_disable_worker_escape");
}

int32_t UpgradeRestore::Init(const std::string &backupRetoreDir, const std::string &upgradeFilePath, bool isUpgrade)
{
    appDataPath_ = backupRetoreDir;
    string photosPreferencesPath;
    if (sceneCode_ == DUAL_FRAME_CLONE_RESTORE_ID) {
        filePath_ = backupRetoreDir;
        galleryDbPath_ = backupRetoreDir + "/" + GALLERY_DB_NAME;
        audioDbPath_ = backupRetoreDir + INTERNAL_PREFIX + "/0/" + AUDIO_DB_NAME;
        photosPreferencesPath = backupRetoreDir + "/" + galleryAppName_ + "_preferences.xml";
        // gallery db may include both internal & external, set flag to differentiate, default false
        shouldIncludeSd_ = BackupFileUtils::ShouldIncludeSd(filePath_);
        backupDatabaseHelper_.Init(sceneCode_, shouldIncludeSd_, filePath_);
        SetParameterForClone();
#ifdef CLOUD_SYNC_MANAGER
        FileManagement::CloudSync::CloudSyncManager::GetInstance().StopSync("com.ohos.medialibrary.medialibrarydata");
#endif
    } else {
        filePath_ = upgradeFilePath;
        galleryDbPath_ = backupRetoreDir + "/" + galleryAppName_ + "/ce/databases/gallery.db";
        externalDbPath_ = backupRetoreDir + "/" + mediaAppName_ + "/ce/databases/external.db";
        photosPreferencesPath =
            backupRetoreDir + "/" + galleryAppName_ + "/ce/shared_prefs/" + galleryAppName_ + "_preferences.xml";
        shouldIncludeSd_ = false;
        if (!MediaFileUtils::IsFileExists(externalDbPath_)) {
            MEDIA_ERR_LOG("External db is not exist.");
            return EXTERNAL_DB_NOT_EXIST;
        }
        int32_t externalErr = BackupDatabaseUtils::InitDb(externalRdb_, EXTERNAL_DB_NAME, externalDbPath_,
            mediaAppName_, false);
        if (externalRdb_ == nullptr) {
            MEDIA_ERR_LOG("External init rdb fail, err = %{public}d", externalErr);
            return E_FAIL;
        }
        backupDatabaseHelper_.AddDb(BackupDatabaseHelper::DbType::EXTERNAL, externalRdb_);
    }
    MEDIA_INFO_LOG("Shoud include Sd: %{public}d", static_cast<int32_t>(shouldIncludeSd_));
    return InitDbAndXml(photosPreferencesPath, isUpgrade);
}

int32_t UpgradeRestore::InitDbAndXml(std::string xmlPath, bool isUpgrade)
{
    if (isUpgrade && BaseRestore::Init() != E_OK) {
        return E_FAIL;
    }
    if (sceneCode_ == UPGRADE_RESTORE_ID) {
        MediaLibraryDataManager::GetInstance()->ReCreateMediaDir();
    }
    if (!MediaFileUtils::IsFileExists(galleryDbPath_)) {
        MEDIA_ERR_LOG("Gallery media db is not exist.");
    } else {
        int32_t galleryErr = BackupDatabaseUtils::InitDb(galleryRdb_, GALLERY_DB_NAME, galleryDbPath_,
            galleryAppName_, false);
        if (galleryRdb_ == nullptr) {
            MEDIA_ERR_LOG("Gallery init rdb fail, err = %{public}d", galleryErr);
            return E_FAIL;
        }
    }

    if (!MediaFileUtils::IsFileExists(audioDbPath_)) {
        MEDIA_ERR_LOG("audio mediaInfo db is not exist.");
    } else {
        int32_t audioErr = BackupDatabaseUtils::InitDb(audioRdb_, AUDIO_DB_NAME, audioDbPath_,
            audioAppName_, false);
        if (audioRdb_ == nullptr) {
            MEDIA_ERR_LOG("audio init rdb fail, err = %{public}d", audioErr);
            return E_FAIL;
        }
    }
    ParseXml(xmlPath);
    this->photoAlbumRestore_.OnStart(this->mediaLibraryRdb_, this->galleryRdb_);
    this->photosRestore_.OnStart(this->mediaLibraryRdb_, this->galleryRdb_);
    geoKnowledgeRestore_.Init(this->sceneCode_, this->taskId_, this->mediaLibraryRdb_, this->galleryRdb_);
    highlightRestore_.Init(this->sceneCode_, this->taskId_, this->mediaLibraryRdb_, this->galleryRdb_);
    MEDIA_INFO_LOG("Init db succ.");
    return E_OK;
}

bool UpgradeRestore::HasLowQualityImage()
{
    std::string sql = "SELECT count(1) AS count FROM gallery_media WHERE (local_media_id != -1) AND \
        (storage_id IN (0, 65537)) AND relative_bucket_id NOT IN (SELECT DISTINCT relative_bucket_id FROM \
        garbage_album WHERE type = 1) AND _size = 0 AND photo_quality = 0";
    int count = BackupDatabaseUtils::QueryInt(galleryRdb_, sql, CUSTOM_COUNT);
    MEDIA_INFO_LOG("HasLowQualityImage count:%{public}d", count);
    hasLowQualityImage_ = (count > 0);
    return hasLowQualityImage_;
}

int UpgradeRestore::StringToInt(const std::string& str)
{
    if (str.empty()) {
        return 0;
    }
    int base = 0;
    size_t num = 0;
    int sign = 1;
    size_t len = static_cast<ssize_t>(str.length());
    while (num < len && str[num] == ' ') {
        num++;
    }
    if (num < len && (str[num] == '-' || str[num] == '+')) {
        sign = (str[num++] == '-') ? -1 : 1;
    }
    while (num < len && std::isdigit(str[num])) {
        if (base > INT_MAX / BASE_TEN_NUMBER || (base == INT_MAX / BASE_TEN_NUMBER && str[num] - '0' > SEVEN_NUMBER)) {
            MEDIA_INFO_LOG("The number is INT_MAX");
            return 0;
        }
        base = BASE_TEN_NUMBER * base + (str[num++] - '0');
    }
    if (num < len && !std::isdigit(str[num])) {
        MEDIA_INFO_LOG("Not digit");
        return 0;
    }
    return base * sign;
}

int32_t UpgradeRestore::HandleXmlNode(xmlNodePtr cur)
{
    if (cur->type == XML_ELEMENT_NODE) {
        xmlChar* name = xmlGetProp(cur, BAD_CAST"name");
        if (name != nullptr && xmlStrcmp(name, BAD_CAST"filter_selected_size") == 0) {
            xmlChar* value = xmlGetProp(cur, BAD_CAST"value");
            if (value != nullptr) {
                fileMinSize_ = StringToInt((const char *)(value));
                xmlFree(value);
                return E_SUCCESS;
            }
            xmlFree(name);
            return E_ERR;
        }
        xmlFree(name);
    }
    return E_ERR;
}

int32_t UpgradeRestore::ParseXml(string path)
{
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> docPtr(
        xmlReadFile(path.c_str(), nullptr, XML_PARSE_NOBLANKS), xmlFreeDoc);
    if (docPtr == nullptr) {
        MEDIA_ERR_LOG("failed to read xml file");
        return E_ERR;
    }
    auto root = xmlDocGetRootElement(docPtr.get());
    if (root == nullptr) {
        MEDIA_ERR_LOG("failed to read root node");
        return E_ERR;
    }
    for (xmlNodePtr cur = root->children; cur != NULL; cur = cur->next) {
        if (HandleXmlNode(cur) == E_SUCCESS) {
            return E_SUCCESS;
        }
    }
    return E_ERR;
}

void UpgradeRestore::RestoreAudio(void)
{
    if (sceneCode_ == DUAL_FRAME_CLONE_RESTORE_ID) {
        if (!MediaFileUtils::IsFileExists(RESTORE_MUSIC_LOCAL_DIR)) {
            MEDIA_INFO_LOG("music dir is not exists!!!");
            MediaFileUtils::CreateDirectory(RESTORE_MUSIC_LOCAL_DIR);
        }
        RestoreAudioFromFile();
    }
    (void)NativeRdb::RdbHelper::DeleteRdbStore(audioDbPath_);

    int32_t restoreMode = BaseRestore::GetRestoreMode();
    if (restoreMode == RESTORE_MODE_PROC_ALL_DATA || restoreMode == RESTORE_MODE_PROC_TWIN_DATA) {
        (void)NativeRdb::RdbHelper::DeleteRdbStore(externalDbPath_);
    } else {
        MEDIA_INFO_LOG("restore mode no need to del external db");
    }
}

void UpgradeRestore::RestoreAudioFromFile()
{
    MEDIA_INFO_LOG("start restore audio from audio_MediaInfo0");
    int32_t totalNumber = BackupDatabaseUtils::QueryInt(audioRdb_, QUERY_DUAL_CLONE_AUDIO_COUNT, CUSTOM_COUNT);
    MEDIA_INFO_LOG("totalNumber = %{public}d", totalNumber);
    audioTotalNumber_ += static_cast<uint64_t>(totalNumber);
    MEDIA_INFO_LOG("onProcess Update audioTotalNumber_: %{public}lld", (long long)audioTotalNumber_);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestoreAudioBatch(offset); }, { &offset }, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
}

void UpgradeRestore::RestoreAudioBatch(int32_t offset)
{
    MEDIA_INFO_LOG("start restore audio from external, offset: %{public}d", offset);
    std::vector<FileInfo> infos = QueryAudioFileInfosFromAudio(offset);
    InsertAudio(sceneCode_, infos);
}

std::vector<FileInfo> UpgradeRestore::QueryAudioFileInfosFromAudio(int32_t offset)
{
    std::vector<FileInfo> result;
    result.reserve(QUERY_COUNT);
    if (audioRdb_ == nullptr) {
        MEDIA_ERR_LOG("audioRdb_ is nullptr, Maybe init failed.");
        return result;
    }
    std::string queryAllAudioByCount = QUERY_ALL_AUDIOS_FROM_AUDIODB + " limit " + std::to_string(offset) + ", " +
        std::to_string(QUERY_COUNT);
    auto resultSet = audioRdb_->QuerySql(queryAllAudioByCount);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo tmpInfo;
        if (ParseResultSetFromAudioDb(resultSet, tmpInfo)) {
            result.emplace_back(tmpInfo);
        }
    }
    return result;
}

bool UpgradeRestore::ParseResultSetFromAudioDb(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info)
{
    info.fileType = MediaType::MEDIA_TYPE_AUDIO;
    info.oldPath = GetStringVal(AUDIO_DATA, resultSet);
    if (!ConvertPathToRealPath(info.oldPath, filePath_, info.filePath, info.relativePath)) {
        MEDIA_ERR_LOG("Invalid path: %{public}s.",
            BackupFileUtils::GarbleFilePath(info.oldPath, DEFAULT_RESTORE_ID).c_str());
        return false;
    }
    info.showDateToken = GetInt64Val(EXTERNAL_DATE_MODIFIED, resultSet);
    info.dateModified = GetInt64Val(EXTERNAL_DATE_MODIFIED, resultSet) * MSEC_TO_SEC;
    info.displayName = BackupFileUtils::GetFileNameFromPath(info.filePath);
    info.title = BackupFileUtils::GetFileTitle(info.displayName);
    info.packageName = BackupFileUtils::GetFileFolderFromPath(info.relativePath, false);
    info.isFavorite = 0;
    info.recycledTime = 0;
    return true;
}

int32_t UpgradeRestore::GetHighlightCloudMediaCnt()
{
    const std::string QUERY_SQL = "SELECT COUNT(1) AS count FROM t_story_album t1 "
        "WHERE COALESCE(t1.name, '') <> '' AND t1.displayable = 1 "
        "AND EXISTS "
        "(SELECT t2._id FROM gallery_media t2 WHERE t2.local_media_id = -1 "
        "AND (t2.story_id LIKE '%,'||t1.story_id||',%' OR t2.portrait_id LIKE '%,'||t1.story_id||',%'))";
    std::shared_ptr<NativeRdb::ResultSet> resultSet =
        BackupDatabaseUtils::QuerySql(this->galleryRdb_, QUERY_SQL, {});
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("query count of highlight cloud media failed.");
        return -1;
    }
    int32_t cnt = GetInt32Val("count", resultSet);
    MEDIA_INFO_LOG("GetHighlightCloudMediaCnt is %{public}d", cnt);
    resultSet->Close();
    return cnt;
}

void UpgradeRestore::RestoreHighlightAlbums(bool isSyncSwitchOpen)
{
    int32_t highlightCloudMediaCnt = GetHighlightCloudMediaCnt();
    UpgradeRestoreTaskReport().SetSceneCode(sceneCode_).SetTaskId(taskId_)
        .Report("Highlight Restore", "",
        "sceneCode_: " + std::to_string(sceneCode_) +
        ", dualDeviceSoftName_: " + dualDeviceSoftName_ +
        ", highlightCloudMediaCnt: " + std::to_string(highlightCloudMediaCnt) +
        ", isAccountValid_: " + std::to_string(isAccountValid_) +
        ", isSyncSwitchOpen: " + std::to_string(isSyncSwitchOpen));
    if ((sceneCode_ == UPGRADE_RESTORE_ID || dualDeviceSoftName_.empty()
        || dualDeviceSoftName_.find("4", dualDeviceSoftName_.find(" ")) == dualDeviceSoftName_.find(" ") + 1)
        && (highlightCloudMediaCnt == 0 || (isAccountValid_ && isSyncSwitchOpen))) {
        MEDIA_INFO_LOG("start to restore highlight albums");
        highlightRestore_.RestoreAlbums(albumOdid_);
    }
}

void UpgradeRestore::RestorePhotoInner()
{
    std::string dbIntegrityCheck = CheckGalleryDbIntegrity();
    if (dbIntegrityCheck == DB_INTEGRITY_CHECK) {
        bool isSyncSwitchOpen = CloudSyncHelper::GetInstance()->IsSyncSwitchOpen();
        MEDIA_INFO_LOG("the isAccountValid is %{public}d, sync switch open is %{public}d", isAccountValid_,
            isSyncSwitchOpen);
        // upgrade gallery.db
        DataTransfer::GalleryDbUpgrade().OnUpgrade(this->galleryRdb_);
        AnalyzeGallerySource();
        InitGarbageAlbum();
        // restore PhotoAlbum
        this->photoAlbumRestore_.Restore();
        RestoreFromGalleryPortraitAlbum();
        geoKnowledgeRestore_.RestoreGeoKnowledgeInfos();
        RestoreHighlightAlbums(isSyncSwitchOpen);
        // restore Photos
        RestoreFromGallery();
        if (isAccountValid_ && isSyncSwitchOpen) {
            MEDIA_INFO_LOG("here cloud clone");
            RestoreCloudFromGallery();
            MEDIA_INFO_LOG("Migrate LCD:%{public}" PRIu64 ",THM:%{public}" PRIu64
            ",Rotate LCD:%{public}" PRIu64 ",THM: %{public}" PRIu64 ", migrateCloud: %{public}" PRIu64
            ", migrateDatabase: %{public}" PRIu64,
            (cloudLcdCount_.load(std::memory_order_relaxed) + localLcdCount_.load(std::memory_order_relaxed)),
            (cloudThumbnailCount_.load(std::memory_order_relaxed) +
            localThumbnailCount_.load(std::memory_order_relaxed)),
            rotateLcdMigrateFileNumber_.load(), rotateThmMigrateFileNumber_.load(),
            totalCloudMetaNumber_.load(), migrateDatabaseNumber_.load());
        }
    } else {
        maxId_ = 0;
        SetErrorCode(RestoreError::GALLERY_DATABASE_CORRUPTION);
        ErrorInfo errorInfo(RestoreError::GALLERY_DATABASE_CORRUPTION, 0, "", dbIntegrityCheck);
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
    }
}

void UpgradeRestore::RestorePhoto()
{
    if (!IsRestorePhoto()) {
        return;
    }
    AnalyzeSource();
    RestorePhotoInner();
    StopParameterForClone(sceneCode_);
    MEDIA_INFO_LOG("migrate from gallery number: %{public}lld, file number: %{public}lld",
        (long long) migrateDatabaseNumber_, (long long) migrateFileNumber_);
    if (sceneCode_ == UPGRADE_RESTORE_ID) {
        RestoreFromExternal(true);
        MEDIA_INFO_LOG("migrate from camera number: %{public}lld, file number: %{public}lld",
            (long long) migrateDatabaseNumber_, (long long) migrateFileNumber_);
        RestoreFromExternal(false);
        MEDIA_INFO_LOG("migrate from others number: %{public}lld, file number: %{public}lld",
            (long long) migrateDatabaseNumber_, (long long) migrateFileNumber_);
    }

    if (sceneCode_ == UPGRADE_RESTORE_ID) {
        UpdateFaceAnalysisStatus();
    } else {
        UpdateDualCloneFaceAnalysisStatus();
    }

    geoKnowledgeRestore_.ReportGeoRestoreTask();
    highlightRestore_.UpdateAlbums();
    ReportPortraitStat(sceneCode_);

    int32_t restoreMode = BaseRestore::GetRestoreMode();
    UpgradeRestoreTaskReport()
        .SetSceneCode(sceneCode_)
        .SetTaskId(taskId_)
        .ReportRestoreMode(restoreMode, BaseRestore::GetNotFoundNumber());
    if (restoreMode == RESTORE_MODE_PROC_ALL_DATA || restoreMode == RESTORE_MODE_PROC_TWIN_DATA) {
        (void)NativeRdb::RdbHelper::DeleteRdbStore(galleryDbPath_);
    } else {
        MEDIA_INFO_LOG("restore mode no need to del gallery db");
    }
    PrcoessContinuousShootingPhotos();
}

void UpgradeRestore::AnalyzeSource()
{
    MEDIA_INFO_LOG("start AnalyzeSource.");
    DatabaseReport()
        .SetSceneCode(this->sceneCode_)
        .SetTaskId(this->taskId_)
        .ReportExternal(this->externalRdb_,  this->galleryRdb_)
        .ReportMedia(this->mediaLibraryRdb_, DatabaseReport::PERIOD_BEFORE);
    MEDIA_INFO_LOG("end AnalyzeSource.");
}

void UpgradeRestore::AnalyzeGalleryErrorSource()
{
    if (galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("galleryRdb_ is nullptr, Maybe init failed.");
        return;
    }
    AnalyzeGalleryDuplicateData();
}

void UpgradeRestore::AnalyzeGalleryDuplicateData()
{
    int32_t count = 0;
    int32_t total = 0;
    BackupDatabaseUtils::QueryGalleryDuplicateDataCount(galleryRdb_, count, total);
    MEDIA_INFO_LOG("Duplicate data count: %{public}d, total: %{public}d", count, total);
    this->photosRestore_.GetDuplicateData(count);
}

void UpgradeRestore::AnalyzeGallerySource()
{
    MEDIA_INFO_LOG("start AnalyzeGallerySource.");
    AnalyzeGalleryErrorSource();
    DatabaseReport()
        .SetSceneCode(this->sceneCode_)
        .SetTaskId(this->taskId_)
        .ReportGallery(this->galleryRdb_, this->shouldIncludeSd_);
    MEDIA_INFO_LOG("end AnalyzeGallerySource.");
}

void UpgradeRestore::InitGarbageAlbum()
{
    BackupDatabaseUtils::InitGarbageAlbum(galleryRdb_, cacheSet_, nickMap_);
}

void UpgradeRestore::RestoreFromGallery()
{
    this->photosRestore_.LoadPhotoAlbums();
    HasLowQualityImage();
    // local count
    int32_t totalNumber = this->photosRestore_.GetGalleryMediaCount(this->shouldIncludeSd_, this->hasLowQualityImage_);
    MEDIA_INFO_LOG("local totalNumber = %{public}d", totalNumber);
    totalNumber_ += static_cast<uint64_t>(totalNumber);
    MEDIA_INFO_LOG("onProcess Update totalNumber_: %{public}lld", (long long)totalNumber_);
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_THREAD_NUM);
    needReportFailed_ = false;
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestoreBatch(offset); }, { &offset }, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
    size_t vectorLen = galleryFailedOffsets.size();
    needReportFailed_ = true;
    for (size_t offset = 0; offset < vectorLen; offset++) {
        RestoreBatch(galleryFailedOffsets[offset]);
    }
}

void UpgradeRestore::RestoreCloudFromGallery()
{
    MEDIA_INFO_LOG("RestoreCloudFromGallery");
    this->photosRestore_.LoadPhotoAlbums();
    // cloud count
    int32_t cloudMetaCount = this->photosRestore_.GetCloudMetaCount(this->shouldIncludeSd_, false);
    MEDIA_INFO_LOG("the cloud count is %{public}d", cloudMetaCount);
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_THREAD_NUM);
    needReportFailed_ = false;
    totalNumber_ += static_cast<uint64_t>(cloudMetaCount);
    for (int32_t offset = 0; offset < cloudMetaCount; offset += RESTORE_CLOUD_QUERY_COUNT) {
        MEDIA_INFO_LOG("the offset is %{public}d", offset);
        ffrt::submit([this, offset]() { RestoreBatchForCloud(offset); }, { &offset }, {},
            ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
    size_t vectorLen = galleryFailedOffsets.size();
    needReportFailed_ = true;
    for (size_t offset = 0; offset < vectorLen; offset++) {
        RestoreBatchForCloud(galleryFailedOffsets[offset]);
    }
}

void UpgradeRestore::RestoreBatchForCloud(int32_t offset)
{
    MEDIA_INFO_LOG("START STEP 1 RESTORE BATCH");
    std::vector<FileInfo> infos = QueryCloudFileInfos(offset);
    MEDIA_INFO_LOG("the infos size is %{public}zu", infos.size());
    if (InsertCloudPhoto(sceneCode_, infos, SourceType::GALLERY) != E_OK) {
        galleryFailedOffsets.push_back(offset);
    }
    this->tabOldPhotosRestore_.Restore(this->mediaLibraryRdb_, infos);
    auto fileIdPairs = BackupDatabaseUtils::CollectFileIdPairs(infos);
    BackupDatabaseUtils::UpdateAnalysisTotalTblStatus(mediaLibraryRdb_, fileIdPairs);
    MEDIA_INFO_LOG("END STEP 1 RESTORE BATCH");
}

void UpgradeRestore::RestoreBatch(int32_t offset)
{
    MEDIA_INFO_LOG("start restore from gallery, offset: %{public}d", offset);
    std::vector<FileInfo> infos = QueryFileInfos(offset);
    if (InsertPhoto(sceneCode_, infos, SourceType::GALLERY) != E_OK) {
        galleryFailedOffsets.push_back(offset);
    }
    auto fileIdPairs = BackupDatabaseUtils::CollectFileIdPairs(infos);
    BackupDatabaseUtils::UpdateAnalysisTotalTblStatus(mediaLibraryRdb_, fileIdPairs);
}

void UpgradeRestore::RestoreFromExternal(bool isCamera)
{
    MEDIA_INFO_LOG("start restore from %{public}s", (isCamera ? "camera" : "others"));
    int32_t maxId = BackupDatabaseUtils::QueryInt(galleryRdb_, isCamera ?
        QUERY_MAX_ID_CAMERA_SCREENSHOT : QUERY_MAX_ID_OTHERS, CUSTOM_MAX_ID);
    maxId = (maxId_ == -1) ? maxId : maxId_;
    int32_t type = isCamera ? SourceType::EXTERNAL_CAMERA : SourceType::EXTERNAL_OTHERS;
    int32_t totalNumber = QueryNotSyncTotalNumber(maxId, isCamera);
    MEDIA_INFO_LOG("totalNumber = %{public}d, maxId = %{public}d", totalNumber, maxId);
    totalNumber_ += static_cast<uint64_t>(totalNumber);
    MEDIA_INFO_LOG("onProcess Update totalNumber_: %{public}lld", (long long)totalNumber_);
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_THREAD_NUM);
    needReportFailed_ = false;
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        ffrt::submit([this, offset, maxId, isCamera, type]() {
                RestoreExternalBatch(offset, maxId, isCamera, type);
            }, { &offset }, {}, ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
    size_t vectorLen = externalFailedOffsets.size();
    needReportFailed_ = true;
    for (size_t offset = 0; offset < vectorLen; offset++) {
        RestoreExternalBatch(externalFailedOffsets[offset], maxId, isCamera, type);
    }
}

void UpgradeRestore::RestoreExternalBatch(int32_t offset, int32_t maxId, bool isCamera, int32_t type)
{
    MEDIA_INFO_LOG("start restore from external, offset: %{public}d", offset);
    std::vector<FileInfo> infos = QueryFileInfosFromExternal(offset, maxId, isCamera);
    if (InsertPhoto(sceneCode_, infos, type) != E_OK) {
        externalFailedOffsets.push_back(offset);
    }
}

int32_t UpgradeRestore::QueryNotSyncTotalNumber(int32_t maxId, bool isCamera)
{
    std::string queryCamera = isCamera ? IN_CAMERA : NOT_IN_CAMERA;
    std::string queryNotSyncByCount = QUERY_COUNT_FROM_FILES + queryCamera + " AND " +
        COMPARE_ID + std::to_string(maxId) + " AND " + QUERY_NOT_SYNC;
    return BackupDatabaseUtils::QueryInt(externalRdb_, queryNotSyncByCount, CUSTOM_COUNT);
}

void UpgradeRestore::HandleRestData(void)
{
    MEDIA_INFO_LOG("Start to handle rest data in native.");
    RestoreThumbnail();

    int32_t restoreMode = BaseRestore::GetRestoreMode();
    if (restoreMode != RESTORE_MODE_PROC_ALL_DATA && restoreMode != RESTORE_MODE_PROC_TWIN_DATA) {
        MEDIA_DEBUG_LOG("restore mode no need to del rest data");
        return;
    }

    std::string photoData = appDataPath_ + "/" + galleryAppName_;
    std::string mediaData = appDataPath_ + "/" + mediaAppName_;
    if (MediaFileUtils::IsFileExists(photoData)) {
        MEDIA_DEBUG_LOG("Start to delete photo data.");
        (void)MediaFileUtils::DeleteDir(photoData);
    }
    if (MediaFileUtils::IsFileExists(mediaData)) {
        MEDIA_DEBUG_LOG("Start to delete media data.");
        (void)MediaFileUtils::DeleteDir(mediaData);
    }
    BackupFileUtils::DeleteSdDatabase(filePath_);
}

std::vector<FileInfo> UpgradeRestore::QueryFileInfos(int32_t offset)
{
    std::vector<FileInfo> result;
    result.reserve(QUERY_COUNT);
    CHECK_AND_RETURN_RET_LOG(galleryRdb_ != nullptr, result, "galleryRdb_ is nullptr, Maybe init failed.");
    auto resultSet = this->photosRestore_.GetGalleryMedia(
        offset, QUERY_COUNT, this->shouldIncludeSd_, this->hasLowQualityImage_);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo tmpInfo;
        if (ParseResultSetFromGallery(resultSet, tmpInfo)) {
            result.emplace_back(tmpInfo);
        }
    }
    return result;
}

std::vector<FileInfo> UpgradeRestore::QueryCloudFileInfos(int32_t offset)
{
    MEDIA_INFO_LOG("UpgradeRestore::QueryCloudFileInfos");
    std::vector<FileInfo> result;
    result.reserve(RESTORE_CLOUD_QUERY_COUNT);
    CHECK_AND_RETURN_RET_LOG(galleryRdb_ != nullptr, result, "cloud galleryRdb_ is nullptr, Maybe init failed.");
    auto resultSet = this->photosRestore_.GetCloudGalleryMedia(
        offset, RESTORE_CLOUD_QUERY_COUNT, this->shouldIncludeSd_, this->hasLowQualityImage_);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query cloud resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo tmpInfo;
        if (ParseResultSetFromGallery(resultSet, tmpInfo)) {
            result.emplace_back(tmpInfo);
        }
    }
    return result;
}

bool UpgradeRestore::ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info)
{
    info.oldPath = GetStringVal(EXTERNAL_FILE_DATA, resultSet);
    int32_t mediaType = GetInt32Val(EXTERNAL_MEDIA_TYPE, resultSet);
    CHECK_AND_RETURN_RET_LOG(mediaType == DUAL_MEDIA_TYPE::AUDIO_TYPE, false,
        "Invalid media type: %{public}d, path: %{public}s", mediaType,
        BackupFileUtils::GarbleFilePath(info.oldPath, DEFAULT_RESTORE_ID).c_str());
    info.fileType = MediaType::MEDIA_TYPE_AUDIO;
    CHECK_AND_RETURN_RET_LOG(BaseRestore::ConvertPathToRealPath(info.oldPath, filePath_, info.filePath,
        info.relativePath), false, "Invalid path: %{public}s.",
        BackupFileUtils::GarbleFilePath(info.oldPath, DEFAULT_RESTORE_ID).c_str());
    info.displayName = GetStringVal(EXTERNAL_DISPLAY_NAME, resultSet);
    info.title = GetStringVal(EXTERNAL_TITLE, resultSet);
    info.fileSize = GetInt64Val(EXTERNAL_FILE_SIZE, resultSet);
    CHECK_AND_WARN_LOG(info.fileSize >= GARBAGE_PHOTO_SIZE, "maybe garbage path = %{public}s.",
        BackupFileUtils::GarbleFilePath(info.oldPath, DEFAULT_RESTORE_ID).c_str());
    info.duration = GetInt64Val(GALLERY_DURATION, resultSet);
    info.isFavorite = GetInt32Val(EXTERNAL_IS_FAVORITE, resultSet);
    info.dateModified = GetInt64Val(EXTERNAL_DATE_MODIFIED, resultSet) * MSEC_TO_SEC;
    return true;
}

std::vector<FileInfo> UpgradeRestore::QueryFileInfosFromExternal(int32_t offset, int32_t maxId, bool isCamera)
{
    std::vector<FileInfo> result;
    result.reserve(QUERY_COUNT);
    CHECK_AND_RETURN_RET_LOG(externalRdb_ != nullptr, result, "Pointer rdb_ is nullptr, Maybe init failed.");
    std::string queryCamera = isCamera ? IN_CAMERA : NOT_IN_CAMERA;
    std::string queryFilesByCount = QUERY_FILE_COLUMN + queryCamera + " AND " +
        COMPARE_ID + std::to_string(maxId) + " AND " + QUERY_NOT_SYNC + " limit " + std::to_string(offset) + ", " +
        std::to_string(QUERY_COUNT);
    auto resultSet = externalRdb_->QuerySql(queryFilesByCount);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo tmpInfo;
        if (ParseResultSetFromExternal(resultSet, tmpInfo)) {
            std::string findPath = tmpInfo.relativePath;
            bool isValid = IsValidDir(findPath);
            if (isValid) {
                result.emplace_back(tmpInfo);
            }
        }
    }
    return result;
}

bool UpgradeRestore::IsValidDir(const string &path)
{
    bool isValid = true;
    for (auto &cacheDir : cacheSet_) {
        if (path.find(cacheDir) == 0) {
            isValid = false;
            break;
        }
    }
    return isValid;
}
bool UpgradeRestore::ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
    string dbName)
{
    // only parse image and video
    CHECK_AND_RETURN_RET(IsBasicInfoValid(resultSet, info, dbName), false);
    info.title = GetStringVal(GALLERY_TITLE, resultSet);
    info.userComment = GetStringVal(GALLERY_DESCRIPTION, resultSet);
    info.duration = GetInt64Val(GALLERY_DURATION, resultSet);
    info.isFavorite = GetInt32Val(GALLERY_IS_FAVORITE, resultSet);
    info.specialFileType = GetInt32Val(GALLERY_SPECIAL_FILE_TYPE, resultSet);
    // only local data need livePhoto path
    if (info.localMediaId != -1 && BackupFileUtils::IsLivePhoto(info) &&
        !BackupFileUtils::ConvertToMovingPhoto(info)) {
        ErrorInfo errorInfo(RestoreError::MOVING_PHOTO_CONVERT_FAILED, 1, "",
            BackupLogUtils::FileInfoToString(sceneCode_, info));
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return false;
    }
    info.height = GetInt64Val(GALLERY_HEIGHT, resultSet);
    info.width = GetInt64Val(GALLERY_WIDTH, resultSet);
    info.resolution = GetStringVal(GALLERY_RESOLUTION, resultSet);
    // For cloud data, prioritize using resolution parsing to obtain the width and height.
    // If parsing fails, set both width and height to 0
    if (info.localMediaId == -1) {
        BackupFileUtils::ParseResolution(info.resolution, info.width, info.height);
    }
    info.orientation = GetInt64Val(GALLERY_ORIENTATION, resultSet);
    info.dateModified = GetInt64Val(EXTERNAL_DATE_MODIFIED, resultSet) * MSEC_TO_SEC;
    info.firstUpdateTime = GetInt64Val(GALLERY_FIRST_UPDATE_TIME, resultSet);
    info.dateTaken = GetInt64Val(GALLERY_DATE_TAKEN, resultSet);
    info.detailTime = GetStringVal(GALLERY_DETAIL_TIME, resultSet);
    info.userId = BackupFileUtils::GetUserId(info.oldPath);
    return true;
}

bool UpgradeRestore::ParseResultSetFromGallery(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info)
{
    info.localMediaId = GetInt32Val(GALLERY_LOCAL_MEDIA_ID, resultSet);
    info.hidden = (info.localMediaId == GALLERY_HIDDEN_ID) ? 1 : 0;
    info.recycledTime = GetInt64Val(GALLERY_RECYCLED_TIME, resultSet);
    info.showDateToken = GetInt64Val(GALLERY_SHOW_DATE_TOKEN, resultSet);
    // fetch relative_bucket_id, recycleFlag, is_hw_burst, hash field to generate burst_key
    info.relativeBucketId = GetStringVal(GALLERY_MEDIA_BUCKET_ID, resultSet);
    info.recycleFlag = GetInt32Val(GALLERY_RECYCLE_FLAG, resultSet);
    info.isBurst = GetInt32Val(GALLERY_IS_BURST, resultSet);
    info.hashCode = GetStringVal(GALLERY_HASH, resultSet);
    info.fileIdOld = GetInt32Val(GALLERY_ID, resultSet);
    info.photoQuality = GetInt32Val(PhotoColumn::PHOTO_QUALITY, resultSet);
    info.thumbType = GetInt32Val(GALLERY_THUMB_TYPE, resultSet);
    info.filePath = GetStringVal(GALLERY_FILE_DATA, resultSet);
    info.albumId = GetStringVal(GALLERY_ALBUM_ID, resultSet);
    info.orientation = GetInt32Val(GALLERY_ORIENTATION, resultSet);
    info.uniqueId = GetStringVal(GALLERY_UNIQUE_ID, resultSet);
    info.localThumbPath = GetStringVal(GALLERY_LOCAL_THUMB_PATH_ID, resultSet);
    info.localBigThumbPath = GetStringVal(GALLERY_LOCAL_BIG_THUMB_PATH_ID, resultSet);

    bool isSuccess = ParseResultSet(resultSet, info, GALLERY_DB_NAME);
    CHECK_AND_RETURN_RET_LOG(isSuccess, isSuccess, "ParseResultSetFromGallery fail");
    info.burstKey = burstKeyGenerator_.FindBurstKey(info);
    // Pre-Fetch: sourcePath, lPath
    info.sourcePath = GetStringVal(GALLERY_MEDIA_SOURCE_PATH, resultSet);
    info.lPath = GetStringVal(GALLERY_ALBUM_IPATH, resultSet);
    // Find lPath, bundleName, packageName by sourcePath, lPath
    info.lPath = this->photosRestore_.FindlPath(info);
    info.bundleName = this->photosRestore_.FindBundleName(info);
    info.packageName = this->photosRestore_.FindPackageName(info);
    info.photoQuality = this->photosRestore_.FindPhotoQuality(info);
    info.latitude = GetDoubleVal("latitude", resultSet);
    info.longitude = GetDoubleVal("longitude", resultSet);
    info.storyIds = GetStringVal("story_id", resultSet);
    info.portraitIds = GetStringVal("portrait_id", resultSet);
    return isSuccess;
}

bool UpgradeRestore::ParseResultSetFromExternal(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
    int mediaType)
{
    bool isSuccess;
    if (mediaType == DUAL_MEDIA_TYPE::AUDIO_TYPE) {
        isSuccess = ParseResultSetForAudio(resultSet, info);
    } else {
        isSuccess = ParseResultSet(resultSet, info, EXTERNAL_DB_NAME);
    }
    CHECK_AND_RETURN_RET_LOG(isSuccess, isSuccess, "ParseResultSetFromExternal fail");
    info.showDateToken = GetInt64Val(EXTERNAL_DATE_TAKEN, resultSet);
    info.dateTaken = GetInt64Val(EXTERNAL_DATE_TAKEN, resultSet);
    info.sourcePath = GetStringVal(EXTERNAL_FILE_DATA, resultSet);
    info.localMediaId = GetInt32Val(EXTERNAL_FILE_ID, resultSet);
    return isSuccess;
}

NativeRdb::ValuesBucket UpgradeRestore::GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
    int32_t sourceType)
{
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
    values.PutString(MediaColumn::MEDIA_TITLE, fileInfo.title);
    values.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    values.PutString(PhotoColumn::PHOTO_MEDIA_SUFFIX, ScannerUtils::GetFileExtension(fileInfo.displayName));
    values.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.fileType);
    if (fileInfo.firstUpdateTime != 0) {
        values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.firstUpdateTime);
    } else if (fileInfo.dateTaken != 0) {
        values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.dateTaken);
    }
    if (fileInfo.dateTaken != 0) {
        values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, fileInfo.dateTaken);
    }
    values.PutString(PhotoColumn::PHOTO_DETAIL_TIME, fileInfo.detailTime);
    values.PutLong(MediaColumn::MEDIA_DURATION, fileInfo.duration);
    values.PutInt(MediaColumn::MEDIA_IS_FAV, fileInfo.isFavorite);
    if (fileInfo.isFavorite != 0) {
        string fileName = fileInfo.displayName;
        MEDIA_WARN_LOG("the file :%{public}s is favorite.", BackupFileUtils::GarbleFileName(fileName).c_str());
    }
    values.PutLong(MediaColumn::MEDIA_DATE_TRASHED, this->photosRestore_.FindDateTrashed(fileInfo));
    values.PutInt(MediaColumn::MEDIA_HIDDEN, fileInfo.hidden);
    if (fileInfo.hidden != 0) {
        string fileName = fileInfo.displayName;
        MEDIA_WARN_LOG("the file :%{public}s is hidden.", BackupFileUtils::GarbleFileName(fileName).c_str());
    }
    values.PutInt(PhotoColumn::PHOTO_HEIGHT, fileInfo.height);
    values.PutInt(PhotoColumn::PHOTO_WIDTH, fileInfo.width);
    values.PutString(PhotoColumn::PHOTO_USER_COMMENT, fileInfo.userComment);
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, fileInfo.orientation);
    std::string package_name = fileInfo.packageName;
    if (package_name != "") {
        values.PutString(PhotoColumn::MEDIA_PACKAGE_NAME, package_name);
    }
    values.PutInt(PhotoColumn::PHOTO_QUALITY, fileInfo.photoQuality);
    values.PutInt(PhotoColumn::PHOTO_SUBTYPE, this->photosRestore_.FindSubtype(fileInfo));
    values.PutInt(PhotoColumn::PHOTO_BURST_COVER_LEVEL, this->photosRestore_.FindBurstCoverLevel(fileInfo));
    values.PutString(PhotoColumn::PHOTO_BURST_KEY, this->photosRestore_.FindBurstKey(fileInfo));
    // find album_id by lPath.
    values.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, this->photosRestore_.FindAlbumId(fileInfo));
    // fill the source_path at last.
    values.PutString(PhotoColumn::PHOTO_SOURCE_PATH, this->photosRestore_.FindSourcePath(fileInfo));
    values.PutInt(PhotoColumn::PHOTO_STRONG_ASSOCIATION, this->photosRestore_.FindStrongAssociation(fileInfo));
    values.PutInt(PhotoColumn::PHOTO_CE_AVAILABLE, this->photosRestore_.FindCeAvailable(fileInfo));
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, PHOTO_SYNC_STATUS_NOT_VISIBLE); // set invisible for local & cloud
    // for cloud clone
    if (fileInfo.localMediaId == -1) {
        values.PutString(PhotoColumn::PHOTO_CLOUD_ID, fileInfo.uniqueId);
        values.PutInt(PhotoColumn::PHOTO_POSITION, PHOTO_CLOUD_POSITION);
        values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyTypes::TYPE_SYNCED));
    } else {
        values.PutInt(PhotoColumn::PHOTO_DIRTY, this->photosRestore_.FindDirty(fileInfo));
    }
    return values;
}

bool UpgradeRestore::ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix,
    std::string &newPath, std::string &relativePath)
{
    size_t pos = 0;
    CHECK_AND_RETURN_RET(BackupFileUtils::GetPathPosByPrefixLevel(sceneCode_, srcPath,
        INTERNAL_PREFIX_LEVEL, pos), false);
    newPath = prefix + srcPath;
    relativePath = srcPath.substr(pos);
    return true;
}

bool UpgradeRestore::ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix,
    std::string &newPath, std::string &relativePath, FileInfo &fileInfo)
{
    if (MediaFileUtils::StartsWith(srcPath, INTERNAL_PREFIX)) {
        return ConvertPathToRealPath(srcPath, prefix, newPath, relativePath);
    }
    size_t pos = 0;
    if (!BackupFileUtils::GetPathPosByPrefixLevel(sceneCode_, srcPath, SD_PREFIX_LEVEL, pos)) {
        return false;
    }
    relativePath = srcPath.substr(pos);
    if (fileInfo.fileSize < TAR_FILE_LIMIT || fileInfo.localMediaId == GALLERY_HIDDEN_ID ||
        fileInfo.localMediaId == GALLERY_TRASHED_ID) {
        newPath = prefix + srcPath; // packed as tar, hidden or trashed, use path in DB
    } else {
        newPath = prefix + relativePath; // others, remove sd prefix, use relative path
    }
    fileInfo.isInternal = false;
    return true;
}
 
/**
 * @brief Update the FileInfo if it has a copy in system.
 */
bool UpgradeRestore::HasSameFileForDualClone(FileInfo &fileInfo)
{
    PhotosDao::PhotosRowData rowData = this->photosRestore_.FindSameFile(fileInfo);
    int32_t fileId = rowData.fileId;
    std::string cloudPath = rowData.data;
    if (fileId <= 0 || cloudPath.empty()) {
        return false;
    }
    // Meed extra check to determine whether or not to drop the duplicate file.
    return ExtraCheckForCloneSameFile(fileInfo, rowData);
}

void UpgradeRestore::RestoreFromGalleryPortraitAlbum()
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t totalNumber = QueryPortraitAlbumTotalNumber();
    MEDIA_INFO_LOG("QueryPortraitAlbumTotalNumber, totalNumber = %{public}d", totalNumber);

    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        std::vector<std::string> tagNameToDeleteSelection;
        std::vector<std::string> tagIds;
        vector<PortraitAlbumInfo> portraitAlbumInfos = QueryPortraitAlbumInfos(offset,
            tagNameToDeleteSelection);
        CHECK_AND_RETURN_LOG(BackupDatabaseUtils::DeleteDuplicatePortraitAlbum(tagNameToDeleteSelection,
            tagIds, mediaLibraryRdb_), "Batch delete duplicate portrait album failed.");
        InsertPortraitAlbum(portraitAlbumInfos);
    }

    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    migratePortraitTotalTimeCost_ += end - start;
}

int32_t UpgradeRestore::QueryPortraitAlbumTotalNumber()
{
    bool isSyncSwitchOpen = CloudSyncHelper::GetInstance()->IsSyncSwitchOpen();
    return BackupDatabaseUtils::QueryInt(galleryRdb_,
        ((isAccountValid_ && isSyncSwitchOpen) ?
        QUERY_GALLERY_PORTRAIT_ALBUM_WITH_CLOUD_COUNT : QUERY_GALLERY_PORTRAIT_ALBUM_COUNT), CUSTOM_COUNT);
}

vector<PortraitAlbumInfo> UpgradeRestore::QueryPortraitAlbumInfos(int32_t offset,
    std::vector<std::string>& tagNameToDeleteSelection)
{
    vector<PortraitAlbumInfo> result;
    result.reserve(QUERY_COUNT);
    bool isSyncSwitchOpen = CloudSyncHelper::GetInstance()->IsSyncSwitchOpen();

    std::string querySql = "SELECT " + GALLERY_MERGE_TAG_TAG_ID + ", " + GALLERY_GROUP_TAG + ", " +
        GALLERY_TAG_NAME + ", " + GALLERY_USER_OPERATION + ", " + GALLERY_RENAME_OPERATION +
        " FROM " + ((isAccountValid_ && isSyncSwitchOpen) ?
        GALLERY_PORTRAIT_ALBUM_TABLE_WITH_CLOUD : GALLERY_PORTRAIT_ALBUM_TABLE);
    querySql += " LIMIT " + std::to_string(offset) + ", " + std::to_string(QUERY_COUNT);

    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(galleryRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PortraitAlbumInfo portraitAlbumInfo;
        if (!ParsePortraitAlbumResultSet(resultSet, portraitAlbumInfo)) {
            MEDIA_ERR_LOG("Parse portrait album result set failed, exclude %{public}s",
                portraitAlbumInfo.tagName.c_str());
            continue;
        }
        if (!SetAttributes(portraitAlbumInfo)) {
            MEDIA_ERR_LOG("Set attributes failed, exclude %{public}s", portraitAlbumInfo.tagName.c_str());
            continue;
        }
        if (!portraitAlbumInfo.tagName.empty()) {
            tagNameToDeleteSelection.emplace_back(portraitAlbumInfo.tagName);
        }

        result.emplace_back(portraitAlbumInfo);
    }
    return result;
}

bool UpgradeRestore::ParsePortraitAlbumResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    PortraitAlbumInfo &portraitAlbumInfo)
{
    portraitAlbumInfo.tagIdOld = GetStringVal(GALLERY_MERGE_TAG_TAG_ID, resultSet);
    portraitAlbumInfo.groupTagOld = GetStringVal(GALLERY_GROUP_TAG, resultSet);
    portraitAlbumInfo.tagName = GetStringVal(GALLERY_TAG_NAME, resultSet);
    portraitAlbumInfo.userOperation = GetInt32Val(GALLERY_USER_OPERATION, resultSet);
    portraitAlbumInfo.renameOperation = GetInt32Val(GALLERY_RENAME_OPERATION, resultSet);
    return true;
}

bool UpgradeRestore::SetAttributes(PortraitAlbumInfo &portraitAlbumInfo)
{
    return BackupDatabaseUtils::SetTagIdNew(portraitAlbumInfo, tagIdMap_);
}

void UpgradeRestore::InsertPortraitAlbum(std::vector<PortraitAlbumInfo> &portraitAlbumInfos)
{
    CHECK_AND_RETURN_LOG(mediaLibraryRdb_ != nullptr, "mediaLibraryRdb_ is null");
    CHECK_AND_RETURN_LOG(!portraitAlbumInfos.empty(), "portraitAlbumInfos are empty");

    int64_t startInsertAlbum = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t albumRowNum = InsertPortraitAlbumByTable(portraitAlbumInfos, true);
    if (albumRowNum <= 0) {
        BackupDatabaseUtils::PrintErrorLog("Insert portrait album failed", startInsertAlbum);
        return;
    }

    int64_t startInsertTag = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t tagRowNum = InsertPortraitAlbumByTable(portraitAlbumInfos, false);
    if (tagRowNum <= 0) {
        BackupDatabaseUtils::PrintErrorLog("Insert face tag failed", startInsertTag);
        return;
    }

    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    BatchQueryAlbum(portraitAlbumInfos);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("insert %{public}ld albums cost %{public}ld, %{public}ld tags cost %{public}ld, query cost "
        "%{public}ld.", (long)albumRowNum, (long)(startInsertTag - startInsertAlbum), (long)tagRowNum,
        (long)(startQuery - startInsertTag), (long)(end - startQuery));
}

int32_t UpgradeRestore::InsertPortraitAlbumByTable(std::vector<PortraitAlbumInfo> &portraitAlbumInfos,
    bool isAlbum)
{
    std::vector<NativeRdb::ValuesBucket> values = GetInsertValues(portraitAlbumInfos, isAlbum);
    int64_t rowNum = 0;
    std::string tableName = isAlbum ? ANALYSIS_ALBUM_TABLE : VISION_FACE_TAG_TABLE;
    int32_t errCode = BatchInsertWithRetry(tableName, values, rowNum);
    CHECK_AND_RETURN_RET(errCode == E_OK, 0);
    return rowNum;
}

std::vector<NativeRdb::ValuesBucket> UpgradeRestore::GetInsertValues(std::vector<PortraitAlbumInfo> &portraitAlbumInfos,
    bool isAlbum)
{
    std::vector<NativeRdb::ValuesBucket> values;
    for (auto &portraitAlbumInfo : portraitAlbumInfos) {
        NativeRdb::ValuesBucket value = GetInsertValue(portraitAlbumInfo, isAlbum);
        values.emplace_back(value);
    }
    return values;
}

NativeRdb::ValuesBucket UpgradeRestore::GetInsertValue(const PortraitAlbumInfo &portraitAlbumInfo, bool isAlbum)
{
    NativeRdb::ValuesBucket values;
    values.PutString(TAG_ID, portraitAlbumInfo.tagIdNew);
    values.PutInt(COUNT, 0);
    if (isAlbum) {
        values.PutString(ALBUM_NAME, portraitAlbumInfo.tagName);
        values.PutString(GROUP_TAG, portraitAlbumInfo.groupTagOld);
        values.PutInt(USER_OPERATION, portraitAlbumInfo.userOperation);
        values.PutInt(RENAME_OPERATION, RENAME_OPERATION_RENAMED);
        values.PutInt(ALBUM_TYPE, PhotoAlbumType::SMART);
        values.PutInt(ALBUM_SUBTYPE, PhotoAlbumSubType::PORTRAIT);
        values.PutInt(USER_DISPLAY_LEVEL, PortraitPages::FIRST_PAGE);
        values.PutInt(IS_LOCAL, IS_LOCAL_TRUE);
    } else {
        values.PutString(TAG_VERSION, E_VERSION); // updated by analysis service
    }
    return values;
}

void UpgradeRestore::BatchQueryAlbum(std::vector<PortraitAlbumInfo> &portraitAlbumInfos)
{
    std::string tagIdSelection;
    for (auto &portraitAlbumInfo : portraitAlbumInfos) {
        BackupDatabaseUtils::UpdateSelection(tagIdSelection, portraitAlbumInfo.tagIdNew, true);
    }
    std::string querySql = "SELECT " + ALBUM_ID + ", " + TAG_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " +
        TAG_ID + " IN (" + tagIdSelection + ")";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "resultSet is nullptr");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t albumId = GetInt32Val(ALBUM_ID, resultSet);
        std::string tagId = GetStringVal(TAG_ID, resultSet);
        if (albumId <= 0 || tagId.empty()) {
            continue;
        }
        portraitAlbumIdMap_[tagId] = albumId;
    }
}

bool UpgradeRestore::NeedBatchQueryPhotoForPortrait(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap)
{
    if (portraitAlbumIdMap_.empty()) {
        return false;
    }
    std::string selection;
    for (const auto &fileInfo : fileInfos) {
        BackupDatabaseUtils::UpdateSelection(selection, std::to_string(fileInfo.fileIdOld), false);
    }
    std::unordered_set<std::string> needQuerySet;
    std::string querySql = "SELECT DISTINCT " + GALLERY_MERGE_FACE_HASH + " FROM " + GALLERY_FACE_TABLE_JOIN_TAG +
        " HAVING " + GALLERY_MEDIA_ID + " IN (" + selection + ") AND " + GALLERY_TAG_NAME_NOT_NULL_OR_EMPTY;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(galleryRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string hash = GetStringVal(GALLERY_MERGE_FACE_HASH, resultSet);
        if (hash.empty()) {
            continue;
        }
        needQuerySet.insert(hash);
    }
    CHECK_AND_RETURN_RET(!needQuerySet.empty(), false);
    needQueryMap[PhotoRelatedType::PORTRAIT] = needQuerySet;
    return true;
}

void UpgradeRestore::InsertFaceAnalysisData(const std::vector<FileInfo> &fileInfos, const NeedQueryMap &needQueryMap,
    int64_t &faceRowNum, int64_t &mapRowNum, int64_t &photoNum)
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    if (needQueryMap.count(PhotoRelatedType::PORTRAIT) == 0) {
        return;
    }
    bool cond = (mediaLibraryRdb_ == nullptr || fileInfos.empty());
    CHECK_AND_RETURN_LOG(!cond, "mediaLibraryRdb_ is null or fileInfos empty");

    std::string hashSelection;
    std::unordered_map<std::string, FileInfo> fileInfoMap;
    SetHashReference(fileInfos, needQueryMap, hashSelection, fileInfoMap);

    int32_t totalNumber = QueryFaceTotalNumber(hashSelection);
    MEDIA_INFO_LOG("Current %{public}zu / %{public}zu have %{public}d faces", fileInfoMap.size(), fileInfos.size(),
        totalNumber);
    std::unordered_set<std::string> excludedFiles;
    std::unordered_set<std::string> filesWithFace;
    auto uniqueFileIdPairs = BackupDatabaseUtils::CollectFileIdPairs(fileInfos);
    BackupDatabaseUtils::DeleteExistingImageFaceData(mediaLibraryRdb_, uniqueFileIdPairs);

    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        std::vector<FaceInfo> faceInfos = QueryFaceInfos(hashSelection, fileInfoMap, offset, excludedFiles);
        int64_t startInsertFace = MediaFileUtils::UTCTimeMilliSeconds();
        faceRowNum += InsertFaceAnalysisDataByTable(faceInfos, false, excludedFiles);
        if (faceRowNum <= 0) {
            BackupDatabaseUtils::PrintErrorLog("Insert face failed", startInsertFace);
            continue;
        }
        int64_t startInsertMap = MediaFileUtils::UTCTimeMilliSeconds();
        mapRowNum += InsertFaceAnalysisDataByTable(faceInfos, true, excludedFiles);
        if (mapRowNum <= 0) {
            BackupDatabaseUtils::PrintErrorLog("Insert map failed", startInsertMap);
            continue;
        }
        UpdateFilesWithFace(filesWithFace, faceInfos);
        int64_t endInsert = MediaFileUtils::UTCTimeMilliSeconds();
        MEDIA_INFO_LOG("insert %{public}ld faces cost %{public}ld, %{public}ld maps cost %{public}ld", (long)faceRowNum,
            (long)(startInsertMap - startInsertFace), (long)mapRowNum, (long)(endInsert - startInsertMap));
    }
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    photoNum = static_cast<int64_t>(filesWithFace.size());
    migratePortraitFaceNumber_ += faceRowNum;
    migratePortraitPhotoNumber_ += photoNum;
    migratePortraitTotalTimeCost_ += end - start;
}

void UpgradeRestore::SetHashReference(const std::vector<FileInfo> &fileInfos, const NeedQueryMap &needQueryMap,
    std::string &hashSelection, std::unordered_map<std::string, FileInfo> &fileInfoMap)
{
    auto needQuerySet = needQueryMap.at(PhotoRelatedType::PORTRAIT);
    for (const auto &fileInfo : fileInfos) {
        if (needQuerySet.count(fileInfo.hashCode) == 0 || fileInfo.fileIdNew <= 0) {
            continue;
        }
        if (fileInfoMap.count(fileInfo.hashCode) > 0) {
            continue; // select the first one to build map
        }
        BackupDatabaseUtils::UpdateSelection(hashSelection, fileInfo.hashCode, true);
        fileInfoMap[fileInfo.hashCode] = fileInfo;
    }
}

int32_t UpgradeRestore::QueryFaceTotalNumber(const std::string &hashSelection)
{
    std::string querySql = "SELECT count(1) as count FROM " + GALLERY_FACE_TABLE_FULL + " AND " +
        GALLERY_MERGE_FACE_HASH + " IN (" + hashSelection + ")";
    return BackupDatabaseUtils::QueryInt(galleryRdb_, querySql, CUSTOM_COUNT);
}

std::vector<FaceInfo> UpgradeRestore::QueryFaceInfos(const std::string &hashSelection,
    const std::unordered_map<std::string, FileInfo> &fileInfoMap, int32_t offset,
    std::unordered_set<std::string> &excludedFiles)
{
    vector<FaceInfo> result;
    result.reserve(QUERY_COUNT);
    std::string querySql = "SELECT " + GALLERY_SCALE_X + ", " + GALLERY_SCALE_Y + ", " + GALLERY_SCALE_WIDTH + ", " +
        GALLERY_SCALE_HEIGHT + ", " + GALLERY_PITCH + ", " + GALLERY_YAW + ", " + GALLERY_ROLL + ", " +
        GALLERY_PROB + ", " + GALLERY_TOTAL_FACE + ", " + GALLERY_MERGE_FACE_HASH + ", " + GALLERY_MERGE_FACE_FACE_ID +
        ", " + GALLERY_MERGE_FACE_TAG_ID + ", " + GALLERY_LANDMARKS + " FROM " + GALLERY_FACE_TABLE_FULL + " AND " +
        GALLERY_MERGE_FACE_HASH + " IN (" + hashSelection + ") ORDER BY " + GALLERY_MERGE_FACE_HASH + ", " +
        GALLERY_MERGE_FACE_FACE_ID;
    querySql += " LIMIT " + std::to_string(offset) + ", " + std::to_string(QUERY_COUNT);
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(galleryRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FaceInfo faceInfo;
        if (!ParseFaceResultSet(resultSet, faceInfo)) {
            MEDIA_ERR_LOG("Parse face result set failed, exclude %{public}s", faceInfo.hash.c_str());
            excludedFiles.insert(faceInfo.hash);
            continue;
        }
        if (!SetAttributes(faceInfo, fileInfoMap)) {
            MEDIA_ERR_LOG("Set attributes failed, exclude %{public}s", faceInfo.hash.c_str());
            excludedFiles.insert(faceInfo.hash);
            continue;
        }
        result.emplace_back(faceInfo);
    }
    return result;
}

bool UpgradeRestore::ParseFaceResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FaceInfo &faceInfo)
{
    faceInfo.scaleX = GetDoubleVal(GALLERY_SCALE_X, resultSet);
    faceInfo.scaleY = GetDoubleVal(GALLERY_SCALE_Y, resultSet);
    faceInfo.scaleWidth = GetDoubleVal(GALLERY_SCALE_WIDTH, resultSet);
    faceInfo.scaleHeight = GetDoubleVal(GALLERY_SCALE_HEIGHT, resultSet);
    faceInfo.pitch = GetDoubleVal(GALLERY_PITCH, resultSet);
    faceInfo.yaw = GetDoubleVal(GALLERY_YAW, resultSet);
    faceInfo.roll = GetDoubleVal(GALLERY_ROLL, resultSet);
    faceInfo.prob = GetDoubleVal(GALLERY_PROB, resultSet);
    faceInfo.totalFaces = GetInt32Val(GALLERY_TOTAL_FACE, resultSet);
    faceInfo.hash = GetStringVal(GALLERY_MERGE_FACE_HASH, resultSet);
    faceInfo.faceId = GetStringVal(GALLERY_MERGE_FACE_FACE_ID, resultSet);
    faceInfo.tagIdOld = GetStringVal(GALLERY_MERGE_FACE_TAG_ID, resultSet);
    faceInfo.landmarks = BackupDatabaseUtils::GetLandmarksStr(GALLERY_LANDMARKS, resultSet);
    CHECK_AND_RETURN_RET_LOG(!faceInfo.landmarks.empty(), false,
        "Get invalid landmarks for face %{public}s", faceInfo.faceId.c_str());
    return true;
}

bool UpgradeRestore::SetAttributes(FaceInfo &faceInfo, const std::unordered_map<std::string, FileInfo> &fileInfoMap)
{
    return BackupDatabaseUtils::SetLandmarks(faceInfo, fileInfoMap) &&
        BackupDatabaseUtils::SetFileIdNew(faceInfo, fileInfoMap) &&
        BackupDatabaseUtils::SetTagIdNew(faceInfo, tagIdMap_) &&
        BackupDatabaseUtils::SetAlbumIdNew(faceInfo, portraitAlbumIdMap_);
}

int32_t UpgradeRestore::InsertFaceAnalysisDataByTable(const std::vector<FaceInfo> &faceInfos, bool isMap,
    const std::unordered_set<std::string> &excludedFiles)
{
    std::vector<NativeRdb::ValuesBucket> values = GetInsertValues(faceInfos, isMap, excludedFiles);
    int64_t rowNum = 0;
    std::string tableName = isMap ? ANALYSIS_PHOTO_MAP_TABLE : VISION_IMAGE_FACE_TABLE;
    int32_t errCode = BatchInsertWithRetry(tableName, values, rowNum);
    CHECK_AND_RETURN_RET(errCode == E_OK, 0);
    return rowNum;
}

std::vector<NativeRdb::ValuesBucket> UpgradeRestore::GetInsertValues(const std::vector<FaceInfo> &faceInfos, bool isMap,
    const std::unordered_set<std::string> &excludedFiles)
{
    std::vector<NativeRdb::ValuesBucket> values;
    for (auto &faceInfo : faceInfos) {
        if (excludedFiles.count(faceInfo.hash) > 0) {
            continue;
        }
        if (isMap && faceInfo.tagIdNew == TAG_ID_UNPROCESSED) {
            continue;
        }
        NativeRdb::ValuesBucket value = GetInsertValue(faceInfo, isMap);
        values.emplace_back(value);
    }
    return values;
}

NativeRdb::ValuesBucket UpgradeRestore::GetInsertValue(const FaceInfo &faceInfo, bool isMap)
{
    NativeRdb::ValuesBucket values;
    if (isMap) {
        values.PutInt(MAP_ALBUM, faceInfo.albumIdNew);
        values.PutInt(MAP_ASSET, faceInfo.fileIdNew);
    } else {
        values.PutDouble(SCALE_X, faceInfo.scaleX);
        values.PutDouble(SCALE_Y, faceInfo.scaleY);
        values.PutDouble(SCALE_WIDTH, faceInfo.scaleWidth);
        values.PutDouble(SCALE_HEIGHT, faceInfo.scaleHeight);
        values.PutDouble(PITCH, faceInfo.pitch);
        values.PutDouble(YAW, faceInfo.yaw);
        values.PutDouble(ROLL, faceInfo.roll);
        values.PutDouble(PROB, faceInfo.prob);
        values.PutInt(TOTAL_FACES, faceInfo.totalFaces);
        values.PutInt(FILE_ID, faceInfo.fileIdNew);
        values.PutString(FACE_ID, faceInfo.faceId);
        values.PutString(TAG_ID, faceInfo.tagIdNew);
        values.PutString(LANDMARKS, faceInfo.landmarks);
        values.PutString(IMAGE_FACE_VERSION, DEFAULT_BACKUP_VERSION); // replaced by the latest
        values.PutString(IMAGE_FEATURES_VERSION, E_VERSION); // updated by analysis service
    }
    return values;
}

void UpgradeRestore::UpdateFilesWithFace(std::unordered_set<std::string> &filesWithFace,
    const std::vector<FaceInfo> &faceInfos)
{
    for (const auto &faceInfo : faceInfos) {
        if (faceInfo.hash.empty()) {
            continue;
        }
        filesWithFace.insert(faceInfo.hash);
    }
}

void UpgradeRestore::UpdateFaceAnalysisStatus()
{
    if (portraitAlbumIdMap_.empty()) {
        MEDIA_INFO_LOG("There is no need to update face analysis status");
        return;
    }
    int64_t startUpdateGroupTag = MediaFileUtils::UTCTimeMilliSeconds();
    BackupDatabaseUtils::UpdateFaceGroupTagOfDualFrame(mediaLibraryRdb_);
    int64_t startUpdateTotal = MediaFileUtils::UTCTimeMilliSeconds();
    BackupDatabaseUtils::UpdateAnalysisTotalStatus(mediaLibraryRdb_);
    int64_t startUpdateFaceTag = MediaFileUtils::UTCTimeMilliSeconds();
    BackupDatabaseUtils::UpdateAnalysisFaceTagStatus(mediaLibraryRdb_);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("Update group tag cost %{public}lld, update total table cost %{public}lld, update face tag table "
        "cost %{public}lld", (long long)(startUpdateTotal - startUpdateGroupTag),
        (long long)(startUpdateFaceTag - startUpdateTotal), (long long)(end - startUpdateFaceTag));
    migratePortraitTotalTimeCost_ += end - startUpdateGroupTag;
}

void UpgradeRestore::UpdateDualCloneFaceAnalysisStatus()
{
    if (portraitAlbumIdMap_.empty()) {
        MEDIA_INFO_LOG("There is no need to update face analysis status");
        return;
    }

    BackupDatabaseUtils::UpdateFaceGroupTagOfDualFrame(mediaLibraryRdb_);
    BackupDatabaseUtils::UpdateAnalysisPhotoMapStatus(mediaLibraryRdb_);
    BackupDatabaseUtils::UpdateFaceAnalysisTblStatus(mediaLibraryRdb_);
}

std::string UpgradeRestore::CheckInvalidFile(const FileInfo &fileInfo, int32_t errCode)
{
    CHECK_AND_RETURN_RET(errCode == E_NO_SUCH_FILE, "");
    int32_t dbType = BackupDatabaseHelper::DbType::DEFAULT;
    int32_t dbStatus = E_OK;
    int32_t fileStatus = E_OK;
    backupDatabaseHelper_.IsFileExist(sceneCode_, fileInfo, dbType, dbStatus, fileStatus);
    MEDIA_INFO_LOG("Check status type: %{public}d, db: %{public}d, file: %{public}d", dbType, dbStatus, fileStatus);
    return BackupLogUtils::FileDbCheckInfoToString(FileDbCheckInfo(dbType, dbStatus, fileStatus));
}

int32_t UpgradeRestore::GetNoNeedMigrateCount()
{
    return GalleryMediaDao(this->galleryRdb_).GetNoNeedMigrateCount(this->shouldIncludeSd_);
}

bool UpgradeRestore::IsBasicInfoValid(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
    const std::string &dbName)
{
    info.displayName = GetStringVal(GALLERY_DISPLAY_NAME, resultSet);
    info.oldPath = GetStringVal(GALLERY_FILE_DATA, resultSet);
    info.fileType = GetInt32Val(GALLERY_MEDIA_TYPE, resultSet);
    info.fileSize = GetInt64Val(GALLERY_FILE_SIZE, resultSet); // read basic info from db first
    if (this->photosRestore_.IsDuplicateData(info.oldPath)) {
        ErrorInfo errorInfo(RestoreError::DUPLICATE_DATA, 1, "",
            BackupLogUtils::FileInfoToString(sceneCode_, info));
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return false;
    }
    if (info.thumbType != 0) {
        if (sceneCode_ == UPGRADE_RESTORE_ID ?
            !BaseRestore::ConvertPathToRealPath(info.oldPath, filePath_, info.filePath, info.relativePath) :
            !ConvertPathToRealPath(info.oldPath, filePath_, info.filePath, info.relativePath, info)) {
            ErrorInfo errorInfo(RestoreError::PATH_INVALID, 1, "",
                BackupLogUtils::FileInfoToString(sceneCode_, info));
            UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
            return false;
        }
    }
    info.fileType = this->photosRestore_.FindMediaType(info);
    if (info.fileType != MediaType::MEDIA_TYPE_IMAGE && info.fileType != MediaType::MEDIA_TYPE_VIDEO) {
        ErrorInfo errorInfo(RestoreError::MEDIA_TYPE_INVALID, 1, std::to_string(info.fileType),
            BackupLogUtils::FileInfoToString(sceneCode_, info));
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return false;
    }
    if (info.fileSize < fileMinSize_ && dbName == EXTERNAL_DB_NAME) {
        MEDIA_WARN_LOG("maybe garbage path = %{public}s, minSize:%{public}d.",
            BackupFileUtils::GarbleFilePath(info.oldPath, DEFAULT_RESTORE_ID).c_str(), fileMinSize_);
        ErrorInfo errorInfo(RestoreError::SIZE_INVALID, 1, "Db size < " + std::to_string(fileMinSize_),
            BackupLogUtils::FileInfoToString(sceneCode_, info));
        UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).ReportError(errorInfo);
        return false;
    }
    return true;
}

std::string UpgradeRestore::CheckGalleryDbIntegrity()
{
    MEDIA_INFO_LOG("start handle gallery integrity check.");
    std::string dbIntegrityCheck = DB_INTEGRITY_CHECK;
    std::string dbSize = "";
    struct stat statInfo {};
    if (stat(galleryDbPath_.c_str(), &statInfo) == 0) {
        dbSize = std::to_string(statInfo.st_size);
    }
    int64_t dbIntegrityCheckTime = MediaFileUtils::UTCTimeMilliSeconds();
    dbIntegrityCheck = BackupDatabaseUtils::CheckDbIntegrity(galleryRdb_, sceneCode_, "GALLERY_DB_CORRUPTION");
    dbIntegrityCheckTime = MediaFileUtils::UTCTimeMilliSeconds() - dbIntegrityCheckTime;
    UpgradeRestoreTaskReport()
        .SetSceneCode(this->sceneCode_)
        .SetTaskId(this->taskId_)
        .ReportProgress("GalleryDbCheck", dbSize + ";" + std::to_string(dbIntegrityCheckTime));
    MEDIA_INFO_LOG("end handle gallery integrity check, cost %{public}lld, size %{public}s.", \
        (long long)(dbIntegrityCheckTime), dbSize.c_str());
    return dbIntegrityCheck;
}

void UpgradeRestore::PrcoessContinuousShootingPhotos()
{
    BackupDatabaseUtils::UpdateContinuousShootingPhotos(galleryRdb_, maxfileId_);
    MEDIA_INFO_LOG(" prcoess continous shooting photos end");
}
} // namespace Media
} // namespace OHOS