/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaLibraryMetaRecovery"

#include "medialibrary_meta_recovery.h"

#include <cerrno>
#include <dirent.h>
#include <fcntl.h>

#include "acl.h"
#include "cloud_sync_helper.h"
#include "dfx_utils.h"
#include "directory_ex.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner_const.h"
#include "media_scanner_db.h"
#include "media_scanner_manager.h"
#include "metadata.h"
#include "metadata_extractor.h"
#include "medialibrary_album_fusion_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_notify.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "mimetype_utils.h"
#include "parameter.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "post_event_utils.h"
#include "result_set_utils.h"
#include "vision_column.h"

namespace OHOS {
namespace Media {
using namespace std;
using json = nlohmann::json;
using ResultTypeMap = unordered_map<string, ResultSetDataType>;

namespace {
    const string META_RECOVERY_ROOT_DIR = ROOT_MEDIA_DIR + ".meta/";
    const string META_RECOVERY_PHOTO_RELATIVE_PATH = "/Photo/";
    const string META_RECOVERY_META_RELATIVE_PATH = "/.meta/Photo/";
    const string META_RECOVERY_META_FILE_SUFFIX = ".json";
    const string META_RECOVERY_ALBUM_PATH = META_RECOVERY_ROOT_DIR + "album.json";
    const string META_STATUS_PATH = META_RECOVERY_ROOT_DIR + "status.json";
    constexpr int32_t QUERY_BATCH_SIZE = 500;
    const int32_t META_RETRY_MAX_COUNTS = 10;

    const ResultTypeMap RESULT_TYPE_MAP = {
        { MediaColumn::MEDIA_FILE_PATH, TYPE_STRING },
        { MediaColumn::MEDIA_SIZE, TYPE_INT64 },
        { MediaColumn::MEDIA_TITLE, TYPE_STRING },
        { MediaColumn::MEDIA_NAME, TYPE_STRING },
        { MediaColumn::MEDIA_TYPE, TYPE_INT32 },
        { MediaColumn::MEDIA_MIME_TYPE, TYPE_STRING },
        { MediaColumn::MEDIA_OWNER_PACKAGE, TYPE_STRING },
        { MediaColumn::MEDIA_OWNER_APPID, TYPE_STRING },
        { MediaColumn::MEDIA_PACKAGE_NAME, TYPE_STRING },
        { MediaColumn::MEDIA_DEVICE_NAME, TYPE_STRING },
        { MediaColumn::MEDIA_DATE_ADDED, TYPE_INT64 },
        { MediaColumn::MEDIA_DATE_MODIFIED, TYPE_INT64 },
        { MediaColumn::MEDIA_DATE_TAKEN, TYPE_INT64 },
        { MediaColumn::MEDIA_DURATION, TYPE_INT32 },
        { MediaColumn::MEDIA_TIME_PENDING, TYPE_INT64 },
        { MediaColumn::MEDIA_IS_FAV, TYPE_INT32 },
        { MediaColumn::MEDIA_DATE_TRASHED, TYPE_INT64 },
        { MediaColumn::MEDIA_DATE_DELETED, TYPE_INT64 },
        { MediaColumn::MEDIA_HIDDEN, TYPE_INT32 },
        { MediaColumn::MEDIA_PARENT_ID, TYPE_INT32 },
        { MediaColumn::MEDIA_RELATIVE_PATH, TYPE_STRING },
        { PhotoColumn::PHOTO_DIRTY, TYPE_INT32 },
        { PhotoColumn::PHOTO_CLOUD_ID, TYPE_STRING },
        { PhotoColumn::PHOTO_META_DATE_MODIFIED, TYPE_INT64 },
        { PhotoColumn::PHOTO_SYNC_STATUS, TYPE_INT32 },
        { PhotoColumn::PHOTO_CLOUD_VERSION, TYPE_INT64 },
        { PhotoColumn::PHOTO_ORIENTATION, TYPE_INT32 },
        { PhotoColumn::PHOTO_LATITUDE, TYPE_DOUBLE },
        { PhotoColumn::PHOTO_LONGITUDE, TYPE_DOUBLE },
        { PhotoColumn::PHOTO_HEIGHT, TYPE_INT32 },
        { PhotoColumn::PHOTO_WIDTH, TYPE_INT32 },
        { PhotoColumn::PHOTO_EDIT_TIME, TYPE_INT64 },
        { PhotoColumn::PHOTO_LCD_VISIT_TIME, TYPE_INT64 },
        { PhotoColumn::PHOTO_POSITION, TYPE_INT32 },
        { PhotoColumn::PHOTO_SUBTYPE, TYPE_INT32 },
        { PhotoColumn::PHOTO_ORIGINAL_SUBTYPE, TYPE_INT32 },
        { PhotoColumn::CAMERA_SHOT_KEY, TYPE_STRING },
        { PhotoColumn::PHOTO_USER_COMMENT, TYPE_STRING },
        { PhotoColumn::PHOTO_ALL_EXIF, TYPE_STRING },
        { PhotoColumn::PHOTO_DATE_YEAR, TYPE_STRING },
        { PhotoColumn::PHOTO_DATE_MONTH, TYPE_STRING },
        { PhotoColumn::PHOTO_DATE_DAY, TYPE_STRING },
        { PhotoColumn::PHOTO_SHOOTING_MODE, TYPE_STRING },
        { PhotoColumn::PHOTO_SHOOTING_MODE_TAG, TYPE_STRING },
        { PhotoColumn::PHOTO_LAST_VISIT_TIME, TYPE_INT64 },
        { PhotoColumn::PHOTO_HIDDEN_TIME, TYPE_INT64 },
        { PhotoColumn::PHOTO_THUMB_STATUS, TYPE_INT32 },
        { PhotoColumn::PHOTO_CLEAN_FLAG, TYPE_INT32 },
        { PhotoColumn::PHOTO_ID, TYPE_STRING },
        { PhotoColumn::PHOTO_QUALITY, TYPE_INT32 },
        { PhotoColumn::PHOTO_FIRST_VISIT_TIME, TYPE_INT64 },
        { PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, TYPE_INT32 },
        { PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, TYPE_INT32 },
        { PhotoColumn::MOVING_PHOTO_EFFECT_MODE, TYPE_INT32 },
        { PhotoColumn::PHOTO_COVER_POSITION, TYPE_INT64 },
        { PhotoColumn::PHOTO_LCD_SIZE, TYPE_STRING },
        { PhotoColumn::PHOTO_THUMB_SIZE, TYPE_STRING },
        { PhotoColumn::PHOTO_FRONT_CAMERA, TYPE_STRING },
        { PhotoColumn::PHOTO_IS_TEMP, TYPE_INT32 },
        { PhotoColumn::PHOTO_BURST_COVER_LEVEL, TYPE_INT32 },
        { PhotoColumn::PHOTO_BURST_KEY, TYPE_STRING },
        { PhotoColumn::PHOTO_CE_AVAILABLE, TYPE_INT32 },
        { PhotoColumn::PHOTO_CE_STATUS_CODE, TYPE_INT32 },
        { PhotoColumn::PHOTO_STRONG_ASSOCIATION, TYPE_INT32 },
        { PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, TYPE_INT32 },
        { PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, TYPE_INT32 },
        { PhotoColumn::PHOTO_DETAIL_TIME, TYPE_STRING },
        { PhotoColumn::PHOTO_OWNER_ALBUM_ID, TYPE_INT32 },
        { PhotoColumn::PHOTO_ORIGINAL_ASSET_CLOUD_ID, TYPE_STRING },
        { PhotoColumn::PHOTO_SOURCE_PATH, TYPE_STRING },
    };
} // namespace

static void SetStartupParam()
{
    static constexpr uint32_t BASE_USER_RANGE = 200000; // for get uid
    uid_t uid = getuid() / BASE_USER_RANGE;
    const string key = "multimedia.medialibrary.startup." + to_string(uid);
    string value = "true";
    int ret = SetParameter(key.c_str(), value.c_str());
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to set startup, result: %{public}d", ret);
    } else {
        MEDIA_INFO_LOG("Set startup success: %{public}s", to_string(uid).c_str());
    }
}

static int32_t RefreshThumbnail()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("RefreshThumbnail: failed to get rdb store handler");
        return E_HAS_DB_ERROR;
    }

    MediaLibraryKvStoreManager::GetInstance().RebuildInvalidKvStore(KvStoreValueType::MONTH_ASTC);
    MediaLibraryKvStoreManager::GetInstance().RebuildInvalidKvStore(KvStoreValueType::YEAR_ASTC);
    Acl::AclSetDatabase();
    return E_OK;
}

static int32_t RefreshAlbumCount()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("RefreshAlbumCount: failed to get rdb store handler");
        return E_HAS_DB_ERROR;
    }
    auto rawRdbStore = rdbStore->GetRaw();
    if (rawRdbStore == nullptr) {
        MEDIA_ERR_LOG("rawRdbStore == nullptr");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryRdbUtils::UpdateAllAlbums(rawRdbStore);
    MediaLibraryAlbumFusionUtils::RefreshAllAlbums();
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("Can not get MediaLibraryNotify Instance");
        return E_ERR;
    }

    watch->Notify(PhotoAlbumColumns::ALBUM_URI_PREFIX, NotifyType::NOTIFY_ADD);
    watch->Notify(PhotoAlbumColumns::ALBUM_URI_PREFIX, NotifyType::NOTIFY_UPDATE);
    return E_OK;
}

static int32_t getMetaPathFromOrignalPath(const std::string &srcPath, std::string &metaPath)
{
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("getMetaPathFromOrignalPath: source file invalid!");
        return E_INVALID_PATH;
    }

    size_t pos = srcPath.find(META_RECOVERY_PHOTO_RELATIVE_PATH);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("getMetaPathFromOrignalPath: source path is not a photo path");
        return E_INVALID_PATH;
    }

    metaPath = srcPath;
    metaPath.replace(pos, META_RECOVERY_PHOTO_RELATIVE_PATH.length(), META_RECOVERY_META_RELATIVE_PATH);
    metaPath += META_RECOVERY_META_FILE_SUFFIX;

    return E_OK;
}

static std::optional<std::string> GetStringFromJson(const nlohmann::json &j, const std::string &key)
{
    if (j.contains(key) && j.at(key).is_string()) {
        std::string value = j.at(key);
        MEDIA_DEBUG_LOG("get string json ok, %{private}s: %{private}s", key.c_str(), value.c_str());
        return std::optional<std::string>(value);
    } else {
        MEDIA_ERR_LOG("get key: %{private}s failed", key.c_str());
        return std::nullopt;
    }
}

static std::optional<int64_t> GetNumberFromJson(const nlohmann::json &j, const std::string &key)
{
    if (j.contains(key) && j.at(key).is_number_integer()) {
        int64_t value = j.at(key);
        MEDIA_DEBUG_LOG("get number json ok, %{private}s: %{private}lld", key.c_str(), value);
        return std::optional<int64_t>(value);
    } else {
        MEDIA_ERR_LOG("get key: %{private}s failed", key.c_str());
        return std::nullopt;
    }
}

static std::optional<double> GetDoubleFromJson(const nlohmann::json &j, const std::string &key)
{
    if (j.contains(key) && j.at(key).is_number_float()) {
        double value = j.at(key);
        MEDIA_DEBUG_LOG("get double json ok, %{private}s: %{private}f", key.c_str(), value);
        return std::optional<double>(value);
    } else {
        MEDIA_ERR_LOG("get key: %{private}s failed", key.c_str());
        return std::nullopt;
    }
}

static shared_ptr<NativeRdb::RdbStore> GetRdbStoreRaw()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Get rdb store failed from unistore manager");
        return nullptr;
    }

    return rdbStore->GetRaw();
}

static void SetValuesFromFileAsset(const FileAsset &fileAsset, ValuesBucket &values)
{
    for (const auto &item : RESULT_TYPE_MAP) {
        string name = item.first;
        int type = item.second;
        if (type == TYPE_STRING) {
            values.PutString(name, fileAsset.GetStrMember(name));
            MEDIA_DEBUG_LOG("insert: string: %{private}s %{private}s",
                name.c_str(), fileAsset.GetStrMember(name).c_str());
        } else if (type == TYPE_INT32) {
            values.PutInt(name, fileAsset.GetInt32Member(name));
            MEDIA_DEBUG_LOG("insert: int32: %{private}s %{public}d", name.c_str(), fileAsset.GetInt32Member(name));
        } else if (type == TYPE_INT64) {
            values.PutLong(name, fileAsset.GetInt64Member(name));
            MEDIA_DEBUG_LOG("insert: int64: %{private}s %{public}lld", name.c_str(), fileAsset.GetInt64Member(name));
        } else if (type == TYPE_DOUBLE) {
            values.PutDouble(name, fileAsset.GetDoubleMember(name));
            MEDIA_DEBUG_LOG("insert: double: %{private}s %{public}f", name.c_str(), fileAsset.GetDoubleMember(name));
        } else {
            MEDIA_DEBUG_LOG("insert: error %{public}d", type);
        }
    }
}

static void SetValuesFromPhotoAlbum(shared_ptr<PhotoAlbum> &photoAlbumPtr, ValuesBucket &values)
{
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, photoAlbumPtr->GetPhotoAlbumType());
    values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, photoAlbumPtr->GetPhotoAlbumSubType());
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, photoAlbumPtr->GetAlbumName());
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, photoAlbumPtr->GetDateModified());
    values.PutInt(PhotoAlbumColumns::CONTAINS_HIDDEN, photoAlbumPtr->GetContainsHidden());
    values.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, photoAlbumPtr->GetBundleName());
    values.PutString(PhotoAlbumColumns::ALBUM_LOCAL_LANGUAGE, photoAlbumPtr->GetLocalLanguage());
    values.PutInt(PhotoAlbumColumns::ALBUM_IS_LOCAL, photoAlbumPtr->GetIsLocal());
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_ADDED, photoAlbumPtr->GetDateAdded());
    values.PutString(PhotoAlbumColumns::ALBUM_LPATH, photoAlbumPtr->GetLPath());
    values.PutInt(PhotoAlbumColumns::ALBUM_PRIORITY, photoAlbumPtr->GetPriority());
}

MediaLibraryMetaRecovery &MediaLibraryMetaRecovery::GetInstance()
{
    static MediaLibraryMetaRecovery instance;
    return instance;
}

void MediaLibraryMetaRecovery::CheckRecoveryState()
{
    MediaLibraryMetaRecoveryState expect = MediaLibraryMetaRecoveryState::STATE_NONE;
    if (recoveryState_.compare_exchange_strong(expect, MediaLibraryMetaRecoveryState::STATE_BACKING_UP)) {
        std::thread([this]() {
            MEDIA_INFO_LOG("Start backing up");
            int64_t backupStartTime = MediaFileUtils::UTCTimeMilliSeconds();
            this->DoBackupMetadata();
            int64_t backupTotalTime = MediaFileUtils::UTCTimeMilliSeconds() - backupStartTime;

            MediaLibraryMetaRecoveryState expect =  MediaLibraryMetaRecoveryState::STATE_BACKING_UP;
            if (recoveryState_.compare_exchange_strong(expect, MediaLibraryMetaRecoveryState::STATE_NONE)) {
                MEDIA_INFO_LOG("End backing up normaly, elapse time %{public}lld ms", backupTotalTime);
            } else {
                MEDIA_INFO_LOG("End backing up interrupted, elapse time %{public}lld ms", backupTotalTime);
            }
        }).detach();
    } else {
        MEDIA_INFO_LOG("Ignore backing up, current status = %{public}d", expect);
    }
}

void MediaLibraryMetaRecovery::InterruptRecovery()
{
    switch (recoveryState_.load()) {
        case MediaLibraryMetaRecoveryState::STATE_BACKING_UP: {
            MediaLibraryMetaRecoveryState expect = MediaLibraryMetaRecoveryState::STATE_BACKING_UP;
            if (recoveryState_.compare_exchange_strong(expect, MediaLibraryMetaRecoveryState::STATE_NONE)) {
                MEDIA_INFO_LOG("InterruptRecovery: success send interrupt request");
            } else {
                MEDIA_INFO_LOG("InterruptRecovery: backup process is finished, no need to interrupt");
            }
            break;
        }
        case MediaLibraryMetaRecoveryState::STATE_RECOVERING: {
            MEDIA_INFO_LOG("InterruptRecovery: need to interrupt recovery process");
            break;
        }
        default: {
            MEDIA_INFO_LOG("InterruptRecovery: nother recovery or backup is processing, ignore");
            break;
        }
    }
}

void MediaLibraryMetaRecovery::LoadAlbumMaps(const string &path)
{
    // 1. album.json to oldAlbumIdToLpath
    int32_t ret = E_OK;
    std::vector<shared_ptr<PhotoAlbum>> vecPhotoAlbum;
    ret = ReadPhotoAlbumFromFile(path, vecPhotoAlbum);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("read album file failed, path=%{public}s", DfxUtils::GetSafePath(path).c_str());
        return;
    }
    for (auto it : vecPhotoAlbum) {
        oldAlbumIdToLpath[it->GetAlbumId()] = it->GetLPath();
        MEDIA_INFO_LOG("oldAlbumIdToLpath, json id %{public}d, path=%{public}s", it->GetAlbumId(),
            it->GetLPath().c_str());
    }
    // 2. db PhotoAlbum to lpathToNewAlbumId
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    vector<string> columns = {PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_LPATH};
    auto resultSet = MediaLibraryRdbStore::Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet == nullptr)");
        return;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        string lPath = GetStringVal(PhotoAlbumColumns::ALBUM_LPATH, resultSet);
        lpathToNewAlbumId[lPath] = albumId;
        MEDIA_INFO_LOG("lpathToNewAlbumId, path=%{public}s db id %{public}d, ", lPath.c_str(), albumId);
    }
    return;
}

void MediaLibraryMetaRecovery::DoDataBaseRecovery()
{
    SetStartupParam();
    StopCloudSync();
    RefreshThumbnail();
    MEDIA_INFO_LOG("Album recovery start");
    if (AlbumRecovery(ROOT_MEDIA_DIR + ".meta/album.json") != E_OK) {
        MEDIA_ERR_LOG("Recovery Album failed");
    }
    MEDIA_INFO_LOG("Album recovery end");

    LoadAlbumMaps(ROOT_MEDIA_DIR+".meta/album.json");

    MEDIA_INFO_LOG("Photo recovery start");
    if (PhotoRecovery(ROOT_MEDIA_DIR + ".meta/Photo") != E_OK) {
        MEDIA_ERR_LOG("Recover Photo failed");
    }
    MEDIA_INFO_LOG("Photo recovery end");

    RefreshAlbumCount();
    RestartCloudSync();
    oldAlbumIdToLpath.clear();
    lpathToNewAlbumId.clear();
}

int32_t MediaLibraryMetaRecovery::AlbumRecovery(const string &path)
{
    int32_t ret = E_OK;
    std::vector<shared_ptr<PhotoAlbum>> vecPhotoAlbum;

    do {
        ret = access(path.c_str(), F_OK | R_OK);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("file is not exist or no read access, path=%{public}s", DfxUtils::GetSafePath(path).c_str());
            break;
        }

        ret = ReadPhotoAlbumFromFile(path, vecPhotoAlbum);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("read album file failed, errCode=%{public}d", ret);
            break;
        }

        ret = InsertMetadataInDb(vecPhotoAlbum);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("AlbumRecovery: insert album failed, errCode=%{public}d", ret);
            break;
        }

        MEDIA_INFO_LOG("AlbumRecovery: photo album is recovered successful");
    }while (false);

    return ret;
}

int32_t MediaLibraryMetaRecovery::PhotoRecovery(const string &path)
{
    string realPath;
    int32_t bucket_id = -1;

    if (!PathToRealPath(path, realPath)) {
        if (errno == ENOENT) {
            //Delte Metastatus Json;
            remove(META_STATUS_PATH.c_str());
            //Delete status
            metaStatus.clear();
            MEDIA_ERR_LOG("no meta file no need to recovery");
            return E_OK;
        }
        MEDIA_ERR_LOG("Failed to get real path %{private}s, errno %{public}d", path.c_str(), errno);
        return E_INVALID_PATH;
    }

    if (!ScannerUtils::IsDirectory(realPath)) {
        MEDIA_ERR_LOG("The path %{private}s is not a directory", realPath.c_str());
        return E_INVALID_PATH;
    }

    int err = ScanMetaDir(path, bucket_id);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to ScanMetaDir, errCode=%{public}d", err);
    }

    MEDIA_INFO_LOG("recovery success totalCount=%{public}d", ReadMetaRecoveryCountFromFile());

    //Delte Metastatus Json;
    int ret = remove(META_STATUS_PATH.c_str());
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to remove MetaStatus file, err=%{public}d", ret);
    }

    //Delete status
    metaStatus.clear();

    return err;
}

int32_t MediaLibraryMetaRecovery::WriteSingleMetaDataById(int32_t rowId)
{
    MEDIA_INFO_LOG("WriteSingleMetaDataById : rowId %{public}d", rowId);
    auto asset = MediaLibraryAssetOperations::QuerySinglePhoto(rowId);
    if (asset == nullptr) {
        MEDIA_ERR_LOG("QuerySinglePhoto : rowId %{public}d failed", rowId);
        return E_HAS_DB_ERROR;
    }

    return WriteSingleMetaData(*asset);
}

int32_t MediaLibraryMetaRecovery::WriteSingleMetaData(const FileAsset &asset)
{
    string metaFilePath;
    int32_t ret = E_OK;
    ret = getMetaPathFromOrignalPath(asset.GetPath(), metaFilePath);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("invalid photo path, path = %{public}s", DfxUtils::GetSafePath(asset.GetPath()).c_str());
        return ret;
    }

    // Create direcotry
    const string metaParentPath = MediaFileUtils::GetParentPath(metaFilePath);
    if (!MediaFileUtils::CreateDirectory(metaParentPath)) {
        MEDIA_ERR_LOG("photo: CreateDirectory failed, filePath = %{public}s",
            DfxUtils::GetSafePath(metaParentPath).c_str());
        return E_HAS_FS_ERROR;
    }

    // Create metadata file
    ret = WriteMetadataToFile(metaFilePath, asset);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("photo: WriteMetadataToFile failed, filePath = %{public}s",
            DfxUtils::GetSafePath(metaFilePath).c_str());
        return ret;
    }

    // Up to date
    ret = UpdateMetadataFlagInDb(asset.GetId(), MetadataFlags::TYPE_UPTODATE);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("photo: Up to date failed, filePath = %{public}s", DfxUtils::GetSafePath(metaFilePath).c_str());
        return ret;
    }

    return ret;
}

void MediaLibraryMetaRecovery::DoBackupMetadata()
{
    // Backing up photo albums
    AlbumBackup();

    // Backing up photos
    PhotoBackupBatch();
}

void MediaLibraryMetaRecovery::AlbumBackup()
{
    vector<shared_ptr<PhotoAlbum>> photoAlbumVector;
    MediaLibraryAssetOperations::QueryTotalAlbum(photoAlbumVector);
    int photoAlbumCount = photoAlbumVector.size();
    if (photoAlbumCount <= 0) {
        MEDIA_INFO_LOG("AlbumBackup: no photo albums need to backup");
        return;
    }

    MEDIA_INFO_LOG("AlbumBackup: album count = %{public}d", photoAlbumCount);
    if (E_OK != WritePhotoAlbumToFile(META_RECOVERY_ALBUM_PATH, photoAlbumVector)) {
        MEDIA_ERR_LOG("AlbumBackup: WritePhotoAlbumToFile failed");
    }
}

void MediaLibraryMetaRecovery::PhotoBackupBatch()
{
    int32_t photoTotaldCount = 0;
    int32_t photoProcessedCount = 0;
    int32_t photoSuccessedCount = 0;
    vector<shared_ptr<FileAsset>> photoVector;
    do {
        if (recoveryState_.load() != MediaLibraryMetaRecoveryState::STATE_BACKING_UP) {
            MEDIA_INFO_LOG("PhotoBackupBatch: process is interrupted");
            break;
        }

        photoVector.clear();
        MediaLibraryAssetOperations::QueryTotalPhoto(photoVector, QUERY_BATCH_SIZE);
        if (photoVector.size() > 0) {
            photoTotaldCount += photoVector.size();
            PhotoBackup(photoVector, photoProcessedCount, photoSuccessedCount);
        }
    } while (photoVector.size() == QUERY_BATCH_SIZE);
    MEDIA_INFO_LOG("PhotoBackupBatch: Photo backup end, result = %{public}d/%{public}d/%{public}d",
        photoSuccessedCount, photoProcessedCount, photoTotaldCount);
}

void MediaLibraryMetaRecovery::PhotoBackup(const vector<shared_ptr<FileAsset>> &photoVector,
                                           int32_t &processCount,
                                           int32_t &successCount)
{
    MEDIA_INFO_LOG("Start backup batched photos, count = %{public}u", photoVector.size());
    for (auto &asset : photoVector) {
        if (asset == NULL) {
            MEDIA_ERR_LOG("asset null");
            continue;
        }
        // Check interrupt request
        if (recoveryState_.load() != MediaLibraryMetaRecoveryState::STATE_BACKING_UP) {
            MEDIA_INFO_LOG("Photo backing up process is interrupted");
            break;
        }

        processCount++;

        if (!asset) {
            MEDIA_ERR_LOG("Photo asset pointer is null");
            continue;
        }

        if (E_OK != WriteSingleMetaData(*asset)) {
            MEDIA_ERR_LOG("WriteSingleMetaData failed");
            continue;
        }

        successCount++;
    }
}

int32_t MediaLibraryMetaRecovery::ScanMetaDir(const string &path, int32_t bucket_id)
{
    int err = E_OK;
    DIR *dirPath = nullptr;
    struct dirent *ent = nullptr;
    size_t len = path.length();
    struct stat statInfo;

    if (len >= FILENAME_MAX - 1) {
        return ERR_INCORRECT_PATH;
    }

    auto fName = (char *)calloc(FILENAME_MAX, sizeof(char));
    if (fName == nullptr) {
        return ERR_MEM_ALLOC_FAIL;
    }

    if (strcpy_s(fName, FILENAME_MAX, path.c_str()) != ERR_SUCCESS) {
        FREE_MEMORY_AND_SET_NULL(fName);
        return ERR_MEM_ALLOC_FAIL;
    }
    fName[len++] = '/';
    if ((dirPath = opendir(path.c_str())) == nullptr) {
        MEDIA_ERR_LOG("Failed to opendir %{private}s, errno %{private}d", path.c_str(), errno);
        FREE_MEMORY_AND_SET_NULL(fName);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, -errno},
            {KEY_OPT_FILE, path}, {KEY_OPT_TYPE, OptType::SCAN}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return ERR_NOT_ACCESSIBLE;
    }

    int32_t recoverySuccessCnt = 0;
    while ((ent = readdir(dirPath)) != nullptr) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
            continue;
        }

        if (strncpy_s(fName + len, FILENAME_MAX - len, ent->d_name, FILENAME_MAX - len)) {
            continue;
        }

        if (lstat(fName, &statInfo) == -1) {
            continue;
        }

        string currentPath = fName;
        if (S_ISDIR(statInfo.st_mode)) {
            int32_t cur_bucket = atoi(ent->d_name);
            MEDIA_INFO_LOG("currentPath=%{public}s, path=%{public}s, cur_bucket %{public}d recovery start",
                           DfxUtils::GetSafePath(currentPath).c_str(), DfxUtils::GetSafePath(path).c_str(), cur_bucket);

            //recovery after interrupt, skip bucket which scanned.
            if (metaStatus.find(cur_bucket) != metaStatus.end()) {
                MEDIA_INFO_LOG("skip bucket id=%{public}d", cur_bucket);
                continue;
            }
            (void)ScanMetaDir(currentPath, cur_bucket);
            RefreshAlbumCount();
        } else {
            MEDIA_DEBUG_LOG("currentPath=%{public}s, path=%{public}s",
                DfxUtils::GetSafePath(currentPath).c_str(), DfxUtils::GetSafePath(path).c_str());
            bool albumIdDirtyFlag = false;
            FileAsset fileAsset;
            if (ReadMetadataFromFile(currentPath, fileAsset, albumIdDirtyFlag) != E_OK) {
                MEDIA_ERR_LOG("ScanMetaDir: ReadMetadataFrom file failed");
                continue;
            }

            // Insert fileAsset to DB
            int32_t retry_cnt = 0;
            do {
                if (InsertMetadataInDb(fileAsset, albumIdDirtyFlag) != E_OK) {
                    MEDIA_ERR_LOG("ScanMetaDir: InsertMetadataInDb failed, retry_cnt=%{public}d", retry_cnt);
                    int32_t sleep_time = 100;
                    this_thread::sleep_for(chrono::milliseconds(sleep_time));
                } else {
                    break;
                }
                retry_cnt++;
            } while (retry_cnt < META_RETRY_MAX_COUNTS);
            if (retry_cnt < META_RETRY_MAX_COUNTS) {
                recoverySuccessCnt++;
            } else {
                MEDIA_ERR_LOG("ScanMetaDir: InsertMetadataInDb finally failed, retry_cnt=%{public}d", retry_cnt);
            }
        }
    }

    closedir(dirPath);
    FREE_MEMORY_AND_SET_NULL(fName);

    if (bucket_id != -1) {
        err = WriteMetaStatusToFile(to_string(bucket_id), recoverySuccessCnt);
        if (err != E_OK) {
            MEDIA_ERR_LOG("write meta status failed");
        }
        MEDIA_INFO_LOG("cur_bucket %{public}d recovery end", bucket_id);
    }

    return err;
}

bool MediaLibraryMetaRecovery::WriteJsonFile(const std::string &filePath, const nlohmann::json &j)
{
    const string parentDir = MediaFileUtils::GetParentPath(filePath);
    if (!MediaFileUtils::CreateDirectory(parentDir)) {
        MEDIA_ERR_LOG("CreateDirectory failed, dir = %{public}s", DfxUtils::GetSafePath(parentDir).c_str());
        return false;
    }

    std::ofstream outFile(filePath, std::ofstream::out | std::ofstream::trunc);
    if (!outFile.is_open()) {
        MEDIA_ERR_LOG("open filePath: %{private}s failed", filePath.c_str());
        return false;
    }
    outFile << j << std::endl;
    outFile.close();
    return true;
}

bool MediaLibraryMetaRecovery::ReadJsonFile(const std::string &filePath, nlohmann::json &j)
{
    std::ifstream inFile(filePath);
    if (!inFile.is_open()) {
        MEDIA_ERR_LOG("open filePath: %{private}s failed", filePath.c_str());
        return false;
    }
    std::string buffer = std::string((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
    j = json::parse(buffer, nullptr, false);
    inFile.close();
    return !j.is_discarded();
}

int32_t MediaLibraryMetaRecovery::WriteMetadataToFile(const string &filePath, const FileAsset &fileAsset)
{
    json jsonMetadata;
    AddMetadataToJson(jsonMetadata, fileAsset);
    if (!WriteJsonFile(filePath, jsonMetadata)) {
        MEDIA_ERR_LOG("WriteJsonFile failed");
        return E_FILE_OPER_FAIL;
    }
    return E_OK;
}

void MediaLibraryMetaRecovery::AddMetadataToJson(nlohmann::json &j, const FileAsset &fileAsset)
{
    for (const auto &[key, type] : RESULT_TYPE_MAP) {
        if (type == TYPE_STRING) {
            string value = fileAsset.GetStrMember(key);
            MEDIA_DEBUG_LOG("Writejson string: %{private}s: %{private}s", key.c_str(), value.c_str());
            j[key] = json::string_t(value);
        } else if (type == TYPE_INT32) {
            int32_t value = fileAsset.GetInt32Member(key);
            MEDIA_DEBUG_LOG("Writejson int32_t: %{private}s: %{public}d", key.c_str(), value);
            j[key] = json::number_integer_t(value);
        } else if (type == TYPE_INT64) {
            int64_t value = fileAsset.GetInt64Member(key);
            MEDIA_DEBUG_LOG("Writejson int64_t: %{private}s: %{public}lld", key.c_str(), value);
            j[key] = json::number_integer_t(value);
        } else if (type == TYPE_DOUBLE) {
            double value = fileAsset.GetDoubleMember(key);
            MEDIA_DEBUG_LOG("Writejson double: %{private}s: %{public}f", key.c_str(), value);
            j[key] = json::number_float_t(value);
        } else {
            MEDIA_ERR_LOG("WriteFile: error type: %{public}d", type);
        }
    }
}

bool MediaLibraryMetaRecovery::GetMetadataFromJson(const nlohmann::json &j, FileAsset &fileAsset, bool &flag)
{
    bool ret = true;
    for (const auto &[name, type] : RESULT_TYPE_MAP) {
        MEDIA_DEBUG_LOG("ReadFile: %{private}s %{public}d", name.c_str(), type);
        if (type == TYPE_STRING) {
            optional<string> value = GetStringFromJson(j, name);
            if (value.has_value()) {
                fileAsset.SetMemberValue(name, value.value());
            } else {
                ret = false;
            }
        } else if (type == TYPE_INT32) {
            optional<int64_t> value = GetNumberFromJson(j, name);
            if (!value.has_value()) {
                ret = false;
                continue;
            }
            int val0 = (int32_t)value.value();
            int val = (int32_t)value.value();
            if (name == PhotoColumn::PHOTO_OWNER_ALBUM_ID) {
                auto lpath = oldAlbumIdToLpath.find(val);
                if (lpath != oldAlbumIdToLpath.end() &&
                    lpathToNewAlbumId.find(lpath->second) != lpathToNewAlbumId.end()) {
                    val = lpathToNewAlbumId[lpath->second];
                    MEDIA_INFO_LOG("convert album %{public}d to %{public}d", val0, val);
                }
                flag = (val0 != val);
            }
            fileAsset.SetMemberValue(name, val);
        } else if (type == TYPE_INT64) {
            optional<int64_t> value = GetNumberFromJson(j, name);
            if (value.has_value()) {
                fileAsset.SetMemberValue(name, (int64_t)value.value());
            } else {
                ret = false;
            }
        } else if (type == TYPE_DOUBLE) {
            optional<double> value = GetDoubleFromJson(j, name);
            if (value.has_value()) {
                fileAsset.SetMemberValue(name, (double)value.value());
            } else {
                ret = false;
            }
        } else {
            MEDIA_ERR_LOG("ReadFile: error %{public}d", type);
        }
    }

    return ret;
}

int32_t MediaLibraryMetaRecovery::ReadMetadataFromFile(const string &filePath, FileAsset &fileAsset, bool &flag)
{
    int ret = E_OK;
    json jsonMetadata;
    if (!ReadJsonFile(filePath, jsonMetadata)) {
        MEDIA_ERR_LOG("ReadJsonFile failed");
        return E_FILE_OPER_FAIL;
    }

    if (!GetMetadataFromJson(jsonMetadata, fileAsset, flag)) {
        MEDIA_ERR_LOG("GetMetadataFromJson not all right");
    }

    // Media file path
    string mediaFilePath = filePath;
    size_t pos = mediaFilePath.find(META_RECOVERY_META_RELATIVE_PATH);
    if (pos != string::npos) {
        mediaFilePath.replace(pos, META_RECOVERY_META_RELATIVE_PATH.length(), META_RECOVERY_PHOTO_RELATIVE_PATH);
    }
    if (MediaFileUtils::EndsWith(mediaFilePath, META_RECOVERY_META_FILE_SUFFIX)) {
        mediaFilePath.erase(mediaFilePath.length() - META_RECOVERY_META_FILE_SUFFIX.length());
    }
    fileAsset.SetFilePath(mediaFilePath);

    // Media Type
    fileAsset.SetMediaType(MediaFileUtils::GetMediaType(mediaFilePath));

    // MimeType
    string extension = MediaFileUtils::GetExtensionFromPath(mediaFilePath);
    fileAsset.SetMimeType(MimeTypeUtils::GetMimeTypeFromExtension(extension));

    // Date added
    struct stat statInfo = {0};
    if (stat(mediaFilePath.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("ReadMetadataFromFile: stat syscall err %{public}d", errno);
        ret = E_SYSCALL;
        if (errno == ENOENT) {
            remove(filePath.c_str());
        }
    }

    return ret;
}

void MediaLibraryMetaRecovery::AddPhotoAlbumToJson(nlohmann::json &j, const PhotoAlbum &photoAlbum)
{
    j = json {
        {PhotoAlbumColumns::ALBUM_ID, json::number_integer_t(photoAlbum.GetAlbumId())},
        {PhotoAlbumColumns::ALBUM_TYPE, json::number_integer_t(photoAlbum.GetPhotoAlbumType())},
        {PhotoAlbumColumns::ALBUM_SUBTYPE, json::number_integer_t(photoAlbum.GetPhotoAlbumSubType())},
        {PhotoAlbumColumns::ALBUM_NAME, json::string_t(photoAlbum.GetAlbumName())},
        {PhotoAlbumColumns::ALBUM_DATE_MODIFIED, json::number_integer_t(photoAlbum.GetDateModified())},
        {PhotoAlbumColumns::CONTAINS_HIDDEN, json::number_integer_t(photoAlbum.GetContainsHidden())},
        {PhotoAlbumColumns::ALBUM_ORDER, json::number_integer_t(photoAlbum.GetOrder())},
        {PhotoAlbumColumns::ALBUM_BUNDLE_NAME, json::string_t(photoAlbum.GetBundleName())},
        {PhotoAlbumColumns::ALBUM_LOCAL_LANGUAGE, json::string_t(photoAlbum.GetLocalLanguage())},
        {PhotoAlbumColumns::ALBUM_DATE_ADDED, json::number_integer_t(photoAlbum.GetDateAdded())},
        {PhotoAlbumColumns::ALBUM_IS_LOCAL, json::number_integer_t(photoAlbum.GetIsLocal())},
        {PhotoAlbumColumns::ALBUM_LPATH, json::string_t(photoAlbum.GetLPath())},
        {PhotoAlbumColumns::ALBUM_PRIORITY, json::number_integer_t(photoAlbum.GetPriority())}
    };
}

bool MediaLibraryMetaRecovery::GetPhotoAlbumFromJson(const nlohmann::json &j, PhotoAlbum &photoAlbum)
{
    bool ret = true;
    optional<int64_t> albumId = GetNumberFromJson(j, PhotoAlbumColumns::ALBUM_ID);
    if (albumId.has_value()) {
        photoAlbum.SetAlbumId((int32_t)albumId.value());
    } else {
        ret = false;
    }

    optional<int64_t> albumType = GetNumberFromJson(j, PhotoAlbumColumns::ALBUM_TYPE);
    if (albumType.has_value()) {
        int32_t type = (int32_t)albumType.value();
        photoAlbum.SetPhotoAlbumType(static_cast<PhotoAlbumType>(type));
    } else {
        ret = false;
    }

    optional<int64_t> albumSubType = GetNumberFromJson(j, PhotoAlbumColumns::ALBUM_SUBTYPE);
    if (albumSubType.has_value()) {
        int32_t type = (int32_t)albumSubType.value();
        photoAlbum.SetPhotoAlbumSubType(static_cast<PhotoAlbumSubType>(type));
    } else {
        ret = false;
    }

    optional<string> albumName = GetStringFromJson(j, PhotoAlbumColumns::ALBUM_NAME);
    if (albumName.has_value()) {
        photoAlbum.SetAlbumName(albumName.value());
    } else {
        ret = false;
    }

    optional<int64_t> dateModified = GetNumberFromJson(j, PhotoAlbumColumns::ALBUM_DATE_MODIFIED);
    if (dateModified.has_value()) {
        photoAlbum.SetDateModified(dateModified.value());
    } else {
        ret = false;
    }

    optional<int64_t> containsHidden = GetNumberFromJson(j, PhotoAlbumColumns::CONTAINS_HIDDEN);
    if (containsHidden.has_value()) {
        photoAlbum.SetContainsHidden((int32_t)containsHidden.value());
    } else {
        ret = false;
    }

    optional<int64_t> order = GetNumberFromJson(j, PhotoAlbumColumns::ALBUM_ORDER);
    if (order.has_value()) {
        photoAlbum.SetOrder((int32_t)order.value());
    } else {
        ret = false;
    }

    optional<string> bundleName = GetStringFromJson(j, PhotoAlbumColumns::ALBUM_BUNDLE_NAME);
    if (bundleName.has_value()) {
        photoAlbum.SetBundleName(bundleName.value());
    } else {
        ret = false;
    }

    optional<string> localLanguage = GetStringFromJson(j, PhotoAlbumColumns::ALBUM_LOCAL_LANGUAGE);
    if (localLanguage.has_value()) {
        photoAlbum.SetLocalLanguage(localLanguage.value());
    } else {
        ret = false;
    }

    optional<int64_t> dateAdded = GetNumberFromJson(j, PhotoAlbumColumns::ALBUM_DATE_ADDED);
    if (dateAdded.has_value()) {
        photoAlbum.SetDateAdded(dateAdded.value());
    } else {
        ret = false;
    }

    optional<int64_t> isLocal = GetNumberFromJson(j, PhotoAlbumColumns::ALBUM_IS_LOCAL);
    if (isLocal.has_value()) {
        photoAlbum.SetIsLocal((int32_t)isLocal.value());
    } else {
        ret = false;
    }

    optional<string> lPath = GetStringFromJson(j, PhotoAlbumColumns::ALBUM_LPATH);
    if (lPath.has_value()) {
        photoAlbum.SetLPath(lPath.value());
    } else {
        ret = false;
    }

    optional<int64_t> priority = GetNumberFromJson(j, PhotoAlbumColumns::ALBUM_PRIORITY);
    if (priority.has_value()) {
        photoAlbum.SetPriority((int32_t)priority.value());
    } else {
        ret = false;
    }

    return ret;
}

int32_t MediaLibraryMetaRecovery::WritePhotoAlbumToFile(const string &filePath,
                                                        const vector<shared_ptr<PhotoAlbum>> &vecPhotoAlbum)
{
    MEDIA_DEBUG_LOG("WritePhotoAlbumToFile start\n");

    const string parentDir = MediaFileUtils::GetParentPath(filePath);
    if (!MediaFileUtils::CreateDirectory(parentDir)) {
        MEDIA_ERR_LOG("CreateDirectory failed, dir = %{public}s", DfxUtils::GetSafePath(parentDir).c_str());
        return false;
    }

    json jsonArray = json::array();
    for (auto &album : vecPhotoAlbum) {
        if (album == nullptr) {
            MEDIA_ERR_LOG("album == nullptr");
            continue;
        }

        json jsonPhotoAlbumItem;
        OHOS::Media::PhotoAlbum &photoAlbumRef = *album.get();
        AddPhotoAlbumToJson(jsonPhotoAlbumItem, photoAlbumRef);

        jsonArray.push_back(jsonPhotoAlbumItem);
    }

    if (!WriteJsonFile(filePath, jsonArray)) {
        MEDIA_ERR_LOG("WriteJsonFile failed");
        return E_FILE_OPER_FAIL;
    }

    MEDIA_DEBUG_LOG("WritePhotoAlbumToFile end\n");
    return E_OK;
}

int32_t MediaLibraryMetaRecovery::ReadPhotoAlbumFromFile(const string &filePath,
                                                         vector<shared_ptr<PhotoAlbum>> &photoAlbumVector)
{
    json jsonArray;
    if (!ReadJsonFile(filePath, jsonArray)) {
        MEDIA_ERR_LOG("ReadJsonFile failed");
        return E_FILE_OPER_FAIL;
    }
    if (!jsonArray.is_array()) {
        MEDIA_ERR_LOG("json not is array");
        return E_ERR;
    }

    int ret = 0;
    for (const json &j : jsonArray) {
        PhotoAlbum photoAlbum;
        if (!GetPhotoAlbumFromJson(j, photoAlbum)) {
            MEDIA_WARN_LOG("GetPhotoAlbumFromJson failed");
            ret = E_ERR;
        }
        if (photoAlbum.GetPhotoAlbumSubType() != 1 && photoAlbum.GetLPath() == "") {
            continue;
        }
        photoAlbumVector.emplace_back(make_shared<PhotoAlbum>(photoAlbum));
    }

    return ret;
}

int32_t MediaLibraryMetaRecovery::WriteMetaStatusToFile(const string &keyPath, const int32_t status)
{
    json j;
    if (std::filesystem::exists(META_STATUS_PATH) && !ReadJsonFile(META_STATUS_PATH, j)) {
        MEDIA_WARN_LOG("ReadFile META_STATUS_PATH failed, will write new META_STATUS_PATH file");
        j = json::object();
    }

    j[keyPath] = json::number_integer_t(status);

    if (!WriteJsonFile(META_STATUS_PATH, j)) {
        MEDIA_ERR_LOG("WriteJsonFile failed");
        return E_FILE_OPER_FAIL;
    }

    return E_OK;
}

int32_t MediaLibraryMetaRecovery::ReadMetaStatusFromFile(set<int32_t> &status)
{
    json j;
    if (!ReadJsonFile(META_STATUS_PATH, j)) {
        MEDIA_ERR_LOG("ReadFile META_STATUS_PATH failed");
        return E_FILE_OPER_FAIL;
    }

    for (const auto& [key, value] : j.items()) {
        if (!value.is_number_integer()) {
            MEDIA_ERR_LOG("key: %{public}s not is number", key.c_str());
            continue;
        }
        // Read bucket_id which finish recovery
        int32_t val = atoi(key.c_str());
        MEDIA_INFO_LOG("finish recovery bucket_id: %{public}s", key.c_str());
        status.insert(val);
    }

    return E_OK;
}

int32_t MediaLibraryMetaRecovery::ReadMetaRecoveryCountFromFile()
{
    json j;
    int32_t recoverySuccessCnt = 0;

    if (!ReadJsonFile(META_STATUS_PATH, j)) {
        MEDIA_ERR_LOG("ReadFile META_STATUS_PATH failed");
        return E_FILE_OPER_FAIL;
    }

    for (const auto& [key, value] : j.items()) {
        if (!value.is_number_integer()) {
            MEDIA_ERR_LOG("key: %{public}s not is number", key.c_str());
            continue;
        }
        int32_t val = value.get<int32_t>();
        recoverySuccessCnt += val;
        MEDIA_INFO_LOG("finish recovery bucket_id: %{public}s, recovery success count=%{public}d", key.c_str(), val);
    }

    return recoverySuccessCnt;
}

int32_t MediaLibraryMetaRecovery::InsertMetadataInDb(const FileAsset &fileAsset, bool flag)
{
    std::string filePath = fileAsset.GetFilePath();
    MEDIA_INFO_LOG("InsertMetadataInDb: photo filepath = %{public}s", DfxUtils::GetSafePath(filePath).c_str());
    if (E_OK == MediaLibraryAssetOperations::CheckExist(filePath)) {
        MEDIA_INFO_LOG("InsertMetadataInDb: insert: photo is exist in db, ignore");
        return E_OK;
    }

    auto rawRdbStore = GetRdbStoreRaw();
    if (rawRdbStore == nullptr) {
        MEDIA_ERR_LOG("GetRdbStoreRaw failed, return nullptr");
        return E_HAS_DB_ERROR;
    }

    TransactionOperations transactionOprn(rawRdbStore);
    int32_t errCode = transactionOprn.Start();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("transaction operation start failed, error=%{public}d", errCode);
        return errCode;
    }

    ValuesBucket valuesBucket;
    SetValuesFromFileAsset(fileAsset, valuesBucket);

    // set meta flag uptodate, to avoid backup db into meta again
    valuesBucket.PutInt(PhotoColumn::PHOTO_METADATA_FLAGS,
                        flag ? static_cast<int>(MetadataFlags::TYPE_DIRTY) :
                        static_cast<int>(MetadataFlags::TYPE_UPTODATE));

    int64_t outRowId = -1;
    errCode = rawRdbStore->Insert(outRowId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    if (errCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Insert photo failed, errCode = %{public}d", errCode);
        return errCode;
    }
    transactionOprn.Finish();

    MEDIA_INFO_LOG("InsertMetadataInDb: photo insert done, rowId = %{public}lld", outRowId);
    return E_OK;
}

int32_t MediaLibraryMetaRecovery::InsertMetadataInDb(const std::vector<shared_ptr<PhotoAlbum>> &vecPhotoAlbum)
{
    auto rawRdbStore = GetRdbStoreRaw();
    if (rawRdbStore == nullptr) {
        MEDIA_ERR_LOG("GetRdbStoreRaw failed, return nullptr");
        return E_HAS_DB_ERROR;
    }

    for (auto iter : vecPhotoAlbum) {
        if (iter == NULL) {
            MEDIA_ERR_LOG("iter nullptr");
            continue;
        }
        MEDIA_INFO_LOG("InsertMetadataInDb: album name = %{private}s", iter->GetAlbumName().c_str());
        RdbPredicates predicates(PhotoAlbumColumns::TABLE);
        vector<string> columns = {PhotoAlbumColumns::ALBUM_ID,
            PhotoAlbumColumns::ALBUM_LPATH};
        predicates.IsNotNull(PhotoAlbumColumns::ALBUM_LPATH)->And()->EqualTo(PhotoAlbumColumns::ALBUM_LPATH,
                             iter->GetLPath());
        auto resultSet = MediaLibraryRdbStore::Query(predicates, columns);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("resultSet == nullptr)");
            continue;
        }
        if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            MEDIA_ERR_LOG("skip duplicate lpath %{public}s", iter->GetLPath().c_str());
            continue;
        }

        TransactionOperations transactionOprn(rawRdbStore);
        int32_t errCode = transactionOprn.Start();
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("transaction operation start failed, error=%{public}d", errCode);
            return errCode;
        }

        ValuesBucket valuesBucket;
        SetValuesFromPhotoAlbum(iter, valuesBucket);
        
        int64_t outRowId = -1;
        errCode = rawRdbStore->Insert(outRowId, PhotoAlbumColumns::TABLE, valuesBucket);
        if (errCode != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("InsertMetadataInDb: insert album failed, errCode = %{public}d", errCode);
            return errCode;
        }

        RdbPredicates predicatesOrder(PhotoAlbumColumns::TABLE);
        predicatesOrder.EqualTo(PhotoAlbumColumns::ALBUM_ID, outRowId);

        ValuesBucket valuesOrder;
        valuesOrder.PutInt(PhotoAlbumColumns::ALBUM_ORDER, iter->GetOrder());

        int32_t changedRows = -1;
        errCode = rawRdbStore->Update(changedRows, valuesOrder, predicatesOrder);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Update album order failed, error=%{public}d", errCode);
            return E_HAS_DB_ERROR;
        }

        transactionOprn.Finish();
    }

    return E_OK;
}

int32_t MediaLibraryMetaRecovery::UpdateMetadataFlagInDb(const int32_t fieldId, const MetadataFlags &flag)
{
    int32_t errCode = E_OK;

    MEDIA_INFO_LOG("Update photo metadata flag, fieldId = %{public}d, new flag = %{public}d", fieldId, flag);
    std::shared_ptr<NativeRdb::RdbStore> rdbRawPtr = GetRdbStoreRaw();
    if (!rdbRawPtr) {
        MEDIA_ERR_LOG("GetRdbStoreRaw failed");
        return E_HAS_DB_ERROR;
    }

    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(MediaColumn::MEDIA_ID, fieldId);

    TransactionOperations transactionOprn(rdbRawPtr);
    errCode = transactionOprn.Start();
    if (errCode != E_OK) {
            MEDIA_ERR_LOG("transaction operation start failed, errCode = %{public}d", errCode);
            return errCode;
    }

    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_METADATA_FLAGS, static_cast<int>(flag));

    int32_t changedRows = -1;
    errCode = rdbRawPtr->Update(changedRows, values, predicates);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Database update failed, error=%{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    transactionOprn.Finish();

    return E_OK;
}

int32_t MediaLibraryMetaRecovery::SetRdbRebuiltStatus(bool status)
{
    rdbRebuilt_ = status;
    return E_OK;
}

int32_t MediaLibraryMetaRecovery::StartAsyncRecovery()
{
    MEDIA_INFO_LOG("StartAsyncRecovery: rebuild status %{public}d", rdbRebuilt_);

    MediaLibraryMetaRecoveryState oldState;
    bool hasStatusFile = bool(access(META_STATUS_PATH.c_str(), F_OK) == E_OK);
    switch (recoveryState_.load()) {
        case MediaLibraryMetaRecoveryState::STATE_RECOVERING: {
            MEDIA_INFO_LOG("StartAsyncRecovery: recovery process is already running");
            return E_OK;
        }
        case MediaLibraryMetaRecoveryState::STATE_RECOVERING_ABORT: {
            oldState = recoveryState_.exchange(MediaLibraryMetaRecoveryState::STATE_RECOVERING);
            break;
        }
        default: {
            if (!hasStatusFile && !rdbRebuilt_) {
                MEDIA_INFO_LOG("StartAsyncRecovery: no need to recovery");
                return E_OK;
            }
            recoveryState_.exchange(MediaLibraryMetaRecoveryState::STATE_RECOVERING);
            oldState = hasStatusFile ? MediaLibraryMetaRecoveryState::STATE_RECOVERING_ABORT :
                                       MediaLibraryMetaRecoveryState::STATE_NONE;
            break;
        }
    }

    if (oldState == MediaLibraryMetaRecoveryState::STATE_RECOVERING_ABORT) {
        if (ReadMetaStatusFromFile(metaStatus) != E_OK) {
            MEDIA_ERR_LOG("StartAsyncRecovery: ReadMetaStatusFromFile failed");
        }
    } else {
        // create status.json if not exist
        const string parentDir = MediaFileUtils::GetParentPath(META_STATUS_PATH);
        if (MediaFileUtils::CreateDirectory(parentDir)) {
            MediaFileUtils::CreateFile(META_STATUS_PATH);
        } else {
            MEDIA_ERR_LOG("CreateDirectory failed, dir = %{public}s", DfxUtils::GetSafePath(parentDir).c_str());
        }
    }

    std::thread([this]() {
        MEDIA_INFO_LOG("Start recovery");
        int64_t recoveryStartTime = MediaFileUtils::UTCTimeMilliSeconds();
        this->DoDataBaseRecovery();
        int64_t recoveryTotalTime = MediaFileUtils::UTCTimeMilliSeconds() - recoveryStartTime;

        bool isStatusFileExist = bool(access(META_STATUS_PATH.c_str(), F_OK) == E_OK);
        if (isStatusFileExist) {
            recoveryState_.exchange(MediaLibraryMetaRecoveryState::STATE_RECOVERING_ABORT);
        } else {
            recoveryState_.exchange(MediaLibraryMetaRecoveryState::STATE_NONE);
        }
        MEDIA_INFO_LOG("Recovery finished, elapse time %{public}lld ms", recoveryTotalTime);
    }).detach();

    return E_OK;
}

int32_t MediaLibraryMetaRecovery::DeleteMetaDataByPath(const string &filePath)
{
    string metaFilePath;
    if (E_OK != getMetaPathFromOrignalPath(filePath, metaFilePath)) {
        MEDIA_ERR_LOG("DeleteMetaDataByPath: invalid photo filePath, %{public}s",
            DfxUtils::GetSafePath(filePath).c_str());
        return E_INVALID_PATH;
    }

    if (remove(metaFilePath.c_str()) != 0 && errno != ENOENT) {
        MEDIA_ERR_LOG("remove metafile failed %{public}d, path %s", errno, DfxUtils::GetSafePath(metaFilePath).c_str());
    }

    MEDIA_INFO_LOG("DeleteMetaDataByPath: metafile removed successful, %{public}s",
        DfxUtils::GetSafePath(metaFilePath).c_str());
    return E_OK;
}

void MediaLibraryMetaRecovery::StopCloudSync()
{
    MEDIA_INFO_LOG("Begin StopCloudSync");
    FileManagement::CloudSync::CloudSyncManager::GetInstance().StopSync(BUNDLE_NAME, true);
}

void MediaLibraryMetaRecovery::RestartCloudSync()
{
    MEDIA_INFO_LOG("Begin reset cloud cursor");
    static uint32_t baseUserRange = 200000; // uid base offset
    uid_t uid = getuid() / baseUserRange;
    FileManagement::CloudSync::CloudSyncManager::GetInstance().ResetCursor();

    int32_t ret = FileManagement::CloudSync::CloudSyncManager::GetInstance().StartSync(BUNDLE_NAME);
    if (ret != 0) {
        MEDIA_ERR_LOG("StartCloudSync fail, errcode=%{public}d", ret);
    }
    MEDIA_INFO_LOG("End StartCloudSync");
}
} // namespace Media
} // namespace OHOS