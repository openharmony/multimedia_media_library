/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "DataManager"

#include "medialibrary_data_manager.h"

#include <cstdlib>
#include <future>
#include <shared_mutex>
#include <unordered_set>
#include <sstream>
#include <regex>

#include "ability_scheduler_interface.h"
#include "abs_rdb_predicates.h"
#include "acl.h"
#include "albums_refresh_manager.h"
#include "background_cloud_file_processor.h"
#include "background_task_mgr_helper.h"
#include "cloud_media_asset_manager.h"
#include "cloud_sync_switch_observer.h"
#include "datashare_abs_result_set.h"
#include "dfx_manager.h"
#include "dfx_reporter.h"
#include "dfx_utils.h"
#include "directory_ex.h"
#include "efficiency_resource_info.h"
#include "ffrt_inner.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "location_column.h"
#include "media_analysis_helper.h"
#include "media_column.h"
#include "media_datashare_ext_ability.h"
#include "media_directory_type_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_old_photos_column.h"
#include "media_facard_photos_column.h"
#include "media_scanner_manager.h"
#include "media_smart_album_column.h"
#include "media_smart_map_column.h"
#include "media_visit_count_manager.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_analysis_album_operations.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_app_uri_permission_operations.h"
#include "medialibrary_app_uri_sensitive_operations.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_audio_operations.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_inotify.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_location_operations.h"
#include "medialibrary_meta_recovery.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_operation_record.h"
#include "medialibrary_ptp_operations.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_restore.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "medialibrary_story_operations.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_tab_old_photos_operations.h"
#include "medialibrary_tab_asset_and_album_operations.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_uripermission_operations.h"
#include "medialibrary_urisensitive_operations.h"
#include "medialibrary_vision_operations.h"
#include "medialibrary_search_operations.h"
#include "medialibrary_tab_asset_and_album_operations.h"
#include "mimetype_utils.h"
#include "multistages_capture_manager.h"
#ifdef MEDIALIBRARY_FEATURE_CLOUD_ENHANCEMENT
#include "enhancement_manager.h"
#endif
#include "permission_utils.h"
#include "photo_album_column.h"
#include "photo_day_month_year_operation.h"
#include "photo_map_operations.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "resource_type.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "source_album.h"
#include "system_ability_definition.h"
#include "shooting_mode_column.h"
#include "timer.h"
#include "value_object.h"
#include "photo_storage_operation.h"
#include "post_event_utils.h"
#include "medialibrary_formmap_operations.h"
#include "medialibrary_facard_operations.h"
#include "ithumbnail_helper.h"
#include "vision_db_sqls_more.h"
#include "vision_face_tag_column.h"
#include "vision_photo_map_column.h"
#include "parameter.h"
#include "parameters.h"
#ifdef DEVICE_STANDBY_ENABLE
#include "medialibrary_standby_service_subscriber.h"
#endif
#ifdef HAS_THERMAL_MANAGER_PART
#include "thermal_mgr_client.h"
#endif
#include "vision_db_sqls.h"
#include "cloud_media_asset_uri.h"
#include "album_operation_uri.h"
#include "custom_record_operations.h"
#include "medialibrary_photo_operations.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedKv;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

namespace {
const OHOS::DistributedKv::AppId KVSTORE_APPID = {"com.ohos.medialibrary.medialibrarydata"};
const OHOS::DistributedKv::StoreId KVSTORE_STOREID = {"medialibrary_thumbnail"};
};

namespace OHOS {
namespace Media {
unique_ptr<MediaLibraryDataManager> MediaLibraryDataManager::instance_ = nullptr;
unordered_map<string, DirAsset> MediaLibraryDataManager::dirQuerySetMap_ = {};
mutex MediaLibraryDataManager::mutex_;
const int32_t PROPER_DEVICE_TEMPERATURE_LEVEL = 2;
constexpr int32_t DEFAULT_THUMBNAIL_SIZE = 256;
constexpr int32_t MAX_DEFAULT_THUMBNAIL_SIZE = 768;
static const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
static const std::string NO_DELETE_DISK_DATA_INDEX = "no_delete_disk_data_index";
static const std::string NO_UPDATE_EDITDATA_SIZE = "no_update_editdata_size";
static const std::string UPDATE_EDITDATA_SIZE_COUNT = "update_editdata_size_count";

#ifdef DEVICE_STANDBY_ENABLE
static const std::string SUBSCRIBER_NAME = "POWER_USAGE";
static const std::string MODULE_NAME = "com.ohos.medialibrary.medialibrarydata";
#endif

const std::vector<std::string> PRESET_ROOT_DIRS = {
    CAMERA_DIR_VALUES, VIDEO_DIR_VALUES, PIC_DIR_VALUES, AUDIO_DIR_VALUES,
    PHOTO_BUCKET + "/", AUDIO_BUCKET + "/", BACKUP_DATA_DIR_VALUE, EDIT_DATA_DIR_VALUE + "/",
    BACKUP_SINGLE_DATA_DIR_VALUE, CACHE_DIR_VALUE, CUSTOM_RESTORE_VALUES
};

const std::vector<std::string> E_POLICY_DIRS = {
    ROOT_MEDIA_DIR + CAMERA_DIR_VALUES,
    ROOT_MEDIA_DIR + VIDEO_DIR_VALUES,
    ROOT_MEDIA_DIR + PIC_DIR_VALUES,
    ROOT_MEDIA_DIR + PHOTO_BUCKET,
    ROOT_MEDIA_DIR + BACKUP_SINGLE_DATA_DIR_VALUE,
    ROOT_MEDIA_DIR + THUMB_DIR_VALUE,
    ROOT_MEDIA_DIR + CACHE_DIR_VALUE,
    ROOT_MEDIA_DIR + EDIT_DATA_DIR_VALUE,
};

MediaLibraryDataManager::MediaLibraryDataManager(void)
{
}

MediaLibraryDataManager::~MediaLibraryDataManager(void)
{
}

MediaLibraryDataManager* MediaLibraryDataManager::GetInstance()
{
    if (instance_ == nullptr) {
        lock_guard<mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = make_unique<MediaLibraryDataManager>();
        }
    }
    return instance_.get();
}

static DataShare::DataShareExtAbility *MediaDataShareCreator(const unique_ptr<Runtime> &runtime)
{
    MEDIA_INFO_LOG("MediaLibraryCreator::%{public}s", __func__);
    return  MediaDataShareExtAbility::Create(runtime);
}

__attribute__((constructor)) void RegisterDataShareCreator()
{
    MEDIA_INFO_LOG("MediaLibraryDataManager::%{public}s", __func__);
    DataShare::DataShareExtAbility::SetCreator(MediaDataShareCreator);
    MEDIA_INFO_LOG("MediaLibraryDataManager::%{public}s End", __func__);
}

static void MakeRootDirs(AsyncTaskData *data)
{
    const unordered_set<string> DIR_CHECK_SET = { ROOT_MEDIA_DIR + BACKUP_DATA_DIR_VALUE,
        ROOT_MEDIA_DIR + BACKUP_SINGLE_DATA_DIR_VALUE };
    for (auto &dir : PRESET_ROOT_DIRS) {
        Uri createAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);
        ValuesBucket valuesBucket;
        valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR + dir);
        MediaLibraryCommand cmd(createAlbumUri, valuesBucket);
        auto ret = MediaLibraryAlbumOperations::CreateAlbumOperation(cmd);
        if (ret == E_FILE_EXIST) {
            MEDIA_INFO_LOG("Root dir: %{private}s is exist", dir.c_str());
        } else if (ret <= 0) {
            MEDIA_ERR_LOG("Failed to preset root dir: %{private}s", dir.c_str());
        }
        MediaFileUtils::CheckDirStatus(DIR_CHECK_SET, ROOT_MEDIA_DIR + dir);
    }
    MediaFileUtils::MediaFileDeletionRecord();
    // recover temp dir
    MediaFileUtils::RecoverMediaTempDir();
}

void MediaLibraryDataManager::ReCreateMediaDir()
{
    MediaFileUtils::BackupPhotoDir();
    // delete E policy dir
    for (const string &dir : E_POLICY_DIRS) {
        if (!MediaFileUtils::DeleteDir(dir)) {
            MEDIA_ERR_LOG("Delete dir fail, dir: %{public}s", DfxUtils::GetSafePath(dir).c_str());
        }
    }
    // create C policy dir
    InitACLPermission();
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_LOG(asyncWorker != nullptr, "Can not get asyncWorker");

    AsyncTaskData* taskData = new (std::nothrow) AsyncTaskData();
    CHECK_AND_RETURN_LOG(taskData != nullptr, "Failed to new taskData");

    shared_ptr<MediaLibraryAsyncTask> makeRootDirTask = make_shared<MediaLibraryAsyncTask>(MakeRootDirs, taskData);
    if (makeRootDirTask != nullptr) {
        asyncWorker->AddTask(makeRootDirTask, true);
    } else {
        MEDIA_WARN_LOG("Can not init make root dir task");
    }
}

static int32_t ReconstructMediaLibraryPhotoMap()
{
    if (system::GetParameter("persist.multimedia.medialibrary.albumFusion.status", "1") == "1") {
        return E_OK;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Failed to get rdbstore, try again!");
        rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_DB_FAIL,
            "Fatal error! Failed to get rdbstore, new cloud data is not processed!!");
    }
    MediaLibraryRdbStore::ReconstructMediaLibraryStorageFormat(rdbStore);
    return E_OK;
}

void MediaLibraryDataManager::HandleOtherInitOperations()
{
    InitRefreshAlbum();
    UriPermissionOperations::DeleteAllTemporaryAsync();
    UriSensitiveOperations::DeleteAllSensitiveAsync();
}

static int32_t ExcuteAsyncWork()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_ERR, "Can not get asyncWorker");

    AsyncTaskData* taskData = new (std::nothrow) AsyncTaskData();
    CHECK_AND_RETURN_RET_LOG(taskData != nullptr, E_ERR, "Failed to new taskData");

    taskData->dataDisplay = E_POLICY;
    shared_ptr<MediaLibraryAsyncTask> makeRootDirTask = make_shared<MediaLibraryAsyncTask>(MakeRootDirs, taskData);
    if (makeRootDirTask != nullptr) {
        asyncWorker->AddTask(makeRootDirTask, true);
    } else {
        MEDIA_WARN_LOG("Can not init make root dir task");
    }
    return E_OK;
}

__attribute__((no_sanitize("cfi"))) int32_t MediaLibraryDataManager::InitMediaLibraryMgr(
    const shared_ptr<OHOS::AbilityRuntime::Context> &context,
    const shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext, int32_t &sceneCode, bool isNeedCreateDir,
    bool isInMediaLibraryOnStart)
{
    lock_guard<shared_mutex> lock(mgrSharedMutex_);

    if (refCnt_.load() > 0) {
        MEDIA_DEBUG_LOG("already initialized");
        refCnt_++;
        return E_OK;
    }

    InitResourceInfo();
    context_ = context;
    int32_t errCode = InitMediaLibraryRdbStore();
    if (errCode != E_OK) {
        sceneCode = DfxType::START_RDB_STORE_FAIL;
        return errCode;
    }
    if (!MediaLibraryKvStoreManager::GetInstance().InitMonthAndYearKvStore(KvStoreRoleType::OWNER)) {
        MEDIA_ERR_LOG("failed at InitMonthAndYearKvStore");
    }
    MimeTypeUtils::InitMimeTypeMap();
    errCode = MakeDirQuerySetMap(dirQuerySetMap_);
    CHECK_AND_WARN_LOG(errCode == E_OK, "failed at MakeDirQuerySetMap");
    InitACLPermission();
    InitDatabaseACLPermission();
    if (isNeedCreateDir) {
        errCode = ExcuteAsyncWork();
        CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at ExcuteAsyncWork");
    }
    errCode = InitialiseThumbnailService(extensionContext);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at InitialiseThumbnailService");
    ReconstructMediaLibraryPhotoMap();
    HandleOtherInitOperations();

    if (AlbumsRefreshManager::GetInstance().HasRefreshingSystemAlbums()) {
        SyncNotifyInfo info;
        info.forceRefreshType = ForceRefreshType::EXCEPTION;
        AlbumsRefreshManager::GetInstance().AddAlbumRefreshTask(info);
    }
    auto shareHelper = MediaLibraryHelperContainer::GetInstance()->GetDataShareHelper();
    cloudPhotoObserver_ = std::make_shared<CloudSyncObserver>();
    cloudPhotoAlbumObserver_ = std::make_shared<CloudSyncObserver>();
    galleryRebuildObserver_= std::make_shared<CloudSyncObserver>();
    cloudGalleryPhotoObserver_ = std::make_shared<CloudSyncObserver>();
    cloudGalleryDownloadObserver_ = std::make_shared<CloudSyncObserver>();
    shareHelper->RegisterObserverExt(Uri(PhotoColumn::PHOTO_CLOUD_URI_PREFIX), cloudPhotoObserver_, true);
    shareHelper->RegisterObserverExt(
        Uri(PhotoColumn::PHOTO_CLOUD_GALLERY_REBUILD_URI_PREFIX),
        galleryRebuildObserver_, true);
    shareHelper->RegisterObserverExt(Uri(PhotoAlbumColumns::ALBUM_GALLERY_CLOUD_URI_PREFIX),
        cloudPhotoAlbumObserver_, true);
    shareHelper->RegisterObserverExt(Uri(PhotoAlbumColumns::PHOTO_GALLERY_CLOUD_SYNC_INFO_URI_PREFIX),
        cloudPhotoAlbumObserver_, true);
    shareHelper->RegisterObserverExt(Uri(PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX),
        cloudGalleryPhotoObserver_, true);
    shareHelper->RegisterObserverExt(Uri(PhotoAlbumColumns::PHOTO_GALLERY_DOWNLOAD_URI_PREFIX),
        cloudGalleryDownloadObserver_, true);

    HandleUpgradeRdbAsync(isInMediaLibraryOnStart);
    CloudSyncSwitchManager cloudSyncSwitchManager;
    cloudSyncSwitchManager.RegisterObserver();
    SubscriberPowerConsumptionDetection();
    MediaLibraryFaCardOperations::InitFaCard();

    refCnt_++;

#ifdef META_RECOVERY_SUPPORT
    // TEMP: avoid Process backup call StartAsyncRecovery
    // Should remove this judgment at refactor in OpenHarmony5.1
    if (extensionContext != nullptr) {
        MediaLibraryMetaRecovery::GetInstance().StartAsyncRecovery();
    }
#endif

    return E_OK;
}

static void FillMediaSuffixForHistoryData(const shared_ptr<MediaLibraryRdbStore>& store)
{
    MEDIA_INFO_LOG("start to fill media suffix for history data");

    // Calculate the substring after the last dot in the display_name. If there is no dot, return an empty string.
    const string calculatedSuffix = "CASE WHEN (INSTR(display_name, '.') > 0) THEN "
        "REPLACE(display_name, RTRIM(display_name, REPLACE(display_name, '.', '')), '') ELSE '' END";
    const string sql = "UPDATE " + PhotoColumn::PHOTOS_TABLE +
                 " SET " + PhotoColumn::PHOTO_MEDIA_SUFFIX + " = " + calculatedSuffix +
                 " WHERE " + PhotoColumn::PHOTO_MEDIA_SUFFIX + " IS NULL";
    int ret = store->ExecuteSql(sql);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "FillMediaSuffixForHistoryData failed: execute sql failed");
    MEDIA_INFO_LOG("end fill media suffix for history data");
}

static void AddImageFaceTagIdIndex(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("Adding TAG_ID index for VISION_IMAGE_FACE_TABLE");
    int ret = store->ExecuteSql(CREATE_IMAGE_FACE_TAG_ID_INDEX);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "AddImageFaceTagIdIndex failed: execute sql failed");
    MEDIA_INFO_LOG("end TAG_ID index for VISION_IMAGE_FACE_TABLE");
}

static void AddGroupTagIndex(const shared_ptr<MediaLibraryRdbStore>& store)
{
    MEDIA_INFO_LOG("start to add group tag index");

    int ret = store->ExecuteSql(CREATE_ANALYSIS_ALBUM_GROUP_TAG_INDEX);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "AddGroupTagIndex failed: execute sql failed");

    MEDIA_INFO_LOG("end add group tag index");
}

static void AddAnalysisPhotoMapAssetIndex(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("Adding map_asset index for ANALYSIS_PHOTO_MAP");
    int ret = store->ExecuteSql(CREATE_ANALYSIS_PHOTO_MAP_MAP_ASSET_INDEX);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "AddAnalysisPhotoMapAssetIndex failed: execute sql failed");
    MEDIA_INFO_LOG("end map_asset index for ANALYSIS_PHOTO_MAP");
}

static void FixTabExtDirtyData(const shared_ptr<MediaLibraryRdbStore>& store)
{
    MEDIA_INFO_LOG("start to fix tab ext dirty data");
    std::string cleanExtDirtyDataSql = "DELETE FROM " + PhotoExtColumn::PHOTOS_EXT_TABLE +
                            " WHERE NOT EXISTS (" +
                            " SELECT 1 " +
                            " FROM " + PhotoColumn::PHOTOS_TABLE +
                            " WHERE " + PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID +
                            " = " + PhotoExtColumn::PHOTOS_EXT_TABLE + "." + PhotoExtColumn::PHOTO_ID +
                            ");";
    int ret = store->ExecuteSql(cleanExtDirtyDataSql);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "FixTabExtDirtyData failed: execute sql failed");
    MEDIA_INFO_LOG("end fix tab ext dirty data");
}

static void UpdateIsRectificationCover(const shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "RdbStore is null!");

    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.NotEqualTo(PhotoColumn::PHOTO_COVER_POSITION, 0);

    ValuesBucket values;
    values.PutLong(PhotoColumn::PHOTO_IS_RECTIFICATION_COVER, 1);

    int32_t changedRows = 0;
    int32_t err = rdbStore->Update(changedRows, values, predicates);
    CHECK_AND_PRINT_LOG(err == NativeRdb::E_OK, "RdbStore Update is_rectification_cover failed, err: %{public}d", err);
}

static void FixOrientation180DirtyThumbnail(const shared_ptr<MediaLibraryRdbStore>& store)
{
    MEDIA_INFO_LOG("Start to fix dirty thumbnail");
    std::string sql =
        "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_THUMBNAIL_READY + " = 6" +
        " WHERE " + PhotoColumn::PHOTO_ORIENTATION + " = 180 AND " + MediaColumn::MEDIA_TYPE + " = 1";
    int ret = store->ExecuteSql(sql);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Execute sql failed");
    MEDIA_INFO_LOG("End fix dirty thumbnail");
}

static void AddShootingModeAlbumIndex(const shared_ptr<MediaLibraryRdbStore>& store)
{
    MEDIA_INFO_LOG("Start to add shooting mode album index");
    const vector<string> sqls = {
        PhotoColumn::CREATE_PHOTO_SHOOTING_MODE_ALBUM_GENERAL_INDEX,
        PhotoColumn::CREATE_PHOTO_BURST_MODE_ALBUM_INDEX,
        PhotoColumn::CREATE_PHOTO_FRONT_CAMERA_ALBUM_INDEX,
        PhotoColumn::CREATE_PHOTO_RAW_IMAGE_ALBUM_INDEX,
        PhotoColumn::CREATE_PHOTO_MOVING_PHOTO_ALBUM_INDEX,
    };
    for (const auto& sql : sqls) {
        int ret = store->ExecuteSql(sql);
        CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Execute sql failed");
    }
    MEDIA_INFO_LOG("End add shooting mode album index");
}

static void AddHistoryPanoramaModeAlbumData(const shared_ptr<MediaLibraryRdbStore>& store)
{
    MEDIA_INFO_LOG("Start to add panorama mode album data");
    const string panoramaModeAlbumType = to_string(static_cast<int32_t>(ShootingModeAlbumType::PANORAMA_MODE));
    const string sql = "UPDATE Photos SET shooting_mode = " + panoramaModeAlbumType +
        " WHERE shooting_mode_tag IN (" + CAMERA_CUSTOM_SM_PANORAMA +
        ", " + CAMERA_CUSTOM_SM_PHOTO_STITCHING + ")";
    int ret = store->ExecuteSql(sql);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Execute sql failed");
    MEDIA_INFO_LOG("End add panorama mode album data");
}

static void AddHistoryAIHighPixelModeAlbumData(const shared_ptr<MediaLibraryRdbStore>& store)
{
    MEDIA_INFO_LOG("Start to add ai high pixel mode album data");
    const string highPixelModeAlbumType = to_string(static_cast<int32_t>(ShootingModeAlbumType::HIGH_PIXEL));
    const string sql = "UPDATE Photos SET shooting_mode = " + highPixelModeAlbumType +
        " WHERE shooting_mode_tag = " + AI_HIGH_PIXEL_TAG;
    int ret = store->ExecuteSql(sql);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Execute sql failed");
    MEDIA_INFO_LOG("End add ai high pixel mode album data");
}

static void UpdateAllShootingModeAlbums(const shared_ptr<MediaLibraryRdbStore>& rdbStore)
{
    vector<int32_t> albumIds;
    vector<string> albumIdsStr;
    CHECK_AND_RETURN_LOG(MediaLibraryRdbUtils::QueryAllShootingModeAlbumIds(albumIds),
        "Failed to query shooting mode album ids");
    for (auto albumId : albumIds) {
        albumIdsStr.push_back(to_string(albumId));
    }

    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore, albumIdsStr);
}

void HandleUpgradeRdbAsyncPart3(const shared_ptr<MediaLibraryRdbStore> rdbStore, int32_t oldVersion)
{
    if (oldVersion < VERSION_FIX_DB_UPGRADE_FROM_API18) {
        MEDIA_INFO_LOG("Start VERSION_ADD_GROUP_TAG_INDEX");
        AddGroupTagIndex(rdbStore);
        MEDIA_INFO_LOG("End VERSION_ADD_GROUP_TAG_INDEX");

        MEDIA_INFO_LOG("Start VERSION_IMAGE_FACE_TAG_ID_INDEX");
        AddImageFaceTagIdIndex(rdbStore);
        MEDIA_INFO_LOG("End VERSION_IMAGE_FACE_TAG_ID_INDEX");

        MEDIA_INFO_LOG("Start VERSION_ADD_INDEX_FOR_PHOTO_SORT");
        MediaLibraryRdbStore::AddPhotoSortIndex(rdbStore);
        MEDIA_INFO_LOG("End VERSION_ADD_INDEX_FOR_PHOTO_SORT");

        rdbStore->SetOldVersion(VERSION_FIX_DB_UPGRADE_FROM_API18);
    }

    if (oldVersion < VERSION_TRANSFER_OWNERAPPID_TO_TOKENID) {
        MediaLibraryRdbUtils::TransformOwnerAppIdToTokenId(rdbStore);
        rdbStore->SetOldVersion(VERSION_TRANSFER_OWNERAPPID_TO_TOKENID);
    }
}

void HandleUpgradeRdbAsyncPart2(const shared_ptr<MediaLibraryRdbStore> rdbStore, int32_t oldVersion)
{
    if (oldVersion < VERSION_FIX_DB_UPGRADE_FROM_API15) {
        MEDIA_INFO_LOG("Start VERSION_ANALYZE_PHOTOS");
        MediaLibraryRdbUtils::AnalyzePhotosData();
        MEDIA_INFO_LOG("End VERSION_ANALYZE_PHOTOS");

        MEDIA_INFO_LOG("Start VERSION_ADD_MEDIA_SUFFIX_COLUMN");
        FillMediaSuffixForHistoryData(rdbStore);
        MEDIA_INFO_LOG("End VERSION_ADD_MEDIA_SUFFIX_COLUMN");

        rdbStore->SetOldVersion(VERSION_FIX_DB_UPGRADE_FROM_API15);
    }

    if (oldVersion < VERSION_FIX_TAB_EXT_DIRTY_DATA) {
        FixTabExtDirtyData(rdbStore);
        rdbStore->SetOldVersion(VERSION_FIX_TAB_EXT_DIRTY_DATA);
    }

    if (oldVersion < VERSION_ADD_IS_RECTIFICATION_COVER) {
        MEDIA_INFO_LOG("Start VERSION_ADD_IS_RECTIFICATION_COVER");
        UpdateIsRectificationCover(rdbStore);
        MEDIA_INFO_LOG("End VERSION_ADD_IS_RECTIFICATION_COVER");

        rdbStore->SetOldVersion(VERSION_ADD_IS_RECTIFICATION_COVER);
    }

    if (oldVersion < VERSION_FIX_ORIENTATION_180_DIRTY_THUMBNAIL) {
        FixOrientation180DirtyThumbnail(rdbStore);
        rdbStore->SetOldVersion(VERSION_FIX_ORIENTATION_180_DIRTY_THUMBNAIL);
    }

    if (oldVersion < VERSION_ADD_INDEX_FOR_PHOTO_SORT) {
        MediaLibraryRdbStore::AddPhotoSortIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_INDEX_FOR_PHOTO_SORT);
    }

    if (oldVersion < VERSION_ADD_PHOTO_QUERY_THUMBNAIL_WHITE_BLOCKS_INDEX) {
        MediaLibraryRdbStore::AddPhotoWhiteBlocksIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_PHOTO_QUERY_THUMBNAIL_WHITE_BLOCKS_INDEX);
    }

    if (oldVersion < VERSION_SHOOTING_MODE_ALBUM_SECOND_INTERATION) {
        AddShootingModeAlbumIndex(rdbStore);
        AddHistoryPanoramaModeAlbumData(rdbStore);
        AddHistoryAIHighPixelModeAlbumData(rdbStore);
        UpdateAllShootingModeAlbums(rdbStore);
        rdbStore->SetOldVersion(VERSION_SHOOTING_MODE_ALBUM_SECOND_INTERATION);
    }

    HandleUpgradeRdbAsyncPart3(rdbStore, oldVersion);
    // !! Do not add upgrade code here !!
}

void HandleUpgradeRdbAsyncPart1(const shared_ptr<MediaLibraryRdbStore> rdbStore, int32_t oldVersion)
{
    if (oldVersion < VERSION_FIX_PHOTO_QUALITY_CLONED) {
        MediaLibraryRdbStore::UpdatePhotoQualityCloned(rdbStore);
        rdbStore->SetOldVersion(VERSION_FIX_PHOTO_QUALITY_CLONED);
    }

    if (oldVersion < VERSION_ADD_MEDIA_SUFFIX_COLUMN) {
        FillMediaSuffixForHistoryData(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_MEDIA_SUFFIX_COLUMN);
    }

    if (oldVersion < VERSION_UPDATE_LOCATION_KNOWLEDGE_INDEX) {
        MediaLibraryRdbStore::UpdateLocationKnowledgeIdx(rdbStore);
        rdbStore->SetOldVersion(VERSION_UPDATE_LOCATION_KNOWLEDGE_INDEX);
    }

    if (oldVersion < VERSION_IMAGE_FACE_TAG_ID_INDEX) {
        AddImageFaceTagIdIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_IMAGE_FACE_TAG_ID_INDEX);
    }

    if (oldVersion < VERSION_ADD_GROUP_TAG_INDEX) {
        AddGroupTagIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_GROUP_TAG_INDEX);
    }

    if (oldVersion < VERSION_ANALYZE_PHOTOS) {
        MediaLibraryRdbUtils::AnalyzePhotosData();
        rdbStore->SetOldVersion(VERSION_ANALYZE_PHOTOS);
    }

    if (oldVersion < VERSION_ADD_ANALYSIS_PHOTO_MAP_MAP_ASSET_INDEX) {
        AddAnalysisPhotoMapAssetIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_ANALYSIS_PHOTO_MAP_MAP_ASSET_INDEX);
    }

    if (oldVersion < VERSION_UPDATE_MDIRTY_TRIGGER_FOR_TDIRTY) {
        MediaLibraryRdbStore::UpdateMdirtyTriggerForTdirty(rdbStore);
        rdbStore->SetOldVersion(VERSION_UPDATE_MDIRTY_TRIGGER_FOR_TDIRTY);
    }

    if (oldVersion < VERSION_ADD_ALBUM_SUBTYPE_AND_NAME_INDEX) {
        MediaLibraryRdbStore::AddAlbumSubtypeAndNameIdx(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_ALBUM_SUBTYPE_AND_NAME_INDEX);
    }

    HandleUpgradeRdbAsyncPart2(rdbStore, oldVersion);
    // !! Do not add upgrade code here !!
}

void HandleUpgradeRdbAsyncExtension(const shared_ptr<MediaLibraryRdbStore> rdbStore, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_READY_COUNT_INDEX) {
        MediaLibraryRdbStore::AddReadyCountIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_READY_COUNT_INDEX);
    }

    if (oldVersion < VERSION_FIX_PICTURE_LCD_SIZE) {
        MediaLibraryRdbStore::UpdateLcdStatusNotUploaded(rdbStore);
        rdbStore->SetOldVersion(VERSION_FIX_PICTURE_LCD_SIZE);
    }

    if (oldVersion < VERSION_REVERT_FIX_DATE_ADDED_INDEX) {
        MediaLibraryRdbStore::RevertFixDateAddedIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_REVERT_FIX_DATE_ADDED_INDEX);
    }

    if (oldVersion < VERSION_ADD_CLOUD_ENHANCEMENT_ALBUM_INDEX) {
        MediaLibraryRdbStore::AddCloudEnhancementAlbumIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_CLOUD_ENHANCEMENT_ALBUM_INDEX);
    }

    if (oldVersion < VERSION_ADD_PHOTO_DATEADD_INDEX) {
        MediaLibraryRdbStore::AddPhotoDateAddedIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_PHOTO_DATEADD_INDEX);
    }

    if (oldVersion < VERSION_ADD_ALBUM_INDEX) {
        MediaLibraryRdbStore::AddAlbumIndex(rdbStore);
        rdbStore->SetOldVersion(VERSION_ADD_ALBUM_INDEX);
    }

    if (oldVersion < VERSION_REFRESH_PERMISSION_APPID) {
        MediaLibraryRdbUtils::TransformAppId2TokenId(rdbStore);
        rdbStore->SetOldVersion(VERSION_REFRESH_PERMISSION_APPID);
    }

    if (oldVersion < VERSION_UPDATE_PHOTOS_DATE_AND_IDX) {
        PhotoDayMonthYearOperation::UpdatePhotosDateAndIdx(rdbStore);
        rdbStore->SetOldVersion(VERSION_UPDATE_PHOTOS_DATE_AND_IDX);
    }

    if (oldVersion < VERSION_UPDATE_LATITUDE_AND_LONGITUDE_DEFAULT_NULL) {
        MediaLibraryRdbStore::UpdateLatitudeAndLongitudeDefaultNull(rdbStore);
        rdbStore->SetOldVersion(VERSION_UPDATE_LATITUDE_AND_LONGITUDE_DEFAULT_NULL);
    }

    if (oldVersion < VERSION_UPDATE_PHOTOS_DATE_IDX) {
        PhotoDayMonthYearOperation::UpdatePhotosDateIdx(rdbStore);
        rdbStore->SetOldVersion(VERSION_UPDATE_PHOTOS_DATE_IDX);
    }

    if (oldVersion < VERSION_UPDATE_MEDIA_TYPE_AND_THUMBNAIL_READY_IDX) {
        MediaLibraryRdbStore::UpdateMediaTypeAndThumbnailReadyIdx(rdbStore);
        rdbStore->SetOldVersion(VERSION_UPDATE_MEDIA_TYPE_AND_THUMBNAIL_READY_IDX);
    }

    HandleUpgradeRdbAsyncPart1(rdbStore, oldVersion);
    // !! Do not add upgrade code here !!
}

static void MultiStagesInitOperation()
{
    MultiStagesPhotoCaptureManager::GetInstance().Init();
    MultiStagesVideoCaptureManager::GetInstance().Init();
}

void MediaLibraryDataManager::HandleUpgradeRdbAsync(bool isInMediaLibraryOnStart)
{
    std::thread([isInMediaLibraryOnStart] {
        if (isInMediaLibraryOnStart) {
            MultiStagesInitOperation();
        }

        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr!");
        int32_t oldVersion = rdbStore->GetOldVersion();
        bool cond = (oldVersion == -1 || oldVersion >= MEDIA_RDB_VERSION);
        CHECK_AND_RETURN_INFO_LOG(!cond, "No need to upgrade rdb, oldVersion: %{public}d", oldVersion);

        MEDIA_INFO_LOG("oldVersion:%{public}d", oldVersion);
        // compare older version, update and set old version
        if (oldVersion < VERSION_CREATE_BURSTKEY_INDEX) {
            MediaLibraryRdbStore::CreateBurstIndex(rdbStore);
            rdbStore->SetOldVersion(VERSION_CREATE_BURSTKEY_INDEX);
        }

        if (oldVersion < VERSION_UPDATE_BURST_DIRTY) {
            MediaLibraryRdbStore::UpdateBurstDirty(rdbStore);
            rdbStore->SetOldVersion(VERSION_UPDATE_BURST_DIRTY);
        }

        if (oldVersion < VERSION_UPGRADE_THUMBNAIL) {
            MediaLibraryRdbStore::UpdateReadyOnThumbnailUpgrade(rdbStore);
            rdbStore->SetOldVersion(VERSION_UPGRADE_THUMBNAIL);
        }
        if (oldVersion < VERSION_ADD_DETAIL_TIME) {
            MediaLibraryRdbStore::UpdateDateTakenToMillionSecond(rdbStore);
            MediaLibraryRdbStore::UpdateDateTakenIndex(rdbStore);
            ThumbnailService::GetInstance()->AstcChangeKeyFromDateAddedToDateTaken();
            rdbStore->SetOldVersion(VERSION_ADD_DETAIL_TIME);
        }
        if (oldVersion < VERSION_MOVE_AUDIOS) {
            MediaLibraryAudioOperations::MoveToMusic();
            MediaLibraryRdbStore::ClearAudios(rdbStore);
            rdbStore->SetOldVersion(VERSION_MOVE_AUDIOS);
        }
        if (oldVersion < VERSION_UPDATE_INDEX_FOR_COVER) {
            MediaLibraryRdbStore::UpdateIndexForCover(rdbStore);
            rdbStore->SetOldVersion(VERSION_UPDATE_INDEX_FOR_COVER);
        }
        if (oldVersion < VERSION_UPDATE_DATETAKEN_AND_DETAILTIME) {
            MediaLibraryRdbStore::UpdateDateTakenAndDetalTime(rdbStore);
            rdbStore->SetOldVersion(VERSION_UPDATE_DATETAKEN_AND_DETAILTIME);
        }

        HandleUpgradeRdbAsyncExtension(rdbStore, oldVersion);
        // !! Do not add upgrade code here !!
        rdbStore->SetOldVersion(MEDIA_RDB_VERSION);
    }).detach();
}

void MediaLibraryDataManager::InitResourceInfo()
{
    BackgroundTaskMgr::EfficiencyResourceInfo resourceInfo =
        BackgroundTaskMgr::EfficiencyResourceInfo(BackgroundTaskMgr::ResourceType::CPU, true, 0, "apply", true, true);
    BackgroundTaskMgr::BackgroundTaskMgrHelper::ApplyEfficiencyResources(resourceInfo);
}

__attribute__((no_sanitize("cfi"))) void MediaLibraryDataManager::ClearMediaLibraryMgr()
{
    lock_guard<shared_mutex> lock(mgrSharedMutex_);

    refCnt_--;
    if (refCnt_.load() > 0) {
        MEDIA_DEBUG_LOG("still other extension exist");
        return;
    }

    BackgroundCloudFileProcessor::StopTimer();

    auto shareHelper = MediaLibraryHelperContainer::GetInstance()->GetDataShareHelper();
    CHECK_AND_RETURN_LOG(shareHelper != nullptr, "DataShareHelper is null");

    shareHelper->UnregisterObserverExt(Uri(PhotoColumn::PHOTO_CLOUD_URI_PREFIX), cloudPhotoObserver_);
    shareHelper->UnregisterObserverExt(Uri(PhotoColumn::PHOTO_CLOUD_GALLERY_REBUILD_URI_PREFIX), cloudPhotoObserver_);
    shareHelper->UnregisterObserverExt(Uri(PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX), cloudPhotoAlbumObserver_);
    shareHelper->UnregisterObserverExt(
        Uri(PhotoAlbumColumns::ALBUM_GALLERY_CLOUD_URI_PREFIX), cloudPhotoAlbumObserver_);
    shareHelper->UnregisterObserverExt(
        Uri(PhotoAlbumColumns::PHOTO_GALLERY_CLOUD_SYNC_INFO_URI_PREFIX), cloudPhotoAlbumObserver_);
    shareHelper->UnregisterObserverExt(
        Uri(PhotoAlbumColumns::PHOTO_GALLERY_DOWNLOAD_URI_PREFIX), cloudGalleryDownloadObserver_);
    rdbStore_ = nullptr;
    MediaLibraryKvStoreManager::GetInstance().CloseAllKvStore();
    MEDIA_INFO_LOG("CloseKvStore success");

    if (thumbnailService_ != nullptr) {
        thumbnailService_->ReleaseService();
        thumbnailService_ = nullptr;
    }
    auto watch = MediaLibraryInotify::GetInstance();
    if (watch != nullptr) {
        watch->DoStop();
    }
    MediaLibraryUnistoreManager::GetInstance().Stop();
    extension_ = nullptr;
}

int32_t MediaLibraryDataManager::InitMediaLibraryRdbStore()
{
    if (rdbStore_) {
        return E_OK;
    }

    int32_t ret = MediaLibraryUnistoreManager::GetInstance().Init(context_);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "init MediaLibraryUnistoreManager failed");

    rdbStore_ = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_ERR, "rdbStore is nullptr");

    return E_OK;
}

void MediaLibraryDataManager::InitRefreshAlbum()
{
    bool isNeedRefresh = false;
    int32_t ret = MediaLibraryRdbUtils::IsNeedRefreshByCheckTable(rdbStore_, isNeedRefresh);
    if (ret != E_OK || isNeedRefresh) {
        // Only set flag here, should not do any task in InitDataMgr
        MediaLibraryRdbUtils::SetNeedRefreshAlbum(true);
    }
}

shared_ptr<MediaDataShareExtAbility> MediaLibraryDataManager::GetOwner()
{
    return extension_;
}

void MediaLibraryDataManager::SetOwner(const shared_ptr<MediaDataShareExtAbility> &datashareExternsion)
{
    extension_ = datashareExternsion;
}

string MediaLibraryDataManager::GetType(const Uri &uri)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::GetType");
    MediaLibraryCommand cmd(uri);
    switch (cmd.GetOprnObject()) {
        case OperationObject::CLOUD_MEDIA_ASSET_OPERATE:
            return CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetGetTypeOperations(cmd);
        default:
            break;
    }

    MEDIA_INFO_LOG("GetType uri: %{private}s", uri.ToString().c_str());
    return "";
}

int32_t MediaLibraryDataManager::MakeDirQuerySetMap(unordered_map<string, DirAsset> &outDirQuerySetMap)
{
    int32_t count = -1;
    vector<string> columns;
    AbsRdbPredicates dirAbsPred(MEDIATYPE_DIRECTORY_TABLE);
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_ERR, "rdbStore_ is nullptr");

    auto queryResultSet = rdbStore_->QueryByStep(dirAbsPred, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, E_ERR, "queryResultSet is nullptr");

    auto ret = queryResultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_ERR, "rdb failed");

    MEDIA_INFO_LOG("MakeDirQuerySetMap count = %{public}d", count);
    CHECK_AND_RETURN_RET_LOG(count != 0, E_ERR, "can not find any dirAsset");

    DirAsset dirAsset;
    string dirVal;
    outDirQuerySetMap.clear();
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        dirVal = get<string>(
            ResultSetUtils::GetValFromColumn(DIRECTORY_DB_DIRECTORY, queryResultSet, TYPE_STRING));
        dirAsset.SetDirectory(dirVal);
        dirAsset.SetDirType(get<int32_t>(
            ResultSetUtils::GetValFromColumn(DIRECTORY_DB_DIRECTORY_TYPE, queryResultSet, TYPE_INT32)));
        dirAsset.SetMediaTypes(get<string>(
            ResultSetUtils::GetValFromColumn(DIRECTORY_DB_MEDIA_TYPE, queryResultSet, TYPE_STRING)));
        dirAsset.SetExtensions(get<string>(
            ResultSetUtils::GetValFromColumn(DIRECTORY_DB_EXTENSION, queryResultSet, TYPE_STRING)));
        outDirQuerySetMap.insert(make_pair(dirVal, dirAsset));
    }
    return E_OK;
}

unordered_map<string, DirAsset> MediaLibraryDataManager::GetDirQuerySetMap()
{
    return dirQuerySetMap_;
}

#ifdef MEDIALIBRARY_COMPATIBILITY
static void ChangeUriFromValuesBucket(ValuesBucket &values)
{
    if (!values.HasColumn(MEDIA_DATA_DB_URI)) {
        return;
    }

    ValueObject value;
    if (!values.GetObject(MEDIA_DATA_DB_URI, value)) {
        return;
    }
    string oldUri;
    if (value.GetString(oldUri) != NativeRdb::E_OK) {
        return;
    }
    string newUri = MediaFileUtils::GetRealUriFromVirtualUri(oldUri);
    values.Delete(MEDIA_DATA_DB_URI);
    values.PutString(MEDIA_DATA_DB_URI, newUri);
}
#endif

int32_t MediaLibraryDataManager::SolveInsertCmd(MediaLibraryCommand &cmd)
{
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET:
            return MediaLibraryFileOperations::HandleFileOperation(cmd);

        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::FILESYSTEM_AUDIO:
        case OperationObject::PTP_OPERATION:
            return MediaLibraryAssetOperations::HandleInsertOperation(cmd);

        case OperationObject::FILESYSTEM_ALBUM:
            return MediaLibraryAlbumOperations::CreateAlbumOperation(cmd);

        case OperationObject::ANALYSIS_PHOTO_ALBUM:
        case OperationObject::PHOTO_ALBUM:
        case OperationObject::PTP_ALBUM_OPERATION:
            return MediaLibraryAlbumOperations::HandlePhotoAlbumOperations(cmd);
        case OperationObject::FILESYSTEM_DIR:
            return MediaLibraryDirOperations::HandleDirOperation(cmd);

        case OperationObject::SMART_ALBUM: {
            string packageName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
            MEDIA_INFO_LOG("%{public}s call smart album insert!", packageName.c_str());
            return MediaLibrarySmartAlbumOperations::HandleSmartAlbumOperation(cmd);
        }
        case OperationObject::SMART_ALBUM_MAP:
            return MediaLibrarySmartAlbumMapOperations::HandleSmartAlbumMapOperation(cmd);

        case OperationObject::THUMBNAIL:
            return HandleThumbnailOperations(cmd);

        case OperationObject::BUNDLE_PERMISSION:
            return UriPermissionOperations::HandleUriPermOperations(cmd);
        case OperationObject::APP_URI_PERMISSION_INNER: {
            int32_t ret = UriSensitiveOperations::InsertOperation(cmd);
            CHECK_AND_RETURN_RET(ret >= 0, ret);
            return UriPermissionOperations::InsertOperation(cmd);
        }
        case OperationObject::MEDIA_APP_URI_PERMISSION: {
            int32_t ret = MediaLibraryAppUriSensitiveOperations::HandleInsertOperation(cmd);
            CHECK_AND_RETURN_RET(ret == MediaLibraryAppUriSensitiveOperations::SUCCEED, ret);
            return MediaLibraryAppUriPermissionOperations::HandleInsertOperation(cmd);
        }
        default:
            break;
    }
    return SolveInsertCmdSub(cmd);
}

int32_t MediaLibraryDataManager::SolveInsertCmdSub(MediaLibraryCommand &cmd)
{
    if (MediaLibraryRestore::GetInstance().IsRealBackuping()) {
        MEDIA_INFO_LOG("[SolveInsertCmdSub] rdb is backuping");
        return E_FAIL;
    }
    switch (cmd.GetOprnObject()) {
        case OperationObject::VISION_START ... OperationObject::VISION_END:
            return MediaLibraryVisionOperations::InsertOperation(cmd);

        case OperationObject::GEO_DICTIONARY:
        case OperationObject::GEO_KNOWLEDGE:
        case OperationObject::GEO_PHOTO:
            return MediaLibraryLocationOperations::InsertOperation(cmd);
        case OperationObject::PAH_FORM_MAP:
            return MediaLibraryFormMapOperations::HandleStoreFormIdOperation(cmd);
        case OperationObject::TAB_FACARD_PHOTO:
            return MediaLibraryFaCardOperations::HandleStoreGalleryFormOperation(cmd);
        case OperationObject::SEARCH_TOTAL: {
            return MediaLibrarySearchOperations::InsertOperation(cmd);
        }
        case OperationObject::STORY_ALBUM:
        case OperationObject::STORY_COVER:
        case OperationObject::STORY_PLAY:
        case OperationObject::USER_PHOTOGRAPHY:
        case OperationObject::ANALYSIS_ASSET_SD_MAP:
        case OperationObject::ANALYSIS_ALBUM_ASSET_MAP:
            return MediaLibraryStoryOperations::InsertOperation(cmd);
        case OperationObject::ANALYSIS_PHOTO_MAP: {
            return MediaLibrarySearchOperations::InsertOperation(cmd);
        }
        default:
            MEDIA_ERR_LOG("MediaLibraryDataManager SolveInsertCmd: unsupported OperationObject: %{public}d",
                cmd.GetOprnObject());
            break;
    }
    return E_FAIL;
}

static int32_t LogMovingPhoto(MediaLibraryCommand &cmd, const DataShareValuesBucket &dataShareValue)
{
    bool isValid = false;
    bool adapted = bool(dataShareValue.Get("adapted", isValid));
    CHECK_AND_RETURN_RET_LOG(isValid, E_ERR, "Invalid adapted value");

    string packageName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    CHECK_AND_WARN_LOG(!packageName.empty(), "Package name is empty, adapted: %{public}d", static_cast<int>(adapted));
    DfxManager::GetInstance()->HandleAdaptationToMovingPhoto(packageName, adapted);
    return E_OK;
}

static int32_t LogMedialibraryAPI(MediaLibraryCommand &cmd, const DataShareValuesBucket &dataShareValue)
{
    string packageName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    bool isValid = false;
    string saveUri = string(dataShareValue.Get("saveUri", isValid));
    CHECK_AND_RETURN_RET_LOG(isValid, E_FAIL, "Invalid saveUri value");
    int32_t ret = DfxReporter::ReportMedialibraryAPI(packageName, saveUri);
    CHECK_AND_PRINT_LOG(ret == E_SUCCESS, "Log medialibrary API failed");
    return ret;
}

static int32_t SolveOtherInsertCmd(MediaLibraryCommand &cmd, const DataShareValuesBucket &dataShareValue,
    bool &solved)
{
    solved = false;
    switch (cmd.GetOprnObject()) {
        case OperationObject::MISCELLANEOUS: {
            if (cmd.GetOprnType() == OperationType::LOG_MOVING_PHOTO) {
                solved = true;
                return LogMovingPhoto(cmd, dataShareValue);
            }
            if (cmd.GetOprnType() == OperationType::LOG_MEDIALIBRARY_API) {
                solved = true;
                return LogMedialibraryAPI(cmd, dataShareValue);
            }
            if (cmd.GetOprnType() == OperationType::QUERY_ACTIVE_USER_ID) {
                solved = true;
                constexpr int32_t baseUserRange = 200000;
                uid_t activeUserId = getuid() / baseUserRange;
                cmd.SetResult(to_string(activeUserId));
                return E_OK;
            }
            return E_OK;
        }
        default:
            return E_FAIL;
    }
}

int32_t MediaLibraryDataManager::Insert(MediaLibraryCommand &cmd, const DataShareValuesBucket &dataShareValue)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }
    // visit count
    if (cmd.GetUri().ToString().find(MEDIA_DATA_DB_THUMBNAIL) != string::npos &&
        cmd.GetUri().ToString().find(PhotoColumn::PHOTO_LCD_VISIT_COUNT) != string::npos) {
        auto fileId = cmd.GetOprnFileId();
        MediaVisitCountManager::AddVisitCount(MediaVisitCountManager::VisitCountType::PHOTO_LCD, std::move(fileId));
        return E_SUCCESS;
    }

    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Insert: Input parameter is invalid");
        return E_INVALID_VALUES;
    }
#ifdef MEDIALIBRARY_COMPATIBILITY
    ChangeUriFromValuesBucket(value);
#endif
    cmd.SetValueBucket(value);

    OperationType oprnType = cmd.GetOprnType();
    if (oprnType == OperationType::CREATE || oprnType == OperationType::SUBMIT_CACHE
        || oprnType == OperationType::ADD_FILTERS) {
        CHECK_AND_PRINT_LOG(SetCmdBundleAndDevice(cmd) == ERR_OK,
            "MediaLibraryDataManager SetCmdBundleAndDevice failed.");
    }
    // boardcast operation
    if (oprnType == OperationType::SCAN) {
        return MediaScannerManager::GetInstance()->ScanDir(ROOT_MEDIA_DIR, nullptr);
    } else if (oprnType == OperationType::DELETE_TOOL) {
        return MediaLibraryAssetOperations::DeleteToolOperation(cmd);
    }

    bool solved = false;
    int32_t ret = SolveOtherInsertCmd(cmd, dataShareValue, solved);
    if (solved) {
        return ret;
    }
    return SolveInsertCmd(cmd);
}

int32_t MediaLibraryDataManager::InsertExt(MediaLibraryCommand &cmd, const DataShareValuesBucket &dataShareValue,
    string &result)
{
    int32_t ret = Insert(cmd, dataShareValue);
    result = cmd.GetResult();
    return ret;
}

int32_t MediaLibraryDataManager::HandleThumbnailOperations(MediaLibraryCommand &cmd)
{
    CHECK_AND_RETURN_RET(thumbnailService_ != nullptr, E_THUMBNAIL_SERVICE_NULLPTR);
    int32_t result = E_FAIL;
    switch (cmd.GetOprnType()) {
        case OperationType::GENERATE:
            result = thumbnailService_->GenerateThumbnailBackground();
            break;
        case OperationType::AGING:
            result = thumbnailService_->LcdAging();
            break;
        default:
            MEDIA_ERR_LOG("bad operation type %{public}u", cmd.GetOprnType());
    }
    return result;
}

int32_t MediaLibraryDataManager::BatchInsert(MediaLibraryCommand &cmd, const vector<DataShareValuesBucket> &values)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    CHECK_AND_RETURN_RET_LOG(refCnt_.load() > 0, E_FAIL, "MediaLibraryDataManager is not initialized");

    string uriString = cmd.GetUri().ToString();
    if (uriString == UFM_PHOTO_ALBUM_ADD_ASSET || uriString == PAH_PHOTO_ALBUM_ADD_ASSET) {
        return PhotoMapOperations::AddPhotoAssets(values);
    } else if (cmd.GetOprnObject() == OperationObject::ANALYSIS_PHOTO_MAP) {
        return PhotoMapOperations::AddAnaLysisPhotoAssets(values);
    } else if (cmd.GetOprnObject() == OperationObject::ADD_ASSET_HIGHLIGHT_ALBUM) {
        return PhotoMapOperations::AddHighlightPhotoAssets(values);
    } else if (cmd.GetOprnObject() == OperationObject::APP_URI_PERMISSION_INNER) {
        int32_t ret = UriSensitiveOperations::GrantUriSensitive(cmd, values);
        CHECK_AND_RETURN_RET(ret >= 0, ret);
        return UriPermissionOperations::GrantUriPermission(cmd, values);
    } else if (cmd.GetOprnObject() == OperationObject::MEDIA_APP_URI_PERMISSION) {
        int32_t ret = MediaLibraryAppUriSensitiveOperations::BatchInsert(cmd, values);
        CHECK_AND_RETURN_RET(ret == MediaLibraryAppUriSensitiveOperations::SUCCEED, ret);
        CHECK_AND_RETURN_RET(!MediaLibraryAppUriSensitiveOperations::BeForceSensitive(cmd, values), ret);
        return MediaLibraryAppUriPermissionOperations::BatchInsert(cmd, values);
    } else if (cmd.GetOprnObject() == OperationObject::MTH_AND_YEAR_ASTC) {
        return AstcMthAndYearInsert(cmd, values);
    } else if (cmd.GetOprnObject() == OperationObject::CUSTOM_RECORDS_OPERATION) {
        return CustomRecordOperations::BatchAddCustomRecords(cmd, values);
    }
    if (uriString.find(MEDIALIBRARY_DATA_URI) == string::npos) {
        MEDIA_ERR_LOG("MediaLibraryDataManager BatchInsert: Input parameter is invalid");
        return E_INVALID_URI;
    }

    int insertResult = BatchInsertMediaAnalysisData(cmd, values);
    if (insertResult > 0) {
        return insertResult;
    }

    int32_t rowCount = 0;
    for (auto it = values.begin(); it != values.end(); it++) {
        if (Insert(cmd, *it) >= 0) {
            rowCount++;
        }
    }

    return rowCount;
}

int32_t MediaLibraryDataManager::Delete(MediaLibraryCommand &cmd, const DataSharePredicates &predicates)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    string uriString = cmd.GetUri().ToString();
    if (MediaFileUtils::StartsWith(uriString, PhotoColumn::PHOTO_CACHE_URI_PREFIX)) {
        return MediaLibraryAssetOperations::DeleteOperation(cmd);
    }
    if (MediaFileUtils::StartsWith(uriString, CustomRecordsColumns::CUSTOM_RECORDS_URI_PREFIX)) {
        NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates,
            cmd.GetTableName());
        cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
        cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
        return MediaLibraryAppUriPermissionOperations::DeleteOperation(rdbPredicate);
    }
    CHECK_AND_RETURN_RET_LOG(uriString.find(MEDIALIBRARY_DATA_URI) != string::npos,
        E_INVALID_URI, "Not Data ability Uri");

    MediaLibraryTracer tracer;
    tracer.Start("CheckWhereClause");
    auto whereClause = predicates.GetWhereClause();
    CHECK_AND_RETURN_RET_LOG(MediaLibraryCommonUtils::CheckWhereClause(whereClause), E_SQL_CHECK_FAIL,
        "illegal query whereClause input %{private}s", whereClause.c_str());
    tracer.Finish();

    // MEDIALIBRARY_TABLE just for RdbPredicates
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates,
        cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return DeleteInRdbPredicates(cmd, rdbPredicate);
}

bool CheckIsDismissAsset(NativeRdb::RdbPredicates &rdbPredicate)
{
    auto whereClause = rdbPredicate.GetWhereClause();
    if (whereClause.find(MAP_ALBUM) != string::npos && whereClause.find(MAP_ASSET) != string::npos) {
        return true;
    }
    return false;
}

int32_t MediaLibraryDataManager::DeleteInRdbPredicates(MediaLibraryCommand &cmd, NativeRdb::RdbPredicates &rdbPredicate)
{
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET:
        case OperationObject::FILESYSTEM_DIR:
        case OperationObject::FILESYSTEM_ALBUM: {
            vector<string> columns = { MEDIA_DATA_DB_ID, MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_PARENT_ID,
                MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_DATA_DB_IS_TRASH, MEDIA_DATA_DB_RELATIVE_PATH };
            auto fileAsset = MediaLibraryObjectUtils::GetFileAssetByPredicates(*cmd.GetAbsRdbPredicates(), columns);
            CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_ARGUMENTS, "Get fileAsset failed.");
            if (fileAsset->GetRelativePath() == "") {
                return E_DELETE_DENIED;
            }
            return (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) ?
                MediaLibraryObjectUtils::DeleteFileObj(move(fileAsset)) :
                MediaLibraryObjectUtils::DeleteDirObj(move(fileAsset));
        }
        case OperationObject::PHOTO_ALBUM: {
            return MediaLibraryAlbumOperations::DeletePhotoAlbum(rdbPredicate);
        }
        case OperationObject::HIGHLIGHT_DELETE: {
            return MediaLibraryAlbumOperations::DeleteHighlightAlbums(rdbPredicate);
        }
        case OperationObject::PHOTO_MAP: {
            return PhotoMapOperations::RemovePhotoAssets(rdbPredicate);
        }
        case OperationObject::ANALYSIS_PHOTO_MAP: {
            if (CheckIsDismissAsset(rdbPredicate)) {
                return PhotoMapOperations::DismissAssets(rdbPredicate);
            }
            break;
        }
        case OperationObject::MEDIA_APP_URI_PERMISSION:
        case OperationObject::APP_URI_PERMISSION_INNER: {
            return MediaLibraryAppUriPermissionOperations::DeleteOperation(rdbPredicate);
        }
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::FILESYSTEM_AUDIO: {
            return MediaLibraryAssetOperations::DeleteOperation(cmd);
        }
        case OperationObject::PAH_FORM_MAP: {
            return MediaLibraryFormMapOperations::RemoveFormIdOperations(rdbPredicate);
        }
        case OperationObject::TAB_FACARD_PHOTO: {
            return MediaLibraryFaCardOperations::HandleRemoveGalleryFormOperation(rdbPredicate);
        }
        default:
            return DeleteInRdbPredicatesMore(cmd, rdbPredicate);
    }
    return DeleteInRdbPredicatesAnalysis(cmd, rdbPredicate);
}

int32_t MediaLibraryDataManager::DeleteInRdbPredicatesMore(MediaLibraryCommand &cmd,
    NativeRdb::RdbPredicates &rdbPredicate)
{
    switch (cmd.GetOprnObject()) {
        case OperationObject::PTP_OPERATION: {
            return MediaLibraryPtpOperations::DeletePtpPhoto(rdbPredicate);
        }
        case OperationObject::PTP_ALBUM_OPERATION: {
            return MediaLibraryPtpOperations::DeletePtpAlbum(rdbPredicate);
        }
        default:
            break;
    }
    return DeleteInRdbPredicatesAnalysis(cmd, rdbPredicate);
}

int32_t MediaLibraryDataManager::DeleteInRdbPredicatesAnalysis(MediaLibraryCommand &cmd,
    NativeRdb::RdbPredicates &rdbPredicate)
{
    if (MediaLibraryRestore::GetInstance().IsRealBackuping()) {
        MEDIA_INFO_LOG("[DeleteInRdbPredicatesAnalysis] rdb is backuping");
        return E_FAIL;
    }
    switch (cmd.GetOprnObject()) {
        case OperationObject::VISION_START ... OperationObject::VISION_END: {
            return MediaLibraryVisionOperations::DeleteOperation(cmd);
        }
        case OperationObject::GEO_DICTIONARY:
        case OperationObject::GEO_KNOWLEDGE:
        case OperationObject::GEO_PHOTO: {
            return MediaLibraryLocationOperations::DeleteOperation(cmd);
        }

        case OperationObject::STORY_ALBUM:
        case OperationObject::STORY_COVER:
        case OperationObject::STORY_PLAY:
        case OperationObject::USER_PHOTOGRAPHY: {
            return MediaLibraryStoryOperations::DeleteOperation(cmd);
        }
        case OperationObject::SEARCH_TOTAL: {
            return MediaLibrarySearchOperations::DeleteOperation(cmd);
        }
        case OperationObject::ASSET_ALBUM_OPERATION: {
            return MediaLibraryTableAssetAlbumOperations::Delete(rdbPredicate);
        }
        default:
            break;
    }

    return E_FAIL;
}

int32_t MediaLibraryDataManager::Update(MediaLibraryCommand &cmd, const DataShareValuesBucket &dataShareValue,
    const DataSharePredicates &predicates)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::Update");
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Update:Input parameter is invalid ");
        return E_INVALID_VALUES;
    }

#ifdef MEDIALIBRARY_COMPATIBILITY
    ChangeUriFromValuesBucket(value);
#endif

    cmd.SetValueBucket(value);
    cmd.SetDataSharePred(predicates);
    // MEDIALIBRARY_TABLE just for RdbPredicates
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates,
        cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());

    return UpdateInternal(cmd, value, predicates);
}

static std::vector<std::string> SplitUriString(const std::string& str, char delimiter)
{
    std::vector<std::string> elements;
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) {
            elements.emplace_back(item);
        }
    }
    return elements;
}

static std::string ExtractFileIdFromUri(const std::string& uri)
{
    auto uriParts = SplitUriString(uri, '/');
    CHECK_AND_RETURN_RET(uriParts.size() < MediaLibraryDataManager::URI_MIN_NUM,
        uriParts[uriParts.size() - MediaLibraryDataManager::URI_MIN_NUM]);
    return "";
}

static std::string BuildWhereClause(const std::vector<std::string>& dismissAssetArray, int32_t albumId)
{
    std::string whereClause = MediaColumn::MEDIA_ID + " IN (";

    for (size_t i = 0; i < dismissAssetArray.size(); ++i) {
        std::string fileId = ExtractFileIdFromUri(dismissAssetArray[i]);
        CHECK_AND_CONTINUE(!fileId.empty());
        if (i > 0) {
            whereClause += ",";
        }
        whereClause += "'" + fileId + "'";
    }

    whereClause += ") AND EXISTS (SELECT 1 FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE " + ANALYSIS_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID +
        " = " + std::to_string(albumId) + " AND " +
        ANALYSIS_ALBUM_TABLE + ".tag_id = " + VISION_IMAGE_FACE_TABLE + ".tag_id)";

    return whereClause;
}

int MediaLibraryDataManager::HandleAnalysisFaceUpdate(MediaLibraryCommand& cmd, NativeRdb::ValuesBucket &value,
    const DataShare::DataSharePredicates &predicates)
{
    string keyOperation = cmd.GetQuerySetParam(MEDIA_OPERN_KEYWORD);
    if (keyOperation.empty() || keyOperation != UPDATE_DISMISS_ASSET) {
        cmd.SetValueBucket(value);
        return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd);
    }

    const string &clause = predicates.GetWhereClause();
    std::vector<std::string> clauses = SplitUriString(clause, ',');
    CHECK_AND_RETURN_RET_LOG(!clause.empty(), E_INVALID_FILEID, "Clause is empty, cannot extract album ID.");
    std::string albumStr = clauses[0];
    int32_t albumId {0};
    std::stringstream ss(albumStr);
    CHECK_AND_RETURN_RET_LOG((ss >> albumId), E_INVALID_FILEID, "Unable to convert albumId string to integer.");

    std::vector<std::string> uris;
    for (size_t i = 1; i < clauses.size(); ++i) {
        uris.push_back(clauses[i]);
    }
    CHECK_AND_RETURN_RET_LOG(!uris.empty(), E_INVALID_FILEID, "No URIs found after album ID.");

    std::string predicate = BuildWhereClause(uris, albumId);
    cmd.SetValueBucket(value);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicate);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd);
}

static int32_t HandleFilesystemOperations(MediaLibraryCommand &cmd)
{
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET: {
            auto ret = MediaLibraryFileOperations::ModifyFileOperation(cmd);
            if (ret == E_SAME_PATH) {
                return E_OK;
            } else {
                return ret;
            }
        }
        case OperationObject::FILESYSTEM_DIR:
            // supply a ModifyDirOperation here to replace
            // modify in the HandleDirOperations in Insert function, if need
            return E_OK;

        case OperationObject::FILESYSTEM_ALBUM: {
            return MediaLibraryAlbumOperations::ModifyAlbumOperation(cmd);
        }
        default:
            return E_OK;
    }
}

int32_t MediaLibraryDataManager::UpdateInternal(MediaLibraryCommand &cmd, NativeRdb::ValuesBucket &value,
    const DataShare::DataSharePredicates &predicates)
{
    int32_t result = HandleFilesystemOperations(cmd);
    if (result != E_OK) {
        return result;
    }
    switch (cmd.GetOprnObject()) {
        case OperationObject::PAH_PHOTO:
        case OperationObject::PAH_VIDEO:
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::FILESYSTEM_AUDIO:
        case OperationObject::PTP_OPERATION: {
            return MediaLibraryAssetOperations::UpdateOperation(cmd);
        }
        case OperationObject::ANALYSIS_PHOTO_ALBUM: {
            if ((cmd.GetOprnType() >= OperationType::PORTRAIT_DISPLAY_LEVEL &&
                 cmd.GetOprnType() <= OperationType::GROUP_COVER_URI)) {
                return MediaLibraryAlbumOperations::HandleAnalysisPhotoAlbum(cmd.GetOprnType(), value, predicates);
            }
            break;
        }
        case OperationObject::PHOTO_ALBUM:
        case OperationObject::PTP_ALBUM_OPERATION:
            return MediaLibraryAlbumOperations::HandlePhotoAlbum(cmd.GetOprnType(), value, predicates);
        case OperationObject::GEO_DICTIONARY:
        case OperationObject::GEO_KNOWLEDGE:
            return MediaLibraryLocationOperations::UpdateOperation(cmd);
        case OperationObject::STORY_ALBUM:
        case OperationObject::STORY_COVER:
        case OperationObject::STORY_PLAY:
        case OperationObject::USER_PHOTOGRAPHY:
            return MediaLibraryStoryOperations::UpdateOperation(cmd);
        case OperationObject::PAH_MULTISTAGES_CAPTURE: {
            std::vector<std::string> columns;
            MultiStagesPhotoCaptureManager::GetInstance().HandleMultiStagesOperation(cmd, columns);
            return E_OK;
        }
        case OperationObject::PAH_BATCH_THUMBNAIL_OPERATE:
            return ProcessThumbnailBatchCmd(cmd, value, predicates);
#ifdef MEDIALIBRARY_FEATURE_CLOUD_ENHANCEMENT
        case OperationObject::PAH_CLOUD_ENHANCEMENT_OPERATE:
            return EnhancementManager::GetInstance().HandleEnhancementUpdateOperation(cmd);
#endif
        case OperationObject::VISION_IMAGE_FACE:
            return HandleAnalysisFaceUpdate(cmd, value, predicates);
        case OperationObject::ANALYSIS_PHOTO_MAP:
            if (cmd.GetOprnType() == OperationType::UPDATE_ORDER) {
                return MediaLibraryAnalysisAlbumOperations::SetAnalysisAlbumOrderPosition(cmd);
            }
            break;
        default:
            break;
    }
    // ModifyInfoByIdInDb can finish the default update of smartalbum and smartmap,
    // so no need to distinct them in switch-case deliberately
    cmd.SetValueBucket(value);
    return MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd);
}

void MediaLibraryDataManager::InterruptBgworker()
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return;
    }
    shared_ptr<MediaLibraryAsyncWorker> mediaAsyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (mediaAsyncWorker != nullptr) {
        mediaAsyncWorker->Interrupt();
    }
}

void MediaLibraryDataManager::InterruptThumbnailBgWorker()
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return;
    }
    CHECK_AND_RETURN_LOG(thumbnailService_ != nullptr, "thumbnailService_ is nullptr");
    thumbnailService_->InterruptBgworker();
}

int32_t MediaLibraryDataManager::GenerateThumbnailBackground()
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    return thumbnailService_->GenerateThumbnailBackground();
}

int32_t MediaLibraryDataManager::GenerateHighlightThumbnailBackground()
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    return thumbnailService_->GenerateHighlightThumbnailBackground();
}

int32_t MediaLibraryDataManager::UpgradeThumbnailBackground(bool isWifiConnected)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    return thumbnailService_->UpgradeThumbnailBackground(isWifiConnected);
}

int32_t MediaLibraryDataManager::RestoreThumbnailDualFrame()
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    return thumbnailService_->RestoreThumbnailDualFrame();
}


int MediaLibraryDataManager::GetThumbnail(const string &uri)
{
    CHECK_AND_RETURN_RET(thumbnailService_ != nullptr, E_THUMBNAIL_SERVICE_NULLPTR);

    if (!uri.empty() && MediaLibraryObjectUtils::CheckUriPending(uri)) {
        MEDIA_ERR_LOG("failed to get thumbnail, the file:%{private}s is pending", uri.c_str());
        return E_FAIL;
    }
    return thumbnailService_->GetThumbnailFd(uri);
}

void MediaLibraryDataManager::CreateThumbnailAsync(const string &uri, const string &path,
    std::shared_ptr<Media::Picture> originalPhotoPicture)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return;
    }

    if (thumbnailService_ == nullptr) {
        return;
    }
    if (!uri.empty()) {
        if (MediaLibraryObjectUtils::CheckUriPending(uri)) {
            MEDIA_ERR_LOG("failed to get thumbnail, the file:%{private}s is pending", uri.c_str());
            return;
        }
        int32_t err = 0;
        if (originalPhotoPicture == nullptr) {
            err = thumbnailService_->CreateThumbnailFileScaned(uri, path);
        } else {
            err = thumbnailService_->CreateThumbnailFileScanedWithPicture(uri, path, originalPhotoPicture, false);
        }
        CHECK_AND_PRINT_LOG(err == E_SUCCESS, "ThumbnailService CreateThumbnailFileScaned failed : %{public}d", err);
    }
}

static shared_ptr<NativeRdb::ResultSet> HandleAnalysisAlbumQuery(MediaLibraryCommand &cmd,
    const vector<string> &columns, const DataSharePredicates &predicates)
{
    if (cmd.GetOprnType() == OperationType::QUERY_ORDER) {
        return MediaLibraryRdbStore::QueryWithFilter(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
    }
    return PhotoMapOperations::QueryPhotoAssets(RdbUtils::ToPredicates(predicates, PhotoColumn::PHOTOS_TABLE), columns);
}

shared_ptr<ResultSetBridge> MediaLibraryDataManager::Query(MediaLibraryCommand &cmd,
    const vector<string> &columns, const DataSharePredicates &predicates, int &errCode)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        errCode = E_FAIL;
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, errCode},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }

    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataManager::Query");
    if (rdbStore_ == nullptr) {
        errCode = E_FAIL;
        MEDIA_ERR_LOG("Rdb Store is not initialized");
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, errCode},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }

    auto absResultSet = QueryRdb(cmd, columns, predicates, errCode);
    if (absResultSet == nullptr) {
        errCode = (errCode != E_OK) ? errCode : E_FAIL;
        MEDIA_ERR_LOG("Query rdb failed, errCode: %{public}d", errCode);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, errCode},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }
    return RdbUtils::ToResultSetBridge(absResultSet);
}

static const map<OperationObject, string> QUERY_CONDITION_MAP {
    { OperationObject::SMART_ALBUM, SMARTALBUM_DB_ID },
    { OperationObject::SMART_ALBUM_MAP, SMARTALBUMMAP_DB_ALBUM_ID },
    { OperationObject::FILESYSTEM_DIR, MEDIA_DATA_DB_ID },
    { OperationObject::ALL_DEVICE, "" },
    { OperationObject::ACTIVE_DEVICE, "" },
    { OperationObject::ASSETMAP, "" },
    { OperationObject::SMART_ALBUM_ASSETS, "" },
    { OperationObject::BUNDLE_PERMISSION, "" },
};

bool CheckIsPortraitAlbum(MediaLibraryCommand &cmd)
{
    auto predicates = cmd.GetAbsRdbPredicates();
    auto whereClause = predicates->GetWhereClause();
    if (whereClause.find(USER_DISPLAY_LEVEL) != string::npos || whereClause.find(IS_ME) != string::npos ||
        whereClause.find(ALBUM_NAME_NOT_NULL) != string::npos) {
        return true;
    }
    return false;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryDataManager::QuerySet(MediaLibraryCommand &cmd,
    const vector<string> &columns, const DataSharePredicates &predicates, int &errCode)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryRdb");
    tracer.Start("CheckWhereClause");
    MEDIA_DEBUG_LOG("CheckWhereClause start %{public}s", cmd.GetUri().ToString().c_str());
    auto whereClause = predicates.GetWhereClause();
    if (!MediaLibraryCommonUtils::CheckWhereClause(whereClause)) {
        errCode = E_INVALID_VALUES;
        MEDIA_ERR_LOG("illegal query whereClause input %{private}s", whereClause.c_str());
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, errCode},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }
    MEDIA_DEBUG_LOG("CheckWhereClause end");
    tracer.Finish();

    cmd.SetDataSharePred(predicates);
    // MEDIALIBRARY_TABLE just for RdbPredicates
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates, MEDIALIBRARY_TABLE);
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(rdbPredicate.GetOrder());
    MediaLibraryRdbUtils::AddVirtualColumnsOfDateType(const_cast<vector<string> &>(columns));

    OperationObject oprnObject = cmd.GetOprnObject();
    auto it = QUERY_CONDITION_MAP.find(oprnObject);
    if (it != QUERY_CONDITION_MAP.end()) {
        return MediaLibraryObjectUtils::QueryWithCondition(cmd, columns, it->second);
    }

    return QueryInternal(cmd, columns, predicates);
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryDataManager::QueryAnalysisAlbum(MediaLibraryCommand &cmd,
    const vector<string> &columns, const DataSharePredicates &predicates)
{
    if (cmd.GetOprnType() == OperationType::QUERY_HIGHLIGHT_DIRECTORY_SIZE) {
        auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, nullptr, "uniStore is nullptr!");
        return PhotoStorageOperation().QueryHighlightDirectorySize(uniStore);
    }
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, cmd.GetTableName());
    int32_t albumSubtype = MediaLibraryRdbUtils::GetAlbumSubtypeArgument(rdbPredicates);
    MEDIA_DEBUG_LOG("Query analysis album of subtype: %{public}d", albumSubtype);
    if (albumSubtype == PhotoAlbumSubType::GROUP_PHOTO) {
        return MediaLibraryAnalysisAlbumOperations::QueryGroupPhotoAlbum(cmd, columns);
    }
    if (CheckIsPortraitAlbum(cmd)) {
        return MediaLibraryAlbumOperations::QueryPortraitAlbum(cmd, columns);
    }
    return MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
}

inline bool CheckLatitudeAndLongitude(const string &latitude, const string &longitude)
{
    return latitude != "" && longitude != "" && !(latitude == "0" && longitude == "0");
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryDataManager::QueryGeo(const RdbPredicates &rdbPredicates,
    const vector<string> &columns)
{
    auto queryResult = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResult != nullptr, queryResult,
        "Query Geographic Information Failed, queryResult is nullptr");

    const vector<string> &whereArgs = rdbPredicates.GetWhereArgs();
    bool cond = (whereArgs.empty() || whereArgs.front().empty());
    CHECK_AND_RETURN_RET_LOG(!cond, queryResult, "Query Geographic Information can not get fileId");

    string fileId = whereArgs.front();
    CHECK_AND_RETURN_RET_LOG(queryResult->GoToNextRow() == NativeRdb::E_OK, queryResult,
        "Query Geographic Information Failed, fileId: %{public}s", fileId.c_str());

    string latitude = GetStringVal(PhotoColumn::PHOTOS_TABLE + "." + LATITUDE, queryResult);
    string longitude = GetStringVal(PhotoColumn::PHOTOS_TABLE + "." + LONGITUDE, queryResult);
    string addressDescription = GetStringVal(ADDRESS_DESCRIPTION, queryResult);
    MEDIA_INFO_LOG(
        "QueryGeo, fileId: %{public}s, latitude: %{public}s, longitude: %{public}s, addressDescription: %{private}s",
        fileId.c_str(), latitude.c_str(), longitude.c_str(), addressDescription.c_str());

    if (CheckLatitudeAndLongitude(latitude, longitude) && addressDescription.empty()) {
        std::packaged_task<bool()> pt(
            [=] { return MediaAnalysisHelper::ParseGeoInfo({ fileId + "," + latitude + "," + longitude }, false); });
        std::future<bool> futureResult = pt.get_future();
        ffrt::thread(std::move(pt)).detach();

        bool parseResult = false;
        const int timeout = 2;
        std::future_status futureStatus = futureResult.wait_for(std::chrono::seconds(timeout));
        if (futureStatus == std::future_status::ready) {
            parseResult = futureResult.get();
        } else {
            MEDIA_ERR_LOG("ParseGeoInfo Failed, fileId: %{public}s, futureStatus: %{public}d", fileId.c_str(),
                static_cast<int>(futureStatus));
        }

        if (parseResult) {
            queryResult = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
        }
        MEDIA_INFO_LOG("ParseGeoInfo completed, fileId: %{public}s, parseResult: %{public}d", fileId.c_str(),
            parseResult);
    }
    return queryResult;
}

shared_ptr<NativeRdb::ResultSet> QueryGeoAssets(const RdbPredicates &rdbPredicates, const vector<string> &columns,
    bool isForce)
{
    MEDIA_INFO_LOG("Query Geo Assets");
    auto queryResult = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
    if (queryResult == nullptr) {
        MEDIA_ERR_LOG("Query Geographic Information Failed, queryResult is nullptr");
        return queryResult;
    }
    const vector<string> &whereArgs = rdbPredicates.GetWhereArgs();
    bool cond = (whereArgs.empty() || whereArgs.front().empty());
    CHECK_AND_RETURN_RET_LOG(!cond, queryResult, "Query Geographic Information can not get info");
 
    if (isForce) {
        std::vector<std::string> geoInfo;
        while (queryResult->GoToNextRow() == NativeRdb::E_OK) {
            string fileId = to_string(GetInt32Val(MediaColumn::MEDIA_ID, queryResult));
            string latitude = GetStringVal(PhotoColumn::PHOTOS_TABLE + "." + LATITUDE, queryResult);
            string longitude = GetStringVal(PhotoColumn::PHOTOS_TABLE + "." + LONGITUDE, queryResult);
            string addressDescription = GetStringVal(ADDRESS_DESCRIPTION, queryResult);
            MEDIA_INFO_LOG(
                "QueryGeo, fileId: %{public}s, latitude: %{public}s, longitude: %{public}s, "
                "addressDescription: %{private}s",
                fileId.c_str(), latitude.c_str(), longitude.c_str(), addressDescription.c_str());
            if (CheckLatitudeAndLongitude(latitude, longitude) && addressDescription.empty()) {
                geoInfo.push_back(fileId + "," + latitude + "," + longitude);
            }
        }

        CHECK_AND_RETURN_RET_INFO_LOG(!geoInfo.empty(), queryResult, "No need to query geo info assets");
        std::packaged_task<bool()> pt(
            [geoInfo = std::move(geoInfo)] { return MediaAnalysisHelper::ParseGeoInfo(std::move(geoInfo), true); });
        std::future<bool> futureResult = pt.get_future();
        ffrt::thread(std::move(pt)).detach();

        bool parseResult = false;
        const int timeout = 5;
        std::future_status futureStatus = futureResult.wait_for(std::chrono::seconds(timeout));
        if (futureStatus == std::future_status::ready) {
            parseResult = futureResult.get();
        } else {
            MEDIA_ERR_LOG("ParseGeoInfoAssets Failed, futureStatus: %{public}d", static_cast<int>(futureStatus));
        }

        if (parseResult) {
            queryResult = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
        }
        MEDIA_INFO_LOG("ParseGeoInfoAssets completed, parseResult: %{public}d", parseResult);
    }
    return queryResult;
}

shared_ptr<NativeRdb::ResultSet> QueryIndex(MediaLibraryCommand &cmd, const vector<string> &columns,
    const DataSharePredicates &predicates)
{
    switch (cmd.GetOprnType()) {
        case OperationType::UPDATE_SEARCH_INDEX:
            return MediaLibraryRdbStore::Query(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
        default:
            /* add filter */
            return MediaLibraryRdbStore::QueryWithFilter(RdbUtils::ToPredicates(predicates, cmd.GetTableName()),
                columns);
    }
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryDataManager::QueryInternal(MediaLibraryCommand &cmd,
    const vector<string> &columns, const DataSharePredicates &predicates)
{
    MediaLibraryTracer tracer;
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ALBUM:
        case OperationObject::MEDIA_VOLUME:
            return MediaLibraryAlbumOperations::QueryAlbumOperation(cmd, columns);
        case OperationObject::INDEX_CONSTRUCTION_STATUS:
            return MediaLibrarySearchOperations::QueryIndexConstructProgress();
        case OperationObject::PHOTO_ALBUM:
            return MediaLibraryAlbumOperations::QueryPhotoAlbum(cmd, columns);
        case OperationObject::ANALYSIS_PHOTO_ALBUM:
            return QueryAnalysisAlbum(cmd, columns, predicates);
        case OperationObject::PHOTO_MAP:
        case OperationObject::ANALYSIS_PHOTO_MAP:
            return HandleAnalysisAlbumQuery(cmd, columns, predicates);
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::FILESYSTEM_AUDIO:
        case OperationObject::PAH_MOVING_PHOTO:
        case OperationObject::EDIT_DATA_EXISTS:
        case OperationObject::MOVING_PHOTO_VIDEO_READY:
            return MediaLibraryAssetOperations::QueryOperation(cmd, columns);
        case OperationObject::VISION_START ... OperationObject::VISION_END:
            return MediaLibraryRdbStore::QueryWithFilter(RdbUtils::ToPredicates(predicates, cmd.GetTableName()),
                columns);
        case OperationObject::GEO_DICTIONARY:
        case OperationObject::GEO_KNOWLEDGE:
        case OperationObject::GEO_PHOTO:
        case OperationObject::CONVERT_PHOTO:
        case OperationObject::STORY_ALBUM:
        case OperationObject::STORY_COVER:
        case OperationObject::STORY_PLAY:
        case OperationObject::USER_PHOTOGRAPHY:
        case OperationObject::APP_URI_PERMISSION_INNER:
            return MediaLibraryRdbStore::QueryWithFilter(RdbUtils::ToPredicates(predicates, cmd.GetTableName()),
                columns);
        case OperationObject::SEARCH_TOTAL:
            return QueryIndex(cmd, columns, predicates);
        case OperationObject::PAH_MULTISTAGES_CAPTURE:
            return MultiStagesPhotoCaptureManager::GetInstance().HandleMultiStagesOperation(cmd, columns);
#ifdef MEDIALIBRARY_FEATURE_CLOUD_ENHANCEMENT
        case OperationObject::PAH_CLOUD_ENHANCEMENT_OPERATE:
            return EnhancementManager::GetInstance().HandleEnhancementQueryOperation(cmd, columns);
#endif
        case OperationObject::ANALYSIS_ADDRESS:
            return QueryGeo(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
        case OperationObject::ANALYSIS_ADDRESS_ASSETS:
            return QueryGeoAssets(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns, false);
        case OperationObject::ANALYSIS_ADDRESS_ASSETS_ACTIVE:
            return QueryGeoAssets(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns, true);
        case OperationObject::TAB_OLD_PHOTO:
            return MediaLibraryTabOldPhotosOperations().Query(
                RdbUtils::ToPredicates(predicates, TabOldPhotosColumn::OLD_PHOTOS_TABLE), columns);
        case OperationObject::ASSET_ALBUM_OPERATION:
            return MediaLibraryTableAssetAlbumOperations().Query(
                RdbUtils::ToPredicates(predicates, PhotoColumn::TAB_ASSET_AND_ALBUM_OPERATION_TABLE), columns);
        case OperationObject::ANALYSIS_FOREGROUND:
            return MediaLibraryVisionOperations::HandleForegroundAnalysisOperation(cmd);
        case OperationObject::CUSTOM_RECORDS_OPERATION:
            return MediaLibraryRdbStore::QueryWithFilter(RdbUtils::ToPredicates(predicates, cmd.GetTableName()),
                columns);
        case OperationObject::ANALYSIS_ASSET_SD_MAP:
        case OperationObject::ANALYSIS_ALBUM_ASSET_MAP:
            return MediaLibraryRdbStore::Query(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
        default:
            tracer.Start("QueryFile");
            return MediaLibraryFileOperations::QueryFileOperation(cmd, columns);
    }
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryDataManager::QueryRdb(MediaLibraryCommand &cmd,
    const vector<string> &columns, const DataSharePredicates &predicates, int &errCode)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        errCode = E_FAIL;
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, errCode},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return nullptr;
    }

    return QuerySet(cmd, columns, predicates, errCode);
}

static void AddToMediaVisitCount(OperationObject &oprnObject, MediaLibraryCommand &cmd)
{
    bool isValidCount = false;
    auto visitType = MediaVisitCountManager::VisitCountType::PHOTO_FS;
    if (oprnObject == OperationObject::FILESYSTEM_PHOTO) {
        isValidCount = true;
    } else if (oprnObject == OperationObject::THUMBNAIL) {
        visitType = MediaVisitCountManager::VisitCountType::PHOTO_LCD;
        auto height = std::atoi(cmd.GetQuerySetParam(MEDIA_DATA_DB_HEIGHT).c_str());
        auto width = std::atoi(cmd.GetQuerySetParam(MEDIA_DATA_DB_WIDTH).c_str());
        int min = std::min(width, height);
        int max = std::max(width, height);
        if (min == DEFAULT_ORIGINAL && max == DEFAULT_ORIGINAL) {
            isValidCount = true;
        } else if (min <= DEFAULT_THUMBNAIL_SIZE && max <= MAX_DEFAULT_THUMBNAIL_SIZE) {
            isValidCount = false;
        } else {
            isValidCount = true;
        }
    } else {
        MEDIA_DEBUG_LOG("AddToMediaVisitCount oprnObject: %{public}d", static_cast<int>(oprnObject));
    }

    if (isValidCount) {
        auto fileId = cmd.GetOprnFileId();
        MediaVisitCountManager::AddVisitCount(visitType, std::move(fileId));
    }
}

int32_t MediaLibraryDataManager::OpenFile(MediaLibraryCommand &cmd, const string &mode)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataManager::OpenFile");
    auto oprnObject = cmd.GetOprnObject();
    AddToMediaVisitCount(oprnObject, cmd);
    if (oprnObject == OperationObject::FILESYSTEM_PHOTO || oprnObject == OperationObject::FILESYSTEM_AUDIO ||
        oprnObject == OperationObject::HIGHLIGHT_COVER  || oprnObject == OperationObject::HIGHLIGHT_URI ||
        oprnObject == OperationObject::PTP_OPERATION) {
        return MediaLibraryAssetOperations::OpenOperation(cmd, mode);
    }

#ifdef MEDIALIBRARY_COMPATIBILITY
    if (oprnObject != OperationObject::THUMBNAIL && oprnObject != OperationObject::THUMBNAIL_ASTC &&
        oprnObject != OperationObject::REQUEST_PICTURE && oprnObject != OperationObject::PHOTO_REQUEST_PICTURE_BUFFER &&
        oprnObject != OperationObject::KEY_FRAME) {
        string opObject = MediaFileUri::GetPathFirstDentry(const_cast<Uri &>(cmd.GetUri()));
        if (opObject == IMAGE_ASSET_TYPE || opObject == VIDEO_ASSET_TYPE || opObject == URI_TYPE_PHOTO) {
            cmd.SetOprnObject(OperationObject::FILESYSTEM_PHOTO);
            return MediaLibraryAssetOperations::OpenOperation(cmd, mode);
        }
        if (opObject == AUDIO_ASSET_TYPE || opObject == URI_TYPE_AUDIO_V10) {
            cmd.SetOprnObject(OperationObject::FILESYSTEM_AUDIO);
            return MediaLibraryAssetOperations::OpenOperation(cmd, mode);
        }
    }
#endif

    return MediaLibraryObjectUtils::OpenFile(cmd, mode);
}

void MediaLibraryDataManager::NotifyChange(const Uri &uri)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return;
    }

    if (extension_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataManager::NotifyChange failed");
        return;
    }

    extension_->NotifyChange(uri);
}

int32_t MediaLibraryDataManager::InitialiseThumbnailService(
    const shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext)
{
    if (thumbnailService_ != nullptr) {
        return E_OK;
    }
    thumbnailService_ = ThumbnailService::GetInstance();
    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    thumbnailService_->Init(rdbStore_,  extensionContext);
    return E_OK;
}

void MediaLibraryDataManager::InitACLPermission()
{
    if (access(THUMB_DIR.c_str(), F_OK) == 0) {
        return;
    }

    if (!MediaFileUtils::CreateDirectory(THUMB_DIR)) {
        MEDIA_ERR_LOG("Failed create thumbs Photo dir");
        return;
    }
}

void MediaLibraryDataManager::InitDatabaseACLPermission()
{
    if (access(RDB_DIR.c_str(), F_OK) != E_OK) {
        if (!MediaFileUtils::CreateDirectory(RDB_DIR)) {
            MEDIA_ERR_LOG("Failed create media rdb dir");
            return;
        }
    }

    if (access(KVDB_DIR.c_str(), F_OK) != E_OK) {
        if (!MediaFileUtils::CreateDirectory(KVDB_DIR)) {
            MEDIA_ERR_LOG("Failed create media kvdb dir");
            return;
        }
    }

    if (Acl::AclSetDatabase() != E_OK) {
        MEDIA_ERR_LOG("Failed to set the acl db permission for the media db dir");
    }
}

int32_t ScanFileCallback::OnScanFinished(const int32_t status, const string &uri, const string &path)
{
    auto instance = MediaLibraryDataManager::GetInstance();
    if (instance != nullptr) {
        instance->CreateThumbnailAsync(uri, path, originalPhotoPicture);
    }
    return E_OK;
}

int32_t MediaLibraryDataManager::SetCmdBundleAndDevice(MediaLibraryCommand &outCmd)
{
    string clientBundle = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    if (clientBundle.empty()) {
        MEDIA_ERR_LOG("GetClientBundleName failed");
        return E_GET_CLIENTBUNDLE_FAIL;
    }
    outCmd.SetBundleName(clientBundle);
    return 0;
}

int32_t MediaLibraryDataManager::RevertPendingByFileId(const std::string &fileId)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE);
    ValuesBucket values;
    values.PutLong(Media::MEDIA_DATA_DB_TIME_PENDING, 0);
    cmd.SetValueBucket(values);

    int32_t retVal = MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, fileId);
    CHECK_AND_RETURN_RET_LOG(retVal > 0, retVal, "failed to revert pending error, fileId:%{private}s", fileId.c_str());
    auto fileAsset = MediaLibraryObjectUtils::GetFileAssetFromId(fileId);
    string srcPath = fileAsset->GetPath();
    MediaLibraryObjectUtils::ScanFileAsync(srcPath, fileId, MediaLibraryApi::API_10);
    return E_SUCCESS;
}

int32_t MediaLibraryDataManager::RevertPendingByPackage(const std::string &bundleName)
{
    MediaLibraryCommand queryCmd(OperationObject::FILESYSTEM_ASSET, OperationType::QUERY);
    queryCmd.GetAbsRdbPredicates()
        ->EqualTo(MEDIA_DATA_DB_OWNER_PACKAGE, bundleName)
        ->And()
        ->NotEqualTo(MEDIA_DATA_DB_TIME_PENDING, to_string(0));
    vector<string> columns = { MEDIA_DATA_DB_ID };
    auto result = MediaLibraryObjectUtils::QueryWithCondition(queryCmd, columns);
    if (result == nullptr) {
        return E_HAS_DB_ERROR;
    }

    int32_t ret = E_SUCCESS;
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int32_t id = GetInt32Val(MEDIA_DATA_DB_ID, result);
        int32_t retVal = RevertPendingByFileId(to_string(id));
        if (retVal != E_SUCCESS) {
            ret = retVal;
            MEDIA_ERR_LOG("Revert file %{public}d failed, ret=%{public}d", id, retVal);
            continue;
        }
    }
    return ret;
}

void MediaLibraryDataManager::SetStartupParameter()
{
    MEDIA_INFO_LOG("Start to set parameter.");
    static constexpr uint32_t BASE_USER_RANGE = 200000; // for get uid
    uid_t uid = getuid() / BASE_USER_RANGE;
    const string key = "multimedia.medialibrary.startup." + to_string(uid);
    string value = "true";
    int32_t ret = SetParameter(key.c_str(), value.c_str());
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to set startup, result: %{public}d", ret);
    } else {
        MEDIA_INFO_LOG("Set startup success: %{public}s", to_string(uid).c_str());
    }
    // init backup param
    std::string backupParam = "persist.multimedia.medialibrary.rdb_switch_status";
    ret = system::SetParameter(backupParam, "0");
    if (ret != 0) {
        MEDIA_ERR_LOG("Failed to set parameter backup, ret:%{public}d", ret);
    }
    std::string nextFlag = "persist.update.hmos_to_next_flag";
    auto isUpgrade = system::GetParameter(nextFlag, "");
    MEDIA_INFO_LOG("isUpgrade:%{public}s", isUpgrade.c_str());
    if (isUpgrade != "1") {
        return;
    }
    std::string CLONE_FLAG = "multimedia.medialibrary.cloneFlag";
    auto currentTime = to_string(MediaFileUtils::UTCTimeSeconds());
    MEDIA_INFO_LOG("SetParameterForClone currentTime:%{public}s", currentTime.c_str());
    bool retFlag = system::SetParameter(CLONE_FLAG, currentTime);
    CHECK_AND_PRINT_LOG(retFlag, "Failed to set parameter cloneFlag, retFlag:%{public}d", retFlag);
}

int32_t MediaLibraryDataManager::ProcessThumbnailBatchCmd(const MediaLibraryCommand &cmd,
    const NativeRdb::ValuesBucket &value, const DataShare::DataSharePredicates &predicates)
{
    CHECK_AND_RETURN_RET(thumbnailService_ != nullptr, E_THUMBNAIL_SERVICE_NULLPTR);

    int32_t requestId = 0;
    ValueObject valueObject;
    if (value.GetObject(THUMBNAIL_BATCH_GENERATE_REQUEST_ID, valueObject)) {
        valueObject.GetInt(requestId);
    }

    if (cmd.GetOprnType() == OperationType::START_GENERATE_THUMBNAILS) {
        NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates, PhotoColumn::PHOTOS_TABLE);
        return thumbnailService_->CreateAstcBatchOnDemand(rdbPredicate, requestId);
    } else if (cmd.GetOprnType() == OperationType::STOP_GENERATE_THUMBNAILS) {
        thumbnailService_->CancelAstcBatchTask(requestId);
        return E_OK;
    } else if (cmd.GetOprnType() == OperationType::GENERATE_THUMBNAILS_RESTORE) {
        int32_t restoreAstcCount = 0;
        if (value.GetObject(RESTORE_REQUEST_ASTC_GENERATE_COUNT, valueObject)) {
            valueObject.GetInt(restoreAstcCount);
        }
        return thumbnailService_->RestoreThumbnailDualFrame(restoreAstcCount);
    } else if (cmd.GetOprnType() == OperationType::LOCAL_THUMBNAIL_GENERATION) {
        return thumbnailService_->LocalThumbnailGeneration();
    } else {
        MEDIA_ERR_LOG("invalid mediaLibrary command");
        return E_INVALID_ARGUMENTS;
    }
}

int32_t MediaLibraryDataManager::CheckCloudThumbnailDownloadFinish()
{
    CHECK_AND_RETURN_RET_LOG(thumbnailService_ != nullptr, E_THUMBNAIL_SERVICE_NULLPTR, "thumbanilService is nullptr");
    return thumbnailService_->CheckCloudThumbnailDownloadFinish();
}

void MediaLibraryDataManager::SubscriberPowerConsumptionDetection()
{
#ifdef DEVICE_STANDBY_ENABLE
    auto subscriber = new (std::nothrow) MediaLibraryStandbyServiceSubscriber();
    if (subscriber == nullptr) {
        return;
    }
    subscriber->SetSubscriberName(SUBSCRIBER_NAME);
    subscriber->SetModuleName(MODULE_NAME);
    DevStandbyMgr::StandbyServiceClient::GetInstance().SubscribeStandbyCallback(subscriber);
#endif
}

int32_t MediaLibraryDataManager::AstcMthAndYearInsert(MediaLibraryCommand &cmd,
    const std::vector<DataShare::DataShareValuesBucket> &values)
{
    int32_t insertCount = 0;
    int32_t successCount = 0;
    for (auto value : values) {
        for (auto iter = value.valuesMap.begin(); iter != value.valuesMap.end(); iter++) {
            insertCount++;
            string idString = iter->first;
            CHECK_AND_BREAK(ThumbnailService::GetInstance()->CreateAstcMthAndYear(idString));
            successCount++;
        }
    }
    CHECK_AND_RETURN_RET(successCount != 0, -1);
    CHECK_AND_RETURN_RET(successCount != insertCount, 1);
    return E_OK;
}

static int32_t SearchDateTakenWhenZero(const shared_ptr<MediaLibraryRdbStore> rdbStore, bool &needUpdate,
    unordered_map<string, string> &updateData)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_FAIL, "rdbStore is nullptr");
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.LessThanOrEqualTo(MediaColumn::MEDIA_DATE_TAKEN, "0");
    vector<string> columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_DATE_MODIFIED};
    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "failed to acquire result from visitor query.");
    int32_t count;
    int32_t retCount = resultSet->GetRowCount(count);
    bool cond = (retCount != E_SUCCESS || count < 0);
    CHECK_AND_RETURN_RET(!cond, E_HAS_DB_ERROR);

    CHECK_AND_RETURN_RET_LOG(count != 0, E_OK, "No dateTaken need to update");
    needUpdate = true;
    MEDIA_INFO_LOG("Have dateTaken need to update, count = %{public}d", count);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId =
            get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
        int64_t newDateTaken =
            get<int64_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_DATE_MODIFIED, resultSet, TYPE_INT64));
        updateData.emplace(to_string(fileId), to_string(newDateTaken));
    }
    return E_OK;
}

static void Update500EditDataSize(const shared_ptr<MediaLibraryRdbStore> rdbStore, std::string startFileId,
    bool &hasMore)
{
    std::vector<std::string> filePaths;
    std::vector<std::string> fileIds;
    int32_t ret = MediaLibraryPhotoOperations::Get500FileIdsAndPathS(rdbStore, fileIds, filePaths,
        startFileId, hasMore);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Failed to get filePaths and IDs, error code: %{public}d", ret);
        return;
    }

    if (filePaths.empty() || fileIds.empty()) {
        hasMore = false;
        MEDIA_INFO_LOG("No files need to update edit data size");
        return;
    }

    MEDIA_INFO_LOG("Start to update edit data size for %{public}zu files", fileIds.size());
    int32_t successCount = 0;
    int32_t failedCount = 0;

    for (size_t i = 0; i < fileIds.size(); ++i) {
        const auto &fileId = fileIds[i];
        const auto &filePath = filePaths[i];

        std::string editDataFilePath;
        ret = MediaLibraryPhotoOperations::ConvertPhotoCloudPathToLocalData(filePath, editDataFilePath);
        if (ret != E_OK) {
            MEDIA_WARN_LOG("Skip invalid file ID: %{public}s (error code: %{public}d)",
                fileId.c_str(), ret);
            failedCount++;
            continue;
        }

        ret = MediaLibraryRdbStore::UpdateEditDataSize(rdbStore, fileId, editDataFilePath);
        if (ret == E_OK) {
            successCount++;
        } else {
            MEDIA_ERR_LOG("Update failed for ID: %{public}s, Path: %{public}s (error code: %{public}d)",
                fileId.c_str(), editDataFilePath.c_str(), ret);
            failedCount++;
        }
    }

    MEDIA_INFO_LOG("Edit data size update completed: success=%{public}d, failed=%{public}d",
                   successCount, failedCount);
    if (failedCount > 0) {
        MEDIA_WARN_LOG("%{public}d files failed to update, check above logs for details", failedCount);
    }
}

int32_t MediaLibraryDataManager::UpdateMediaSizeFromStorage()
{
    if (!MedialibrarySubscriber::IsCurrentStatusOn()) {
        MEDIA_INFO_LOG("Current status is off, skip disk cleanup");
        return E_OK;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (!rdbStore) {
        MEDIA_ERR_LOG("RdbStore is null");
        return E_HAS_DB_ERROR;
    }

    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    if (prefs == nullptr) {
        MEDIA_ERR_LOG("Get preferences error: %{public}d", errCode);
        return errCode;
    }

    int32_t startFileId = prefs->GetInt(UPDATE_EDITDATA_SIZE_COUNT, 0);
    bool hasMore = true;
    while (hasMore) {
        if (!MedialibrarySubscriber::IsCurrentStatusOn()) {
            MEDIA_INFO_LOG("Current status is off, skip disk cleanup");
            return E_OK;
        }
        prefs->PutInt(UPDATE_EDITDATA_SIZE_COUNT, startFileId);
        prefs->FlushSync();
        Update500EditDataSize(rdbStore, std::to_string(startFileId), hasMore);
        // 一次500张图片
        startFileId += 500;
    }

    prefs->PutInt(NO_UPDATE_EDITDATA_SIZE, 1);
    prefs->FlushSync();
    return E_OK;
}

int32_t MediaLibraryDataManager::BatchInsertMediaAnalysisData(MediaLibraryCommand &cmd,
    const vector<DataShareValuesBucket> &values)
{
    if (values.empty()) {
        return E_FAIL;
    }

    if (MediaLibraryRestore::GetInstance().IsRealBackuping()) {
        MEDIA_INFO_LOG("[BatchInsertMediaAnalysisData] rdb is backuping");
        return E_FAIL;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET(rdbStore != nullptr, E_HAS_DB_ERROR);
    switch (cmd.GetOprnObject()) {
        case OperationObject::VISION_START ... OperationObject::VISION_END:
        case OperationObject::GEO_DICTIONARY:
        case OperationObject::GEO_KNOWLEDGE:
        case OperationObject::GEO_PHOTO:
        case OperationObject::SEARCH_TOTAL:
        case OperationObject::STORY_ALBUM:
        case OperationObject::STORY_COVER:
        case OperationObject::STORY_PLAY:
        case OperationObject::USER_PHOTOGRAPHY:
        case OperationObject::ANALYSIS_ASSET_SD_MAP:
        case OperationObject::ANALYSIS_ALBUM_ASSET_MAP:
        case OperationObject::ANALYSIS_PHOTO_MAP: {
            std::vector<ValuesBucket> insertValues;
            for (auto value : values) {
                ValuesBucket valueInsert = RdbUtils::ToValuesBucket(value);
                insertValues.push_back(valueInsert);
            }
            int64_t outRowId = -1;
            int32_t ret = rdbStore->BatchInsert(outRowId, cmd.GetTableName(), insertValues);
            bool cond = (ret != NativeRdb::E_OK || outRowId < 0);
            CHECK_AND_RETURN_RET_LOG(!cond, E_FAIL, "Batch insert media analysis values fail, err = %{public}d", ret);
            return outRowId;
        }
        default:
            break;
    }
    return E_FAIL;
}
}  // namespace Media
}  // namespace OHOS
