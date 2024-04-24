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

#include <shared_mutex>
#include <unordered_set>

#include "ability_scheduler_interface.h"
#include "abs_rdb_predicates.h"
#include "acl.h"
#include "background_task_mgr_helper.h"
#include "datashare_abs_result_set.h"
#ifdef DISTRIBUTED
#include "device_manager.h"
#include "device_manager_callback.h"
#endif
#include "efficiency_resource_info.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "media_column.h"
#include "media_datashare_ext_ability.h"
#include "media_directory_type_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "media_smart_album_column.h"
#include "media_smart_map_column.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_audio_operations.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_common_utils.h"
#ifdef DISTRIBUTED
#include "medialibrary_device.h"
#include "medialibrary_device_info.h"
#endif
#include "medialibrary_dir_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_inotify.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_location_operations.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "medialibrary_story_operations.h"
#include "medialibrary_sync_operation.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_uripermission_operations.h"
#include "medialibrary_vision_operations.h"
#include "medialibrary_search_operations.h"
#include "mimetype_utils.h"
#include "multistages_capture_manager.h"
#include "permission_utils.h"
#include "photo_map_operations.h"
#include "resource_type.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "system_ability_definition.h"
#include "timer.h"
#include "trash_async_worker.h"
#include "value_object.h"
#include "post_event_utils.h"
#include "medialibrary_formmap_operations.h"
#include "ithumbnail_helper.h"
#include "vision_face_tag_column.h"
#include "vision_photo_map_column.h"
#include "parameter.h"

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

#ifdef DISTRIBUTED
static constexpr int MAX_QUERY_THUMBNAIL_KEY_COUNT = 20;
#endif
MediaLibraryDataManager::MediaLibraryDataManager(void)
{
}

MediaLibraryDataManager::~MediaLibraryDataManager(void)
{
    MediaLibraryKvStoreManager::GetInstance().CloseAllKvStore();
#ifdef DISTRIBUTED
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(KVSTORE_APPID, kvStorePtr_);
        kvStorePtr_ = nullptr;
    }
#endif
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
    MEDIA_DEBUG_LOG("MediaLibraryCreator::%{public}s", __func__);
    return  MediaDataShareExtAbility::Create(runtime);
}

__attribute__((constructor)) void RegisterDataShareCreator()
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::%{public}s", __func__);
    DataShare::DataShareExtAbility::SetCreator(MediaDataShareCreator);
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::%{public}s End", __func__);
}

static void MakeRootDirs(AsyncTaskData *data)
{
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
        MediaFileUtils::CreateDirectory(ROOT_MEDIA_DIR + dir + ".recycle");
    }
}

int32_t MediaLibraryDataManager::InitMediaLibraryMgr(const shared_ptr<OHOS::AbilityRuntime::Context> &context,
    const shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext)
{
    lock_guard<shared_mutex> lock(mgrSharedMutex_);

    if (refCnt_.load() > 0) {
        MEDIA_DEBUG_LOG("already initialized");
        refCnt_++;
        return E_OK;
    }

    BackgroundTaskMgr::EfficiencyResourceInfo resourceInfo =
        BackgroundTaskMgr::EfficiencyResourceInfo(BackgroundTaskMgr::ResourceType::CPU, true, 0, "apply", true, true);
    BackgroundTaskMgr::BackgroundTaskMgrHelper::ApplyEfficiencyResources(resourceInfo);

    context_ = context;
    int32_t errCode = InitMediaLibraryRdbStore();
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at InitMediaLibraryRdbStore");

#ifdef DISTRIBUTED
    errCode = InitDeviceData();
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at InitDeviceData");
#endif

    MimeTypeUtils::InitMimeTypeMap();
    errCode = MakeDirQuerySetMap(dirQuerySetMap_);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at MakeDirQuerySetMap");

    InitACLPermission();
    InitDatabaseACLPermission();

    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Can not get asyncWorker");
        return E_ERR;
    }
    shared_ptr<MediaLibraryAsyncTask> makeRootDirTask = make_shared<MediaLibraryAsyncTask>(MakeRootDirs, nullptr);
    if (makeRootDirTask != nullptr) {
        asyncWorker->AddTask(makeRootDirTask, true);
    } else {
        MEDIA_WARN_LOG("Can not init make root dir task");
    }

    errCode = InitialiseThumbnailService(extensionContext);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at InitialiseThumbnailService");

    InitRefreshAlbum();

    cloudDataObserver_ = std::make_shared<CloudThumbnailObserver>();
    auto shareHelper = MediaLibraryHelperContainer::GetInstance()->GetDataShareHelper();
    shareHelper->RegisterObserverExt(Uri(PHOTO_URI_PREFIX), cloudDataObserver_, true);

    refCnt_++;
    return E_OK;
}

#ifdef DISTRIBUTED
int32_t MediaLibraryDataManager::InitDeviceData()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataManager InitDeviceData rdbStore is null");
        return E_ERR;
    }

    MediaLibraryTracer tracer;
    tracer.Start("InitDeviceRdbStoreTrace");
    if (!MediaLibraryDevice::GetInstance()->InitDeviceRdbStore(rdbStore_)) {
        MEDIA_ERR_LOG("MediaLibraryDataManager InitDeviceData failed!");
        return E_ERR;
    }
    return E_OK;
}
#endif

void MediaLibraryDataManager::ClearMediaLibraryMgr()
{
    lock_guard<shared_mutex> lock(mgrSharedMutex_);

    refCnt_--;
    if (refCnt_.load() > 0) {
        MEDIA_DEBUG_LOG("still other extension exist");
        return;
    }

    auto shareHelper = MediaLibraryHelperContainer::GetInstance()->GetDataShareHelper();
    shareHelper->UnregisterObserverExt(Uri(PHOTO_URI_PREFIX), cloudDataObserver_);
    rdbStore_ = nullptr;
    MediaLibraryKvStoreManager::GetInstance().CloseAllKvStore();

#ifdef DISTRIBUTED
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(KVSTORE_APPID, kvStorePtr_);
        kvStorePtr_ = nullptr;
    }

    if (MediaLibraryDevice::GetInstance()) {
        MediaLibraryDevice::GetInstance()->Stop();
    };
#endif

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
    if (ret != E_OK) {
        MEDIA_ERR_LOG("init MediaLibraryUnistoreManager failed");
        return ret;
    }
    rdbStore_ = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (ret != E_OK) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

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
    MEDIA_INFO_LOG("GetType uri: %{private}s", uri.ToString().c_str());
    return "";
}

int32_t MediaLibraryDataManager::MakeDirQuerySetMap(unordered_map<string, DirAsset> &outDirQuerySetMap)
{
    int32_t count = -1;
    vector<string> columns;
    AbsRdbPredicates dirAbsPred(MEDIATYPE_DIRECTORY_TABLE);
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return E_ERR;
    }
    auto queryResultSet = rdbStore_->QueryByStep(dirAbsPred, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("queryResultSet is nullptr");
        return E_ERR;
    }
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdb failed");
        return E_ERR;
    }
    MEDIA_INFO_LOG("MakeDirQuerySetMap count = %{public}d", count);
    if (count == 0) {
        MEDIA_ERR_LOG("can not find any dirAsset");
        return E_ERR;
    }
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
            return MediaLibraryAssetOperations::HandleInsertOperation(cmd);

        case OperationObject::FILESYSTEM_ALBUM:
            return MediaLibraryAlbumOperations::CreateAlbumOperation(cmd);

        case OperationObject::ANALYSIS_PHOTO_ALBUM:
        case OperationObject::PHOTO_ALBUM:
            return MediaLibraryAlbumOperations::HandlePhotoAlbumOperations(cmd);

        case OperationObject::FILESYSTEM_DIR:
            return MediaLibraryDirOperations::HandleDirOperation(cmd);

        case OperationObject::SMART_ALBUM:
            return MediaLibrarySmartAlbumOperations::HandleSmartAlbumOperation(cmd);

        case OperationObject::SMART_ALBUM_MAP:
            return MediaLibrarySmartAlbumMapOperations::HandleSmartAlbumMapOperation(cmd);

        case OperationObject::THUMBNAIL:
            return HandleThumbnailOperations(cmd);

        case OperationObject::BUNDLE_PERMISSION:
            return UriPermissionOperations::HandleUriPermOperations(cmd);

        case OperationObject::VISION_START ... OperationObject::VISION_END:
            return MediaLibraryVisionOperations::InsertOperation(cmd);

        case OperationObject::GEO_DICTIONARY:
        case OperationObject::GEO_KNOWLEDGE:
        case OperationObject::GEO_PHOTO:
            return MediaLibraryLocationOperations::InsertOperation(cmd);

        case OperationObject::PAH_FORM_MAP:
            return MediaLibraryFormMapOperations::HandleStoreFormIdOperation(cmd);
        case OperationObject::SEARCH_TOTAL: {
            return MediaLibrarySearchOperations::InsertOperation(cmd);
        }

        case OperationObject::STORY_ALBUM:
        case OperationObject::STORY_COVER:
        case OperationObject::STORY_PLAY:
        case OperationObject::USER_PHOTOGRAPHY:
            return MediaLibraryStoryOperations::InsertOperation(cmd);

        case OperationObject::ANALYSIS_PHOTO_MAP: {
            return MediaLibrarySearchOperations::InsertOperation(cmd);
        }

        default:
            MEDIA_ERR_LOG("MediaLibraryDataManager SolveInsertCmd: unsupported OperationObject: %{public}d",
                cmd.GetOprnObject());
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
    if (oprnType == OperationType::CREATE || oprnType == OperationType::SUBMIT_CACHE) {
        if (SetCmdBundleAndDevice(cmd) != ERR_OK) {
            MEDIA_ERR_LOG("MediaLibraryDataManager SetCmdBundleAndDevice failed.");
        }
    }
    // boardcast operation
    if (oprnType == OperationType::SCAN) {
        return MediaScannerManager::GetInstance()->ScanDir(ROOT_MEDIA_DIR, nullptr);
#ifdef MEDIALIBRARY_MEDIATOOL_ENABLE
    } else if (oprnType == OperationType::DELETE_TOOL) {
        return MediaLibraryAssetOperations::DeleteToolOperation(cmd);
#endif
    }
    return SolveInsertCmd(cmd);
}

int32_t MediaLibraryDataManager::InsertExt(MediaLibraryCommand &cmd, const DataShareValuesBucket &dataShareValue,
    string &result)
{
    int32_t res = Insert(cmd, dataShareValue);
    result = cmd.GetResult();
    return res;
}

int32_t MediaLibraryDataManager::HandleThumbnailOperations(MediaLibraryCommand &cmd)
{
    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    int32_t result = E_FAIL;
    switch (cmd.GetOprnType()) {
        case OperationType::GENERATE:
            result = thumbnailService_->GenerateThumbnails();
            break;
        case OperationType::AGING:
            result = thumbnailService_->LcdAging();
            break;
#ifdef DISTRIBUTED
        case OperationType::DISTRIBUTE_AGING:
            result = DistributeDeviceAging();
            break;
#endif
        default:
            MEDIA_ERR_LOG("bad operation type %{public}u", cmd.GetOprnType());
    }
    return result;
}

int32_t MediaLibraryDataManager::BatchInsert(MediaLibraryCommand &cmd, const vector<DataShareValuesBucket> &values)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_ERR_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    string uriString = cmd.GetUri().ToString();
    if (uriString == UFM_PHOTO_ALBUM_ADD_ASSET || uriString == PAH_PHOTO_ALBUM_ADD_ASSET) {
        return PhotoMapOperations::AddPhotoAssets(values);
    } else if (cmd.GetOprnObject() == OperationObject::ANALYSIS_PHOTO_MAP) {
        return PhotoMapOperations::AddAnaLysisPhotoAssets(values);
    }
    if (uriString.find(MEDIALIBRARY_DATA_URI) == string::npos) {
        MEDIA_ERR_LOG("MediaLibraryDataManager BatchInsert: Input parameter is invalid");
        return E_INVALID_URI;
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

    if (uriString.find(MEDIALIBRARY_DATA_URI) == string::npos) {
        MEDIA_ERR_LOG("Not Data ability Uri");
        return E_INVALID_URI;
    }
    MediaLibraryTracer tracer;
    tracer.Start("CheckWhereClause");
    auto whereClause = predicates.GetWhereClause();
    if (!MediaLibraryCommonUtils::CheckWhereClause(whereClause)) {
        MEDIA_ERR_LOG("illegal query whereClause input %{private}s", whereClause.c_str());
        return E_SQL_CHECK_FAIL;
    }
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
        case OperationObject::PHOTO_MAP: {
            return PhotoMapOperations::RemovePhotoAssets(rdbPredicate);
        }
        case OperationObject::ANALYSIS_PHOTO_MAP: {
            if (CheckIsDismissAsset(rdbPredicate)) {
                return PhotoMapOperations::DismissAssets(rdbPredicate);
            }
            break;
        }
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::FILESYSTEM_AUDIO: {
            return MediaLibraryAssetOperations::DeleteOperation(cmd);
        }
        case OperationObject::PAH_FORM_MAP: {
            return MediaLibraryFormMapOperations::RemoveFormIdOperations(rdbPredicate);
        }
        default:
            break;
    }

    return DeleteInRdbPredicatesAnalysis(cmd, rdbPredicate);
}

int32_t MediaLibraryDataManager::DeleteInRdbPredicatesAnalysis(MediaLibraryCommand &cmd,
    NativeRdb::RdbPredicates &rdbPredicate)
{
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

int32_t MediaLibraryDataManager::UpdateInternal(MediaLibraryCommand &cmd, NativeRdb::ValuesBucket &value,
    const DataShare::DataSharePredicates &predicates)
{
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET: {
            auto ret = MediaLibraryFileOperations::ModifyFileOperation(cmd);
            if (ret == E_SAME_PATH) {
                break;
            } else {
                return ret;
            }
        }
        case OperationObject::FILESYSTEM_DIR:
            // supply a ModifyDirOperation here to replace
            // modify in the HandleDirOperations in Insert function, if need
            break;
        case OperationObject::FILESYSTEM_ALBUM: {
            return MediaLibraryAlbumOperations::ModifyAlbumOperation(cmd);
        }
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::FILESYSTEM_AUDIO: {
            return MediaLibraryAssetOperations::UpdateOperation(cmd);
        }
        case OperationObject::ANALYSIS_PHOTO_ALBUM: {
            if (cmd.GetOprnType() >= OperationType::PORTRAIT_DISPLAY_LEVEL &&
                cmd.GetOprnType() <= OperationType::PORTRAIT_COVER_URI) {
                return MediaLibraryAlbumOperations::HandleAnalysisPhotoAlbum(cmd.GetOprnType(), value, predicates);
            }
            break;
        }
        case OperationObject::PHOTO_ALBUM: {
            return MediaLibraryAlbumOperations::HandlePhotoAlbum(cmd.GetOprnType(), value, predicates);
        }
        case OperationObject::GEO_DICTIONARY:
        case OperationObject::GEO_KNOWLEDGE: {
            return MediaLibraryLocationOperations::UpdateOperation(cmd);
        }

        case OperationObject::STORY_ALBUM:
        case OperationObject::STORY_COVER:
        case OperationObject::STORY_PLAY:
        case OperationObject::USER_PHOTOGRAPHY:
            return MediaLibraryStoryOperations::UpdateOperation(cmd);
        
        case OperationObject::PAH_MULTISTAGES_CAPTURE: {
            std::vector<std::string> columns;
            MultiStagesCaptureManager::GetInstance().HandleMultiStagesOperation(cmd, columns);
            return E_OK;
        }
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

    if (thumbnailService_ == nullptr) {
        return;
    }
    thumbnailService_->InterruptBgworker();
    shared_ptr<TrashAsyncTaskWorker> asyncWorker = TrashAsyncTaskWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("asyncWorker null");
        return;
    }
    asyncWorker->Interrupt();
}

int32_t MediaLibraryDataManager::GenerateThumbnails()
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    return thumbnailService_->GenerateThumbnails();
}

static void CacheAging()
{
    filesystem::path cacheDir(MEDIA_CACHE_DIR);
    if (!filesystem::exists(cacheDir)) {
        return;
    }

    std::error_code errCode;
    time_t now = time(nullptr);
    constexpr int thresholdSeconds = 7 * 24 * 60 * 60; // 7 days
    for (const auto& entry : filesystem::recursive_directory_iterator(cacheDir)) {
        string filePath = entry.path().string();
        if (!entry.is_regular_file()) {
            MEDIA_WARN_LOG("skip %{private}s, not regular file", filePath.c_str());
            continue;
        }

        struct stat statInfo {};
        if (stat(filePath.c_str(), &statInfo) != 0) {
            MEDIA_WARN_LOG("skip %{private}s , stat errno: %{public}d", filePath.c_str(), errno);
            continue;
        }
        time_t timeModified = statInfo.st_mtime;
        double duration = difftime(now, timeModified); // diff in seconds
        if (duration < thresholdSeconds) {
            continue;
        }

        if (!filesystem::remove(entry.path(), errCode)) {
            MEDIA_WARN_LOG("Failed to remove %{private}s, err: %{public}d", filePath.c_str(), errCode.value());
        }
    }
}

int32_t MediaLibraryDataManager::DoAging()
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::DoAging IN");
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    CacheAging(); // aging file in .cache

    shared_ptr<TrashAsyncTaskWorker> asyncWorker = TrashAsyncTaskWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("asyncWorker null");
        return E_FAIL;
    }
    asyncWorker->Init();
    return E_OK;
}

#ifdef DISTRIBUTED
int32_t MediaLibraryDataManager::LcdDistributeAging()
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::LcdDistributeAging IN");
    auto deviceInstance = MediaLibraryDevice::GetInstance();
    if ((thumbnailService_ == nullptr) || (deviceInstance == nullptr)) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    int32_t result = E_SUCCESS;
    vector<string> deviceUdids;
    deviceInstance->QueryAllDeviceUdid(deviceUdids);
    for (string &udid : deviceUdids) {
        result = thumbnailService_->LcdDistributeAging(udid);
        if (result != E_SUCCESS) {
            MEDIA_ERR_LOG("LcdDistributeAging fail result is %{public}d", result);
            break;
        }
    }
    return result;
}

int32_t MediaLibraryDataManager::DistributeDeviceAging()
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::DistributeDeviceAging IN");
    auto deviceInstance = MediaLibraryDevice::GetInstance();
    if ((thumbnailService_ == nullptr) || (deviceInstance == nullptr)) {
        return E_FAIL;
    }
    int32_t result = E_FAIL;
    vector<MediaLibraryDeviceInfo> deviceDataBaseList;
    deviceInstance->QueryAgingDeviceInfos(deviceDataBaseList);
    MEDIA_DEBUG_LOG("MediaLibraryDevice InitDeviceRdbStore deviceDataBaseList size =  %{public}d",
        (int) deviceDataBaseList.size());
    for (MediaLibraryDeviceInfo deviceInfo : deviceDataBaseList) {
        result = thumbnailService_->InvalidateDistributeThumbnail(deviceInfo.deviceUdid);
        if (result != E_SUCCESS) {
            MEDIA_ERR_LOG("invalidate fail %{public}d", result);
            continue;
        }
    }
    return result;
}
#endif

int MediaLibraryDataManager::GetThumbnail(const string &uri)
{
    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    if (!uri.empty() && MediaLibraryObjectUtils::CheckUriPending(uri)) {
        MEDIA_ERR_LOG("failed to get thumbnail, the file:%{private}s is pending", uri.c_str());
        return E_FAIL;
    }
    return thumbnailService_->GetThumbnailFd(uri);
}

void MediaLibraryDataManager::CreateThumbnailAsync(const string &uri, const string &path)
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
        int32_t err = thumbnailService_->CreateThumbnail(uri, path);
        if (err != E_SUCCESS) {
            MEDIA_ERR_LOG("ThumbnailService CreateThumbnail failed : %{public}d", err);
        }
    }
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
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, errCode},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }
    return RdbUtils::ToResultSetBridge(absResultSet);
}

#ifdef DISTRIBUTED
int32_t MediaLibraryDataManager::SyncPullThumbnailKeys(const Uri &uri)
{
    if (MediaLibraryDevice::GetInstance() == nullptr || !MediaLibraryDevice::GetInstance()->IsHasActiveDevice()) {
        return E_ERR;
    }
    if (kvStorePtr_ == nullptr) {
        return E_ERR;
    }

    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->BeginWrap()->EqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_IMAGE))
        ->Or()->EqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_VIDEO))->EndWrap()
        ->And()->EqualTo(MEDIA_DATA_DB_DATE_TRASHED, to_string(0))
        ->And()->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, to_string(MEDIA_TYPE_ALBUM))
        ->OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);
    vector<string> columns = { MEDIA_DATA_DB_THUMBNAIL, MEDIA_DATA_DB_LCD };
    auto resultset = MediaLibraryFileOperations::QueryFileOperation(cmd, columns);
    if (resultset == nullptr) {
        return E_HAS_DB_ERROR;
    }

    vector<string> thumbnailKeys;
    int count = 0;
    while (resultset->GoToNextRow() == NativeRdb::E_OK && count < MAX_QUERY_THUMBNAIL_KEY_COUNT) {
        string thumbnailKey =
            get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_THUMBNAIL, resultset, TYPE_STRING));
        thumbnailKeys.push_back(thumbnailKey);
        string lcdKey = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_LCD, resultset, TYPE_STRING));
        thumbnailKeys.push_back(lcdKey);
        count++;
    }

    if (thumbnailKeys.empty()) {
        return E_NO_SUCH_FILE;
    }
    MediaLibrarySyncOperation::SyncPullKvstore(kvStorePtr_, thumbnailKeys,
        MediaFileUtils::GetNetworkIdFromUri(uri.ToString()));
    return E_SUCCESS;
}
#endif

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

static void AddVirtualColumnsOfDateType(vector<string> &columns)
{
    vector<string> dateTypes = { MEDIA_DATA_DB_DATE_ADDED, MEDIA_DATA_DB_DATE_TRASHED, MEDIA_DATA_DB_DATE_MODIFIED };
    vector<string> dateTypeSeconds = { MEDIA_DATA_DB_DATE_ADDED_TO_SECOND,
            MEDIA_DATA_DB_DATE_TRASHED_TO_SECOND, MEDIA_DATA_DB_DATE_MODIFIED_TO_SECOND };
    for (size_t i = 0; i < dateTypes.size(); i++) {
        auto it = find(columns.begin(), columns.end(), dateTypes[i]);
        if (it != columns.end()) {
            columns.push_back(dateTypeSeconds[i]);
        }
    }
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
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates,
        MEDIALIBRARY_TABLE);
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(rdbPredicate.GetOrder());
    AddVirtualColumnsOfDateType(const_cast<vector<string> &>(columns));

    OperationObject oprnObject = cmd.GetOprnObject();
    auto it = QUERY_CONDITION_MAP.find(oprnObject);
    if (it != QUERY_CONDITION_MAP.end()) {
        return MediaLibraryObjectUtils::QueryWithCondition(cmd, columns, it->second);
    }

    return QueryInternal(cmd, columns, predicates);
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryDataManager::QueryInternal(MediaLibraryCommand &cmd,
    const vector<string> &columns, const DataSharePredicates &predicates)
{
    MediaLibraryTracer tracer;
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ALBUM:
        case OperationObject::MEDIA_VOLUME:
            return MediaLibraryAlbumOperations::QueryAlbumOperation(cmd, columns);
        case OperationObject::PHOTO_ALBUM:
            return MediaLibraryAlbumOperations::QueryPhotoAlbum(cmd, columns);
        case OperationObject::ANALYSIS_PHOTO_ALBUM: {
            if (CheckIsPortraitAlbum(cmd)) {
                return MediaLibraryAlbumOperations::QueryPortraitAlbum(cmd, columns);
            }
            return MediaLibraryRdbStore::Query(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
        }
        case OperationObject::PHOTO_MAP:
        case OperationObject::ANALYSIS_PHOTO_MAP: {
            return PhotoMapOperations::QueryPhotoAssets(
                RdbUtils::ToPredicates(predicates, PhotoColumn::PHOTOS_TABLE), columns);
        }
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAssetOperations::QueryOperation(cmd, columns);
        case OperationObject::VISION_START ... OperationObject::VISION_END: {
            auto queryResult = MediaLibraryRdbStore::Query(
                RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
            if (cmd.GetOprnObject() == OperationObject::VISION_OCR && queryResult != nullptr) {
                queryResult = MediaLibraryVisionOperations::DealWithActiveOcrTask(
                    queryResult, predicates, columns, cmd);
            }
            return queryResult;
        }
        case OperationObject::GEO_DICTIONARY:
        case OperationObject::GEO_KNOWLEDGE:
        case OperationObject::GEO_PHOTO:
            return MediaLibraryRdbStore::Query(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
        case OperationObject::SEARCH_TOTAL:
            return MediaLibraryRdbStore::Query(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
        case OperationObject::STORY_ALBUM:
        case OperationObject::STORY_COVER:
        case OperationObject::STORY_PLAY:
        case OperationObject::USER_PHOTOGRAPHY:
            return MediaLibraryRdbStore::Query(RdbUtils::ToPredicates(predicates, cmd.GetTableName()), columns);
        case OperationObject::PAH_MULTISTAGES_CAPTURE:
            return MultiStagesCaptureManager::GetInstance().HandleMultiStagesOperation(cmd, columns);
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

#ifdef DISTRIBUTED
bool MediaLibraryDataManager::QuerySync(const string &networkId, const string &tableName)
{
    if (networkId.empty() || tableName.empty()) {
        return false;
    }

    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    auto ret = deviceManager.GetLocalDeviceInfo(bundleName_, deviceInfo);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("MediaLibraryDataManager QuerySync Failed to get local device info.");
        return false;
    }

    if (networkId == string(deviceInfo.networkId)) {
        return true;
    }

    int32_t syncStatus = DEVICE_SYNCSTATUSING;
    auto result = MediaLibraryDevice::GetInstance()->GetDeviceSyncStatus(networkId, tableName, syncStatus);
    if (result && syncStatus == DEVICE_SYNCSTATUS_COMPLETE) {
        return true;
    }

    vector<string> devices = { networkId };
    MediaLibrarySyncOpts syncOpts;
    syncOpts.rdbStore = rdbStore_;
    syncOpts.table = tableName;
    syncOpts.bundleName = bundleName_;
    return MediaLibrarySyncOperation::SyncPullTable(syncOpts, devices);
}
#endif

int32_t MediaLibraryDataManager::OpenFile(MediaLibraryCommand &cmd, const string &mode)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataManager::OpenFile");
    auto oprnObject = cmd.GetOprnObject();
    if (oprnObject == OperationObject::FILESYSTEM_PHOTO || oprnObject == OperationObject::FILESYSTEM_AUDIO ||
        oprnObject == OperationObject::HIGHLIGHT_COVER) {
        return MediaLibraryAssetOperations::OpenOperation(cmd, mode);
    }

#ifdef MEDIALIBRARY_COMPATIBILITY
    if (oprnObject != OperationObject::THUMBNAIL && oprnObject != OperationObject::THUMBNAIL_ASTC) {
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
#ifdef DISTRIBUTED
    thumbnailService_->Init(rdbStore_, kvStorePtr_, extensionContext);
#else
    thumbnailService_->Init(rdbStore_,  extensionContext);
#endif
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

    if (Acl::AclSetDefault() != E_OK) {
        MEDIA_ERR_LOG("Failed to set the acl read permission for the thumbs Photo dir");
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
        instance->CreateThumbnailAsync(uri, path);
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
#ifdef DISTRIBUTED
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    int32_t ret = deviceManager.GetLocalDeviceInfo(bundleName_, deviceInfo);
    if (ret < 0) {
        MEDIA_ERR_LOG("GetLocalDeviceInfo ret = %{public}d", ret);
    } else {
        outCmd.SetDeviceName(deviceInfo.deviceName);
    }
    return ret;
#endif
    return 0;
}

int32_t MediaLibraryDataManager::DoTrashAging(shared_ptr<int> countPtr)
{
    shared_ptr<int> smartAlbumTrashPtr = make_shared<int>();
    MediaLibrarySmartAlbumMapOperations::HandleAgingOperation(smartAlbumTrashPtr);

    shared_ptr<int> albumTrashtPtr = make_shared<int>();
    MediaLibraryAlbumOperations::HandlePhotoAlbum(OperationType::AGING, {}, {}, albumTrashtPtr);

    shared_ptr<int> audioTrashtPtr = make_shared<int>();
    MediaLibraryAudioOperations::TrashAging(audioTrashtPtr);

    if (countPtr != nullptr) {
      *countPtr = *smartAlbumTrashPtr + *albumTrashtPtr + *audioTrashtPtr;
    }
    return E_SUCCESS;
}

int32_t MediaLibraryDataManager::RevertPendingByFileId(const std::string &fileId)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_ASSET, OperationType::UPDATE);
    ValuesBucket values;
    values.PutLong(Media::MEDIA_DATA_DB_TIME_PENDING, 0);
    cmd.SetValueBucket(values);
    int32_t retVal = MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd, fileId);
    if (retVal <= 0) {
        MEDIA_ERR_LOG("failed to revert pending error, fileId:%{private}s", fileId.c_str());
        return retVal;
    }
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


int32_t MediaLibraryDataManager::GetAgingDataSize(const int64_t &time, int &count)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    return thumbnailService_->GetAgingDataSize(time, count);
}


int32_t MediaLibraryDataManager::QueryNewThumbnailCount(const int64_t &time, int &count)
{
    shared_lock<shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        return E_THUMBNAIL_SERVICE_NULLPTR;
    }
    return thumbnailService_->QueryNewThumbnailCount(time, count);
}

void MediaLibraryDataManager::SetStartupParameter()
{
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
}
}  // namespace Media
}  // namespace OHOS
