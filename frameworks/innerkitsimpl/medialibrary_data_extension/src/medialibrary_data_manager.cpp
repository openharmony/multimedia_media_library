/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include <unordered_set>
#include <shared_mutex>

#include "abs_rdb_predicates.h"
#include "datashare_abs_result_set.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "media_datashare_ext_ability.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_uripermission_operations.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_device.h"
#include "medialibrary_device_info.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_inotify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "medialibrary_sync_table.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_tracer.h"
#include "mimetype_utils.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "system_ability_definition.h"
#include "timer.h"
#include "permission_utils.h"
#include "trash_async_worker.h"

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

std::shared_ptr<MediaLibraryDataManager> MediaLibraryDataManager::instance_ = nullptr;
std::unordered_map<std::string, DirAsset> MediaLibraryDataManager::dirQuerySetMap_ = {};
std::mutex MediaLibraryDataManager::mutex_;

MediaLibraryDataManager::MediaLibraryDataManager(void)
{
}

MediaLibraryDataManager::~MediaLibraryDataManager(void)
{
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(KVSTORE_APPID, kvStorePtr_);
        kvStorePtr_ = nullptr;
    }
}

std::shared_ptr<MediaLibraryDataManager> MediaLibraryDataManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<MediaLibraryDataManager>();
        }
    }
    return instance_;
}

static DataShare::DataShareExtAbility *MediaDataShareCreator(const std::unique_ptr<Runtime> &runtime)
{
    MEDIA_DEBUG_LOG("MediaLibraryCreator::%{public}s", __func__);
    return  MediaDataShareExtAbility::Create(runtime);
}

__attribute__((constructor)) void RegisterDataShareCreator()
{
    MEDIA_DEBUG_LOG("MediaLibraryDataMgr::%{public}s", __func__);
    DataShare::DataShareExtAbility::SetCreator(MediaDataShareCreator);
}

static void MakeRootDirs()
{
    for (auto &dir : PRESET_ROOT_DIRS) {
        Uri createAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);
        ValuesBucket valuesBucket;
        valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR + dir);
        MediaLibraryCommand cmd(createAlbumUri, valuesBucket);
        auto ret = MediaLibraryAlbumOperations::CreateAlbumOperation(cmd);
        if (ret == E_FILE_EXIST) {
            MEDIA_INFO_LOG("Root dir: %{public}s is exist", dir.c_str());
        } else if (ret <= 0) {
            MEDIA_ERR_LOG("Failed to preset root dir: %{public}s", dir.c_str());
        }
        MediaFileUtils::CreateDirectory(ROOT_MEDIA_DIR + dir + ".recycle");
    }
}

int32_t MediaLibraryDataManager::InitMediaLibraryMgr(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context,
    const std::shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext)
{
    std::lock_guard<std::shared_mutex> lock(mgrSharedMutex_);

    if (refCnt_.load() > 0) {
        MEDIA_DEBUG_LOG("already initialized");
        refCnt_++;
        return E_OK;
    }

    context_ = context;
    int32_t errCode = InitMediaLibraryRdbStore();
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at InitMediaLibraryRdbStore");

    errCode = InitDeviceData();
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at InitDeviceData");

    MimeTypeUtils::InitMimeTypeMap();
    errCode = MakeDirQuerySetMap(dirQuerySetMap_);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at MakeDirQuerySetMap");

    MakeRootDirs();
    errCode = InitialiseKvStore();
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at InitialiseKvStore");

    errCode = InitialiseThumbnailService(extensionContext);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at InitialiseThumbnailService");

    errCode = DoTrashAging();
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "failed at DoTrashAging");
    refCnt_++;
    return E_OK;
}

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

void MediaLibraryDataManager::ClearMediaLibraryMgr()
{
    std::lock_guard<std::shared_mutex> lock(mgrSharedMutex_);

    refCnt_--;
    if (refCnt_.load() > 0) {
        MEDIA_DEBUG_LOG("still other extension exist");
        return;
    }

    rdbStore_ = nullptr;

    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(KVSTORE_APPID, kvStorePtr_);
        kvStorePtr_ = nullptr;
    }
    if (MediaLibraryDevice::GetInstance()) {
        MediaLibraryDevice::GetInstance()->Stop();
    };
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

int32_t MediaLibraryDataManager::InitialiseKvStore()
{
    if (kvStorePtr_ != nullptr) {
        return E_OK;
    }

    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .backup = false,
        .autoSync = false,
        .area = DistributedKv::Area::EL2,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .baseDir = context_->GetDatabaseDir(),
    };

    Status status = dataManager_.GetSingleKvStore(options, KVSTORE_APPID, KVSTORE_STOREID, kvStorePtr_);
    if (status != Status::SUCCESS || kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataManager::InitialiseKvStore failed %{private}d", status);
        return E_ERR;
    }
    return E_OK;
}

std::shared_ptr<MediaDataShareExtAbility> MediaLibraryDataManager::GetOwner()
{
    return extension_;
}

void MediaLibraryDataManager::SetOwner(const std::shared_ptr<MediaDataShareExtAbility> &datashareExternsion)
{
    extension_ = datashareExternsion;
}

std::string MediaLibraryDataManager::GetType(const Uri &uri)
{
    MEDIA_INFO_LOG("GetType uri: %{public}s", uri.ToString().c_str());
    return "";
}

int32_t MediaLibraryDataManager::MakeDirQuerySetMap(unordered_map<string, DirAsset> &outDirQuerySetMap)
{
    int32_t count = -1;
    vector<string> columns;
    AbsRdbPredicates dirAbsPred(MEDIATYPE_DIRECTORY_TABLE);
    auto queryResultSet = rdbStore_->QueryByStep(dirAbsPred, columns);
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

std::unordered_map<std::string, DirAsset> MediaLibraryDataManager::GetDirQuerySetMap()
{
    return dirQuerySetMap_;
}

int32_t MediaLibraryDataManager::SolveInsertCmd(MediaLibraryCommand &cmd)
{
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET: {
            return MediaLibraryFileOperations::HandleFileOperation(cmd);
        }
        case OperationObject::FILESYSTEM_ALBUM: {
            return MediaLibraryAlbumOperations::CreateAlbumOperation(cmd);
        }
        case OperationObject::FILESYSTEM_DIR: {
            return MediaLibraryDirOperations::HandleDirOperation(cmd);
        }
        case OperationObject::SMART_ALBUM: {
            return MediaLibrarySmartAlbumOperations::HandleSmartAlbumOperation(cmd);
        }
        case OperationObject::SMART_ALBUM_MAP: {
            return MediaLibrarySmartAlbumMapOperations::HandleSmartAlbumMapOperation(cmd);
        }
        case OperationObject::THUMBNAIL: {
            return HandleThumbnailOperations(cmd);
        }
        case OperationObject::BUNDLE_PERMISSION: {
            return UriPermissionOperations::HandleUriPermOperations(cmd);
        }
        default: {
            return MediaLibraryObjectUtils::InsertInDb(cmd);
        }
    }
}

int32_t MediaLibraryDataManager::Insert(const Uri &uri, const DataShareValuesBucket &dataShareValue)
{
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Insert: Input parameter is invalid");
        return E_INVALID_VALUES;
    }

    MediaLibraryCommand cmd(uri, value);
    OperationType oprnType = cmd.GetOprnType();
    if (oprnType == OperationType::CREATE) {
        if (SetCmdBundleAndDevice(cmd) != ERR_OK) {
            MEDIA_ERR_LOG("MediaLibraryDataManager SetCmdBundleAndDevice failed.");
        }
    }
    cmd.SetDirQuerySetMap(GetDirQuerySetMap());
    // boardcast operation
    if (oprnType == OperationType::SCAN) {
        return MediaScannerManager::GetInstance()->ScanDir(ROOT_MEDIA_DIR, nullptr);
    }
    if (ShouldCheckFileName(cmd.GetOprnObject())) {
        if (oprnType == OperationType::CREATE && !CheckFileNameValid(dataShareValue)) {
            return E_FILE_NAME_INVALID;
        }
    }
    return SolveInsertCmd(cmd);
}

int32_t MediaLibraryDataManager::HandleThumbnailOperations(MediaLibraryCommand &cmd)
{
    int32_t result = E_FAIL;
    switch (cmd.GetOprnType()) {
        case OperationType::GENERATE:
            result = thumbnailService_->GenerateThumbnails();
            break;
        case OperationType::AGING:
            result = thumbnailService_->LcdAging();
            break;
        case OperationType::DISTRIBUTE_AGING:
            result = DistributeDeviceAging();
            break;
        case OperationType::DISTRIBUTE_CREATE:
            result = CreateThumbnail(cmd.GetValueBucket());
            break;
        default:
            MEDIA_ERR_LOG("bad operation type %{public}u", cmd.GetOprnType());
    }
    return result;
}

int32_t MediaLibraryDataManager::BatchInsert(const Uri &uri, const vector<DataShareValuesBucket> &values)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::BatchInsert");
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    string uriString = uri.ToString();
    if (uriString.find(MEDIALIBRARY_DATA_URI) == string::npos) {
        MEDIA_ERR_LOG("MediaLibraryDataManager BatchInsert: Input parameter is invalid");
        return E_INVALID_URI;
    }
    int32_t rowCount = 0;
    for (auto it = values.begin(); it != values.end(); it++) {
        if (Insert(uri, *it) >= 0) {
            rowCount++;
        }
    }

    return rowCount;
}

int32_t MediaLibraryDataManager::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::Delete");
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (uri.ToString().find(MEDIALIBRARY_DATA_URI) == string::npos) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Delete: Not Data ability Uri");
        return E_INVALID_URI;
    }

    MediaLibraryCommand cmd(uri, OperationType::DELETE);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());

    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET:
        case OperationObject::FILESYSTEM_DIR:
        case OperationObject::FILESYSTEM_ALBUM: {
            string fileId = cmd.GetOprnFileId();
            auto fileAsset = MediaLibraryObjectUtils::GetFileAssetFromId(fileId);
            CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_FILEID, "Get fileAsset failed, fileId: %{public}s",
                fileId.c_str());
            if (fileAsset->GetRelativePath() == "") {
                return E_DELETE_DENIED;
            }
            return (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) ?
                MediaLibraryObjectUtils::DeleteFileObj(fileAsset) : MediaLibraryObjectUtils::DeleteDirObj(fileAsset);
        }
        default:
            break;
    }

    // DeleteInfoByIdInDb can finish the default delete of smartalbum and smartmap,
    // so no need to distinct them in switch-case deliberately
    return MediaLibraryObjectUtils::DeleteInfoByIdInDb(cmd);
}

int32_t MediaLibraryDataManager::Update(const Uri &uri, const DataShareValuesBucket &dataShareValue,
    const DataSharePredicates &predicates)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::Update");
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Update:Input parameter is invalid ");
        return E_INVALID_VALUES;
    }

    MediaLibraryCommand cmd(uri, value);
    cmd.SetDirQuerySetMap(GetDirQuerySetMap());
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());

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
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return;
    }

    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
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
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
        return E_FAIL;
    }
    return thumbnailService_->GenerateThumbnails();
}

int32_t MediaLibraryDataManager::DoAging()
{
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::DoAging IN");
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return E_FAIL;
    }

    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
        return E_FAIL;
    }
    int32_t errorCode = thumbnailService_->LcdAging();
    if (errorCode != 0) {
        MEDIA_ERR_LOG("LcdAging exist error %{public}d", errorCode);
    }

    errorCode = DistributeDeviceAging();
    if (errorCode != 0) {
        MEDIA_ERR_LOG("DistributeDeviceAging exist error %{public}d", errorCode);
    }

    errorCode = LcdDistributeAging();
    if (errorCode != 0) {
        MEDIA_ERR_LOG("LcdDistributeAging exist error %{public}d", errorCode);
    }
    shared_ptr<TrashAsyncTaskWorker> asyncWorker = TrashAsyncTaskWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("asyncWorker null");
        return E_FAIL;
    }
    asyncWorker->Init();
    return errorCode;
}

int32_t MediaLibraryDataManager::LcdDistributeAging()
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::LcdDistributeAging IN");
    auto deviceInstance = MediaLibraryDevice::GetInstance();
    if ((thumbnailService_ == nullptr) || (deviceInstance == nullptr)) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
        return E_FAIL;
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
        MEDIA_ERR_LOG("thumbnailService_ is null");
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

shared_ptr<ResultSetBridge> MediaLibraryDataManager::GetThumbnail(const string &uri)
{
    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
        return nullptr;
    }
    return thumbnailService_->GetThumbnail(uri);
}

void MediaLibraryDataManager::CreateThumbnailAsync(const string &uri)
{
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return;
    }

    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
        return;
    }
    if (!uri.empty()) {
        int32_t err = thumbnailService_->CreateThumbnailAsync(uri);
        if (err != E_SUCCESS) {
            MEDIA_ERR_LOG("ThumbnailService CreateThumbnailAsync failed : %{public}d", err);
        }
    }
}

int32_t MediaLibraryDataManager::CreateThumbnail(const ValuesBucket &values)
{
    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
        return E_ERR;
    }
    string actualUri;
    ValueObject valueObject;

    if (values.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
        valueObject.GetString(actualUri);
    }

    if (!actualUri.empty()) {
        int32_t errorCode = thumbnailService_->CreateThumbnail(actualUri);
        if (errorCode != E_OK) {
            MEDIA_ERR_LOG("CreateThumbnail failed : %{public}d", errorCode);
            return errorCode;
        }
    }
    MEDIA_DEBUG_LOG("MediaLibraryDataManager CreateThumbnail: OUT");
    return E_OK;
}

void MediaLibraryDataManager::NeedQuerySync(const string &networkId, OperationObject oprnObject)
{
    if (networkId.empty()) {
        return;
    }
    // tabletype mapping into tablename
    std::string tableName = MEDIALIBRARY_TABLE;
    if (oprnObject == OperationObject::SMART_ALBUM) {
        tableName = SMARTALBUM_TABLE;
    } else if (oprnObject == OperationObject::SMART_ALBUM_MAP) {
        tableName = SMARTALBUM_MAP_TABLE;
    }

    if ((oprnObject != OperationObject::ASSETMAP) && (oprnObject != OperationObject::SMART_ALBUM_ASSETS)) {
        MediaLibraryTracer tracer;
        tracer.Start("QuerySync");
        auto ret = QuerySync(networkId, tableName);
        MEDIA_INFO_LOG("MediaLibraryDataManager QuerySync result = %{private}d", ret);
    }
}

shared_ptr<ResultSetBridge> MediaLibraryDataManager::Query(const Uri &uri,
    const vector<string> &columns, const DataSharePredicates &predicates)
{
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return nullptr;
    }

    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataManager::Query");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Rdb Store is not initialized");
        return nullptr;
    }

    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    shared_ptr<ResultSetBridge> queryResultSet;
    if (cmd.GetOprnObject() == OperationObject::THUMBNAIL) {
        string uriString = uri.ToString();
        if (!ThumbnailService::ParseThumbnailInfo(uriString)) {
            return nullptr;
        }
        tracer.Start("GetThumbnail");
        queryResultSet = GetThumbnail(uriString);
    } else {
        auto absResultSet = QueryRdb(uri, columns, predicates);
        if (absResultSet == nullptr) {
            return nullptr;
        }
        queryResultSet = RdbUtils::ToResultSetBridge(absResultSet);
    }

    return queryResultSet;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryDataManager::QueryRdb(const Uri &uri, const vector<string> &columns,
    const DataSharePredicates &predicates)
{
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (refCnt_.load() <= 0) {
        MEDIA_DEBUG_LOG("MediaLibraryDataManager is not initialized");
        return nullptr;
    }

    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataManager::QueryRdb");
    static const map<OperationObject, string> queryConditionMap {
        { OperationObject::SMART_ALBUM, SMARTALBUM_DB_ID },
        { OperationObject::SMART_ALBUM_MAP, SMARTALBUMMAP_DB_ALBUM_ID },
        { OperationObject::FILESYSTEM_DIR, MEDIA_DATA_DB_ID },
        { OperationObject::ALL_DEVICE, "" },
        { OperationObject::ACTIVE_DEVICE, "" },
        { OperationObject::ASSETMAP, "" },
        { OperationObject::SMART_ALBUM_ASSETS, "" },
        { OperationObject::BUNDLE_PERMISSION, "" },
    };

    auto whereClause = predicates.GetWhereClause();
    if (!MediaLibraryCommonUtils::CheckWhereClause(whereClause)) {
        MEDIA_ERR_LOG("illegal query whereClause input %{public}s", whereClause.c_str());
        return nullptr;
    }

    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    // MEDIALIBRARY_TABLE just for RdbPredicates
    NativeRdb::RdbPredicates rdbPredicate = RdbDataShareAdapter::RdbUtils::ToPredicates(predicates,
        MEDIALIBRARY_TABLE);
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(rdbPredicate.GetOrder());
    NeedQuerySync(cmd.GetOprnDevice(), cmd.GetOprnObject());

    shared_ptr<NativeRdb::ResultSet> queryResultSet;
    OperationObject oprnObject = cmd.GetOprnObject();
    auto it = queryConditionMap.find(oprnObject);
    if (it != queryConditionMap.end()) {
        queryResultSet = MediaLibraryObjectUtils::QueryWithCondition(cmd, columns, it->second);
    } else if (oprnObject == OperationObject::FILESYSTEM_ALBUM || oprnObject == OperationObject::MEDIA_VOLUME) {
        queryResultSet = MediaLibraryAlbumOperations::QueryAlbumOperation(cmd, columns);
    } else {
        tracer.Start("QueryFile");
        queryResultSet = MediaLibraryFileOperations::QueryFileOperation(cmd, columns);
    }
    return queryResultSet;
}

bool MediaLibraryDataManager::QuerySync(const std::string &networkId, const std::string &tableName)
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

    if (networkId == std::string(deviceInfo.networkId)) {
        return true;
    }

    int32_t syncStatus = DEVICE_SYNCSTATUSING;
    auto result = MediaLibraryDevice::GetInstance()->GetDevicieSyncStatus(networkId, syncStatus);
    if (result && syncStatus == DEVICE_SYNCSTATUS_COMPLETE) {
        return true;
    }

    std::vector<std::string> devices = { networkId };
    return MediaLibrarySyncTable::SyncPullTable(rdbStore_, bundleName_, tableName, devices);
}

int32_t MediaLibraryDataManager::OpenFile(const Uri &uri, const std::string &mode)
{
    MediaLibraryCommand cmd(uri, OperationType::OPEN);
    return MediaLibraryObjectUtils::OpenFile(cmd, mode);
}

bool MediaLibraryDataManager::CheckFileNameValid(const DataShareValuesBucket &value)
{
    bool isValid = false;
    std::string displayName = value.Get(MEDIA_DATA_DB_NAME, isValid);
    if (!isValid) {
        return false;
    }

    if (displayName.empty()) {
        return false;
    }

    return true;
}

void MediaLibraryDataManager::NotifyChange(const Uri &uri)
{
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
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
    const std::shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext)
{
    if (thumbnailService_ != nullptr) {
        return E_OK;
    }
    thumbnailService_ = ThumbnailService::GetInstance();
    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataManager::InitialiseThumbnailService failed");
        return E_ERR;
    }
    int ret = thumbnailService_->Init(rdbStore_, kvStorePtr_, extensionContext);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Failed to init ThumbnailService");
        return E_ERR;
    }
    return E_OK;
}

int32_t ScanFileCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path)
{
    auto instance = MediaLibraryDataManager::GetInstance();
    if (instance != nullptr) {
        instance->CreateThumbnailAsync(uri);
    }
    return E_OK;
}

int32_t MediaLibraryDataManager::SetCmdBundleAndDevice(MediaLibraryCommand &outCmd)
{
    int uid = IPCSkeleton::GetCallingUid();
    string clientBundle;
    bool isSystemApp = false;
    PermissionUtils::GetClientBundle(uid, clientBundle, isSystemApp);
    if (clientBundle.empty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager::GetClientBundle failed");
        return E_GET_CLIENTBUNDLE_FAIL;
    }
    outCmd.SetBundleName(clientBundle);
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    int32_t ret = deviceManager.GetLocalDeviceInfo(bundleName_, deviceInfo);
    if (ret < 0) {
        MEDIA_ERR_LOG("GetLocalDeviceInfo ret = %{public}d", ret);
    } else {
        outCmd.SetDeviceName(deviceInfo.deviceName);
    }
    return ret;
}

bool MediaLibraryDataManager::ShouldCheckFileName(const OperationObject &oprnObject)
{
    if ((oprnObject == OperationObject::SMART_ALBUM_MAP) ||
        (oprnObject == OperationObject::SMART_ALBUM) ||
        (oprnObject == OperationObject::FILESYSTEM_DIR)) {
        return false;
    } else {
        return true;
    }
}

int32_t MediaLibraryDataManager::DoTrashAging()
{
    return MediaLibrarySmartAlbumMapOperations::HandleAgingOperation();
}
}  // namespace Media
}  // namespace OHOS
