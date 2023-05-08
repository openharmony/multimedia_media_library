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
#include "medialibrary_object_utils.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "medialibrary_sync_table.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_tracer.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "system_ability_definition.h"
#include "timer.h"
#include "permission_utils.h"

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
        if (ret <= 0) {
            MEDIA_ERR_LOG("Failed to preset root dir: %{public}s", dir.c_str());
        }
        MediaFileUtils::CreateDirectory(ROOT_MEDIA_DIR + dir + ".recycle");
    }
}

void MediaLibraryDataManager::InitMediaLibraryMgr(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context,
    const std::shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext)
{
    std::lock_guard<std::shared_mutex> lock(mgrSharedMutex_);

    refCnt_++;
    if (refCnt_.load() > 1) {
        MEDIA_DEBUG_LOG("already initialized");
        return;
    }

    context_ = context;
    InitMediaLibraryRdbStore();
    InitDeviceData();
    MakeDirQuerySetMap(dirQuerySetMap_);
    MakeRootDirs();
    InitialiseKvStore();
    InitialiseThumbnailService(extensionContext);
}

void MediaLibraryDataManager::InitDeviceData()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataManager InitDeviceData rdbStore is null");
        return;
    }

    MediaLibraryTracer tracer;
    tracer.Start("InitDeviceRdbStoreTrace");
    if (!MediaLibraryDevice::GetInstance()->InitDeviceRdbStore(rdbStore_)) {
        MEDIA_ERR_LOG("MediaLibraryDataManager InitDeviceData failed!");
    }
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
    MediaLibraryUnistoreManager::GetInstance().Stop();
    extension_ = nullptr;
}

int32_t MediaLibraryDataManager::InitMediaLibraryRdbStore()
{
    if (rdbStore_) {
        return E_SUCCESS;
    }

    MediaLibraryUnistoreManager::GetInstance().Init(context_);
    rdbStore_ = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();

    return E_SUCCESS;
}

void MediaLibraryDataManager::InitialiseKvStore()
{
    if (kvStorePtr_ != nullptr) {
        return;
    }

    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .backup = false,
        .autoSync = false,
        .securityLevel = DistributedKv::SecurityLevel::S3,
        .area = DistributedKv::Area::EL2,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .baseDir = context_->GetDatabaseDir(),
    };

    Status status = dataManager_.GetSingleKvStore(options, KVSTORE_APPID, KVSTORE_STOREID, kvStorePtr_);
    if (status != Status::SUCCESS || kvStorePtr_ == nullptr) {
        MEDIA_INFO_LOG("MediaLibraryDataManager::InitialiseKvStore failed %{private}d", status);
    }
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

void MediaLibraryDataManager::MakeDirQuerySetMap(unordered_map<string, DirAsset> &outDirQuerySetMap)
{
    int32_t count = -1;
    int32_t dirTypeVal = -1;
    int32_t columnIndexDir, columnIndexMedia, columnIndexEx, columnIndexDirType;
    string dirVal, mediaVal, exVal;
    vector<string> columns;
    shared_ptr<AbsSharedResultSet> queryResultSet;
    AbsRdbPredicates dirAbsPred(MEDIATYPE_DIRECTORY_TABLE);
    queryResultSet = rdbStore_->Query(dirAbsPred, columns);
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdb failed");
        return;
    }
    MEDIA_INFO_LOG("MakeDirQuerySetMap count = %{public}d", count);
    if (count == 0) {
        MEDIA_ERR_LOG("can not find any dirAsset");
        return;
    }
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        DirAsset dirAsset;
        queryResultSet->GetColumnIndex(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE, columnIndexDirType);
        queryResultSet->GetInt(columnIndexDirType, dirTypeVal);
        queryResultSet->GetColumnIndex(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, columnIndexDir);
        queryResultSet->GetString(columnIndexDir, dirVal);
        queryResultSet->GetColumnIndex(CATEGORY_MEDIATYPE_DIRECTORY_DB_MEDIA_TYPE, columnIndexMedia);
        queryResultSet->GetString(columnIndexMedia, mediaVal);
        queryResultSet->GetColumnIndex(CATEGORY_MEDIATYPE_DIRECTORY_DB_EXTENSION, columnIndexEx);
        queryResultSet->GetString(columnIndexEx, exVal);
        dirAsset.SetDirType(dirTypeVal);
        dirAsset.SetDirectory(dirVal);
        dirAsset.SetMediaTypes(mediaVal);
        dirAsset.SetExtensions(exVal);
        MEDIA_INFO_LOG("dirTypeVal: %{public}d dirVal: %{private}s mediaVal: %{public}s exVal: %{public}s",
            dirTypeVal, dirVal.c_str(), mediaVal.c_str(), exVal.c_str());
        outDirQuerySetMap.insert(make_pair(dirVal, dirAsset));
    }
    MEDIA_DEBUG_LOG("MakeDirQuerySetMap OUT");
}

std::unordered_map<std::string, DirAsset> MediaLibraryDataManager::GetDirQuerySetMap() const
{
    return dirQuerySetMap_;
}

int32_t MediaLibraryDataManager::Insert(const Uri &uri, const DataShareValuesBucket &dataShareValue)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::Insert");
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);

    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Insert: Input parameter is invalid");
        return E_INVALID_VALUES;
    }

    MediaLibraryCommand cmd(uri, value);
    // boardcast operation
    if (cmd.GetOprnType() == OperationType::SCAN) {
        string scanPath = ROOT_MEDIA_DIR;
        return MediaScannerManager::GetInstance()->ScanDir(scanPath, nullptr);
    } else if ((cmd.GetOprnType() == OperationType::CREATE) && !CheckFileNameValid(dataShareValue)) {
        return E_FILE_NAME_INVALID;
    }

    int32_t result = E_FAIL;
    vector<string> devices;
    // after replace all xxxOperations following, remove "operationType"
    string operationType = MediaLibraryDataManagerUtils::GetOperationType(uri.ToString());
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET: {
            result = MediaLibraryFileOperations::HandleFileOperation(cmd);
            break;
        }
        case OperationObject::FILESYSTEM_ALBUM: {
            result = MediaLibraryAlbumOperations::CreateAlbumOperation(cmd);
            break;
        }
        case OperationObject::FILESYSTEM_DIR: {
            MediaLibraryDirOperations dirOprn;
            result = dirOprn.HandleDirOperations(operationType, value, rdbStore_, dirQuerySetMap_);
            MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
            break;
        }
        case OperationObject::SMART_ALBUM: {
            MediaLibrarySmartAlbumOperations smartalbumOprn;
            result = smartalbumOprn.HandleSmartAlbumOperations(operationType, value, rdbStore_);
            MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
            break;
        }
        case OperationObject::SMART_ALBUM_MAP: {
            MediaLibrarySmartAlbumMapOperations smartalbumMapOprn;
            result = smartalbumMapOprn.HandleSmartAlbumMapOperations(operationType, value, rdbStore_, dirQuerySetMap_);
            MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
            break;
        }
        case OperationObject::THUMBNAIL: {
            result = HandleThumbnailOperations(cmd);
            break;
        }
        case OperationObject::BUNDLE_PERMISSION: {
            result = UriPermissionOperations::HandleUriPermOperations(cmd);
            break;
        }
        default: {
            result = MediaLibraryObjectUtils::InsertInDb(cmd);
            MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
            break;
        }
    }
    return result;
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

    string uriString = uri.ToString();
    if (uriString != MEDIALIBRARY_DATA_URI) {
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

    if (uri.ToString().find(MEDIALIBRARY_DATA_URI) == string::npos) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Delete: Not Data ability Uri");
        return E_INVALID_URI;
    }

    MediaLibraryCommand cmd(uri, OperationType::DELETE);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());

    vector<string> devices;
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET: {
            auto ret = MediaLibraryFileOperations::DeleteFileOperation(cmd, dirQuerySetMap_);
            MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
            return ret;
        }
        case OperationObject::FILESYSTEM_DIR:
            // supply a DeleteDirOperation here to replace
            // delete in the HandleDirOperations in Insert function, if need
            break;
        case OperationObject::FILESYSTEM_ALBUM: {
            auto ret = MediaLibraryAlbumOperations::DeleteAlbumOperation(cmd);
            MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
            return ret;
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

    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Update:Input parameter is invalid ");
        return E_INVALID_VALUES;
    }

    MediaLibraryCommand cmd(uri, value);
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
    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
        return;
    }
    thumbnailService_->InterruptBgworker();
}

int32_t MediaLibraryDataManager::GenerateThumbnails()
{
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    if (thumbnailService_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailService_ is null");
        return E_FAIL;
    }
    return thumbnailService_->GenerateThumbnails();
}

int32_t MediaLibraryDataManager::DoAging()
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::DoAging IN");
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
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

shared_ptr<ResultSetBridge> MediaLibraryDataManager::GenThumbnail(const string &uri)
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

    if ((oprnObject != OperationObject::ASSETMAP) && (oprnObject != OperationObject::SMART_ABLUM_ASSETS)) {
        MediaLibraryTracer tracer;
        tracer.Start("QuerySync");
        auto ret = QuerySync(networkId, tableName);
        MEDIA_INFO_LOG("MediaLibraryDataManager QuerySync result = %{private}d", ret);
    }
}

shared_ptr<ResultSetBridge> MediaLibraryDataManager::Query(const Uri &uri,
    const vector<string> &columns, const DataSharePredicates &predicates)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::Query");
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataManager::Query");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Rdb Store is not initialized");
        return nullptr;
    }

    auto whereClause = predicates.GetWhereClause();
    if (!MediaLibraryCommonUtils::CheckWhereClause(whereClause)) {
        MEDIA_ERR_LOG("illegal query whereClause input %{public}s", whereClause.c_str());
        return nullptr;
    }

    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->SetWhereClause(whereClause);
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(predicates.GetOrder());

    string networkId = cmd.GetOprnDevice();
    OperationObject oprnObject = cmd.GetOprnObject();
    NeedQuerySync(networkId, oprnObject);

    shared_ptr<ResultSetBridge> queryResultSet;
    if (cmd.GetOprnObject() == OperationObject::THUMBNAIL) {
        string uriString = uri.ToString();
        if (!ThumbnailService::ParseThumbnailInfo(uriString)) {
            return nullptr;
        }
        tracer.Start("GenThumbnail");
        queryResultSet = GenThumbnail(uriString);
    } else {
        auto absResultSet = QueryRdb(uri, columns, predicates);
        queryResultSet = RdbUtils::ToResultSetBridge(absResultSet);
    }

    return queryResultSet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryDataManager::QueryRdb(const Uri &uri, const vector<string> &columns,
    const DataSharePredicates &predicates)
{
    std::shared_lock<std::shared_mutex> sharedLock(mgrSharedMutex_);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataManager::QueryRdb");
    static const map<OperationObject, string> queryConditionMap {
        { OperationObject::SMART_ALBUM, SMARTALBUM_DB_ID },
        { OperationObject::SMART_ALBUM_MAP, SMARTALBUMMAP_DB_ALBUM_ID },
        { OperationObject::FILESYSTEM_DIR, MEDIA_DATA_DB_ID },
        { OperationObject::ALL_DEVICE, "" },
        { OperationObject::ACTIVE_DEVICE, "" },
        { OperationObject::ASSETMAP, "" },
        { OperationObject::SMART_ABLUM_ASSETS, "" },
        { OperationObject::BUNDLE_PERMISSION, "" },
    };

    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    // MEDIALIBRARY_TABLE just for RdbPredicates
    NativeRdb::RdbPredicates rdbPredicate =  RdbDataShareAdapter::RdbUtils::ToPredicates(predicates,
        MEDIALIBRARY_TABLE);
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(rdbPredicate.GetOrder());

    shared_ptr<AbsSharedResultSet> queryResultSet;
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
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
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
    if (extension_ != nullptr) {
        extension_->NotifyChange(uri);
    }
}

void MediaLibraryDataManager::InitialiseThumbnailService(
    const std::shared_ptr<OHOS::AbilityRuntime::Context> &extensionContext)
{
    if (thumbnailService_ != nullptr) {
        return;
    }
    thumbnailService_ = ThumbnailService::GetInstance();
    if (thumbnailService_ == nullptr) {
        MEDIA_INFO_LOG("MediaLibraryDataManager::InitialiseThumbnailService failed");
    }
    thumbnailService_->Init(rdbStore_, kvStorePtr_, extensionContext);
}

int32_t ScanFileCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path)
{
    auto instance = MediaLibraryDataManager::GetInstance();
    if (instance != nullptr) {
        instance->CreateThumbnailAsync(uri);
    }
    return E_OK;
};
}  // namespace Media
}  // namespace OHOS
