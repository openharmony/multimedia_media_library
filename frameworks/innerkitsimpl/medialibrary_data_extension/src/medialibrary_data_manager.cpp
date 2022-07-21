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

#include "abs_rdb_predicates.h"
#include "bundle_mgr_interface.h"
#include "datashare_abs_result_set.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "media_datashare_ext_ability.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_device.h"
#include "medialibrary_device_info.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_kvstore_operations.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "medialibrary_sync_table.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "sa_mgr_client.h"
#include "system_ability_definition.h"
#include "timer.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedKv;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

namespace {
const OHOS::DistributedKv::AppId KVSTORE_APPID = {"com.ohos.medialibrary.medialibrarydata"};
const OHOS::DistributedKv::StoreId KVSTORE_STOREID = {"ringtone"};
};

namespace OHOS {
namespace Media {
namespace {
std::mutex bundleMgrMutex;
}

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

void MediaLibraryDataManager::InitMediaLibraryMgr(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    std::lock_guard<std::mutex> lock(mgrMutex_);
    refCnt_++;
    context_ = context;
    InitMediaLibraryRdbStore();
    InitDeviceData();

    MakeDirQuerySetMap(dirQuerySetMap_);
    InitialiseKvStore();

    // scan the media dir
    std::string srcPath = ROOT_MEDIA_DIR;
    MediaScannerObj::GetMediaScannerInstance()->ScanDir(srcPath, nullptr);
}

void MediaLibraryDataManager::InitDeviceData()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataManager InitDeviceData rdbStore is null");
        return;
    }

    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "InitDeviceRdbStoreTrace", -1);
    if (!MediaLibraryDevice::GetInstance()->InitDeviceRdbStore(rdbStore_)) {
        MEDIA_ERR_LOG("MediaLibraryDataManager InitDeviceData failed!");
    }
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
}

void MediaLibraryDataManager::ClearMediaLibraryMgr()
{
    std::lock_guard<std::mutex> lock(mgrMutex_);
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

    mediaThumbnail_ = std::make_shared<MediaLibraryThumbnail>();
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
        .autoSync = false,
        .kvStoreType = KvStoreType::SINGLE_VERSION
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
    string getTypeUri = uri.ToString();
    // If get uri contains media operation keyword, follow media operation procedure
    if (getTypeUri.find(MEDIA_OPERN_KEYWORD) != string::npos) {
        MediaLibraryKvStoreOperations kvStoreOprn;

        if (getTypeUri.find(MEDIA_KVSTOREOPRN) != string::npos) {
            return kvStoreOprn.HandleKvStoreGetOperations(getTypeUri, kvStorePtr_);
        }
    }
    return "";
}

void MediaLibraryDataManager::MakeDirQuerySetMap(unordered_map<string, DirAsset> &outDirQuerySetMap)
{
    int32_t count = -1;
    int32_t dirTypeVal = -1;
    int32_t columnIndexDir, columnIndexMedia, columnIndexEx, columnIndexDirType;
    string dirVal, mediaVal, exVal;
    vector<string> columns, selectionArgs;
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

    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Insert: Input parameter is invalid");
        return E_INVALID_VALUES;
    }

    MediaLibraryCommand cmd(uri, value);
    // boardcast operation
    if (cmd.GetOprnType() == OperationType::SCAN) {
        string scanPath = ROOT_MEDIA_DIR;
        return MediaScannerObj::GetMediaScannerInstance()->ScanDir(scanPath, nullptr);
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
            MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName_, SMARTALBUM_MAP_TABLE, devices);
            break;
        }
        case OperationObject::SMART_ALBUM_MAP: {
            MediaLibrarySmartAlbumMapOperations smartalbumMapOprn;
            result = smartalbumMapOprn.HandleSmartAlbumMapOperations(operationType, value, rdbStore_, dirQuerySetMap_);
            MediaLibrarySyncTable::SyncPushTable(rdbStore_, bundleName_, CATEGORY_SMARTALBUM_MAP_TABLE, devices);
            break;
        }
        case OperationObject::KVSTORE: {
            MediaLibraryKvStoreOperations kvStoreOprn;
            result = kvStoreOprn.HandleKvStoreInsertOperations(operationType, value, kvStorePtr_);
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

int32_t MediaLibraryDataManager::BatchInsert(const Uri &uri, const vector<DataShareValuesBucket> &values)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::BatchInsert");

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

    if (uri.ToString().find(MEDIALIBRARY_DATA_URI) == string::npos) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Delete: Not Data ability Uri");
        return E_INVALID_URI;
    }

    MediaLibraryCommand cmd(uri, OperationType::DELETE);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());

    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_ASSET: {
            return MediaLibraryFileOperations::DeleteFileOperation(cmd, dirQuerySetMap_);
        }
        case OperationObject::FILESYSTEM_DIR:
            // supply a DeleteDirOperation here to replace
            // delete in the HandleDirOperations in Insert function, if need
            break;
        case OperationObject::FILESYSTEM_ALBUM: {
            return MediaLibraryAlbumOperations::DeleteAlbumOperation(cmd);
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
            if (ret != E_SUCCESS) {
                return ret;
            }
            break;
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

bool ParseThumbnailInfo(string &uriString, vector<int> &space)
{
    string::size_type pos = uriString.find_last_of('?');
    string queryKeys;
    if (string::npos == pos) {
        return false;
    }
    vector<string> keyWords = {
        MEDIA_OPERN_KEYWORD,
        MEDIA_DATA_DB_WIDTH,
        MEDIA_DATA_DB_HEIGHT
    };
    queryKeys = uriString.substr(pos + 1);
    uriString = uriString.substr(0, pos);
    vector<string> vectorKeys;
    MediaLibraryDataManagerUtils::SplitKeys(queryKeys, vectorKeys);
    if (vectorKeys.size() != keyWords.size()) {
        MEDIA_ERR_LOG("Parse error keys count %{private}d", (int)vectorKeys.size());
        return false;
    }
    string action;
    int width = 0;
    int height = 0;
    for (uint32_t i = 0; i < vectorKeys.size(); i++) {
        string subKey, subVal;
        MediaLibraryDataManagerUtils::SplitKeyValue(vectorKeys[i], subKey, subVal);
        if (subKey.empty()) {
            MEDIA_ERR_LOG("Parse key error [ %{private}s ]", vectorKeys[i].c_str());
            return false;
        }
        if (subKey == MEDIA_OPERN_KEYWORD) {
            action = subVal;
        } else if (subKey == MEDIA_DATA_DB_WIDTH) {
            if (MediaLibraryDataManagerUtils::IsNumber(subVal)) {
                width = stoi(subVal);
            }
        } else if (subKey == MEDIA_DATA_DB_HEIGHT) {
            if (MediaLibraryDataManagerUtils::IsNumber(subVal)) {
                height = stoi(subVal);
            }
        }
    }
    MEDIA_INFO_LOG("ParseThumbnailInfo| action [%{private}s] width %{private}d height %{private}d",
        action.c_str(), width, height);
    if (action != MEDIA_DATA_DB_THUMBNAIL || width <= 0 || height <= 0) {
        MEDIA_ERR_LOG("ParseThumbnailInfo | Error args");
        return false;
    }
    space.push_back(width);
    space.push_back(height);
    return true;
}

shared_ptr<ResultSetBridge> GenThumbnail(shared_ptr<RdbStore> rdb,
    shared_ptr<MediaLibraryThumbnail> thumbnail,
    const string &rowId, vector<int> space, string &networkId)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::GenThumbnail");

    shared_ptr<ResultSetBridge> queryResultSet;
    int width = space[0];
    int height = space[1];
    string filesTableName = MEDIALIBRARY_TABLE;

    if (!networkId.empty()) {
        StartTrace(HITRACE_TAG_FILEMANAGEMENT, "rdb->ObtainDistributedTableName");
        filesTableName = rdb->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE);
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    }

    ThumbRdbOpt opts = {
        .store = rdb,
        .table = filesTableName,
        .row = rowId
    };
    Size size = {
        .width = width,
        .height = height
    };

    MEDIA_INFO_LOG("Get thumbnail [ %{private}s ], width %{private}d", opts.row.c_str(), size.width);
    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "thumbnail->GetThumbnailKey");
    queryResultSet = thumbnail->GetThumbnailKey(opts, size);
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);

    return queryResultSet;
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
        StartTrace(HITRACE_TAG_FILEMANAGEMENT, "QuerySync");
        auto ret = QuerySync(networkId, tableName);
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        MEDIA_INFO_LOG("MediaLibraryDataManager QuerySync result = %{private}d", ret);
    }
}

shared_ptr<ResultSetBridge> MediaLibraryDataManager::Query(const Uri &uri,
    const vector<string> &columns, const DataSharePredicates &predicates)
{
    MEDIA_DEBUG_LOG("MediaLibraryDataManager::Query");
    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "MediaLibraryDataManager::Query");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Rdb Store is not initialized");
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        return nullptr;
    }

    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(predicates.GetOrder());

    string uriString = uri.ToString();
    string networkId = cmd.GetOprnDevice();
    OperationObject oprnObject = cmd.GetOprnObject();
    NeedQuerySync(networkId, oprnObject);

    shared_ptr<ResultSetBridge> queryResultSet;
    vector<int> space;
    bool thumbnailQuery = ParseThumbnailInfo(uriString, space);
    MEDIA_DEBUG_LOG("uriString = %{private}s, thumbnailQuery %{private}d, Rdb Verison %{private}d",
        uriString.c_str(), thumbnailQuery, MEDIA_RDB_VERSION);
    if (thumbnailQuery) {
        StartTrace(HITRACE_TAG_FILEMANAGEMENT, "GenThumbnail");
        string rowId = MediaLibraryDataManagerUtils::GetIdFromUri(uriString);
        queryResultSet = GenThumbnail(rdbStore_, mediaThumbnail_, rowId, space, networkId);
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    } else {
        auto absResultSet = QueryRdb(uri, columns, predicates);
        queryResultSet = RdbUtils::ToResultSetBridge(absResultSet);
    }

    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);

    return queryResultSet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryDataManager::QueryRdb(const Uri &uri, const vector<string> &columns,
    const DataSharePredicates &predicates)
{
    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "MediaLibraryDataManager::QueryRdb");
    static const map<OperationObject, string> queryConditionMap {
        { OperationObject::SMART_ALBUM, SMARTALBUM_DB_ID },
        { OperationObject::SMART_ALBUM_MAP, SMARTALBUMMAP_DB_ALBUM_ID },
        { OperationObject::FILESYSTEM_DIR, MEDIA_DATA_DB_ID },
        { OperationObject::ALL_DEVICE, "" },
        { OperationObject::ACTIVE_DEVICE, "" },
        { OperationObject::ASSETMAP, "" },
        { OperationObject::SMART_ABLUM_ASSETS, "" },
    };

    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(predicates.GetOrder());

    shared_ptr<AbsSharedResultSet> queryResultSet;
    OperationObject oprnObject = cmd.GetOprnObject();
    auto it = queryConditionMap.find(oprnObject);
    if (it != queryConditionMap.end()) {
        queryResultSet = MediaLibraryObjectUtils::QueryWithCondition(cmd, columns, it->second);
    } else if (oprnObject == OperationObject::FILESYSTEM_ALBUM || oprnObject == OperationObject::MEDIA_VOLUME) {
        queryResultSet = MediaLibraryAlbumOperations::QueryAlbumOperation(cmd, columns);
    } else {
        StartTrace(HITRACE_TAG_FILEMANAGEMENT, "QueryFile");
        queryResultSet = MediaLibraryFileOperations::QueryFileOperation(cmd, columns);
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    }
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
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
    DataShareValueObject valueObject;
    string displayName("");
    if (!value.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        return false;
    }
    valueObject.GetString(displayName);

    if (displayName.empty()) {
        return false;
    }

    if (displayName.at(0) == '.') {
        std::string bundleName = GetClientBundleName();
        if (IsSameTextStr(displayName, ".nofile") && IsSameTextStr(bundleName, "fms_service")) {
            return true;
        }
        return false;
    }
    return true;
}

sptr<AppExecFwk::IBundleMgr> MediaLibraryDataManager::GetSysBundleManager()
{
    if (bundleMgr_ == nullptr) {
        std::lock_guard<std::mutex> lock(bundleMgrMutex);
        if (bundleMgr_ == nullptr) {
            auto saMgr = OHOS::DelayedSingleton<SaMgrClient>::GetInstance();
            if (saMgr == nullptr) {
                MEDIA_ERR_LOG("failed to get SaMgrClient::GetInstance");
                return nullptr;
            }
            auto bundleObj = saMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
            if (bundleObj == nullptr) {
                MEDIA_ERR_LOG("failed to get GetSystemAbility");
                return nullptr;
            }
            auto bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(bundleObj);
            if (bundleMgr == nullptr) {
                MEDIA_ERR_LOG("failed to iface_cast");
                return nullptr;
            }
            bundleMgr_ = bundleMgr;
        }
    }
    return bundleMgr_;
}

std::string MediaLibraryDataManager::GetClientBundle(int uid)
{
    auto bms = GetSysBundleManager();
    std::string bundleName = "";
    if (bms == nullptr) {
        MEDIA_INFO_LOG("GetClientBundleName bms failed");
        return bundleName;
    }
    auto result = bms->GetBundleNameForUid(uid, bundleName);
    MEDIA_INFO_LOG("uid %{private}d bundleName is %{private}s ", uid, bundleName.c_str());
    if (!result) {
        MEDIA_ERR_LOG("GetBundleNameForUid fail");
        return "";
    }
    return bundleName;
}

std::string MediaLibraryDataManager::GetClientBundleName()
{
    int uid = IPCSkeleton::GetCallingUid();
    return GetClientBundle(uid);
}

void MediaLibraryDataManager::NotifyChange(const Uri &uri)
{
    if (extension_ != nullptr) {
        extension_->NotifyChange(uri);
    }
}
}  // namespace Media
}  // namespace OHOS
