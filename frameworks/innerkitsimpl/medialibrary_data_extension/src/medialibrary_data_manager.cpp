/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "medialibrary_data_manager.h"

#include <unordered_set>

#include "accesstoken_kit.h"
#include "hitrace_meter.h"
#include "bundle_mgr_interface.h"
#include "file_ex.h"
#include "ipc_singleton.h"
#include "media_file_utils.h"
#include "medialibrary_sync_table.h"
#include "ipc_skeleton.h"
#include "sa_mgr_client.h"
#include "string_ex.h"
#include "sys_mgr_client.h"
#include "system_ability_definition.h"
#include "media_scanner.h"
#include "datashare_ext_ability.h"
#include "datashare_ext_ability_context.h"
#include "media_datashare_ext_ability.h"
#include "media_log.h"
#include "rdb_utils.h"
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_object_utils.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedKv;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
namespace {
const std::unordered_set<int32_t> UID_FREE_CHECK {
    1006        // file_manager:x:1006:
};
std::mutex bundleMgrMutex;
}
const std::string MediaLibraryDataManager::PERMISSION_NAME_READ_MEDIA = "ohos.permission.READ_MEDIA";
const std::string MediaLibraryDataManager::PERMISSION_NAME_WRITE_MEDIA = "ohos.permission.WRITE_MEDIA";

std::shared_ptr<MediaLibraryDataManager> MediaLibraryDataManager::instance_ = nullptr;
std::mutex MediaLibraryDataManager::mutex_;

MediaLibraryDataManager::MediaLibraryDataManager(void)
{
    isRdbStoreInitialized = false;
    rdbStore_ = nullptr;
    kvStorePtr_ = nullptr;
    bundleName_ = DEVICE_BUNDLENAME;
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

static DataShare::DataShareExtAbility* MediaDataShareCreator(const std::unique_ptr<Runtime>& runtime)
{
    MEDIA_DEBUG_LOG("MediaLibraryCreator::%{public}s", __func__);
    return MediaDataShareExtAbility::Create(runtime);
}

__attribute__((constructor)) void RegisterDataShareCreator()
{
    MEDIA_DEBUG_LOG("MediaLibraryDataMgr::%{public}s", __func__);
    DataShare::DataShareExtAbility::SetCreator(MediaDataShareCreator);
}

void MediaLibraryDataManager::InitMediaLibraryMgr(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    context_ = context;
    InitMediaLibraryRdbStore();
    MediaLibraryDevice::GetInstance()->SetAbilityContext(move(context));
    InitDeviceData();

    if (rdbStore_ != nullptr) {
        MEDIA_DEBUG_LOG("Distribute StartTrace:SyncPullAllTableTrace");
        StartTrace(HITRACE_TAG_OHOS, "SyncPullAllTableTrace");
        MediaLibrarySyncTable syncTable;
        syncTable.SyncPullAllTable(rdbStore_, bundleName_);
        FinishTrace(HITRACE_TAG_OHOS);
        MEDIA_DEBUG_LOG("Distribute FinishTrace:SyncPullAllTableTrace");
        MakeDirQuerySetMap(dirQuerySetMap_);
    }
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

    StartTrace(HITRACE_TAG_OHOS, "InitDeviceRdbStoreTrace", -1);
    if (!MediaLibraryDevice::GetInstance()->InitDeviceRdbStore(rdbStore_)) {
        MEDIA_ERR_LOG("MediaLibraryDataManager InitDeviceData failed!");
        return;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    MEDIA_INFO_LOG("MediaLibraryDataManager InitDeviceData OUT");
}

void MediaLibraryDataManager::ClearMediaLibraryMgr()
{
    isRdbStoreInitialized = false;
    rdbStore_ = nullptr;
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(KVSTORE_APPID, kvStorePtr_);
        kvStorePtr_ = nullptr;
    }
    if (MediaLibraryDevice::GetInstance()) {
        MediaLibraryDevice::GetInstance()->Stop();
    };
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

int32_t MediaLibraryDataManager::InitMediaLibraryRdbStore()
{
    if (isRdbStoreInitialized) {
        return DATA_ABILITY_SUCCESS;
    }

    MediaLibraryUnistoreManager::GetInstance().Init(context_);
    rdbStore_ = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();

    isRdbStoreInitialized = true;
    mediaThumbnail_ = std::make_shared<MediaLibraryThumbnail>();
    return DATA_ABILITY_SUCCESS;
}

void MediaLibraryDataManager::InitialiseKvStore()
{
    MEDIA_INFO_LOG("MediaLibraryDataManager::InitialiseKvStore");
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

int32_t MediaLibraryDataManager::Insert(const Uri &uri, const DataShareValuesBucket &dataShareValue)
{
    string insertUri = uri.ToString();
    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Insert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
    }

    MediaLibrarySyncTable syncTable;
    std::vector<std::string> devices = std::vector<std::string>();
    int32_t result = DATA_ABILITY_FAIL;
    MediaLibraryCommand cmd(uri, value);
    // boardcast operation
    if (cmd.GetOprnType() == OperationType::SCAN) {
        std::string path = "/storage/media/local/files";
        MediaScannerObj::GetMediaScannerInstance()->ScanDir(path, nullptr);
        return DATA_ABILITY_SUCCESS;
    } else if (cmd.GetOprnType() == OperationType::CREATE) {
        if (!CheckFileNameValid(dataShareValue)) {
            return DATA_ABILITY_FILE_NAME_INVALID;
        }
    }

    string operationType = MediaLibraryDataManagerUtils::GetOperationType(insertUri);
    // for Neusoft:
    // need to do: align operations with function names,
    // like: move 'delete' operations in smartalbum into Delete FUNCTION
    switch(cmd.GetOprnObject()) {
    case OperationObject::FILESYSTEM_ASSET:
    {
        MediaLibraryFileOperations fileOprn;
        return fileOprn.HandleFileOperation(cmd, dirQuerySetMap_);
    }
    case OperationObject::FILESYSTEM_DIR:
    {
        MediaLibraryDirOperations dirOprn;
        result = dirOprn.HandleDirOperations(operationType, value, rdbStore_, dirQuerySetMap_);
        syncTable.SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
        break;
    }
    case OperationObject::FILESYSTEM_ALBUM:
    {
        MediaLibraryAlbumOperations albumOprn;
        return albumOprn.CreateAlbumOperation(cmd);
    }
    case OperationObject::SMART_ALBUM:
    {
        MediaLibrarySmartAlbumOperations smartalbumOprn;
        result = smartalbumOprn.HandleSmartAlbumOperations(operationType, value, rdbStore_);
        syncTable.SyncPushTable(rdbStore_, bundleName_, SMARTALBUM_MAP_TABLE, devices);
        break;
    }
    case OperationObject::SMART_ALBUM_MAP:
    {
        MediaLibrarySmartAlbumMapOperations smartalbumMapOprn;
        result = smartalbumMapOprn.HandleSmartAlbumMapOperations(operationType,
            value, rdbStore_, dirQuerySetMap_);
        syncTable.SyncPushTable(rdbStore_, bundleName_, CATEGORY_SMARTALBUM_MAP_TABLE, devices);
        break;
    }
    case OperationObject::KVSTORE:
    {
        MediaLibraryKvStoreOperations kvStoreOprn;
        result = kvStoreOprn.HandleKvStoreInsertOperations(operationType, value, kvStorePtr_);
        break;
    }
    default:
    {
        // Normal URI scenario
        int64_t outRowId = DATA_ABILITY_FAIL;
        (void)rdbStore_->Insert(outRowId, MEDIALIBRARY_TABLE, value);
        syncTable.SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
        return outRowId;
    }
    }
    return result;
}

int32_t MediaLibraryDataManager::BatchInsert(const Uri &uri, const vector<DataShareValuesBucket> &values)
{
    string uriString = uri.ToString();
    if ((!isRdbStoreInitialized) || (rdbStore_ == nullptr) || (uriString != MEDIALIBRARY_DATA_URI)) {
        MEDIA_ERR_LOG("MediaLibraryDataManager BatchInsert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
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
    MEDIA_INFO_LOG("Delete");
    if (!CheckClientPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        return DATA_ABILITY_PERMISSION_DENIED;
    }

    if (uri.ToString().find(MEDIALIBRARY_DATA_URI) != 0) {
        // uri begin with MEDIALIBRARY_DATA_URI
        MEDIA_ERR_LOG("MediaLibraryDataManager Delete: Not Data ability Uri");
        return DATA_ABILITY_FAIL;
    }

    MediaLibraryCommand cmd(uri, DELETE);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());

    switch (cmd.GetOprnObject()) {
    case OperationObject::FILESYSTEM_ASSET:
    {
        MediaLibraryFileOperations fileOprn;
        return fileOprn.DeleteFileOperation(cmd, dirQuerySetMap_);
    }
    case OperationObject::FILESYSTEM_DIR:
        // for Neusoft:
        // todo: supply a DeleteDirOperation here to replace
        // delete in the HandleDirOperations in Insert function, if need
        break;
    case OperationObject::FILESYSTEM_ALBUM:
    {
        MediaLibraryAlbumOperations albumOprn;
        return albumOprn.DeleteAlbumOperation(cmd);
    }
    default:
        break;
    }

    // for Neusoft:
    // DeleteInfoInDbWithId can finish the default delete of smartalbum and smartmap,
    // so no need to distinct them in switch-case deliberately
    MediaLibraryObjectUtils assetUtils;
    return assetUtils.DeleteInfoInDbWithId(cmd);
}

int32_t MediaLibraryDataManager::Update(const Uri &uri, const DataShareValuesBucket &dataShareValue,
    const DataSharePredicates &predicates)
{
    MEDIA_INFO_LOG("Update");
    ValuesBucket value = RdbUtils::ToValuesBucket(dataShareValue);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Update:Input parameter is invalid ");
        return DATA_ABILITY_FAIL;
    }

    MediaLibraryCommand cmd(uri, value);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());

    switch (cmd.GetOprnObject()) {
    case OperationObject::FILESYSTEM_ASSET:
    {
        MediaLibraryFileOperations fileOprn;
        return fileOprn.ModifyFileOperation(cmd);
    }
    case OperationObject::FILESYSTEM_DIR:
        // for Neusoft:
        // todo: supply a ModifyDirOperation here to replace
        // modify in the HandleDirOperations in Insert function, if need
        break;
    case OperationObject::FILESYSTEM_ALBUM:
    {
        MediaLibraryAlbumOperations albumOprn;
        return albumOprn.ModifyAlbumOperation(cmd);
    }
    default:
        break;
    }
    // for Neusoft:
    // ModifyInfoInDbWithId can finish the default update of smartalbum and smartmap,
    // so no need to distinct them in switch-case deliberately
    MediaLibraryObjectUtils assetUtils;
    return assetUtils.ModifyInfoInDbWithId(cmd);
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
    string &rowId, vector<int> space, string &networkId)
{
    shared_ptr<ResultSetBridge> queryResultSet;
    int width = space[0];
    int height = space[1];
    string filesTableName = MEDIALIBRARY_TABLE;

    if (!networkId.empty()) {
        StartTrace(HITRACE_TAG_OHOS, "rdb->ObtainDistributedTableName");
        filesTableName = rdb->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE);
        FinishTrace(HITRACE_TAG_OHOS);
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
    StartTrace(HITRACE_TAG_OHOS, "thumbnail->GetThumbnailKey");
    queryResultSet = thumbnail->GetThumbnailKey(opts, size);
    FinishTrace(HITRACE_TAG_OHOS);

    return queryResultSet;
}

static void DealWithUriString(string &uriString, TableType &tabletype,
    string &strQueryCondition, string::size_type &pos, string &strRow)
{
    string type = uriString.substr(pos + 1);
    MEDIA_INFO_LOG("MediaLibraryDataManager uriString: %{public}s type: %{public}s", uriString.c_str(), type.c_str());
    if (type == MEDIA_ALBUMOPRN_QUERYALBUM) {
        tabletype = TYPE_ALBUM_TABLE;
        uriString = MEDIALIBRARY_DATA_URI;
    } else if (uriString == MEDIALIBRARY_DIRECTORY_URI) {
        tabletype = TYPE_DIR_TABLE;
    } else if (uriString == MEDIALIBRARY_DATA_URI + "/"
               + MEDIA_ALBUMOPRN_QUERYALBUM + "/" + SMARTABLUMASSETS_VIEW_NAME) {
        tabletype = TYPE_SMARTALBUMASSETS_TABLE;
        uriString = MEDIALIBRARY_SMARTALBUM_URI;
    } else if (uriString == MEDIALIBRARY_DATA_URI + "/"
               + MEDIA_ALBUMOPRN_QUERYALBUM + "/" + ASSETMAP_VIEW_NAME) {
        tabletype = TYPE_ASSETSMAP_TABLE;
        uriString = MEDIALIBRARY_SMARTALBUM_URI;
    } else if (uriString == MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYALLDEVICE) {
        tabletype = TYPE_ALL_DEVICE;
        uriString = MEDIALIBRARY_DATA_URI;
    } else if (uriString == MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYACTIVEDEVICE) {
        tabletype = TYPE_ACTIVE_DEVICE;
        uriString = MEDIALIBRARY_DATA_URI;
    } else if (strQueryCondition.empty() && pos != string::npos) {
        strRow = type;
        uriString = uriString.substr(0, pos);
        string::size_type posTable = uriString.find_last_of('/');
        string tableName = uriString.substr(posTable + 1);
        MEDIA_INFO_LOG("MediaLibraryDataManager tableName = %{private}s", tableName.c_str());
        MEDIA_INFO_LOG("MediaLibraryDataManager strRow = %{private}s", strRow.c_str());
        if (SMARTALBUM_TABLE.compare(tableName) == 0) {
            tabletype = TYPE_SMARTALBUM;
            strQueryCondition = SMARTALBUM_DB_ID + " = " + strRow;
        } else if (SMARTALBUM_MAP_TABLE.compare(tableName) == 0) {
            tabletype = TYPE_SMARTALBUM_MAP;
            strQueryCondition = SMARTALBUMMAP_DB_ALBUM_ID + " = " + strRow;
        } else {
            tabletype = TYPE_DATA;
            strQueryCondition = MEDIA_DATA_DB_ID + " = " + strRow;
        }
    }
}

void MediaLibraryDataManager::NeedQuerySync(const string &networkId, TableType tabletype)
{
    if (!networkId.empty() && (tabletype != TYPE_ASSETSMAP_TABLE) && (tabletype != TYPE_SMARTALBUMASSETS_TABLE)) {
        StartTrace(HITRACE_TAG_OHOS, "QuerySync");
        auto ret = QuerySync();
        FinishTrace(HITRACE_TAG_OHOS);
        MEDIA_INFO_LOG("MediaLibraryDataManager QuerySync result = %{private}d", ret);
    }
}

shared_ptr<ResultSetBridge> MediaLibraryDataManager::Query(const Uri &uri,
    const vector<string> &columns, const DataSharePredicates &predicates)
{
    StartTrace(HITRACE_TAG_OHOS, "MediaLibraryDataManager::Query");
    if ((!isRdbStoreInitialized) || (rdbStore_ == nullptr)) {
        MEDIA_ERR_LOG("Rdb Store is not initialized");
        return nullptr;
    }
    StartTrace(HITRACE_TAG_OHOS, "CheckClientPermission");
    if (!CheckClientPermission(PERMISSION_NAME_READ_MEDIA)) {
        return nullptr;
    }
    FinishTrace(HITRACE_TAG_OHOS);
    shared_ptr<ResultSetBridge> queryResultSet;
    TableType tabletype = TYPE_DATA;
    string strRow, uriString = uri.ToString();
    string strQueryCondition = predicates.GetWhereClause();
    vector<int> space;
    bool thumbnailQuery = ParseThumbnailInfo(uriString, space);
    string::size_type pos = uriString.find_last_of('/');
    string type = uriString.substr(pos + 1);
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uriString);
    MEDIA_DEBUG_LOG("uriString = %{private}s, type = %{private}s, thumbnailQuery %{private}d, Rdb Verison %{private}d",
        uriString.c_str(), type.c_str(), thumbnailQuery, MEDIA_RDB_VERSION);
    DealWithUriString(uriString, tabletype, strQueryCondition, pos, strRow);
    NeedQuerySync(networkId, tabletype);
    if (thumbnailQuery) {
        StartTrace(HITRACE_TAG_OHOS, "GenThumbnail");
        queryResultSet = GenThumbnail(rdbStore_, mediaThumbnail_, strRow, space, networkId);
        FinishTrace(HITRACE_TAG_OHOS);
    } else {
        auto absResultSet = QueryRdb(uri, columns, predicates);
        queryResultSet = RdbUtils::ToResultSetBridge(absResultSet);
    }

    FinishTrace(HITRACE_TAG_OHOS);

    return queryResultSet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryDataManager::QueryRdb(const Uri &uri, const vector<string> &columns,
    const DataSharePredicates &predicates)
{
    StartTrace(HITRACE_TAG_OHOS, "MediaLibraryDataManager::QueryRdb");
    MediaLibraryCommand cmd(uri, QUERY);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(predicates.GetOrder());

    shared_ptr<AbsSharedResultSet> queryResultSet;
    TableType tabletype = TYPE_DATA;
    string strRow, uriString = uri.ToString(), strQueryCondition = predicates.GetWhereClause();
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uriString);
    string::size_type pos = uriString.find_last_of('/');

    DealWithUriString(uriString, tabletype, strQueryCondition, pos, strRow);
    MediaLibraryObjectUtils assetUtils;
    if (tabletype == TYPE_SMARTALBUM) {
        queryResultSet = assetUtils.QueryWithCondition(cmd, columns, SMARTALBUM_DB_ID);
    } else if (tabletype == TYPE_SMARTALBUM_MAP) {
        queryResultSet = assetUtils.QueryWithCondition(cmd, columns, SMARTALBUMMAP_DB_ALBUM_ID);
    } else if (tabletype == TYPE_ASSETSMAP_TABLE || tabletype == TYPE_SMARTALBUMASSETS_TABLE) {
        queryResultSet = assetUtils.QueryView(cmd, columns);
    } else if (tabletype == TYPE_ALL_DEVICE || tabletype == TYPE_ACTIVE_DEVICE) {
        queryResultSet = assetUtils.QueryWithCondition(cmd, columns);
    } else if (tabletype == TYPE_ALBUM_TABLE || cmd.GetOprnObject() == OperationObject::MEDIA_VOLUME) {
        MediaLibraryAlbumOperations albumOprn;
        queryResultSet = albumOprn.QueryAlbumOperation(cmd, columns);
    } else if (tabletype == TYPE_DIR_TABLE) {
        queryResultSet = assetUtils.QueryWithCondition(cmd, columns, MEDIA_DATA_DB_ID);
    } else {
        StartTrace(HITRACE_TAG_OHOS, "QueryFile");
        MediaLibraryFileOperations fileOprn;
        queryResultSet = fileOprn.QueryFileOperation(cmd, columns);
        FinishTrace(HITRACE_TAG_OHOS);
    }
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
    FinishTrace(HITRACE_TAG_OHOS);
    return queryResultSet;
}

bool MediaLibraryDataManager::QuerySync(const std::string &deviceId, const std::string &tableName)
{
    if (deviceId.empty() || tableName.empty()) {
        return false;
    }

    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    auto ret = deviceManager.GetLocalDeviceInfo(bundleName_, deviceInfo);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("MediaLibraryDataManager QuerySync Failed to get local device info.");
        return false;
    }

    if (deviceId == std::string(deviceInfo.deviceId)) {
        return true;
    }

    int32_t syncStatus = DEVICE_SYNCSTATUSING;
    auto result = MediaLibraryDevice::GetInstance()->GetDevicieSyncStatus(deviceId, syncStatus);
    if (result && syncStatus == DEVICE_SYNCSTATUS_COMPLETE) {
        return true;
    }

    std::vector<std::string> devices = { deviceId };
    MediaLibrarySyncTable syncTable;
    return syncTable.SyncPullTable(rdbStore_, bundleName_, tableName, devices);
}

bool MediaLibraryDataManager::QuerySync()
{
    std::string strQueryCondition = DEVICE_DB_SYNC_STATUS + "=" + std::to_string(DEVICE_SYNCSTATUSING) +
        " AND " + DEVICE_DB_DATE_MODIFIED + "=0";

    std::vector<std::string> columns;
    std::vector<std::string> devices;
    AbsRdbPredicates deviceDataSharePredicates(DEVICE_TABLE);
    deviceDataSharePredicates.SetWhereClause(strQueryCondition);

    auto queryResultSet = rdbStore_->Query(deviceDataSharePredicates, columns);
    if (queryResultSet == nullptr) {
        return false;
    }
    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndexId;
        std::string deviceId;
        queryResultSet->GetColumnIndex(DEVICE_DB_DEVICEID, columnIndexId);
        queryResultSet->GetString(columnIndexId, deviceId);

        if (!deviceId.empty()) {
            devices.push_back(deviceId);
        }
    }

    if (devices.empty()) {
        return true;
    }

    MediaLibrarySyncTable syncTable;
    return syncTable.SyncPullAllTableByDeviceId(rdbStore_, bundleName_, devices);
}

/**
 * @brief
 * @param uri
 * @param  mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
 * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
 * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing data,
 *  or "rwt" for read and write access that truncates any existing file.
 * /
 * @return int32_t
 */
int32_t MediaLibraryDataManager::OpenFile(const Uri &uri, const std::string &mode)
{
    MediaLibraryCommand cmd(uri, OPEN);
    MediaLibraryObjectUtils assetUtils;
    return assetUtils.OpenFile(cmd, mode);
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

}  // namespace Media
}  // namespace OHOS
