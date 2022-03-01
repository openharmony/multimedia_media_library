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

#include "medialibrary_data_ability.h"

#include <unordered_set>

#include "accesstoken_kit.h"
#include "ipc_singleton.h"
#include "ipc_skeleton.h"
#include "file_ex.h"
#include "sa_mgr_client.h"
#include "string_ex.h"
#include "sys_mgr_client.h"
#include "system_ability_definition.h"
#include "medialibrary_sync_table.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedKv;

namespace OHOS {
namespace Media {
const std::string MediaLibraryDataAbility::PERMISSION_NAME_READ_MEDIA = "ohos.permission.READ_MEDIA";
const std::string MediaLibraryDataAbility::PERMISSION_NAME_WRITE_MEDIA = "ohos.permission.WRITE_MEDIA";
const std::unordered_set<int32_t> UID_FREE_CHECK {
    1006        // file_manager:x:1006:
};
const std::unordered_set<std::string> BUNDLE_FREE_CHECK {
    "com.ohos.medialibrary.MediaScannerAbilityA",
    "ohos.acts.multimedia.mediaLibrary",
    "com.ohos.photos",
    "com.ohos.camerademo"
};
REGISTER_AA(MediaLibraryDataAbility);

void MediaLibraryDataAbility::OnStart(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("MediaLibraryDataAbility::OnStart");
    Ability::OnStart(want);
    InitMediaLibraryRdbStore();
    MEDIA_INFO_LOG("bundleName = %{public}s", bundleName_.c_str());
    auto abilityContext = std::make_unique<MediaLibraryDataAbility>(*this);
    if (abilityContext != nullptr) {
        MediaLibraryDevice::GetInstance()->SetAbilityContext(move(abilityContext));
    }
    SubscribeRdbStoreObserver();
    InitDeviceData();

    if (rdbStore_ != nullptr) {
        MediaLibrarySyncTable syncTable;
        syncTable.SyncPullAllTable(rdbStore_, bundleName_);
    }
    InitialiseKvStore();
}

void MediaLibraryDataAbility::OnStop()
{
    MEDIA_INFO_LOG("MediaLibraryDataAbility::OnStop");
    Ability::OnStop();
    rdbStore_ = nullptr;
    isRdbStoreInitialized = false;

    if (scannerClient_ != nullptr) {
        scannerClient_->Release();
        scannerClient_ = nullptr;
    }

    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(KVSTORE_APPID, kvStorePtr_);
        kvStorePtr_ = nullptr;
    }
    if (deviceStateCallback_ != nullptr && deviceInitCallback_ != nullptr) {
        auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
        deviceManager.UnInitDeviceManager(bundleName_);
        deviceInitCallback_ = nullptr;
        deviceManager.UnRegisterDevStateCallback(bundleName_);
        deviceStateCallback_ = nullptr;
        MediaLibraryDevice::GetInstance()->ClearAllDevices();
    }
    UnSubscribeRdbStoreObserver();
}

MediaLibraryDataAbility::MediaLibraryDataAbility(void)
{
    isRdbStoreInitialized = false;
    rdbStore_ = nullptr;
    kvStorePtr_ = nullptr;
    bundleName_ = DEVICE_BUNDLENAME;
}

MediaLibraryDataAbility::~MediaLibraryDataAbility(void)
{
    if (kvStorePtr_ != nullptr) {
        dataManager_.CloseKvStore(KVSTORE_APPID, kvStorePtr_);
        kvStorePtr_ = nullptr;
    }
}

int32_t MediaLibraryDataCallBack::OnCreate(RdbStore &store)
{
    int32_t error_code = NativeRdb::E_ERROR;
    error_code = store.ExecuteSql(CREATE_MEDIA_TABLE);
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_SMARTALBUM_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_SMARTALBUMMAP_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_DEVICE_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_CATEGORY_SMARTALBUMMAP_TABLE);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_IMAGE_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_VIDEO_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code = store.ExecuteSql(CREATE_AUDIO_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code= store.ExecuteSql(CREATE_ABLUM_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code= store.ExecuteSql(CREATE_SMARTABLUMASSETS_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        error_code= store.ExecuteSql(CREATE_ASSETMAP_VIEW);
    }
    if (error_code == NativeRdb::E_OK) {
        isDistributedTables = true;
    }
    return error_code;
}

int32_t MediaLibraryDataCallBack::OnUpgrade(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
#ifdef RDB_UPGRADE_MOCK
    const std::string ALTER_MOCK_COLUMN = "ALTER TABLE " + MEDIALIBRARY_TABLE +
                                          " ADD COLUMN upgrade_test_column INT DEFAULT 0";
    MEDIA_INFO_LOG("OnUpgrade |Rdb Verison %{public}d => %{public}d", oldVersion, newVersion);
    int32_t error_code = NativeRdb::E_ERROR;
    error_code = store.ExecuteSql(ALTER_MOCK_COLUMN);
    if (error_code != NativeRdb::E_OK) {
        MEDIA_INFO_LOG("Upgrade rdb error %{public}d", error_code);
    }
#endif
    return E_OK;
}

bool MediaLibraryDataCallBack::GetDistributedTables()
{
    return isDistributedTables;
}

int32_t MediaLibraryDataAbility::InitMediaLibraryRdbStore()
{
    MEDIA_INFO_LOG("InitMediaLibraryRdbStore IN |Rdb Verison %{public}d", MEDIA_RDB_VERSION);
    if (isRdbStoreInitialized) {
        return DATA_ABILITY_SUCCESS;
    }

    int32_t errCode(DATA_ABILITY_FAIL);
    string databaseDir = AbilityContext::GetDatabaseDir() + "/" + MEDIA_DATA_ABILITY_DB_NAME;
    RdbStoreConfig config(databaseDir);
    config.SetBundleName(bundleName_);
    config.SetName(MEDIA_DATA_ABILITY_DB_NAME);
    MediaLibraryDataCallBack rdbDataCallBack;

    rdbStore_ = RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("InitMediaRdbStore GetRdbStore is failed ");
        return errCode;
    }

    if (rdbDataCallBack.GetDistributedTables()) {
        auto ret = rdbStore_->SetDistributedTables(
            {MEDIALIBRARY_TABLE, SMARTALBUM_TABLE, SMARTALBUM_MAP_TABLE, CATEGORY_SMARTALBUM_MAP_TABLE});
        MEDIA_INFO_LOG("InitMediaLibraryRdbStore ret = %{public}d", ret);
    }

    isRdbStoreInitialized = true;
    mediaThumbnail_ = std::make_shared<MediaLibraryThumbnail>();
    MEDIA_INFO_LOG("InitMediaLibraryRdbStore SUCCESS");
    return DATA_ABILITY_SUCCESS;
}

std::string MediaLibraryDataAbility::GetType(const Uri &uri)
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

int32_t MediaLibraryDataAbility::Insert(const Uri &uri, const ValuesBucket &value)
{
    if ((!isRdbStoreInitialized) || (value.IsEmpty()) || (rdbStore_ == nullptr)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Insert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
    }
    if (!CheckClientPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        return DATA_ABILITY_PERMISSION_DENIED;
    }
	
    MediaLibrarySyncTable syncTable;
    string insertUri = uri.ToString();
    std::vector<std::string> devices = std::vector<std::string>();
    // If insert uri contains media opearation, follow media operation procedure
    if (insertUri.find(MEDIA_OPERN_KEYWORD) != string::npos) {
        MediaLibraryFileOperations fileOprn;
        MediaLibraryAlbumOperations albumOprn;
        MediaLibrarySmartAlbumOperations smartalbumOprn;
        MediaLibrarySmartAlbumMapOperations smartalbumMapOprn;
        MediaLibraryKvStoreOperations kvStoreOprn;

        string scanPath("");
        int32_t result(DATA_ABILITY_FAIL);
        string operationType = MediaLibraryDataAbilityUtils::GetOperationType(insertUri);
        MEDIA_INFO_LOG("operationType = %{public}s", operationType.c_str());
        if ((operationType == MEDIA_FILEOPRN_CREATEASSET ||
            operationType == MEDIA_ALBUMOPRN_CREATEALBUM) && !CheckFileNameValid(value)) {
            return DATA_ABILITY_FILE_NAME_INVALID;
        }
        if (insertUri.find(MEDIA_FILEOPRN) != string::npos) {
            result = fileOprn.HandleFileOperation(operationType, value, rdbStore_, mediaThumbnail_);
            // After successfull close asset operation, do a scan file
            if ((result >= 0) && (operationType == MEDIA_FILEOPRN_CLOSEASSET)) {
                ScanFile(value, rdbStore_);
            }
            syncTable.SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
        } else if (insertUri.find(MEDIA_ALBUMOPRN) != string::npos) {
            result = albumOprn.HandleAlbumOperations(operationType, value, rdbStore_);
            syncTable.SyncPushTable(rdbStore_, bundleName_, SMARTALBUM_TABLE, devices);
        } else if (insertUri.find(MEDIA_SMARTALBUMOPRN) != string::npos) {
            result = smartalbumOprn.HandleSmartAlbumOperations(operationType, value, rdbStore_);
            syncTable.SyncPushTable(rdbStore_, bundleName_, SMARTALBUM_MAP_TABLE, devices);
        } else if (insertUri.find(MEDIA_SMARTALBUMMAPOPRN) != string::npos) {
            result = smartalbumMapOprn.HandleSmartAlbumMapOperations(operationType, value, rdbStore_);
            syncTable.SyncPushTable(rdbStore_, bundleName_, CATEGORY_SMARTALBUM_MAP_TABLE, devices);
        } else if (insertUri.find(MEDIA_KVSTOREOPRN) != string::npos) {
            result = kvStoreOprn.HandleKvStoreInsertOperations(operationType, value, kvStorePtr_);
        }
        return result;
    }

    // Normal URI scenario
    int64_t outRowId = DATA_ABILITY_FAIL;
    (void)rdbStore_->Insert(outRowId, MEDIALIBRARY_TABLE, value);

    syncTable.SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
    return outRowId;
}

int32_t MediaLibraryDataAbility::Delete(const Uri &uri, const DataAbilityPredicates &predicates)
{
    if (!isRdbStoreInitialized || (rdbStore_ == nullptr)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Delete:Rdb Store is not initialized");
        return DATA_ABILITY_FAIL;
    }

    if (!CheckClientPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        return DATA_ABILITY_PERMISSION_DENIED;
    }
    string uriString = uri.ToString();
    string strDeleteCondition = predicates.GetWhereClause();
    if (strDeleteCondition.empty()) {
        string::size_type pos = uriString.find_last_of('/');
        CHECK_AND_RETURN_RET_LOG((pos != string::npos) && (pos == MEDIALIBRARY_DATA_URI.length()), DATA_ABILITY_FAIL,
            "Invalid index position");

        string strRow = uriString.substr(pos + 1);
        CHECK_AND_RETURN_RET_LOG(MediaLibraryDataAbilityUtils::IsNumber(strRow), DATA_ABILITY_FAIL, "Index not digit");

        strDeleteCondition = MEDIA_DATA_DB_ID + " = " + strRow;
        uriString = uriString.substr(0, pos);
    }

    // After removing the index values, check whether URI is correct
    CHECK_AND_RETURN_RET_LOG(uriString == MEDIALIBRARY_DATA_URI, DATA_ABILITY_FAIL, "Not Data ability Uri");

    vector<string> whereArgs = predicates.GetWhereArgs();
    int32_t deletedRows = DATA_ABILITY_FAIL;
    (void)rdbStore_->Delete(deletedRows, MEDIALIBRARY_TABLE, strDeleteCondition, whereArgs);

    return deletedRows;
}
unique_ptr<AbsSharedResultSet> QueryBySmartTableType(TableType tabletype,
    string strQueryCondition,
    DataAbilityPredicates predicates,
    vector<string> columns,
    std::shared_ptr<NativeRdb::RdbStore> rdbStore)
{
    unique_ptr<AbsSharedResultSet> queryResultSet;
    if (tabletype == TYPE_SMARTALBUM) {
        AbsRdbPredicates mediaLibSAAbsPred(SMARTALBUM_TABLE);
        if (predicates.IsDistinct()) {
            mediaLibSAAbsPred.Distinct();
        }

        mediaLibSAAbsPred.SetWhereClause(strQueryCondition);
        mediaLibSAAbsPred.SetWhereArgs(predicates.GetWhereArgs());
        mediaLibSAAbsPred.Limit(predicates.GetLimit());
        mediaLibSAAbsPred.SetOrder(predicates.GetOrder());

        queryResultSet = rdbStore->Query(mediaLibSAAbsPred, columns);
        CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
    } else if (tabletype == TYPE_SMARTALBUM_MAP) {
        AbsRdbPredicates mediaLibSAMAbsPred(SMARTALBUM_MAP_TABLE);
        if (predicates.IsDistinct()) {
            mediaLibSAMAbsPred.Distinct();
        }

        mediaLibSAMAbsPred.SetWhereClause(strQueryCondition);
        mediaLibSAMAbsPred.SetWhereArgs(predicates.GetWhereArgs());
        mediaLibSAMAbsPred.Limit(predicates.GetLimit());
        mediaLibSAMAbsPred.SetOrder(predicates.GetOrder());

        queryResultSet = rdbStore->Query(mediaLibSAMAbsPred, columns);
        CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
    }
    return queryResultSet;
}

unique_ptr<AbsSharedResultSet> QueryFile(string strQueryCondition,
    DataAbilityPredicates predicates,
    vector<string> columns,
    std::shared_ptr<NativeRdb::RdbStore> rdbStore,
    string networkId)
{
    unique_ptr<AbsSharedResultSet> queryResultSet;
    string tableName = MEDIALIBRARY_TABLE;
    if (!networkId.empty()) {
        tableName = rdbStore->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE);
        MEDIA_INFO_LOG("tableName in %{public}s", tableName.c_str());
    }
    AbsRdbPredicates mediaLibAbsPredFile(tableName);

    if (!networkId.empty()) {
        MEDIA_INFO_LOG("Not empty networkId %{public}s", networkId.c_str());
        std::vector<string> devices = std::vector<string>();
        devices.push_back(networkId);
        mediaLibAbsPredFile.InDevices(devices);
    }
    if (predicates.IsDistinct()) {
        mediaLibAbsPredFile.Distinct();
    }
    mediaLibAbsPredFile.SetWhereClause(strQueryCondition);
    mediaLibAbsPredFile.SetWhereArgs(predicates.GetWhereArgs());
    mediaLibAbsPredFile.Limit(predicates.GetLimit());
    mediaLibAbsPredFile.SetOrder(predicates.GetOrder());
    queryResultSet = rdbStore->Query(mediaLibAbsPredFile, columns);
    return queryResultSet;
}

string obtionCondition(string &strQueryCondition, const vector<string> &whereArgs)
{
    for (string args : whereArgs) {
        size_t pos = strQueryCondition.rfind('?');
        MEDIA_INFO_LOG("obtionCondition pos = %{public}d", (int)pos);
        if (pos != string::npos) {
            MEDIA_INFO_LOG("obtionCondition before = %{public}s", strQueryCondition.c_str());
            strQueryCondition.replace(pos, 1, args);
            MEDIA_INFO_LOG("obtionCondition end = %{public}s", strQueryCondition.c_str());
        }
    }
    return strQueryCondition;
}

unique_ptr<AbsSharedResultSet> QueryAlbum(string strQueryCondition,
    DataAbilityPredicates predicates,
    vector<string> columns,
    std::shared_ptr<NativeRdb::RdbStore> rdbStore,
    string networkId)
{
    unique_ptr<AbsSharedResultSet> queryResultSet;
    if (!networkId.empty()) {
        string tableName = rdbStore->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE);
        MEDIA_INFO_LOG("tableName is %{public}s", tableName.c_str());
        AbsRdbPredicates mediaLibAbsPredAlbum(tableName);
        string isAlbumCondition = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + std::to_string(MEDIA_TYPE_ALBUM) +
            " AND " + std::to_string(MEDIA_TYPE_FILE);
        if (!strQueryCondition.empty()) {
            strQueryCondition = obtionCondition(strQueryCondition, predicates.GetWhereArgs());
            isAlbumCondition = strQueryCondition + " AND " + isAlbumCondition;
        }
        MEDIA_INFO_LOG("QueryAlbum = %{public}s", isAlbumCondition.c_str());
        string countStr = "SELECT count( date_trashed = 0 OR NULL ) AS count";
        queryResultSet = rdbStore->QuerySql(countStr + ",bucket_id,bucket_display_name,self_id,media_type FROM "
        + tableName + " WHERE " + isAlbumCondition +" GROUP BY bucket_id, media_type, bucket_display_name, self_id");
    } else {
            AbsRdbPredicates mediaLibAbsPredAlbum(ABLUM_VIEW_NAME);
        if (strQueryCondition.empty()) {
            queryResultSet = rdbStore->QuerySql("SELECT * FROM " + ABLUM_VIEW_NAME);
        } else {
            if (predicates.IsDistinct()) {
                mediaLibAbsPredAlbum.Distinct();
            }
            mediaLibAbsPredAlbum.SetWhereClause(strQueryCondition);
            mediaLibAbsPredAlbum.SetWhereArgs(predicates.GetWhereArgs());
            mediaLibAbsPredAlbum.Limit(predicates.GetLimit());
            mediaLibAbsPredAlbum.SetOrder(predicates.GetOrder());
            queryResultSet = rdbStore->Query(mediaLibAbsPredAlbum, columns);
        }
    }
    return queryResultSet;
}

unique_ptr<AbsSharedResultSet> QueryDeviceInfo(string strQueryCondition,
    DataAbilityPredicates predicates, vector<string> columns, std::shared_ptr<NativeRdb::RdbStore> rdbStore)
{
    unique_ptr<AbsSharedResultSet> queryResultSet;
    AbsRdbPredicates deviceAbsRdbPredicates(DEVICE_TABLE);
    if (predicates.IsDistinct()) {
        deviceAbsRdbPredicates.Distinct();
    }

    deviceAbsRdbPredicates.SetWhereClause(strQueryCondition);
    deviceAbsRdbPredicates.SetWhereArgs(predicates.GetWhereArgs());
    deviceAbsRdbPredicates.Limit(predicates.GetLimit());
    deviceAbsRdbPredicates.SetOrder(predicates.GetOrder());

    queryResultSet = rdbStore->Query(deviceAbsRdbPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query All Device failed");
    return queryResultSet;
}

unique_ptr<AbsSharedResultSet> QueryByViewType(TableType tabletype,
    string strQueryCondition,
    DataAbilityPredicates predicates,
    vector<string> columns,
    std::shared_ptr<NativeRdb::RdbStore> rdbStore)
{
    unique_ptr<AbsSharedResultSet> queryResultSet;
    if (tabletype == TYPE_ASSETSMAP_TABLE) {
        AbsRdbPredicates mediaLibAbsPredAlbum(ASSETMAP_VIEW_NAME);
        if (strQueryCondition.empty()) {
            queryResultSet = rdbStore->QuerySql("SELECT * FROM " + ASSETMAP_VIEW_NAME);
        } else {
            if (predicates.IsDistinct()) {
                mediaLibAbsPredAlbum.Distinct();
            }
            mediaLibAbsPredAlbum.SetWhereClause(strQueryCondition);
            mediaLibAbsPredAlbum.SetWhereArgs(predicates.GetWhereArgs());
            mediaLibAbsPredAlbum.Limit(predicates.GetLimit());
            mediaLibAbsPredAlbum.SetOrder(predicates.GetOrder());
            queryResultSet = rdbStore->Query(mediaLibAbsPredAlbum, columns);
        }
    } else if (tabletype == TYPE_SMARTALBUMASSETS_TABLE) {
        AbsRdbPredicates mediaLibAbsPredAlbum(SMARTABLUMASSETS_VIEW_NAME);
        if (strQueryCondition.empty()) {
            queryResultSet = rdbStore->QuerySql("SELECT * FROM " + SMARTABLUMASSETS_VIEW_NAME);
        } else {
            if (predicates.IsDistinct()) {
                mediaLibAbsPredAlbum.Distinct();
            }
            mediaLibAbsPredAlbum.SetWhereClause(strQueryCondition);
            mediaLibAbsPredAlbum.SetWhereArgs(predicates.GetWhereArgs());
            mediaLibAbsPredAlbum.Limit(predicates.GetLimit());
            mediaLibAbsPredAlbum.SetOrder(predicates.GetOrder());
            queryResultSet = rdbStore->Query(mediaLibAbsPredAlbum, columns);
        }
    }
    return queryResultSet;
}
void SplitKeyValue(const string& keyValue, string &key, string &value)
{
    string::size_type pos = keyValue.find('=');
    if (string::npos != pos) {
        key = keyValue.substr(0, pos);
        value = keyValue.substr(pos + 1);
    }
}
void SplitKeys(const string& query, vector<string>& keys)
{
    string::size_type pos1 = 0;
    string::size_type pos2 = query.find('&');
    while (string::npos != pos2) {
        keys.push_back(query.substr(pos1, pos2-pos1));
        pos1 = pos2 + 1;
        pos2 = query.find('&', pos1);
    }
    if (pos1 != query.length()) {
        keys.push_back(query.substr(pos1));
    }
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
    SplitKeys(queryKeys, vectorKeys);
    if (vectorKeys.size() != keyWords.size()) {
        MEDIA_ERR_LOG("Parse error keys count %{public}d", (int)vectorKeys.size());
        return false;
    }
    string action;
    int width = 0;
    int height = 0;
    for (uint32_t i = 0; i < vectorKeys.size(); i++) {
        string subKey, subVal;
        SplitKeyValue(vectorKeys[i], subKey, subVal);
        if (subKey.empty()) {
            MEDIA_ERR_LOG("Parse key error [ %{public}s ]", vectorKeys[i].c_str());
            return false;
        }
        if (subKey == MEDIA_OPERN_KEYWORD) {
            action = subVal;
        } else if (subKey == MEDIA_DATA_DB_WIDTH) {
            if (MediaLibraryDataAbilityUtils::IsNumber(subVal)) {
                width = stoi(subVal);
            }
        } else if (subKey == MEDIA_DATA_DB_HEIGHT) {
            if (MediaLibraryDataAbilityUtils::IsNumber(subVal)) {
                height = stoi(subVal);
            }
        }
    }
    MEDIA_INFO_LOG("ParseThumbnailInfo| action [%{public}s] width %{public}d height %{public}d",
        action.c_str(), width, height);
    if (action != MEDIA_DATA_DB_THUMBNAIL || width <= 0 || height <= 0) {
        MEDIA_ERR_LOG("ParseThumbnailInfo | Error args");
        return false;
    }
    space.push_back(width);
    space.push_back(height);
    return true;
}
void GenThumbnail(shared_ptr<RdbStore> rdb,
                  shared_ptr<MediaLibraryThumbnail> thumbnail,
                  string &rowId, vector<int> space, string &networkId)
{
    int width = space[0];
    int height = space[1];
    string filesTableName = MEDIALIBRARY_TABLE;
    if (!networkId.empty()) {
        filesTableName = rdb->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE);
    }

    MEDIA_INFO_LOG("Get filesTableName [ %{public}s ]", filesTableName.c_str());
    ThumbRdbOpt opts = {
        .store = rdb,
        .table = filesTableName,
        .row = rowId
    };
    Size size = {
        .width = width,
        .height = height
    };
    MEDIA_INFO_LOG("Get thumbnail [ %{public}s ]", opts.row.c_str());
    string kvId = thumbnail->GetThumbnailKey(opts, size);
    if (kvId.empty()) {
        MEDIA_ERR_LOG("Get thumbnail error");
    }
}
static void DealWithUriString(string &uriString, TableType &tabletype,
    string &strQueryCondition, string::size_type &pos, string &strRow)
{
    string type = uriString.substr(pos + 1);
    MEDIA_INFO_LOG("MediaLibraryDataAbility uriString type = %{public}s", type.c_str());
    if (type == MEDIA_ALBUMOPRN_QUERYALBUM) {
        tabletype = TYPE_ALBUM_TABLE;
        uriString = MEDIALIBRARY_DATA_URI;
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
        MEDIA_INFO_LOG("MediaLibraryDataAbility tableName = %{public}s", tableName.c_str());
        MEDIA_INFO_LOG("MediaLibraryDataAbility strRow = %{public}s", strRow.c_str());
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
shared_ptr<AbsSharedResultSet> MediaLibraryDataAbility::Query(const Uri &uri,
                                                              const vector<string> &columns,
                                                              const DataAbilityPredicates &predicates)
{
    if ((!isRdbStoreInitialized) || (rdbStore_ == nullptr)) {
        MEDIA_ERR_LOG("Rdb Store is not initialized");
        return nullptr;
    }
    if (!CheckClientPermission(PERMISSION_NAME_READ_MEDIA)) {
        return nullptr;
    }
    unique_ptr<AbsSharedResultSet> queryResultSet;
    TableType tabletype = TYPE_DATA;
    string strRow, uriString = uri.ToString(), strQueryCondition = predicates.GetWhereClause();

    vector<int> space;
    bool thumbnailQuery = ParseThumbnailInfo(uriString, space);
    string networkId = MediaLibraryDataAbilityUtils::GetNetworkIdFromUri(uriString);
    string::size_type pos = uriString.find_last_of('/');
    string type = uriString.substr(pos + 1);
    MEDIA_INFO_LOG("uriString = %{public}s, type = %{public}s, thumbnailQuery %{public}d, Rdb Verison %{public}d",
        uriString.c_str(), type.c_str(), thumbnailQuery, MEDIA_RDB_VERSION);
    DealWithUriString(uriString, tabletype, strQueryCondition, pos, strRow);
    if (thumbnailQuery) {
        GenThumbnail(rdbStore_, mediaThumbnail_, strRow, space, networkId);
    }
    if (tabletype != TYPE_ASSETSMAP_TABLE && tabletype != TYPE_SMARTALBUMASSETS_TABLE) {
        auto ret = QuerySync();
        MEDIA_INFO_LOG("MediaLibraryDataAbility QuerySync result = %{public}d", ret);
    }
    if (tabletype == TYPE_SMARTALBUM || tabletype == TYPE_SMARTALBUM_MAP) {
        queryResultSet = QueryBySmartTableType(tabletype, strQueryCondition, predicates, columns, rdbStore_);
        CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
    } else if (tabletype == TYPE_ASSETSMAP_TABLE || tabletype == TYPE_SMARTALBUMASSETS_TABLE) {
        queryResultSet = QueryByViewType(tabletype, strQueryCondition, predicates, columns, rdbStore_);
    } else if (tabletype == TYPE_ALL_DEVICE || tabletype == TYPE_ACTIVE_DEVICE) {
        queryResultSet = QueryDeviceInfo(strQueryCondition, predicates, columns, rdbStore_);
    } else if (tabletype == TYPE_ALBUM_TABLE) {
        queryResultSet = QueryAlbum(strQueryCondition, predicates, columns, rdbStore_, networkId);
        CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
    } else {
        queryResultSet = QueryFile(strQueryCondition, predicates, columns, rdbStore_, networkId);
        CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
    }
    return queryResultSet;
}

int32_t MediaLibraryDataAbility::Update(const Uri &uri, const ValuesBucket &value,
    const DataAbilityPredicates &predicates)
{
    MEDIA_INFO_LOG("Update");
    if ((!isRdbStoreInitialized) || (rdbStore_ == nullptr) || (value.IsEmpty())) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Update:Input parameter is invalid ");
        return DATA_ABILITY_FAIL;
    }
    if (!CheckClientPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        return DATA_ABILITY_PERMISSION_DENIED;
    }
    MediaLibraryFileOperations fileOprn;
    int32_t changedRows = DATA_ABILITY_FAIL;
    string uriString = uri.ToString();
    vector<string> devices = vector<string>();
    MEDIA_INFO_LOG("Update uriString = %{public}s", uriString.c_str());
    string strUpdateCondition = predicates.GetWhereClause();
    if (strUpdateCondition.empty()) {
        string::size_type pos = uriString.find_last_of('/');
        CHECK_AND_RETURN_RET_LOG((pos != string::npos) && (pos == MEDIALIBRARY_DATA_URI.length()), DATA_ABILITY_FAIL,
            "Invalid index position");

        string strRow = uriString.substr(pos + 1);
        CHECK_AND_RETURN_RET_LOG(MediaLibraryDataAbilityUtils::IsNumber(strRow), DATA_ABILITY_FAIL, "Index not digit");

        uriString = uriString.substr(0, pos);
        strUpdateCondition = MEDIA_DATA_DB_ID + " = " + strRow;
    }
    // After removing the index values, check whether URI is correct

    vector<string> whereArgs = predicates.GetWhereArgs();
    if (uriString.find(MEDIA_SMARTALBUMOPRN) != string::npos) {
        (void)rdbStore_->Update(changedRows, SMARTALBUM_TABLE, value, strUpdateCondition, whereArgs);
    } else if (uriString.find(MEDIA_SMARTALBUMMAPOPRN) != string::npos) {
        (void)rdbStore_->Update(changedRows, SMARTALBUM_MAP_TABLE, value, strUpdateCondition, whereArgs);
    } else {
        if (uriString == MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN
                + "/" + Media::MEDIA_FILEOPRN_MODIFYASSET) {
        int result = fileOprn.HandleFileOperation(MEDIA_FILEOPRN_MODIFYASSET, value, rdbStore_, mediaThumbnail_);
        if (result < 0) {
            return result;
            }
        }
    (void)rdbStore_->Update(changedRows, MEDIALIBRARY_TABLE, value, strUpdateCondition, whereArgs);
    }
    if (changedRows >= 0) {
        MediaLibrarySyncTable syncTable;
        syncTable.SyncPushTable(rdbStore_, bundleName_, MEDIALIBRARY_TABLE, devices);
    }
    return changedRows;
}

int32_t MediaLibraryDataAbility::BatchInsert(const Uri &uri, const vector<ValuesBucket> &values)
{
    string uriString = uri.ToString();
    if ((!isRdbStoreInitialized) || (rdbStore_ == nullptr) || (uriString != MEDIALIBRARY_DATA_URI)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility BatchInsert: Input parameter is invalid");
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

void MediaLibraryDataAbility::ScanFile(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore1)
{
    if (scannerClient_ == nullptr) {
        scannerClient_ = MediaScannerHelperFactory::CreateScannerHelper();
    }

    if (scannerClient_ != nullptr) {
        string actualUri;
        ValueObject valueObject;

        if (values.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
            valueObject.GetString(actualUri);
        }

        string id = MediaLibraryDataAbilityUtils::GetIdFromUri(actualUri);
        string srcPath = MediaLibraryDataAbilityUtils::GetPathFromDb(id, rdbStore1);
        if (!srcPath.empty()) {
            std::shared_ptr<ScanFileCallback> scanFileCb = make_shared<ScanFileCallback>();
            CHECK_AND_RETURN_LOG(scanFileCb != nullptr, "Failed to create scan file callback object");
            auto ret = scannerClient_->ScanFile(srcPath, scanFileCb);
            CHECK_AND_RETURN_LOG(ret == 0, "Failed to initiate scan request");
        }
    }
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
int32_t MediaLibraryDataAbility::OpenFile(const Uri &uri, const std::string &mode)
{
    string uriString = uri.ToString();
    shared_ptr<FileAsset> fileAsset = MediaLibraryDataAbilityUtils::GetFileAssetFromDb(uriString, rdbStore_);
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, DATA_ABILITY_FAIL, "Failed to obtain path from Database");
    bool isWriteMode = MediaLibraryDataAbilityUtils::checkOpenMode(mode);
    if (isWriteMode) {
        if (MediaLibraryDataAbilityUtils::checkFilePending(fileAsset)) {
            MEDIA_ERR_LOG("MediaLibraryDataAbility OpenFile: File is pending");
            return DATA_ABILITY_HAS_OPENED_FAIL;
        }
    }
    string path = MediaFileUtils::UpdatePath(fileAsset->GetPath(), fileAsset->GetUri());
    int32_t fd = fileAsset->OpenAsset(path, mode);
    if (fd < 0) {
        MEDIA_ERR_LOG("open file fd %{public}d, errno %{public}d", fd, errno);
        return DATA_ABILITY_HAS_FD_ERROR;
    }
    if (isWriteMode && fd > 0) {
        int32_t errorCode = MediaLibraryDataAbilityUtils::setFilePending(uriString, true, rdbStore_);
        if (errorCode == DATA_ABILITY_FAIL) {
            fileAsset->CloseAsset(fd);
            MEDIA_ERR_LOG("MediaLibraryDataAbility OpenFile: Set file to pending DB error");
            return DATA_ABILITY_HAS_DB_ERROR;
        }
    }
    MEDIA_INFO_LOG("MediaLibraryDataAbility OpenFile: Success");
    return fd;
}

void MediaLibraryDataAbility::InitDeviceData()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility InitDeviceData rdbStore is null");
        return;
    }
    std::string extra = "";
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    deviceInitCallback_ = std::make_shared<MediaLibraryInitCallback>();
    if (deviceInitCallback_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility MediaLibraryInitCallback failed!");
        return;
    }
    deviceManager.InitDeviceManager(bundleName_, deviceInitCallback_);

    if (!MediaLibraryDevice::GetInstance()->InitDeviceRdbStore(rdbStore_, bundleName_)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility InitDeviceData failed!");
        return;
    }

    deviceStateCallback_ = std::make_shared<MediaLibraryDeviceStateCallback>(rdbStore_, bundleName_);
    if (deviceStateCallback_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility MediaLibraryDeviceStateCallback failed!");
        return;
    }

    if (deviceManager.RegisterDevStateCallback(bundleName_, extra, deviceStateCallback_) != 0) {
        deviceStateCallback_ = nullptr;
        MEDIA_ERR_LOG("MediaLibraryDataAbility RegisterDevStateCallback failed!");
        return;
    }
    MEDIA_INFO_LOG("MediaLibraryDataAbility InitDeviceData OUT");
}

bool MediaLibraryDataAbility::SubscribeRdbStoreObserver()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility SubscribeRdbStoreObserver rdbStore is null");
        return false;
    }
    rdbStoreObs_ = std::make_shared<MediaLibraryRdbStoreObserver>(bundleName_);
    if (rdbStoreObs_ == nullptr) {
        return false;
    }

    DistributedRdb::SubscribeOption option;
    option.mode = DistributedRdb::SubscribeMode::REMOTE;
    bool ret = rdbStore_->Subscribe(option, rdbStoreObs_.get());
    MEDIA_INFO_LOG("MediaLibraryDataAbility Subscribe ret = %d", ret);

    return ret;
}

bool MediaLibraryDataAbility::UnSubscribeRdbStoreObserver()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility UnSubscribeRdbStoreObserver rdbStore is null");
        return false;
    }

    DistributedRdb::SubscribeOption option;
    option.mode = DistributedRdb::SubscribeMode::REMOTE;
    bool ret = rdbStore_->UnSubscribe(option, rdbStoreObs_.get());
    MEDIA_INFO_LOG("MediaLibraryDataAbility UnSubscribe ret = %d", ret);
    if (ret) {
        rdbStoreObs_ = nullptr;
    }

    return ret;
}

bool MediaLibraryDataAbility::QuerySync(const std::string &deviceId ,const std::string &tableName)
{
    if (deviceId.empty() || tableName.empty()) {
        return false;
    }

    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    auto ret = deviceManager.GetLocalDeviceInfo(bundleName_, deviceInfo);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility QuerySync Failed to get local device info.");
        return false;
    }

    if (deviceId == std::string(deviceInfo.deviceId)) {
        return true;
    }

    int32_t syncStatus = DEVICE_SYNCSTATUSING;
    auto result = MediaLibraryDevice::GetInstance()->GetDevicieSyncStatus(deviceId, syncStatus, bundleName_);
    if (result && syncStatus == DEVICE_SYNCSTATUS_COMPLETE) {
        return true;
    }

    std::vector<std::string> devices = { deviceId };
    MediaLibrarySyncTable syncTable;
    return syncTable.SyncPullTable(rdbStore_, bundleName_, tableName, devices);
}

bool MediaLibraryDataAbility::QuerySync()
{
    std::string strQueryCondition = DEVICE_DB_SYNC_STATUS + "=" + std::to_string(DEVICE_SYNCSTATUSING) +
        " AND " + DEVICE_DB_DATE_MODIFIED + "=0";

    std::vector<std::string> columns;
    std::vector<std::string> devices;
    unique_ptr<AbsSharedResultSet> queryResultSet;
    AbsRdbPredicates deviceAbsRdbPredicates(DEVICE_TABLE);
    deviceAbsRdbPredicates.SetWhereClause(strQueryCondition);

    queryResultSet = rdbStore_->Query(deviceAbsRdbPredicates, columns);
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

bool MediaLibraryDataAbility::CheckFileNameValid(const ValuesBucket &value)
{
    ValueObject valueObject;
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
sptr<AppExecFwk::IBundleMgr> GetSysBundleManager_()
{
    auto bundleObj =
        OHOS::DelayedSingleton<SaMgrClient>::GetInstance()->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleObj == nullptr) {
        MEDIA_ERR_LOG("failed to get bundle manager service");
        return nullptr;
    }
    sptr<AppExecFwk::IBundleMgr> bms = iface_cast<AppExecFwk::IBundleMgr>(bundleObj);
    return bms;
}

sptr<AppExecFwk::IBundleMgr> MediaLibraryDataAbility::GetSysBundleManager()
{
    return GetSysBundleManager_();
}

static int GetClientUid()
{
    int uid = IPCSkeleton::GetCallingUid();
    MEDIA_INFO_LOG("GetClientUid: uid is %{public}d ", uid);
    return uid;
}

static std::string GetClientBundle(int uid)
{
    auto bms = GetSysBundleManager_();
    std::string bundleName = "";
    if (bms == nullptr) {
        MEDIA_INFO_LOG("GetClientBundleName bms failed");
        return bundleName;
    }
    auto result = bms->GetBundleNameForUid(uid, bundleName);
    MEDIA_INFO_LOG("GetClientBundleName: bundleName is %{public}s ", bundleName.c_str());
    if (!result) {
        MEDIA_ERR_LOG("GetBundleNameForUid fail");
        return "";
    }
    return bundleName;
}

std::string MediaLibraryDataAbility::GetClientBundleName()
{
    int uid = GetClientUid();
    return GetClientBundle(uid);
}

bool MediaLibraryDataAbility::CheckClientPermission(const std::string& permissionStr)
{
    int uid = GetClientUid();
    if (UID_FREE_CHECK.find(uid) != UID_FREE_CHECK.end()) {
        MEDIA_ERR_LOG("CheckClientPermission: Pass the uid white list");
        return true;
    }

    std::string bundleName = GetClientBundle(uid);
    if (BUNDLE_FREE_CHECK.find(bundleName) != BUNDLE_FREE_CHECK.end()) {
        MEDIA_INFO_LOG("CheckClientPermission: Pass the bundle name white list");
        return true;
    }

    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int res = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        permissionStr);
    if (res != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Query: Have no media permission");
        return false;
    }
    return true;
}

void MediaLibraryDataAbility::InitialiseKvStore()
{
    MEDIA_INFO_LOG("MediaLibraryDataAbility::InitialiseKvStore");
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
        MEDIA_INFO_LOG("MediaLibraryDataAbility::InitialiseKvStore failed %{public}d", status);
    }
}

void ScanFileCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) {}

void MediaLibraryDeviceStateCallback::OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MediaLibraryDevice::GetInstance()->OnDeviceOnline(deviceInfo, bundleName_);

    MediaLibrarySyncTable syncTable;
    std::string deviceId = deviceInfo.deviceId;
    std::vector<std::string> devices = { deviceId };
    syncTable.SyncPullAllTableByDeviceId(rdbStore_, bundleName_, devices);
}

void MediaLibraryDeviceStateCallback::OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MediaLibraryDevice::GetInstance()->OnDeviceOffline(deviceInfo, bundleName_);
}

void MediaLibraryDeviceStateCallback::OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MediaLibraryDevice::GetInstance()->OnDeviceChanged(deviceInfo);
}

void MediaLibraryDeviceStateCallback::OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    MediaLibraryDevice::GetInstance()->OnDeviceReady(deviceInfo);
}

void MediaLibraryInitCallback::OnRemoteDied()
{
    MEDIA_INFO_LOG("MediaLibraryInitCallback OnRemoteDied call");
}

MediaLibraryRdbStoreObserver::MediaLibraryRdbStoreObserver(std::string &bundleName)
{
    bundleName_ = bundleName;
    isNotifyDeviceChange_ = false;

    if (timer_ == nullptr) {
        timer_ = std::make_unique<OHOS::Utils::Timer>(bundleName_);
        timerId_ = timer_->Register(std::bind(&MediaLibraryRdbStoreObserver::NotifyDeviceChange, this),
                                    NOTIFY_TIME_INTERVAL);
        timer_->Setup();
    }
}

MediaLibraryRdbStoreObserver::~MediaLibraryRdbStoreObserver()
{
    if (timer_ != nullptr) {
        timer_->Shutdown();
        timer_->Unregister(timerId_);
        timer_ = nullptr;
    }
}

void MediaLibraryRdbStoreObserver::OnChange(const std::vector<std::string>& devices)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreObserver OnChange call");
    if (devices.empty() || bundleName_.empty()) {
        return;
    }

    for (auto &deviceId : devices) {
        MediaLibraryDevice::GetInstance()->UpdateDevicieSyncStatus(deviceId, DEVICE_SYNCSTATUS_COMPLETE, bundleName_);
        isNotifyDeviceChange_ = true;
    }
}

void MediaLibraryRdbStoreObserver::NotifyDeviceChange()
{
    if (isNotifyDeviceChange_) {
        MediaLibraryDevice::GetInstance()->NotifyDeviceChange();
        isNotifyDeviceChange_ = false;
    }
}
}  // namespace Media
}  // namespace OHOS
