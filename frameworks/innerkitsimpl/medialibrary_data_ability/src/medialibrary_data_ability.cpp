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

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
REGISTER_AA(MediaLibraryDataAbility);

void MediaLibraryDataAbility::OnStart(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("MediaLibraryDataAbility::OnStart");
    Ability::OnStart(want);
    InitMediaLibraryRdbStore();
}

void MediaLibraryDataAbility::OnStop()
{
    MEDIA_INFO_LOG("MediaLibraryDataAbility::OnStop");
    Ability::OnStop();
    rdbStore = nullptr;
    isRdbStoreInitialized = false;

    if (scannerClient_ != nullptr) {
        scannerClient_->Release();
        scannerClient_ = nullptr;
    }
}

MediaLibraryDataAbility::MediaLibraryDataAbility(void)
{
    isRdbStoreInitialized = false;
    rdbStore = nullptr;
}

MediaLibraryDataAbility::~MediaLibraryDataAbility(void) {}

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
    return error_code;
}

int32_t MediaLibraryDataCallBack::OnUpgrade(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
    return E_OK;
}

int32_t MediaLibraryDataAbility::InitMediaLibraryRdbStore()
{
    if (isRdbStoreInitialized) {
        return DATA_ABILITY_SUCCESS;
    }

    int32_t errCode(DATA_ABILITY_FAIL);
    RdbStoreConfig config(MEDIA_DATA_ABILITY_DB_NAME);
    MediaLibraryDataCallBack rdbDataCallBack;

    rdbStore = RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);   
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility::InitMediaRdbStore GetRdbStore is failed ");
        return errCode;
    }

    isRdbStoreInitialized = true;
    MEDIA_INFO_LOG("DATA_ABILITY_SUCCESS");
    return DATA_ABILITY_SUCCESS;
}
int32_t MediaLibraryDataAbility::Insert(const Uri &uri, const ValuesBucket &value)
{
    MEDIA_INFO_LOG("MediaLibraryDataAbility Insert: IN");
    if ((!isRdbStoreInitialized) || (value.IsEmpty()) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Insert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
    }
    
    string insertUri = uri.ToString();
    MEDIA_INFO_LOG("insertUri = %{public}s",insertUri.c_str());
    // If insert uri contains media opearation, follow media operation procedure
    if (insertUri.find(MEDIA_OPERN_KEYWORD) != string::npos) {
        MediaLibraryFileOperations fileOprn;
        MediaLibraryAlbumOperations albumOprn;
        MediaLibrarySmartAlbumOperations smartalbumOprn;
        MediaLibrarySmartAlbumMapOperations smartalbumMapOprn;
        string scanPath("");
        int32_t result(DATA_ABILITY_FAIL);
        string operationType = MediaLibraryDataAbilityUtils::GetOperationType(insertUri);
        MEDIA_INFO_LOG("operationType = %{public}s", operationType.c_str());
        if (insertUri.find(MEDIA_FILEOPRN) != string::npos) {
            result = fileOprn.HandleFileOperation(operationType, value, rdbStore);
            MEDIA_INFO_LOG("HandleFileOperation result = %{public}d", result);
            // After successfull close asset operation, do a scan file
            if ((result >= 0) && (operationType == MEDIA_FILEOPRN_CLOSEASSET)) {
                ScanFile(value, rdbStore);
            }
        } else if (insertUri.find(MEDIA_ALBUMOPRN) != string::npos) {
            result = albumOprn.HandleAlbumOperations(operationType, value, rdbStore);
        } else if (insertUri.find(MEDIA_SMARTALBUMOPRN) != string::npos) {
            result = smartalbumOprn.HandleSmartAlbumOperations(operationType, value, smartAlbumrdbStore);
        } else if (insertUri.find(MEDIA_SMARTALBUMMAPOPRN) != string::npos){
            result = smartalbumMapOprn.HandleSmartAlbumMapOperations(operationType, value, smartAlbumMaprdbStore);
        } else {
            MEDIA_ERR_LOG("no insertUri = %{public}s",insertUri.c_str());
        }
        MEDIA_INFO_LOG("MediaLibraryDataAbility Insert: MEDIA_OPERN_KEYWORD END");
        return result;
    }

    // Normal URI scenario
    MEDIA_INFO_LOG("MediaLibraryDataAbility Insert: Normal URI scenario");
    int64_t outRowId = DATA_ABILITY_FAIL;
    (void)rdbStore->Insert(outRowId, MEDIALIBRARY_TABLE, value);
    MEDIA_INFO_LOG("no outRowId = %{public}lld", outRowId);
    MEDIA_INFO_LOG("MediaLibraryDataAbility Insert: END");
    return outRowId;
}

int32_t MediaLibraryDataAbility::Delete(const Uri &uri, const DataAbilityPredicates &predicates)
{
    if (!isRdbStoreInitialized || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Delete:Rdb Store is not initialized");
        return DATA_ABILITY_FAIL;
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
    (void)rdbStore->Delete(deletedRows, MEDIALIBRARY_TABLE, strDeleteCondition, whereArgs);

    return deletedRows;
}

shared_ptr<AbsSharedResultSet> MediaLibraryDataAbility::Query(const Uri &uri, const vector<string> &columns,
    const DataAbilityPredicates &predicates)
{
    if ((!isRdbStoreInitialized) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Query:Rdb Store is not initialized");
        return nullptr;
    }

    string uriString = uri.ToString();
    unique_ptr<AbsSharedResultSet> queryResultSet;
    string strRow;
    TableType tabletype;
    string strQueryCondition = predicates.GetWhereClause();
    if (uriString == MEDIALIBRARY_DATA_URI+"/"+MEDIA_ALBUMOPRN_QUERYALBUM) {
        tabletype = TYPE_ALBUM_TABLE;
        uriString = MEDIALIBRARY_DATA_URI;
        } else {
    if (strQueryCondition.empty()) {
        string::size_type pos = uriString.find_last_of('/');
        MEDIA_INFO_LOG("pos = %{public}d",pos);
        MEDIA_INFO_LOG("MEDIALIBRARY_DATA_URI = %{public}d", MEDIALIBRARY_DATA_URI.length());
        MEDIA_INFO_LOG("MEDIALIBRARY_SMARTALBUM_URI.length() = %{public}d", MEDIALIBRARY_SMARTALBUM_URI.length());
        MEDIA_INFO_LOG("MEDIALIBRARY_SMARTALBUM_MAP_URI.length() = %{public}d", MEDIALIBRARY_SMARTALBUM_MAP_URI.length());
        if (pos == MEDIALIBRARY_DATA_URI.length()) {
            MEDIA_INFO_LOG("MEDIALIBRARY_DATA_URI");
            strRow = uriString.substr(pos + 1);
            CHECK_AND_RETURN_RET_LOG(MediaLibraryDataAbilityUtils::IsNumber(strRow), nullptr, "Index not a digit");
            tabletype = TYPE_DATA;
            uriString = uriString.substr(0, pos);
            strQueryCondition = MEDIA_DATA_DB_ID + " = " + strRow;
        } else if (pos == MEDIALIBRARY_SMARTALBUM_URI.length()){
            MEDIA_INFO_LOG("MEDIALIBRARY_SMARTALBUM_URI");
            strRow = uriString.substr(pos + 1);
            CHECK_AND_RETURN_RET_LOG(MediaLibraryDataAbilityUtils::IsNumber(strRow), nullptr, "Index not a digit");
            tabletype = TYPE_SMARTALBUM;
            uriString = uriString.substr(0, pos);
            strQueryCondition = SMARTALBUM_DB_ID + " = " + strRow;
        } else if (pos == MEDIALIBRARY_SMARTALBUM_MAP_URI.length()){
            MEDIA_INFO_LOG("MEDIALIBRARY_SMARTALBUM_MAP_URI");
            strRow = uriString.substr(pos + 1);
            CHECK_AND_RETURN_RET_LOG(MediaLibraryDataAbilityUtils::IsNumber(strRow), nullptr, "Index not a digit");
            tabletype = TYPE_SMARTALBUM_MAP;
            uriString = uriString.substr(0, pos);
            strQueryCondition = SMARTALBUMMAP_DB_ID + " = " + strRow;
        }
    }
        }
    MEDIA_INFO_LOG("uriString = %{public}s",uriString.c_str());
    MEDIA_INFO_LOG("strQueryCondition = %{public}s",strQueryCondition.c_str());

    // After removing the index values, check whether URI is correct
    CHECK_AND_RETURN_RET_LOG((uriString == MEDIALIBRARY_DATA_URI ||
                             uriString == MEDIALIBRARY_SMARTALBUM_URI ||
                             uriString == MEDIALIBRARY_SMARTALBUM_MAP_URI)
                             , nullptr, "Not Data ability Uri");
    if (tabletype == TYPE_SMARTALBUM)
    {
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
    } else {
        if (tabletype == TYPE_ALBUM_TABLE) {
            MEDIA_INFO_LOG("uriString = %{public}s", uriString.c_str());
            AbsRdbPredicates mediaLibAbsPredAlbum(ABLUM_VIEW_NAME);
            if (strQueryCondition == "") {
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
        } else {
            AbsRdbPredicates mediaLibAbsPredFile(MEDIALIBRARY_TABLE);
            if (predicates.IsDistinct()) {
                mediaLibAbsPredFile.Distinct();
            }
            mediaLibAbsPredFile.SetWhereClause(strQueryCondition);
            mediaLibAbsPredFile.SetWhereArgs(predicates.GetWhereArgs());
            mediaLibAbsPredFile.Limit(predicates.GetLimit());
            mediaLibAbsPredFile.SetOrder(predicates.GetOrder());
            queryResultSet = rdbStore->Query(mediaLibAbsPredFile, columns);
            }

        int32_t columnIndex;
        std::string intVal;
        int32_t columnIndex1;
        int32_t intVal1;
        int32_t columnIndex2;
        int32_t intVal2;
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        queryResultSet->GetColumnIndex("bucket_display_name", columnIndex);
        queryResultSet->GetString(columnIndex, intVal);
        MEDIA_INFO_LOG("name = %{public}s",intVal.c_str());
        queryResultSet->GetColumnIndex("count", columnIndex1);
        queryResultSet->GetInt(columnIndex1, intVal1);
        MEDIA_INFO_LOG("count = %{public}d",intVal1);
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex2);
        queryResultSet->GetInt(columnIndex2, intVal2);
        MEDIA_INFO_LOG("id = %{public}d",intVal2);
        }
        CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");
    }
    
    return queryResultSet;
}

int32_t MediaLibraryDataAbility::Update(const Uri &uri, const ValuesBucket &value,
    const DataAbilityPredicates &predicates)
{
    MEDIA_INFO_LOG("Update");
    if ((!isRdbStoreInitialized) || (rdbStore == nullptr) || (value.IsEmpty())) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Update:Input parameter is invalid ");
        return DATA_ABILITY_FAIL;
    }

    string uriString = uri.ToString();
    MEDIA_INFO_LOG("Update uriString = %{public}s",uriString.c_str());
    string strUpdateCondition = predicates.GetWhereClause();
    MEDIA_INFO_LOG("Update strUpdateCondition = %{public}s",strUpdateCondition.c_str());
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
    CHECK_AND_RETURN_RET_LOG(uriString == MEDIALIBRARY_DATA_URI, DATA_ABILITY_FAIL, "Not Data ability Uri");

    int32_t changedRows = DATA_ABILITY_FAIL;
    vector<string> whereArgs = predicates.GetWhereArgs();
    MEDIA_INFO_LOG("Update whereArgs = %{public}s",whereArgs[0].c_str());
    (void)rdbStore->Update(changedRows, MEDIALIBRARY_TABLE, value, strUpdateCondition, whereArgs);

    return changedRows;
}

int32_t MediaLibraryDataAbility::BatchInsert(const Uri &uri, const vector<ValuesBucket> &values)
{
    string uriString = uri.ToString();
    if ((!isRdbStoreInitialized) || (rdbStore == nullptr) || (uriString != MEDIALIBRARY_DATA_URI)) {
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

void MediaLibraryDataAbility::ScanFile(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
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
        string srcPath = MediaLibraryDataAbilityUtils::GetPathFromDb(id, rdbStore);
        if (!srcPath.empty()) {
            std::shared_ptr<ScanFileCallback> scanFileCb = make_shared<ScanFileCallback>();
            CHECK_AND_RETURN_LOG(scanFileCb != nullptr, "Failed to create scan file callback object");
            auto ret = scannerClient_->ScanFile(srcPath, scanFileCb);
            CHECK_AND_RETURN_LOG(ret == 0, "Failed to initiate scan request");
        }
    }
}

int32_t MediaLibraryDataAbility::OpenFile(const Uri &uri, const std::string &mode)
{
    FileAsset fileAsset;

    string id = MediaLibraryDataAbilityUtils::GetIdFromUri(uri.ToString());
    string srcPath = MediaLibraryDataAbilityUtils::GetPathFromDb(id, rdbStore);
    CHECK_AND_RETURN_RET_LOG(!srcPath.empty(), DATA_ABILITY_FAIL, "Failed to obtain path from Database");

    int32_t fd = fileAsset.OpenAsset(srcPath, mode);

    return fd;
}

void ScanFileCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) {}
}  // namespace Media
}  // namespace OHOS