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
    return store.ExecuteSql(CREATE_MEDIA_TABLE);
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
    return DATA_ABILITY_SUCCESS;
}

int32_t MediaLibraryDataAbility::Insert(const Uri &uri, const ValuesBucket &value)
{
    if ((!isRdbStoreInitialized) || (value.IsEmpty()) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Insert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
    }

    string insertUri = uri.ToString();
    // If insert uri contains media opearation, follow media operation procedure
    if (insertUri.find(MEDIA_OPERN_KEYWORD) != string::npos) {
        MediaLibraryFileOperations fileOprn;
        MediaLibraryAlbumOperations albumOprn;

        string scanPath("");
        int32_t result(DATA_ABILITY_FAIL);
        string operationType = MediaLibraryDataAbilityUtils::GetOperationType(insertUri);

        if (insertUri.find(MEDIA_FILEOPRN) != string::npos) {
            result = fileOprn.HandleFileOperation(operationType, value, rdbStore);
            // After successfull close asset operation, do a scan file
            if ((result >= 0) && (operationType == MEDIA_FILEOPRN_CLOSEASSET)) {
                ScanFile(value, rdbStore);
            }
        } else if (insertUri.find(MEDIA_ALBUMOPRN) != string::npos) {
            result = albumOprn.HandleAlbumOperations(operationType, value, rdbStore);
        }

        return result;
    }

    // Normal URI scenario
    int64_t outRowId = DATA_ABILITY_FAIL;
    (void)rdbStore->Insert(outRowId, MEDIALIBRARY_TABLE, value);

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

    string strQueryCondition = predicates.GetWhereClause();
    if (strQueryCondition.empty()) {
        string::size_type pos = uriString.find_last_of('/');
        if (pos == MEDIALIBRARY_DATA_URI.length()) {
            string strRow = uriString.substr(pos + 1);
            CHECK_AND_RETURN_RET_LOG(MediaLibraryDataAbilityUtils::IsNumber(strRow), nullptr, "Index not a digit");

            uriString = uriString.substr(0, pos);
            strQueryCondition = MEDIA_DATA_DB_ID + " = " + strRow;
        }
    }

    // After removing the index values, check whether URI is correct
    CHECK_AND_RETURN_RET_LOG(uriString == MEDIALIBRARY_DATA_URI, nullptr, "Not Data ability Uri");

    AbsRdbPredicates mediaLibAbsPred(MEDIALIBRARY_TABLE);
    if (predicates.IsDistinct()) {
        mediaLibAbsPred.Distinct();
    }

    mediaLibAbsPred.SetWhereClause(strQueryCondition);
    mediaLibAbsPred.SetWhereArgs(predicates.GetWhereArgs());
    mediaLibAbsPred.Limit(predicates.GetLimit());
    mediaLibAbsPred.SetOrder(predicates.GetOrder());

    unique_ptr<AbsSharedResultSet> queryResultSet = rdbStore->Query(mediaLibAbsPred, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr, "Query functionality failed");

    return queryResultSet;
}

int32_t MediaLibraryDataAbility::Update(const Uri &uri, const ValuesBucket &value,
    const DataAbilityPredicates &predicates)
{
    if ((!isRdbStoreInitialized) || (rdbStore == nullptr) || (value.IsEmpty())) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Update:Input parameter is invalid ");
        return DATA_ABILITY_FAIL;
    }

    string uriString = uri.ToString();

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
    CHECK_AND_RETURN_RET_LOG(uriString == MEDIALIBRARY_DATA_URI, DATA_ABILITY_FAIL, "Not Data ability Uri");

    int32_t changedRows = DATA_ABILITY_FAIL;
    vector<string> whereArgs = predicates.GetWhereArgs();
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