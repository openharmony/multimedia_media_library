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
    Ability::OnStart(want);
    InitMediaLibraryRdbStore();
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
    string uriString = uri.ToString();
    if (!isRdbStoreInitialized || value.IsEmpty() || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Insert: Input parameter is invalid");
        return DATA_ABILITY_FAIL;
    }

    if (uriString.find(MEDIA_OPERN_KEYWORD) != string::npos) {
        MediaLibraryFileOperations fileOprn;
        MediaLibraryAlbumOperations albumOprn;

        if (uriString.find(MEDIA_FILEOPRN) != string::npos) {
            return fileOprn.HandleFileOperation(uriString, value, rdbStore);
        } else if (uriString.find(MEDIA_ALBUMOPRN) != string::npos) {
            return albumOprn.HandleAlbumOperations(uriString, value, rdbStore);
        }
    }

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

    string strDeleteCondition = predicates.GetWhereClause();
    string uriString = uri.ToString();
    if (strDeleteCondition.empty()) {
        string::size_type pos = uriString.find_last_of('/');
        CHECK_AND_RETURN_RET_LOG((pos != string::npos) && (pos == MEDIALIBRARY_DATA_URI.length()), DATA_ABILITY_FAIL,
            "Invalid index position");

        string strRow = uriString.substr(pos + 1);
        CHECK_AND_RETURN_RET_LOG(IsNumber(strRow), DATA_ABILITY_FAIL, "Index not a digit");

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
    string uriString = uri.ToString();

    if (!isRdbStoreInitialized || rdbStore == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Query:Rdb Store is not initialized");
        return nullptr;
    }

    string strQueryCondition = predicates.GetWhereClause();
    if (strQueryCondition.empty()) {
        string::size_type pos = uriString.find_last_of('/');
        if (pos == MEDIALIBRARY_DATA_URI.length()) {
            string strRow = uriString.substr(pos + 1);
            CHECK_AND_RETURN_RET_LOG(IsNumber(strRow), nullptr, "Index not a digit");

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

    auto rowCount(0);
    (void)queryResultSet->GetRowCount(rowCount);

    return queryResultSet;
}

int32_t MediaLibraryDataAbility::Update(const Uri &uri, const ValuesBucket &value,
    const DataAbilityPredicates &predicates)
{
    if (!isRdbStoreInitialized || rdbStore == nullptr || value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataAbility Update:Input parameter is invalid ");
        return DATA_ABILITY_FAIL;
    }
    string strUpdateCondition = predicates.GetWhereClause();
    string uriString = uri.ToString();
    if (strUpdateCondition.empty()) {
        string::size_type pos = uriString.find_last_of('/');
        CHECK_AND_RETURN_RET_LOG((pos != string::npos) && (pos == MEDIALIBRARY_DATA_URI.length()), DATA_ABILITY_FAIL,
            "Invalid index position");

        string strRow = uriString.substr(pos + 1);
        CHECK_AND_RETURN_RET_LOG(IsNumber(strRow), DATA_ABILITY_FAIL, "Index not a digit");

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
    if (!isRdbStoreInitialized || rdbStore == nullptr || uriString != MEDIALIBRARY_DATA_URI) {
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

bool MediaLibraryDataAbility::IsNumber(const string &str)
{
    if (str.length() == 0) {
        MEDIA_ERR_LOG("IsNumber input is empty ");
        return false;
    }

    for (char const &c : str) {
        if (isdigit(c) == 0) {
            MEDIA_ERR_LOG("Index is not a number");
            return false;
        }
    }

    return true;
}
}  // namespace Media
}  // namespace OHOS