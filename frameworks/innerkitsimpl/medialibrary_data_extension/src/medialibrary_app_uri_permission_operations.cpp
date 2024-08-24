/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <vector>
#include <map>
#include "medialibrary_app_uri_permission_operations.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_rdb_utils.h"
#include "media_column.h"
#include "datashare_predicates.h"
#include "rdb_utils.h"
#include "media_file_uri.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_rdb_transaction.h"
#include "media_file_utils.h"
#include "medialibrary_appstate_observer.h"
#include "datashare_predicates_objects.h"

using namespace OHOS::DataShare;
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {

const int MediaLibraryAppUriPermissionOperations::ERROR = -1;
const int MediaLibraryAppUriPermissionOperations::SUCCEED = 0;
const int MediaLibraryAppUriPermissionOperations::ALREADY_EXIST = 1;
const int MediaLibraryAppUriPermissionOperations::NO_DATA = 0;

int32_t MediaLibraryAppUriPermissionOperations::HandleInsertOperation(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("insert appUriPermission begin");
    // permissionType from param
    int permissionTypeParam = -1;
    if (!GetIntFromValuesBucket(cmd.GetValueBucket(), AppUriPermissionColumn::PERMISSION_TYPE,
        permissionTypeParam)) {
        return ERROR;
    }
    if (!IsValidPermissionType(permissionTypeParam)) {
        return ERROR;
    }
    // parse fileId
    int fileId = -1;
    if (!GetIntFromValuesBucket(cmd.GetValueBucket(), AppUriPermissionColumn::FILE_ID, fileId)) {
        return ERROR;
    }
    if (!IsPhotoExist(fileId)) {
        return ERROR;
    }
    // query permission data before insert
    int queryFlag = ERROR;
    shared_ptr<ResultSet> resultSet = QueryNewData(cmd.GetValueBucket(), queryFlag);
    // Update the permissionType
    if (queryFlag > 0) {
        return UpdatePermissionType(resultSet, permissionTypeParam);
    }
    if (queryFlag < 0) {
        return ERROR;
    }

    // delete the temporary permission when the app dies
    if (AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.find(permissionTypeParam) !=
        AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.end()) {
        MedialibraryAppStateObserverManager::GetInstance().SubscribeAppState();
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("get rdbStore error");
        return ERROR;
    }
    // insert data
    int64_t outRowId = -1;
    cmd.GetValueBucket().PutLong(AppUriPermissionColumn::DATE_MODIFIED,
        MediaFileUtils::UTCTimeMilliSeconds());
    
    cmd.GetValueBucket().Delete(AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE);
    cmd.SetTableName(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);

    int32_t errCode = rdbStore->Insert(cmd, outRowId);
    if (errCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("insert into db error, errCode=%{public}d", errCode);
        return ERROR;
    }
    MEDIA_INFO_LOG("insert appUriPermission ok");
    return SUCCEED;
}

int32_t MediaLibraryAppUriPermissionOperations::BatchInsert(
    MediaLibraryCommand &cmd, const std::vector<DataShare::DataShareValuesBucket> &values)
{
    MEDIA_INFO_LOG("batch insert begin");
    TransactionOperations transactionOprn(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
    int32_t errCode = transactionOprn.Start();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("start transaction error, errCode = %{public}d", errCode);
        return ERROR;
    }
    if (!IsPhotosAllExist(values)) {
        return ERROR;
    }
    std::vector<ValuesBucket> insertVector;
    for (auto it = values.begin(); it != values.end(); it++) {
        ValuesBucket value = RdbUtils::ToValuesBucket(*it);
        int queryFlag = -1;
        std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet = QueryNewData(value, queryFlag);
        if (queryFlag < 0) {
            return ERROR;
        }
        // permissionType from param
        int permissionTypeParam = -1;
        if (!GetIntFromValuesBucket(value, AppUriPermissionColumn::PERMISSION_TYPE,
            permissionTypeParam)) {
            return ERROR;
        }

        value.Delete(AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE);
        
        if (queryFlag == 0) {
            // delete the temporary permission when the app dies
            if (AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.find(permissionTypeParam) !=
                AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.end()) {
                MedialibraryAppStateObserverManager::GetInstance().SubscribeAppState();
            }
            value.PutLong(AppUriPermissionColumn::DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
            insertVector.push_back(value);
        } else if (UpdatePermissionType(resultSet, permissionTypeParam) == ERROR) {
            return ERROR;
        }
    }
    if (!insertVector.empty()) {
        int64_t outRowId = -1;
        int32_t ret = MediaLibraryRdbStore::BatchInsert(outRowId, AppUriPermissionColumn::APP_URI_PERMISSION_TABLE,
            insertVector);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("batch insert err=%{public}d", ret);
            return ERROR;
        }
    }
    transactionOprn.Finish();
    MEDIA_INFO_LOG("batch insert ok");
    return SUCCEED;
}

int32_t MediaLibraryAppUriPermissionOperations::DeleteOperation(NativeRdb::RdbPredicates &predicates)
{
    MEDIA_INFO_LOG("delete begin");
    int deleteRow = MediaLibraryRdbStore::Delete(predicates);
    MEDIA_INFO_LOG("deleted row=%{public}d", deleteRow);
    return deleteRow < 0 ? ERROR : SUCCEED;
}

std::shared_ptr<OHOS::NativeRdb::ResultSet> MediaLibraryAppUriPermissionOperations::QueryOperation(
    DataShare::DataSharePredicates &predicates, std::vector<std::string> &fetchColumns)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates,
        AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet = MediaLibraryRdbStore::Query(rdbPredicates, fetchColumns);
    if (resultSet == nullptr) {
        return nullptr;
    }
    int32_t numRows = 0;
    resultSet->GetRowCount(numRows);
    if (numRows == 0) {
        return nullptr;
    }
    resultSet->GoToFirstRow();
    return resultSet;
}

std::shared_ptr<OHOS::NativeRdb::ResultSet> MediaLibraryAppUriPermissionOperations::QueryNewData(
    OHOS::NativeRdb::ValuesBucket &valueBucket, int &resultFlag)
{
    // parse appid
    ValueObject appidVO;
    bool appIdRet = valueBucket.GetObject(AppUriPermissionColumn::APP_ID, appidVO);
    if (!appIdRet) {
        MEDIA_ERR_LOG("param without appId");
        resultFlag = ERROR;
        return nullptr;
    }
    string appId = appidVO;

    // parse fileId
    int fileId = -1;
    if (!GetIntFromValuesBucket(valueBucket, AppUriPermissionColumn::FILE_ID, fileId)) {
        resultFlag = ERROR;
        return nullptr;
    }

    // parse uriType
    int uriType = -1;
    if (!GetIntFromValuesBucket(valueBucket, AppUriPermissionColumn::URI_TYPE, uriType)) {
        resultFlag = ERROR;
        return nullptr;
    }

    OHOS::DataShare::DataSharePredicates permissionPredicates;
    permissionPredicates.And()->EqualTo(AppUriPermissionColumn::FILE_ID, fileId);
    permissionPredicates.And()->EqualTo(AppUriPermissionColumn::URI_TYPE, uriType);
    permissionPredicates.And()->EqualTo(AppUriPermissionColumn::APP_ID, appId);

    vector<string> fetchColumns;
    fetchColumns.push_back(AppUriPermissionColumn::ID);
    fetchColumns.push_back(AppUriPermissionColumn::PERMISSION_TYPE);

    shared_ptr<ResultSet> resultSet = QueryOperation(permissionPredicates, fetchColumns);
    resultFlag = (resultSet == nullptr ? NO_DATA : ALREADY_EXIST);
    return resultSet;
}

bool MediaLibraryAppUriPermissionOperations::GetIntFromValuesBucket(
    OHOS::NativeRdb::ValuesBucket &valueBucket, const std::string &column, int &result)
{
    ValueObject valueObject;
    bool ret = valueBucket.GetObject(column, valueObject);
    if (!ret) {
        MEDIA_ERR_LOG("valueBucket param without %{public}s", column.c_str());
        return false;
    }
    result = valueObject;
    return true;
}

int MediaLibraryAppUriPermissionOperations::UpdatePermissionType(shared_ptr<ResultSet> &resultSetDB,
    int &permissionTypeParam)
{
    int32_t permissionTypeDB =
        MediaLibraryRdbStore::GetInt(resultSetDB, AppUriPermissionColumn::PERMISSION_TYPE);
    if (!CanOverride(permissionTypeParam, permissionTypeDB)) {
        return ALREADY_EXIST;
    }

    // delete the temporary permission when the app dies
    if (AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.find(permissionTypeParam) !=
        AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.end()) {
        MedialibraryAppStateObserverManager::GetInstance().SubscribeAppState();
    }

    // update permission type
    ValuesBucket updateVB;
    updateVB.PutInt(AppUriPermissionColumn::PERMISSION_TYPE, permissionTypeParam);
    updateVB.PutLong(AppUriPermissionColumn::DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
    int32_t idDB = MediaLibraryRdbStore::GetInt(resultSetDB, AppUriPermissionColumn::ID);

    OHOS::DataShare::DataSharePredicates updatePredicates;
    updatePredicates.EqualTo(AppUriPermissionColumn::ID, idDB);
    RdbPredicates updateRdbPredicates =
        RdbUtils::ToPredicates(updatePredicates, AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    int32_t updateRows = MediaLibraryRdbStore::Update(updateVB, updateRdbPredicates);
    if (updateRows < 1) {
        MEDIA_ERR_LOG("upgrade permissionType error,idDB=%{public}d", idDB);
        return ERROR;
    }
    MEDIA_INFO_LOG("update ok,Rows=%{public}d", updateRows);
    return SUCCEED;
}

bool MediaLibraryAppUriPermissionOperations::IsValidPermissionType(int &permissionType)
{
    bool isValid = AppUriPermissionColumn::PERMISSION_TYPES_ALL.find(permissionType)
        != AppUriPermissionColumn::PERMISSION_TYPES_ALL.end();
    if (!isValid) {
        MEDIA_ERR_LOG("invalid permissionType=%{public}d", permissionType);
    }
    return isValid;
}

bool MediaLibraryAppUriPermissionOperations::CanOverride(int &permissionTypeParam, int &permissionTypeDB)
{
    MEDIA_INFO_LOG("permissionTypeParam=%{public}d,permissionTypeDB=%{public}d",
        permissionTypeParam, permissionTypeDB);
    // Equal permissions do not need to be overridden
    if (permissionTypeParam == permissionTypeDB) {
        return false;
    }
    // temporary permission can't override persist permission
    if (AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.find(permissionTypeParam) !=
        AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.end()
        && AppUriPermissionColumn::PERMISSION_TYPES_PERSIST.find(permissionTypeDB) !=
        AppUriPermissionColumn::PERMISSION_TYPES_PERSIST.end()
    ) {
        return false;
    }
    // persist permission can override temporary permission
    if (AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.find(permissionTypeDB) !=
        AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.end()
        && AppUriPermissionColumn::PERMISSION_TYPES_PERSIST.find(permissionTypeParam) !=
        AppUriPermissionColumn::PERMISSION_TYPES_PERSIST.end()
    ) {
        return true;
    }
    // Temporary permissions can override each other.
    if (AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.find(permissionTypeParam) !=
        AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.end()
        && AppUriPermissionColumn::PERMISSION_TYPES_TEMPORARY.find(permissionTypeDB) !=
        AppUriPermissionColumn::PERMISSION_TYPES_PERSIST.end()
    ) {
        return true;
    }
    // PERMISSION_PERSIST_READ_WRITE can override PERMISSION_PERSIST_READ, but not vice verse.
    return permissionTypeParam == AppUriPermissionColumn::PERMISSION_PERSIST_READ_WRITE;
}

bool MediaLibraryAppUriPermissionOperations::IsPhotoExist(int32_t &photoFileId)
{
    // query whether photo exists.
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.And()->EqualTo(PhotoColumn::MEDIA_ID, std::to_string(photoFileId));
    vector<string> photoColumns;
    photoColumns.push_back(PhotoColumn::MEDIA_ID);
    shared_ptr<NativeRdb::ResultSet> photoRestultSet = MediaLibraryRdbStore::Query(rdbPredicates, photoColumns);
    if (photoRestultSet == nullptr) {
        MEDIA_ERR_LOG("query photoRestultSet is null,fileId=%{public}d", photoFileId);
        return false;
    }
    int32_t photoNumRows = 0;
    photoRestultSet->GetRowCount(photoNumRows);
    if (photoNumRows == 0) {
        MEDIA_ERR_LOG("query photo not exist,fileId=%{public}d", photoFileId);
        return false;
    }
    return true;
}

bool MediaLibraryAppUriPermissionOperations::IsPhotosAllExist(
    const std::vector<DataShare::DataShareValuesBucket> &values)
{
    std::vector<std::string> fileIds;
    bool isValid = false;
    for (auto it = values.begin(); it != values.end(); it++) {
        int fileId = it->Get(AppUriPermissionColumn::FILE_ID, isValid);
        if (!isValid) {
            MEDIA_ERR_LOG("get fileId error");
            return false;
        }
        fileIds.push_back(std::to_string(static_cast<int32_t>(fileId)));
    }
    // query whether photos exists.
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.And()->In(MediaColumn::MEDIA_ID, fileIds);
    vector<string> photoColumns;
    photoColumns.push_back(PhotoColumn::MEDIA_ID);
    shared_ptr<NativeRdb::ResultSet> photoRestultSet = MediaLibraryRdbStore::Query(rdbPredicates, photoColumns);
    if (photoRestultSet == nullptr) {
        MEDIA_ERR_LOG("query photoRestultSet is null");
        return false;
    }
    int32_t photoNumRows = 0;
    photoRestultSet->GetRowCount(photoNumRows);
    if (photoNumRows != fileIds.size()) {
        MEDIA_ERR_LOG("some photo not exist");
        return false;
    }
    return true;
}

} // namespace Media
} // namespace OHOS