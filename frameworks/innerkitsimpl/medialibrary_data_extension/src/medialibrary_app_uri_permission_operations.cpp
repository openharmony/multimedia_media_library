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

using namespace OHOS::DataShare;
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {

const int MediaLibraryAppUriPermissionOperations::ERROR = -1;
const int MediaLibraryAppUriPermissionOperations::SUCCEED = 0;
const int MediaLibraryAppUriPermissionOperations::ALREADY_EXIST = 1;

int32_t MediaLibraryAppUriPermissionOperations::HandleInsertOperation(MediaLibraryCommand &cmd)
{
    // query permission data before insert
    int queryFlag = ERROR;
    shared_ptr<ResultSet> resultSet = QueryNewData(cmd.GetValueBucket(), queryFlag);

    if (queryFlag > 0) {
        // permissionType from param
        int permissionTypeParam = ERROR;
        if (!GetIntFromValuesBucket(cmd.GetValueBucket(), AppUriPermissionColumn::PERMISSION_TYPE,
            permissionTypeParam)) {
            return ERROR;
        }
        int32_t permissionTypeDB =
            MediaLibraryRdbStore::GetInt(resultSet, AppUriPermissionColumn::PERMISSION_TYPE);
        if (permissionTypeParam == permissionTypeDB ||
            permissionTypeParam == AppUriPermissionColumn::PERMISSION_TEMPORARY_READ ||
            permissionTypeDB == AppUriPermissionColumn::PERMISSION_PERSIST_READ ||
            permissionTypeDB == AppUriPermissionColumn::PERMISSION_PERSIST_READ_WRITE) {
            return ALREADY_EXIST;
        }
        // persist read instead of temporary read in database
        ValuesBucket updateVB;
        updateVB.PutInt(AppUriPermissionColumn::PERMISSION_TYPE, permissionTypeParam);
        updateVB.PutLong(AppUriPermissionColumn::DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        int idDB = MediaLibraryRdbStore::GetInt(resultSet, AppUriPermissionColumn::ID);

        OHOS::DataShare::DataSharePredicates updatePredicates;
        updatePredicates.EqualTo(AppUriPermissionColumn::ID, idDB);
        RdbPredicates updateRdbPredicates =
            RdbUtils::ToPredicates(updatePredicates, AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
        int32_t updateRows = MediaLibraryRdbStore::Update(updateVB, updateRdbPredicates);
        if (updateRows < 1) {
            MEDIA_ERR_LOG("upgrade permissionType error");
            return ERROR;
        }
        return SUCCEED;
    }
    if (queryFlag < 0) {
        return ERROR;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return ERROR;
    }

    // insert data into uriPermission table
    int64_t outRowId = ERROR;
    cmd.GetValueBucket().PutLong(AppUriPermissionColumn::DATE_MODIFIED,
        MediaFileUtils::UTCTimeMilliSeconds());
    int32_t errCode = rdbStore->Insert(cmd, outRowId);
    if (errCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("insert into db failed, errCode = %{public}d", errCode);
        return ERROR;
    }
    return SUCCEED;
}

int32_t MediaLibraryAppUriPermissionOperations::BatchInsert(
    MediaLibraryCommand &cmd, const std::vector<DataShare::DataShareValuesBucket> &values)
{
    TransactionOperations transactionOprn(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
    int32_t errCode = transactionOprn.Start();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("start transaction error, errCode = %{public}d", errCode);
        return ERROR;
    }
    int insertOneFlag = ERROR;
    for (auto it = values.begin(); it != values.end(); it++) {
        ValuesBucket value = RdbUtils::ToValuesBucket(*it);
        cmd.SetValueBucket(value);
        if (value.IsEmpty()) {
            MEDIA_ERR_LOG("Input parameter is invalid");
            return ERROR;
        }
        insertOneFlag = HandleInsertOperation (cmd);
        if (insertOneFlag < 0) {
            return insertOneFlag;
        }
    }
    transactionOprn.Finish();
    return SUCCEED;
}

int32_t MediaLibraryAppUriPermissionOperations::DeleteOperation(NativeRdb::RdbPredicates &predicates)
{
    int deleteRow = MediaLibraryRdbStore::Delete(predicates);
    return deleteRow;
}

std::shared_ptr<OHOS::NativeRdb::ResultSet> MediaLibraryAppUriPermissionOperations::QueryOperation(
    DataShare::DataSharePredicates &predicates, std::vector<std::string> &fetchColumns)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates,
        AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet = MediaLibraryRdbStore::Query(rdbPredicates, fetchColumns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != 0) {
        return nullptr;
    }
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
    int fileId = ERROR;
    if (!GetIntFromValuesBucket(valueBucket, AppUriPermissionColumn::FILE_ID, fileId)) {
        MEDIA_ERR_LOG("param without fileId");
        resultFlag = ERROR;
        return nullptr;
    }

    // parse uriType
    int uriType = ERROR;
    if (!GetIntFromValuesBucket(valueBucket, AppUriPermissionColumn::URI_TYPE, uriType)) {
        MEDIA_ERR_LOG("param without uriType");
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
    resultFlag = (resultSet == nullptr ? SUCCEED : ALREADY_EXIST);
    return resultSet;
}

bool MediaLibraryAppUriPermissionOperations::GetIntFromValuesBucket(
    OHOS::NativeRdb::ValuesBucket &valueBucket, const std::string column, int &result)
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
} // namespace Media
} // namespace OHOS