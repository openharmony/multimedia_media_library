/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "medialibraryuripermissionoperations_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>

#include "ability_context_impl.h"
#include "medialibrary_uripermission_operations.h"
#include "medialibrary_app_uri_permission_operations.h"
#include "datashare_predicates.h"
#include "media_app_uri_permission_column.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_operation.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_unistore.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "userfile_manager_types.h"
#include "values_bucket.h"

namespace OHOS {
using namespace std;
using namespace DataShare;
const int32_t PERMISSION_DEFAULT = -1;
const int32_t URI_DEFAULT = 0;
const int32_t BatchInsertNumber = 5;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    return static_cast<int32_t>(*data);
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static int FuzzPermissionType(const uint8_t *data, size_t size)
{
    vector<int> vecPermissionType;
    vecPermissionType.assign(Media::AppUriPermissionColumn::PERMISSION_TYPES_ALL.begin(),
        Media::AppUriPermissionColumn::PERMISSION_TYPES_ALL.end());
    vecPermissionType.push_back(PERMISSION_DEFAULT);
    uint8_t length = static_cast<uint8_t>(vecPermissionType.size());
    if (*data < length) {
        return vecPermissionType[*data];
    }
    return Media::AppUriPermissionColumn::PERMISSION_TEMPORARY_READ;
}

static int FuzzUriType(const uint8_t *data, size_t size)
{
    vector<int> vecUriType;
    vecUriType.assign(Media::AppUriPermissionColumn::URI_TYPES_ALL.begin(),
        Media::AppUriPermissionColumn::URI_TYPES_ALL.end());
    vecUriType.push_back(URI_DEFAULT);
    uint8_t length = static_cast<uint8_t>(vecUriType.size());
    if (*data < length) {
        return vecUriType[*data];
    }
    return Media::AppUriPermissionColumn::URI_PHOTO;
}

static void HandleInsertOperationFuzzer(string appId, int32_t photoId, int32_t permissionType, int32_t uriType)
{
    DataShareValuesBucket values;
    values.Put(Media::AppUriPermissionColumn::APP_ID, appId);
    values.Put(Media::AppUriPermissionColumn::FILE_ID, photoId);
    values.Put(Media::AppUriPermissionColumn::PERMISSION_TYPE, permissionType);
    values.Put(Media::AppUriPermissionColumn::URI_TYPE, uriType);
    Media::MediaLibraryCommand cmd(Media::OperationObject::APP_URI_PERMISSION_INNER, Media::OperationType::CREATE,
        Media::MediaLibraryApi::API_10);
    NativeRdb::ValuesBucket rdbValue = RdbDataShareAdapter::RdbUtils::ToValuesBucket(values);
    cmd.SetValueBucket(rdbValue);
    Media::UriPermissionOperations::InsertOperation(cmd);
}

static void DeleteOperationFuzzer(string appId, int32_t photoId)
{
    DataShare::DataSharePredicates dataSharePredicate;
    dataSharePredicate.And()->EqualTo(Media::AppUriPermissionColumn::APP_ID, appId);
    dataSharePredicate.And()->EqualTo(Media::AppUriPermissionColumn::FILE_ID, photoId);
    Media::MediaLibraryCommand cmd(Media::OperationObject::APP_URI_PERMISSION_INNER, Media::OperationType::DELETE,
        Media::MediaLibraryApi::API_10);
    cmd.SetTableName(Media::AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    NativeRdb::RdbPredicates rdbPredicate = RdbDataShareAdapter::RdbUtils::ToPredicates(dataSharePredicate,
        Media::AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    cmd.SetDataSharePred(dataSharePredicate);
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    Media::UriPermissionOperations::DeleteOperation(cmd);
}

static void BatchInsertFuzzer(const uint8_t* data, size_t size)
{
    vector<DataShare::DataShareValuesBucket> dataShareValues;
    for (int32_t i = 0; i < BatchInsertNumber; i++) {
        DataShareValuesBucket value;
        int32_t photoId = FuzzInt32(data, size);
        value.Put(Media::AppUriPermissionColumn::APP_ID, FuzzString(data, size));
        value.Put(Media::AppUriPermissionColumn::FILE_ID, photoId);
        value.Put(Media::AppUriPermissionColumn::PERMISSION_TYPE, FuzzPermissionType(data, size));
        value.Put(Media::AppUriPermissionColumn::URI_TYPE, FuzzUriType(data, size));
        dataShareValues.push_back(value);
    }
    Media::MediaLibraryCommand cmd(Media::OperationObject::APP_URI_PERMISSION_INNER, Media::OperationType::CREATE,
        Media::MediaLibraryApi::API_10);
    Media::UriPermissionOperations::GrantUriPermission(cmd, dataShareValues);
}

static void AppUriPermissionOperationsFuzzer(const uint8_t* data, size_t size)
{
    int32_t photoId = FuzzInt32(data, size);
    string appId = FuzzString(data, size);
    int32_t permissionType = FuzzPermissionType(data, size);
    int32_t uriType = FuzzUriType(data, size);

    HandleInsertOperationFuzzer(appId, photoId, permissionType, uriType);
    DeleteOperationFuzzer(appId, photoId);
    BatchInsertFuzzer(data, size);
}

void SetTables()
{
    vector<string> createTableSqlList = {
        Media::PhotoColumn::CREATE_PHOTO_TABLE,
        Media::AppUriPermissionColumn::CREATE_APP_URI_PERMISSION_TABLE,
        Media::AppUriSensitiveColumn::CREATE_APP_URI_SENSITIVE_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibraryMgr failed, ret: %{public}d", ret);

    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AppUriPermissionOperationsFuzzer(data, size);
    return 0;
}
