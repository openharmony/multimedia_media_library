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

#include "media_asset_rdbstore.h"

#include <unordered_set>

#include "media_file_uri.h"
#include "media_file_utils.h"
#include "medialibrary_rdb_utils.h"
#include "parameter.h"
#include "parameters.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;
namespace OHOS {
namespace Media {

const std::string MEDIA_LIBRARY_STARTUP_PARAM_PREFIX = "multimedia.medialibrary.startup.";
constexpr uint32_t BASE_USER_RANGE = 200000;
const std::unordered_set<OperationObject> OPERATION_OBJECT_SET = {
    OperationObject::UFM_PHOTO,
    OperationObject::UFM_AUDIO,
    OperationObject::PAH_PHOTO,
};
const std::unordered_set<OperationType> OPERATION_TYPE_SET = {
    OperationType::QUERY,
};

std::string GetTableNameFromOprnObject(const OperationObject& object)
{
    if (TABLE_NAME_MAP.find(object) != TABLE_NAME_MAP.end()) {
        auto cmdObj = TABLE_NAME_MAP.at(object);
        return cmdObj.begin()->second;
    } else {
        return MEDIALIBRARY_TABLE;
    }
}

OperationType GetOprnTypeFromUri(Uri& uri)
{
    const std::string opType = MediaFileUri::GetPathSecondDentry(uri);
    if (OPRN_TYPE_MAP.find(opType) != OPRN_TYPE_MAP.end()) {
        return OPRN_TYPE_MAP.at(opType);
    } else {
        return OperationType::QUERY;
    }
}

OperationObject GetOprnObjectFromUri(Uri& uri)
{
    const string opObject = MediaFileUri::GetPathFirstDentry(uri);
    if (OPRN_OBJ_MAP.find(opObject) != OPRN_OBJ_MAP.end()) {
        return OPRN_OBJ_MAP.at(opObject);
    }
    std::string uriString = uri.ToString();
    if (MediaFileUtils::StartsWith(uriString, PhotoColumn::PHOTO_CACHE_URI_PREFIX)) {
        return OperationObject::PAH_PHOTO;
    }

    for (const auto &item : OPRN_MAP) {
        if (MediaFileUtils::StartsWith(uriString, item.first)) {
            return item.second;
        }
    }
    return OperationObject::UNKNOWN_OBJECT;
}

MediaAssetRdbStore* MediaAssetRdbStore::GetInstance()
{
    static MediaAssetRdbStore instance;
    return &instance;
}

const std::string MediaAssetRdbStore::CloudSyncTriggerFunc(const std::vector<std::string>& args)
{
    return "true";
}

const std::string MediaAssetRdbStore::IsCallerSelfFunc(const std::vector<std::string>& args)
{
    return "false";
}

MediaAssetRdbStore::MediaAssetRdbStore()
{
    NAPI_INFO_LOG("init visitor rdb");
    if (rdbStore_ != nullptr) {
        NAPI_INFO_LOG("visitor rdb exists");
        return;
    }
    if (TryGetRdbStore() != NativeRdb::E_OK) {
        return;
    }
    NAPI_INFO_LOG("success to init visitor rdb");
}

int32_t MediaAssetRdbStore::TryGetRdbStore(bool isIgnoreSELinux)
{
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        NAPI_ERR_LOG("fail to acquire application Context");
        return NativeRdb::E_ERROR;
    }
    uid_t uid = getuid() / BASE_USER_RANGE;
    const string key = MEDIA_LIBRARY_STARTUP_PARAM_PREFIX + to_string(uid);
    auto rdbInitFlag = system::GetBoolParameter(key, false);
    if (!rdbInitFlag && !isIgnoreSELinux) {
        NAPI_ERR_LOG("media library db update not complete, key:%{public}s", key.c_str());
        return NativeRdb::E_ERROR;
    }
    string name = MEDIA_DATA_ABILITY_DB_NAME;
    string databaseDir = MEDIA_DB_DIR + "/rdb";
    if (access(databaseDir.c_str(), E_OK) != 0) {
        NAPI_ERR_LOG("rdb do not exist");
        return NativeRdb::E_ERROR;
    }
    string dbPath = databaseDir.append("/").append(name);
    int32_t errCode = 0;
    NativeRdb::RdbStoreConfig config {""};
    config.SetName(name);
    config.SetVisitorDir(dbPath);
    config.SetBundleName(context->GetBundleName());
    config.SetArea(context->GetArea());
    config.SetSecurityLevel(SecurityLevel::S3);
    config.SetRoleType(RoleType::VISITOR);
    config.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);

    MediaLibraryDataCallBack rdbDataCallBack;
    rdbStore_ = RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr || errCode != NativeRdb::E_OK) {
        NAPI_ERR_LOG("Get visitor RdbStore is failed, errCode: %{public}d", errCode);
        rdbStore_ = nullptr;
        return errCode;
    }
    return NativeRdb::E_OK;
}

std::shared_ptr<DataShare::DataShareResultSet> MediaAssetRdbStore::Query(
    const DataShare::DataSharePredicates& predicates,
    std::vector<std::string>& columns, OperationObject& object, int& errCode)
{
    if (rdbStore_ == nullptr) {
        NAPI_ERR_LOG("fail to acquire rdb when query");
        return nullptr;
    }
    std::string tableName = GetTableNameFromOprnObject(object);
    NativeRdb::RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, tableName);
    MediaLibraryRdbUtils::AddQueryFilter(rdbPredicates);
    auto resultSet = rdbStore_->Query(rdbPredicates, columns);
    if (resultSet == nullptr) {
        NAPI_ERR_LOG("fail to acquire result from visitor query");
        return nullptr;
    }
    auto resultSetBridge = RdbUtils::ToResultSetBridge(resultSet);
    return make_shared<DataShare::DataShareResultSet>(resultSetBridge);
}

bool MediaAssetRdbStore::IsQueryAccessibleViaSandBox(Uri& uri, OperationObject& object, bool isIgnoreSELinux)
{
    if (access(MEDIA_DB_DIR.c_str(), E_OK) != 0) {
        return false;
    }
    if (rdbStore_ == nullptr) {
        if (TryGetRdbStore(isIgnoreSELinux) != NativeRdb::E_OK) {
            NAPI_ERR_LOG("fail to acquire rdb when query");
            return false;
        }
    }
    object = GetOprnObjectFromUri(uri);
    if (OPERATION_OBJECT_SET.count(object) == 0) {
        return false;
    }
    OperationType type = GetOprnTypeFromUri(uri);
    if (OPERATION_TYPE_SET.count(type) == 0) {
        return false;
    }
    return true;
}

int32_t MediaLibraryDataCallBack::OnCreate(NativeRdb::RdbStore& rdbStore)
{
    return 0;
}

int32_t MediaLibraryDataCallBack::OnUpgrade(NativeRdb::RdbStore& rdbStore, int32_t oldVersion, int32_t newVersion)
{
    return 0;
}

} // namespace Media
} // namespace OHOS