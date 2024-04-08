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

#include "unordered_set"

#include "media_file_uri.h"
#include "medialibrary_rdb_utils.h"
#include "parameter.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;
namespace OHOS {
namespace Media {

const std::string MEDIA_LIBRARY_STARTUP_PARAM_PREFIX = "multimedia.medialibrary.startup";
constexpr uint32_t BASE_USER_RANGE = 200000;

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
    if (rdbStore != nullptr) {
        NAPI_INFO_LOG("visitor rdb exists");
        return;
    }
    if (TryGetRdbStore()
    NAPI_INFO_LOG("success to init visitor rdb");
}

int MediaAssetRdbStore::TryGetRdbStore()
{
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        NAPI_ERR_LOG("fail to acquire application Context");
        return NativeRdb::E_ERROR;
    }
    NativeRdb::RdbStoreConfig config {""};
    int32_t errCode = 0;
    string name = MEDIA_DATA_ABILITY_DB_NAME;
    string dbPath = RdbSqlUtils::GetDefaultDatabasePath(MEDIA_DB_DIR, name, errCode);
    if (errCode != E_OK) {
        NAPI_ERR_LOG("fail to get rdb path");
        return errCode;
    }

    config.SetName(name);
    config.SetVisitorDir(dbPath);
    config.SetBundleName(context->GetBundleName());
    config.SetArea(context->GetArea());
    config.SetSecurityLevel(SecurityLevel::S3);
    config.SetRoleType(RoleType::VISITOR);
    config.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);

    MediaLibraryDataCallBack rdbDataCallBack;
    rdbStore_ = RdbHelper::GetRdbStore(config_, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr || errCode != NativeRdb::E_OK) {
        NAPI_ERR_LOG("Get visitor RdbStore is failed, errCode: %{public}d", errCode);
        rdbStore_ = nullptr;
        return;
    }
}

std::shared_ptr<DataShare::DataShareResultSet> MediaAssetRdbStore::Query(const DataShare::DataSharePredicates& 
    predicates, vector<std::string>& columns)
{
    if (rdbStore_ == nullptr) {
        NAPI_ERR_LOG("fail to acquire rdb when query");
        return nullptr;
    }
    NativeRdb::RdbPredicates rdbPredicates = RdbUtils::ToPredicates(prediacates, PhotoColumn::PHOTOS_TABLE);
    auto resultSet = rdbStore_->Query(predicates, columns);
    if (resultSet == nullptr) {
        NAPI_ERR_LOG("fail to acquire result from visitor query");
        return nullptr;
    }
    auto resultSetBridge = RdbUtils::ToResultSetBridge(resultSet);
    return make_shared<DataShare::DataShareResultSet>(resultSetBridge);
}

bool MediaAssetRdbStore::IsQueryAccessibleViaSandBox(const DataShare::DataSharePredicates& paredicates)
{
    if (access(MEDIA_DB_DIR.c_str(), E_OK) != 0) {
        return false;
    }
    if (rdbStore_ == nullptr) {
        NAPI_ERR_LOG("fail to acquire rdb when query");
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