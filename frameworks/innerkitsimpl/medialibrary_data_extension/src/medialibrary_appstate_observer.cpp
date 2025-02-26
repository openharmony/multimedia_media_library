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
#include "medialibrary_appstate_observer.h"

#include <cstddef>
#include <sstream>
#include <string>

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"
#include "media_library_manager.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "permission_utils.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Media {
using namespace OHOS::AppExecFwk;

sptr<IAppMgr> MedialibraryAppStateObserverManager::GetAppManagerInstance()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        MEDIA_ERR_LOG("systemAbilityManager is nullptr");
        return nullptr;
    }

    sptr<IRemoteObject> object = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (object == nullptr) {
        MEDIA_ERR_LOG("systemAbilityManager remote object is nullptr");
        return nullptr;
    }

    return iface_cast<IAppMgr>(object);
}

void MedialibraryAppStateObserverManager::SubscribeAppState()
{
    MEDIA_INFO_LOG("SubscribeAppState");
    sptr<IAppMgr> appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        MEDIA_ERR_LOG("GetAppManagerInstance failed");
        return;
    }

    if (appStateObserver_ != nullptr) {
        MEDIA_INFO_LOG("appStateObserver has been registed");
        return;
    }

    appStateObserver_ = new (std::nothrow) MedialibraryAppStateObserver();
    if (appStateObserver_ == nullptr) {
        MEDIA_ERR_LOG("get appStateObserver failed");
        return;
    }

    int32_t result = appManager->RegisterApplicationStateObserver(appStateObserver_);
    if (result != E_SUCCESS) {
        MEDIA_ERR_LOG("RegistApplicationStateObserver failed");
        appStateObserver_ = nullptr;
        return;
    }

    MEDIA_INFO_LOG("SubscribeAppState success");
    return;
}

void MedialibraryAppStateObserverManager::UnSubscribeAppState()
{
    if (appStateObserver_ == nullptr) {
        MEDIA_ERR_LOG("appStateObserver_ is nullptr");
        return;
    }

    sptr<IAppMgr> appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        MEDIA_ERR_LOG("GetAppManagerInstance failed");
        return;
    }

    int32_t result = appManager->UnregisterApplicationStateObserver(appStateObserver_);
    if (result != E_SUCCESS) {
        MEDIA_ERR_LOG("UnregisterApplicationStateObserver failed");
        return;
    }

    appStateObserver_ = nullptr;
    MEDIA_INFO_LOG("UnSubscribeAppState success");
    return;
}

MedialibraryAppStateObserverManager &MedialibraryAppStateObserverManager::GetInstance()
{
    static MedialibraryAppStateObserverManager instance;
    return instance;
}

static int32_t CountTemporaryPermission(const std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    NativeRdb::AbsRdbPredicates predicatesUnSubscribe(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    vector<string> permissionTypes;
    permissionTypes.emplace_back(to_string(
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO)));
    permissionTypes.emplace_back(to_string(
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)));
    permissionTypes.emplace_back(to_string(
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)));
    predicatesUnSubscribe.And()->In(AppUriPermissionColumn::PERMISSION_TYPE, permissionTypes);
    vector<string> columns = { AppUriPermissionColumn::ID };
    auto resultSet = rdbStore->Query(predicatesUnSubscribe, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Can not query URIPERMISSION");
        return E_ERR;
    }

    int32_t count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetRowCount failed ret:%{public}d", ret);
        return E_ERR;
    }

    return count;
}

static int32_t CountHideSensitive(const std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    NativeRdb::AbsRdbPredicates predicatesUnSubscribe(AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE);
    vector<string> columns = { AppUriPermissionColumn::ID };
    auto resultSet = rdbStore->Query(predicatesUnSubscribe, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Can not query URIPERMISSION");
        return E_ERR;
    }

    int32_t count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetRowCount failed ret:%{public}d", ret);
        return E_ERR;
    }

    return count;
}

static void TryUnSubscribeAppState(const std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    int32_t countPermission = CountTemporaryPermission(rdbStore);
    int32_t countSensitive = CountHideSensitive(rdbStore);
    if (countPermission < 0 || countSensitive < 0) {
        MEDIA_ERR_LOG("TryUnSubscribeAppState System exception");
    }
    if (countPermission == 0 && countSensitive == 0) {
        MedialibraryAppStateObserverManager::GetInstance().UnSubscribeAppState();
        MEDIA_INFO_LOG("No temporary permission record remains ,UnSubscribeAppState");
    }
}

static int32_t DeleteTemporaryPermission(const std::shared_ptr<MediaLibraryRdbStore> rdbStore, const string &appId)
{
    NativeRdb::AbsRdbPredicates predicates(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    predicates.EqualTo(AppUriPermissionColumn::APP_ID, appId);
    vector<string> permissionTypes;
    permissionTypes.emplace_back(to_string(
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO)));
    permissionTypes.emplace_back(to_string(
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)));
    permissionTypes.emplace_back(to_string(
        static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)));
    predicates.And()->In(AppUriPermissionColumn::PERMISSION_TYPE, permissionTypes);
    int32_t deletedRows = -1;
    auto ret = rdbStore->Delete(deletedRows, predicates);
    if (ret != NativeRdb::E_OK || deletedRows < 0) {
        MEDIA_ERR_LOG("Story Delete db failed, errCode = %{public}d", ret);
    }
    MEDIA_INFO_LOG("Uripermission Delete retVal: %{public}d, deletedRows: %{public}d", ret, deletedRows);

    return deletedRows;
}

static int32_t DeleteHideSensitive(const std::shared_ptr<MediaLibraryRdbStore> rdbStore, const string &appId)
{
    NativeRdb::AbsRdbPredicates predicates(AppUriSensitiveColumn::APP_URI_SENSITIVE_TABLE);
    predicates.EqualTo(AppUriPermissionColumn::APP_ID, appId);
    int32_t deletedRows = -1;
    auto ret = rdbStore->Delete(deletedRows, predicates);
    if (ret != NativeRdb::E_OK || deletedRows < 0) {
        MEDIA_ERR_LOG("Story Delete db failed, errCode = %{public}d", ret);
    }
    MEDIA_INFO_LOG("Uripermission Delete retVal: %{public}d, deletedRows: %{public}d", ret, deletedRows);

    return deletedRows;
}

void MedialibraryAppStateObserver::OnAppStopped(const AppStateData &appStateData)
{
    auto bundleName = appStateData.bundleName;
    auto uid = appStateData.uid;
    MEDIA_INFO_LOG("MedialibraryAppStateObserver OnAppStopped, bundleName:%{public}s", bundleName.c_str());

    auto rdbStore = MediaLibraryDataManager::GetInstance()->rdbStore_;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Uripermission Delete failed, rdbStore is null.");
        return;
    }
    string appId = PermissionUtils::GetAppIdByBundleName(bundleName, uid);
    int32_t deletedRowsPermission = DeleteTemporaryPermission(rdbStore, appId);
    int32_t deletedRowsSensitive = DeleteHideSensitive(rdbStore, appId);
    if (deletedRowsPermission == 0 && deletedRowsSensitive == 0) {
        return;
    }
    TryUnSubscribeAppState(rdbStore);
}
}  // namespace Media
}  // namespace OHOS
