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

#define MLOG_TAG "MediaLibraryCloudSyncUtils"

#include "cloud_sync_utils.h"

#include "datashare_helper.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
static constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
static const std::string CLOUD_BASE_URI = "datashareproxy://generic.cloudstorage/";
static const std::string CLOUD_DATASHARE_URI = CLOUD_BASE_URI + "cloud_sp?Proxy=true";
static const std::string CLOUD_URI = CLOUD_DATASHARE_URI + "&key=useMobileNetworkData";
static const std::string CLOUD_AGING_URI = CLOUD_DATASHARE_URI + "&key=dataAgingPolicy";
static const std::string CLOUD_SYNC_URI = CLOUD_BASE_URI + "sync_module_data?Proxy=true";
static const std::string CLOUD_SYNC_SWITCH_URI = CLOUD_BASE_URI + "sync_switch&bundleName=generic.cloudstorage";
static const std::string MOBILE_NETWORK_STATUS_ON = "1";

static std::shared_ptr<DataShare::DataShareHelper> GetCloudHelper(const std::string &uri)
{
    if (uri.empty()) {
        MEDIA_ERR_LOG("uri is empty.");
        return nullptr;
    }
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get SystemAbilityManagerClient");
        return nullptr;
    }
    OHOS::sptr<OHOS::IRemoteObject> remoteObject = saMgr->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("Token is null.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObject, uri);
}

bool CloudSyncUtils::IsUnlimitedTrafficStatusOn()
{
    std::shared_ptr<DataShare::DataShareHelper> cloudHelper = GetCloudHelper(CLOUD_DATASHARE_URI);
    if (cloudHelper == nullptr) {
        MEDIA_INFO_LOG("cloudHelper is null");
        return false;
    }

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("key", "useMobileNetworkData");
    Uri cloudUri(CLOUD_URI);
    vector<string> columns = { "value" };
    shared_ptr<DataShare::DataShareResultSet> resultSet = cloudHelper->Query(cloudUri, predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_INFO_LOG("resultSet is nullptr");
        return false;
    }
    string switchOn = "0";
    if (resultSet->GoToNextRow() == E_OK) {
        resultSet->GetString(0, switchOn);
    }
    return switchOn == MOBILE_NETWORK_STATUS_ON;
}

bool CloudSyncUtils::IsCloudSyncSwitchOn()
{
    std::shared_ptr<DataShare::DataShareHelper> cloudHelper = GetCloudHelper(CLOUD_SYNC_URI);
    CHECK_AND_RETURN_RET_LOG(cloudHelper != nullptr, false, "cloudHelper is null");

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("bundleName", "generic.cloudstorage");
    Uri cloudUri(CLOUD_SYNC_SWITCH_URI);
    vector<string> columns = { "isSwitchOn" };
    shared_ptr<DataShare::DataShareResultSet> resultSet = cloudHelper->Query(cloudUri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "resultSet is null");

    string switchOn = "0";
    if (resultSet->GoToNextRow() == E_OK) {
        resultSet->GetString(0, switchOn);
    }
    return switchOn == MOBILE_NETWORK_STATUS_ON;
}

bool CloudSyncUtils::IsCloudDataAgingPolicyOn()
{
    std::shared_ptr<DataShare::DataShareHelper> cloudHelper = GetCloudHelper(CLOUD_DATASHARE_URI);
    CHECK_AND_RETURN_RET_LOG(cloudHelper != nullptr, false, "cloudHelper is null");
    
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("key", "dataAgingPolicy");
    Uri cloudUri(CLOUD_AGING_URI);
    vector<string> columns = { "value" };
    shared_ptr<DataShare::DataShareResultSet> resultSet = cloudHelper->Query(cloudUri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "resultSet is nullptr");
    string switchOn = "0";
    if (resultSet->GoToNextRow() == E_OK) {
        resultSet->GetString(0, switchOn);
    }
    return switchOn == MOBILE_NETWORK_STATUS_ON;
}
} // namespace Media
} // namespace OHOS