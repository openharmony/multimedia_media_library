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
static const std::string CLOUD_DATASHARE_URI = "datashareproxy://generic.cloudstorage/cloud_sp?Proxy=true";
static const std::string CLOUD_URI = CLOUD_DATASHARE_URI + "&key=useMobileNetworkData";
static const std::string CLOUD_SYNC_SWITCH_URI = CLOUD_DATASHARE_URI + "/sync_switch";
static const std::string MOBILE_NETWORK_STATUS_ON = "1";

bool CloudSyncUtils::IsUnlimitedTrafficStatusOn()
{
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get SystemAbilityManagerClient");
        return E_ERR;
    }
    OHOS::sptr<OHOS::IRemoteObject> remoteObject = saMgr->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("Token is null.");
        return E_ERR;
    }
    std::shared_ptr<DataShare::DataShareHelper> cloudHelper = DataShare::DataShareHelper::Creator(remoteObject,
        CLOUD_DATASHARE_URI);
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
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get SystemAbilityManagerClient");
        return E_ERR;
    }
    OHOS::sptr<OHOS::IRemoteObject> remoteObject = saMgr->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("Token is null.");
        return E_ERR;
    }
    std::shared_ptr<DataShare::DataShareHelper> cloudHelper = DataShare::DataShareHelper::Creator(remoteObject,
        CLOUD_DATASHARE_URI);
    if (cloudHelper == nullptr) {
        MEDIA_INFO_LOG("cloudHelper is null");
        return false;
    }

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("bundleName", "generic.cloudstorage");
    Uri cloudUri(CLOUD_SYNC_SWITCH_URI);
    vector<string> columns = { "isSwitchOn" };
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
} // namespace Media
} // namespace OHOS