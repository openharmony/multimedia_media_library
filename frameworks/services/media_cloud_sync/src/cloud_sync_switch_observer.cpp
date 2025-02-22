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

#include <string>
#include <vector>

#include "cloud_sync_switch_observer.h"
#include "media_analysis_helper.h"
#include "medialibrary_unistore_manager.h"
#include "parameters.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
const std::string QUERY_URI = "datashareproxy://";
DataShare::CreateOptions options;
constexpr int32_t SYNC_INTERVAL = 20000;

void CloudSyncSwitchObserver::OnChange()
{
    MEDIA_INFO_LOG("Cloud Sync Switch Status change");
    lock_guard<mutex> lock(syncMutex_);
        if (!isPending_) {
            MEDIA_INFO_LOG("CloudSyncSwitchObserver set timer handle index");
            std::thread([this]() {
                this->HandleIndex();
            }).detach();
            isPending_ = true;
        }
}

void CloudSyncSwitchObserver::HandleIndex()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SYNC_INTERVAL));
    lock_guard<mutex> lock(syncMutex_);
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return;
    }

    //delete index
    const std::string queryIdToDeleteIndex = "SELECT file_id FROM tab_analysis_search_index WHERE photo_status = -1";
    auto resultSet = uniStore->QuerySql(queryIdToDeleteIndex);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr!");
    }
    std::vector<std::string> idToDeleteIndex;
    while (resultSet != nullptr && resultSet->GoToNextRow() == NativeRdb::E_OK) {
        idToDeleteIndex.push_back(to_string(GetInt32Val("file_id", resultSet)));
    }
    MEDIA_INFO_LOG("idToDeleteIndex size: %{public}zu", idToDeleteIndex.size());
    if (!idToDeleteIndex.empty()) {
        MediaAnalysisHelper::AsyncStartMediaAnalysisService(
            static_cast<int32_t>(MediaAnalysisProxy::ActivateServiceType::START_DELETE_INDEX), idToDeleteIndex);
    }

    //update index
    const std::string queryIdToUpdateIndex = "SELECT file_id FROM tab_analysis_search_index WHERE photo_status = 2";
    auto resultSetUpdateIndex = uniStore->QuerySql(queryIdToUpdateIndex);
    if (resultSetUpdateIndex == nullptr) {
        MEDIA_ERR_LOG("resultSetUpdateIndex is nullptr!");
        return;
    }
    std::vector<std::string> idToUpdateIndex;
    while (resultSetUpdateIndex->GoToNextRow() == NativeRdb::E_OK) {
        idToUpdateIndex.push_back(to_string(GetInt32Val("file_id", resultSetUpdateIndex)));
    }
    MEDIA_INFO_LOG("idToUpdateIndex size: %{public}zu", idToUpdateIndex.size());
    if (!idToUpdateIndex.empty()) {
        MediaAnalysisHelper::AsyncStartMediaAnalysisService(
            static_cast<int32_t>(MediaAnalysisProxy::ActivateServiceType::START_UPDATE_INDEX), idToUpdateIndex);
    }
    isPending_ = false;
}

void CloudSyncSwitchManager::RegisterObserver()
{
    options.enabled_ = true;
    auto dataShareHelper = DataShare::DataShareHelper::Creator(QUERY_URI, options);
    if (dataShareHelper == nullptr) {
        MEDIA_ERR_LOG("dataShareHelper is nullptr");
        return;
    }

    const string photos = "persist.kernel.bundle_name.photos";
    const string clouddrive = "persist.kernel.bundle_name.clouddrive";
    const std::string GALLERY_BUNDLE_NAME = system::GetParameter(photos, "");
    const std::string CLOUDDRIVE_BUNDLE_NAME = system::GetParameter(clouddrive, "");
    if (GALLERY_BUNDLE_NAME == "") {
        MEDIA_ERR_LOG("can't get gallery bundle name");
        return;
    }
    if (CLOUDDRIVE_BUNDLE_NAME == "") {
        MEDIA_ERR_LOG("can't get clouddrive bundle name");
        return;
    }
    std::string queryUri = QUERY_URI + CLOUDDRIVE_BUNDLE_NAME + "/sync_switch?bundleName=" + GALLERY_BUNDLE_NAME;

    sptr<CloudSyncSwitchObserver> switchObserver(new (std::nothrow) CloudSyncSwitchObserver());
    if (switchObserver == nullptr) {
        return;
    }
    Uri observerUri(queryUri);
    dataShareHelper->RegisterObserver(observerUri, switchObserver);
}

void CloudSyncSwitchManager::UnRegisterObserver()
{
    MEDIA_ERR_LOG("CloudSyncSwitchManager UnRegisterObserver");
}
} // namespace Media
} // namespace OHOS
