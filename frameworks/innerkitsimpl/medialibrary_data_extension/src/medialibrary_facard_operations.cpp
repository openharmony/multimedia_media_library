/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
 
#include "medialibrary_facard_operations.h"
 
#include <memory>
#include <mutex>
#include <string>
#include "abs_shared_result_set.h"
 
#include "media_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdbstore.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"
#include "value_object.h"
#include "values_bucket.h"
#include "datashare_helper.h"
#include "medialibrary_data_manager.h"
#include "media_facard_photos_column.h"
#include "result_set_utils.h"
#include "ability_manager_client.h"
#include "application_context.h"
#include "resource_type.h"
#include "ffrt.h"
#include "ffrt_inner.h"
 
using namespace OHOS::DataShare;
using ChangeType = OHOS::DataShare::DataShareObserver::ChangeType;
using namespace std;
using namespace OHOS::NativeRdb;
 
namespace OHOS {
namespace Media {
std::mutex MediaLibraryFaCardOperations::mutex_;
const string MEDIA_LIBRARY_PROXY_URI = "datashareproxy://com.ohos.medialibrary.medialibrarydata";
static std::map<std::string, std::vector<std::shared_ptr<CardAssetUriObserver>>> formAssetObserversMap;
const string CLOUD_SYNC_PROXY_URI = "datashareproxy://com.huawei.hmos.clouddrive/sync_switch";
static std::map<std::string, std::vector<sptr<FaCloudSyncSwitchObserver>>> formCloudSyncObserversMap;
static std::map<ChangeType, int> changeTypeMap = {
    { ChangeType::INSERT, 0 },
    { ChangeType::DELETE, 1 },
    { ChangeType::UPDATE, 2 },
    { ChangeType::OTHER, 3 },
    { ChangeType::INVAILD, 4 },
};
 
bool CardAssetUriObserver::isTaskPosted = false;
std::shared_ptr<AppExecFwk::EventHandler> CardAssetUriObserver::deviceHandler_ =
std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::Create("MediaLibraryFacard"));
std::mutex CardAssetUriObserver::mtx;
std::unordered_set<
    CardAssetUriObserver::AssetChangeInfo,
    CardAssetUriObserver::AssetChangeInfoHash> CardAssetUriObserver::assetChanges;

bool FaCloudSyncSwitchObserver::isTaskPosted = false;
std::shared_ptr<AppExecFwk::EventHandler> FaCloudSyncSwitchObserver::deviceHandler_ =
std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::Create("MediaLibraryCloudSyncFacard"));
std::mutex FaCloudSyncSwitchObserver::mtx;
std::unordered_set<
    FaCloudSyncSwitchObserver::CloudSyncChangeInfo,
    FaCloudSyncSwitchObserver::CloudSyncChangeInfoHash> FaCloudSyncSwitchObserver::cloudSyncChanges;

std::map<std::string, std::vector<std::string>> MediaLibraryFaCardOperations::GetUris()
{
    lock_guard<mutex> lock(mutex_);
    MediaLibraryCommand queryFaCardCmd(OperationObject::TAB_FACARD_PHOTO, OperationType::QUERY);
    std::map<std::string, std::vector<std::string>> resultMap;
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return resultMap;
    }
    vector<string> columns = {
        TabFaCardPhotosColumn::FACARD_PHOTOS_ASSET_URI,
        TabFaCardPhotosColumn::FACARD_PHOTOS_FORM_ID
    };
    auto queryResult = uniStore->Query(queryFaCardCmd, columns);
    if (queryResult == nullptr) {
        MEDIA_ERR_LOG("Failed to query assetUris!");
        return resultMap;
    }
    while (queryResult->GoToNextRow() == NativeRdb::E_OK) {
        string assetUri = GetStringVal(TabFaCardPhotosColumn::FACARD_PHOTOS_ASSET_URI, queryResult);
        string formId = GetStringVal(TabFaCardPhotosColumn::FACARD_PHOTOS_FORM_ID, queryResult);
        resultMap[formId].push_back(assetUri);
    }
    return resultMap;
}
 
static string GetStringObject(MediaLibraryCommand &cmd, const string &columnName)
{
    ValueObject valueObject;
    ValuesBucket values = cmd.GetValueBucket();
    string value;
    if (values.GetObject(columnName, valueObject)) {
        valueObject.GetString(value);
        return value;
    }
    return "";
}

void CardAssetUriObserver::PostAssetChangeTask()
{
    if (!CardAssetUriObserver::isTaskPosted) {
        CardAssetUriObserver::isTaskPosted = true;
        const int DELAY_MILLISECONDS = 2000;
        CardAssetUriObserver::deviceHandler_->PostTask([this]() {
            std::lock_guard<std::mutex> lock(CardAssetUriObserver::mtx);
            std::vector<std::string> assetChangeUris;
            std::vector<int> assetChangeTypes;
            for (const auto& change : CardAssetUriObserver::assetChanges) {
                assetChangeUris.push_back(change.assetChangeUri);
                MEDIA_DEBUG_LOG("change.assetChangeUri = %{public}s", change.assetChangeUri.c_str());
                assetChangeTypes.push_back(change.assetChangeType);
                MEDIA_DEBUG_LOG("change.assetChangeType = %{public}d", change.assetChangeType);
            }
            AAFwk::Want want;
            want.SetElementName("com.huawei.hmos.photos", "FACardServiceAbility");
            want.SetParam("assetChangeUris", assetChangeUris);
            want.SetParam("assetChangeTypes", assetChangeTypes);
            int32_t userId = -1;
            auto result = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(
                want, nullptr, userId, AppExecFwk::ExtensionAbilityType::SERVICE);
            CardAssetUriObserver::assetChanges.clear();
            CardAssetUriObserver::isTaskPosted = false;
            }, "StartExtensionAbility", DELAY_MILLISECONDS);
    }
}

void FaCloudSyncSwitchObserver::PostAssetChangeTask()
{
    if (!FaCloudSyncSwitchObserver::isTaskPosted) {
        FaCloudSyncSwitchObserver::isTaskPosted = true;
        const int DELAY_MILLISECONDS = 2000;
        FaCloudSyncSwitchObserver::deviceHandler_->PostTask([this]() {
            std::lock_guard<std::mutex> lock(FaCloudSyncSwitchObserver::mtx);
            std::vector<std::string> assetChangeUris;
            std::vector<int> assetChangeTypes;
            for (const auto& change : FaCloudSyncSwitchObserver::cloudSyncChanges) {
                assetChangeUris.push_back(change.cloudSyncChangeUri);
                MEDIA_DEBUG_LOG("change.assetChangeUri = %{public}s", change.cloudSyncChangeUri.c_str());
                assetChangeTypes.push_back(change.cloudSyncChangeType);
                MEDIA_DEBUG_LOG("change.assetChangeType = %{public}d", change.cloudSyncChangeType);
            }
            AAFwk::Want want;
            want.SetElementName("com.huawei.hmos.photos", "FACardServiceAbility");
            want.SetParam("assetChangeUris", assetChangeUris);
            want.SetParam("assetChangeTypes", assetChangeTypes);
            int32_t userId = -1;
            auto result = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(
                want, nullptr, userId, AppExecFwk::ExtensionAbilityType::SERVICE);
            FaCloudSyncSwitchObserver::cloudSyncChanges.clear();
            FaCloudSyncSwitchObserver::isTaskPosted = false;
            }, "StartExtensionAbility", DELAY_MILLISECONDS);
    }
}

void CardAssetUriObserver::OnChange(const ChangeInfo &changeInfo)
{
    if (changeTypeMap.find(changeInfo.changeType_) != changeTypeMap.end()) {
        std::lock_guard<std::mutex> lock(CardAssetUriObserver::mtx);
        MEDIA_DEBUG_LOG("OnChange assetChangeUri = %{public}s", assetChangeUri.c_str());
        MEDIA_DEBUG_LOG("OnChange assetChangeType = %{public}d", static_cast<int>(changeInfo.changeType_));
        CardAssetUriObserver::assetChanges.insert(
            AssetChangeInfo(assetChangeUri, static_cast<int>(changeInfo.changeType_)));

        PostAssetChangeTask();
    }
}

void FaCloudSyncSwitchObserver::OnChange()
{
    std::lock_guard<std::mutex> lock(FaCloudSyncSwitchObserver::mtx);
    const int CLOUD_SYNC_TYPE = 3;
    MEDIA_DEBUG_LOG("OnChange assetChangeUri = %{public}s", cloudSyncChangeUri.c_str());
    MEDIA_DEBUG_LOG("OnChange assetChangeType = %{public}d", static_cast<int>(CLOUD_SYNC_TYPE));
    FaCloudSyncSwitchObserver::cloudSyncChanges.insert(
        CloudSyncChangeInfo(cloudSyncChangeUri, static_cast<int>(CLOUD_SYNC_TYPE)));

    PostAssetChangeTask();
}

void MediaLibraryFaCardOperations::RegisterObserver(const std::string &formId, const std::string &registerUri)
{
    const std::string ASSET_URI_PREFIX = "file://media/";
    const std::string CLOUD_SYNC_SWITCH_URI_PREFIX = "datashareproxy://";
    MEDIA_DEBUG_LOG("registerUri = %{public}s", registerUri.c_str());
 
    std::shared_ptr<DataShare::DataShareObserver> observer;
    sptr<FaCloudSyncSwitchObserver> cloudSyncObserver;
    if (registerUri.find(ASSET_URI_PREFIX) == 0) {
        auto cardAssetUriObserver = std::make_shared<CardAssetUriObserver>(registerUri);
        if (cardAssetUriObserver == nullptr) {
            return;
        }
        MEDIA_DEBUG_LOG("cardAssetUriObserver->uri = %{public}s", cardAssetUriObserver->assetChangeUri.c_str());
        formAssetObserversMap[formId].push_back(cardAssetUriObserver);
        observer = std::static_pointer_cast<DataShare::DataShareObserver>(cardAssetUriObserver);
    } else if (registerUri.find(CLOUD_SYNC_SWITCH_URI_PREFIX) == 0) {
        sptr<FaCloudSyncSwitchObserver> cloudSwitchObserver(new (std::nothrow) FaCloudSyncSwitchObserver(registerUri));
        if (cloudSwitchObserver == nullptr) {
            return;
        }
        MEDIA_DEBUG_LOG("FaCloudSyncuri = %{public}s", cloudSwitchObserver->cloudSyncChangeUri.c_str());
        formCloudSyncObserversMap[formId].push_back(cloudSwitchObserver);
        cloudSyncObserver = cloudSwitchObserver;
    } else {
        MEDIA_ERR_LOG("registerUri is inValid");
        return;
    }
    Uri notifyUri(registerUri);
    CreateOptions options;
    options.enabled_ = true;
    shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    if (registerUri.find(ASSET_URI_PREFIX) == 0) {
        dataShareHelper = DataShare::DataShareHelper::Creator(MEDIA_LIBRARY_PROXY_URI, options);
        dataShareHelper->RegisterObserverExt(notifyUri, observer, true);
    } else if (registerUri.find(CLOUD_SYNC_SWITCH_URI_PREFIX) == 0) {
        dataShareHelper = DataShare::DataShareHelper::Creator(CLOUD_SYNC_PROXY_URI, options);
        dataShareHelper->RegisterObserver(notifyUri, cloudSyncObserver);
    }
}

void MediaLibraryFaCardOperations::UnregisterObserver(const std::string &formId)
{
    CreateOptions options;
    options.enabled_ = true;
    shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    dataShareHelper = DataShare::DataShareHelper::Creator(MEDIA_LIBRARY_PROXY_URI, options);
    if (dataShareHelper == nullptr) {
        MEDIA_ERR_LOG("dataShareHelper is nullptr");
        return;
    }
    auto itAsset = formAssetObserversMap.find(formId);
    if (itAsset == formAssetObserversMap.end()) {
        MEDIA_ERR_LOG("No formAssetObservers found for formId: %{public}s", formId.c_str());
        return;
    }
    const std::vector<std::shared_ptr<CardAssetUriObserver>>& formAssetObservers = itAsset->second;
    for (const auto& observer : formAssetObservers) {
        Uri notifyUri(observer->assetChangeUri);
        dataShareHelper->UnregisterObserverExt(notifyUri,
            std::static_pointer_cast<DataShare::DataShareObserver>(observer));
    }
    formAssetObserversMap.erase(formId);

    dataShareHelper = DataShare::DataShareHelper::Creator(CLOUD_SYNC_PROXY_URI, options);
    if (dataShareHelper == nullptr) {
        MEDIA_ERR_LOG("dataShareHelper is nullptr");
        return;
    }
    auto cloudItAsset = formCloudSyncObserversMap.find(formId);
    if (cloudItAsset == formCloudSyncObserversMap.end()) {
        MEDIA_ERR_LOG("No formCloudSyncObserversMap found for formId: %{public}s", formId.c_str());
        return;
    }
    const std::vector<sptr<FaCloudSyncSwitchObserver>>& formCloudSyncObservers = cloudItAsset->second;
    for (const auto& observer : formCloudSyncObservers) {
        Uri notifyUri(observer->cloudSyncChangeUri);
        dataShareHelper->UnregisterObserver(notifyUri, observer);
    }
    formCloudSyncObserversMap.erase(formId);
}

int32_t MediaLibraryFaCardOperations::HandleStoreGalleryFormOperation(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int64_t outRowId = -1;
    lock_guard<mutex> lock(mutex_);
    int32_t errCode = rdbStore->Insert(cmd, outRowId);
    if (errCode != NativeRdb::E_OK || outRowId < 0) {
        MEDIA_ERR_LOG("Insert into db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    string formId = GetStringObject(cmd, TabFaCardPhotosColumn::FACARD_PHOTOS_FORM_ID);
    MEDIA_DEBUG_LOG("formId = %{public}s", formId.c_str());
    string assetRegisterUri = GetStringObject(cmd, TabFaCardPhotosColumn::FACARD_PHOTOS_ASSET_URI);
    MEDIA_DEBUG_LOG("assetRegisterUri = %{public}s", assetRegisterUri.c_str());
    MediaLibraryFaCardOperations::RegisterObserver(formId, assetRegisterUri);
    return static_cast<int32_t>(outRowId);
}
 
int32_t MediaLibraryFaCardOperations::HandleRemoveGalleryFormOperation(NativeRdb::RdbPredicates &rdbPredicate)
{
    lock_guard<mutex> lock(mutex_);
    string formId = rdbPredicate.GetWhereArgs()[0];
    MediaLibraryFaCardOperations::UnregisterObserver(formId);
    return MediaLibraryRdbStore::Delete(rdbPredicate);
}

void MediaLibraryFaCardOperations::InitRegisterObserver()
{
    const int INIT_NUM = 0;
    const int END_NUM = 10;
    const int DELAY_NUM = 100;
    int cnt = INIT_NUM;
    std::map<std::string, std::vector<std::string>> urisMap = MediaLibraryFaCardOperations::GetUris();
    for (const auto& pair : urisMap) {
        const std::string& formId = pair.first;
        MEDIA_DEBUG_LOG("InitRegisterObserver formId = %{public}s", formId.c_str());
        const std::vector<std::string>& uris = pair.second;
        MEDIA_DEBUG_LOG("InitRegisterObserver uris.size = %{public}d", uris.size());
        for (const std::string& uri : uris) {
            MediaLibraryFaCardOperations::RegisterObserver(formId, uri);
            MEDIA_DEBUG_LOG("InitRegisterObserver uri = %{public}s", uri.c_str());
            cnt ++;
            if (cnt == END_NUM) {
                cnt = INIT_NUM;
                std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_NUM));
            }
        }
    }
}

void MediaLibraryFaCardOperations::InitFaCard()
{
    ffrt::submit([]() { MediaLibraryFaCardOperations::InitRegisterObserver(); });
}
} // namespace Media
} // namespace OHOS