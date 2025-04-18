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
 
using namespace OHOS::DataShare;
using ChangeType = OHOS::DataShare::DataShareObserver::ChangeType;
using namespace std;
using namespace OHOS::NativeRdb;
 
namespace OHOS {
namespace Media {
std::mutex MediaLibraryFaCardOperations::mutex_;
const string MEDIA_LIBRARY_PROXY_URI = "datashareproxy://com.ohos.medialibrary.medialibrarydata";
static std::map<std::string, std::vector<std::shared_ptr<CardAssetUriObserver>>> formAssetObserversMap;
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
 
void MediaLibraryFaCardOperations::RegisterObserver(const std::string &formId, const std::string &registerUri)
{
    const std::string ASSET_URI_PREFIX = "file://media/";
    const std::string CLOUD_SYNC_SWITCH_URI_PREFIX = "datashareproxy://";
    MEDIA_DEBUG_LOG("registerUri = %{public}s", registerUri.c_str());
 
    std::shared_ptr<DataShare::DataShareObserver> observer;
    if (registerUri.find(ASSET_URI_PREFIX) == 0 || registerUri.find(CLOUD_SYNC_SWITCH_URI_PREFIX) == 0) {
        auto cardAssetUriObserver = std::make_shared<CardAssetUriObserver>(registerUri);
        MEDIA_DEBUG_LOG("cardAssetUriObserver->uri = %{public}s", cardAssetUriObserver->assetChangeUri.c_str());
        formAssetObserversMap[formId].push_back(cardAssetUriObserver);
        observer = std::static_pointer_cast<DataShare::DataShareObserver>(cardAssetUriObserver);
    } else {
        MEDIA_ERR_LOG("registerUri is inValid");
        return;
    }
    Uri notifyUri(registerUri);
    CreateOptions options;
    options.enabled_ = true;
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
    DataShare::DataShareHelper::Creator(MEDIA_LIBRARY_PROXY_URI, options);
    if (dataShareHelper == nullptr) {
        MEDIA_ERR_LOG("dataShareHelper is nullptr");
        return;
    }
    MEDIA_DEBUG_LOG("notifyUri = %{public}s", notifyUri.ToString().c_str());
    dataShareHelper->RegisterObserverExt(notifyUri, observer, true);
}
 
void MediaLibraryFaCardOperations::UnregisterObserver(const std::string &formId)
{
    CreateOptions options;
    options.enabled_ = true;
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
    DataShare::DataShareHelper::Creator(MEDIA_LIBRARY_PROXY_URI, options);
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
} // namespace Media
} // namespace OHOS