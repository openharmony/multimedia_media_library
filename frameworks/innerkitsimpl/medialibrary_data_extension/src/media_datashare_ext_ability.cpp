/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "media_datashare_ext_ability.h"

#include "ability_info.h"
#include "accesstoken_kit.h"
#include "bytrace.h"
#include "dataobs_mgr_client.h"
#include "media_datashare_stub_impl.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "datashare_ext_ability_context.h"
#include "runtime.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "medialibrary_data_manager.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedKv;
using namespace OHOS::Media;

namespace OHOS {
namespace AbilityRuntime {

using namespace OHOS::AppExecFwk;
using OHOS::Security::AccessToken::AccessTokenKit;
using DataObsMgrClient = OHOS::AAFwk::DataObsMgrClient;
constexpr int INVALID_VALUE = -1;

MediaDataShareExtAbility* MediaDataShareExtAbility::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new MediaDataShareExtAbility(static_cast<Runtime&>(*runtime));
}

MediaDataShareExtAbility::MediaDataShareExtAbility(Runtime& runtime) : DataShareExtAbility(), runtime_(runtime) {}

MediaDataShareExtAbility::~MediaDataShareExtAbility()
{
}

void MediaDataShareExtAbility::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    DataShareExtAbility::Init(record, application, handler, token);
    auto context = GetContext();
    if (context == nullptr) {
        HILOG_ERROR("Failed to get context");
        return;
    }
    HILOG_INFO("%{public}s runtime language  %{public}d", __func__, runtime_.GetLanguage());

    MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(context);
}

void MediaDataShareExtAbility::OnStart(const AAFwk::Want &want)
{
    HILOG_INFO("%{public}s begin.", __func__);
    Extension::OnStart(want);
    HILOG_INFO("%{public}s end.", __func__);
}

sptr<IRemoteObject> MediaDataShareExtAbility::OnConnect(const AAFwk::Want &want)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin. ", __func__);
    Extension::OnConnect(want);
    sptr<MediaDataShareStubImpl> remoteObject = new (std::nothrow) MediaDataShareStubImpl(
        std::static_pointer_cast<MediaDataShareExtAbility>(shared_from_this()),
        nullptr);
    if (remoteObject == nullptr) {
        HILOG_ERROR("%{public}s No memory allocated for DataShareStubImpl", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s end. klh", __func__);
    return remoteObject->AsObject();
}

std::vector<std::string> MediaDataShareExtAbility::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    //auto ret = MediaLibraryDataManager::GetInstance()->GetFileTypes(uri, mimeTypeFilter);
    HILOG_INFO("%{public}s end.", __func__);
    //return ret;
    std::vector<std::string> ret;
    return ret; 
}

int MediaDataShareExtAbility::OpenFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = MediaLibraryDataManager::GetInstance()->OpenFile(uri, mode);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::OpenRawFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    //auto ret = MediaLibraryDataManager::GetInstance()->OpenRawFile(uri, mode);
    HILOG_INFO("%{public}s end.", __func__);
    //return ret;
    return 0;
}

int MediaDataShareExtAbility::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = MediaLibraryDataManager::GetInstance()->Insert(uri, value);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::Update(const Uri &uri, const DataSharePredicates &predicates,
		const DataShareValuesBucket &value)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = MediaLibraryDataManager::GetInstance()->Update(uri, value, predicates);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = MediaLibraryDataManager::GetInstance()->Delete(uri, predicates);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

std::shared_ptr<ResultSetBridge> MediaDataShareExtAbility::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("klh %{public}s begin.", __func__);

    std::shared_ptr<DataShare::ResultSetBridge> queryResultSet;
    queryResultSet = MediaLibraryDataManager::GetInstance()->Query(uri, columns, predicates);
    HILOG_INFO("klh %{public}s end.", __func__);

    return queryResultSet;
}

std::string MediaDataShareExtAbility::GetType(const Uri &uri)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = MediaLibraryDataManager::GetInstance()->GetType(uri);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    //ret = MediaLibraryDataManager::GetInstance()->BatchInsert(uri, values);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

bool MediaDataShareExtAbility::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("%{public}s begin.", __func__);
    //MediaLibraryDataManager::GetInstance()->RegisterObserver(uri, dataObserver);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        HILOG_ERROR("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->RegisterObserver(uri, dataObserver);
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s obsMgrClient->RegisterObserver error return %{public}d", __func__, ret);
        return false;
    }
    HILOG_INFO("%{public}s end.", __func__);
    return true;
}

bool MediaDataShareExtAbility::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("%{public}s begin.", __func__);
    //MediaLibraryDataManager::GetInstance()->UnregisterObserver(uri, dataObserver);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        HILOG_ERROR("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->UnregisterObserver(uri, dataObserver);
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s obsMgrClient->UnregisterObserver error return %{public}d", __func__, ret);
        return false;
    }
    HILOG_INFO("%{public}s end.", __func__);
    return true;
}

bool MediaDataShareExtAbility::NotifyChange(const Uri &uri)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        HILOG_ERROR("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->NotifyChange(uri);
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s obsMgrClient->NotifyChange error return %{public}d", __func__, ret);
        return false;
    }
    HILOG_INFO("%{public}s end.", __func__);
    return true;
}

Uri MediaDataShareExtAbility::NormalizeUri(const Uri &uri)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = uri;
    //auto ret = MediaLibraryDataManager::GetInstance()->NormalizeUri(uri);
    HILOG_INFO("%{public}s end.", __func__);

    return ret;
    
}

Uri MediaDataShareExtAbility::DenormalizeUri(const Uri &uri)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = uri;
    //auto ret = MediaLibraryDataManager::GetInstance()->DenormalizeUri(uri);

    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

std::vector<std::shared_ptr<DataShareResult>> MediaDataShareExtAbility::ExecuteBatch(
    const std::vector<std::shared_ptr<DataShareOperation>> &operations)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::vector<std::shared_ptr<DataShareResult>> ret;
    //auto ret = MediaLibraryDataManager::GetInstance()->ExecuteBatch(operations);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

bool MediaDataShareExtAbility::CheckCallingPermission(const std::string &permission)
{
    HILOG_INFO("%{public}s begin, permission:%{public}s", __func__, permission.c_str());
    /*
    if (!permission.empty() && AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), permission)
        != AppExecFwk::Constants::PERMISSION_GRANTED) {
        HILOG_ERROR("%{public}s permission not granted.", __func__);
        return false;
    }
    */
    HILOG_INFO("%{public}s end.", __func__);
    return true;
}

} // namespace AbilityRuntime
} // namespace OHOS
