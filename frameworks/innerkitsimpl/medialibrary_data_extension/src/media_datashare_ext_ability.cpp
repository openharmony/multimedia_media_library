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
#include "datashare_stub_impl.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "js_datashare_ext_ability_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AbilityRuntime {

using namespace OHOS::AppExecFwk;
using OHOS::Security::AccessToken::AccessTokenKit;
using DataObsMgrClient = OHOS::AAFwk::DataObsMgrClient;
constexpr int INVALID_VALUE = -1;

MediaDataShareExtAbility* MediaDataShareExtAbility::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new MediaDataShareExtAbility(static_cast<JsRuntime&>(*runtime));
}

MediaDataShareExtAbility::MediaDataShareExtAbility(JsRuntime& jsRuntime) : JsDataShareExtAbility(jsRuntime), jsRuntime_(jsRuntime) {}

MediaDataShareExtAbility::~MediaDataShareExtAbility()
{
}

void MediaDataShareExtAbility::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    DataShareExtAbility::Init(record, application, handler, token);
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
    HILOG_INFO("%{public}s begin. klh", __func__);
    Extension::OnConnect(want);
    sptr<DataShareStubImpl> remoteObject = new (std::nothrow) DataShareStubImpl(
        std::static_pointer_cast<MediaDataShareExtAbility>(shared_from_this()),
        reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine()));
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
    auto ret = DataShareExtAbility::GetFileTypes(uri, mimeTypeFilter);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::OpenFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = DataShareExtAbility::OpenFile(uri, mode);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::OpenRawFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = DataShareExtAbility::OpenRawFile(uri, mode);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
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

    ret = DataShareExtAbility::Insert(uri, value);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::Update(const Uri &uri, const DataShareValuesBucket &value,
    const DataSharePredicates &predicates)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(abilityInfo_->writePermission)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    ret = DataShareExtAbility::Update(uri, value, predicates);
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

    ret = DataShareExtAbility::Delete(uri, predicates);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

std::shared_ptr<DataShareAbstractResultSet> MediaDataShareExtAbility::Query(const Uri &uri,
    std::vector<std::string> &columns, const DataSharePredicates &predicates)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);

    auto ret = DataShareExtAbility::Query(uri, columns, predicates);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

std::string MediaDataShareExtAbility::GetType(const Uri &uri)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = DataShareExtAbility::GetType(uri);
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

    ret = DataShareExtAbility::BatchInsert(uri, values);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

bool MediaDataShareExtAbility::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("%{public}s begin.", __func__);
    DataShareExtAbility::RegisterObserver(uri, dataObserver);
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
    DataShareExtAbility::UnregisterObserver(uri, dataObserver);
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
    DataShareExtAbility::NotifyChange(uri);
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
    auto ret = DataShareExtAbility::NormalizeUri(uri);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

Uri MediaDataShareExtAbility::DenormalizeUri(const Uri &uri)
{
    BYTRACE_NAME(BYTRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = DataShareExtAbility::DenormalizeUri(uri);

    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

std::vector<std::shared_ptr<DataShareResult>> MediaDataShareExtAbility::ExecuteBatch(
    const std::vector<std::shared_ptr<DataShareOperation>> &operations)
{
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = DataShareExtAbility::ExecuteBatch(operations);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

bool MediaDataShareExtAbility::CheckCallingPermission(const std::string &permission)
{
    HILOG_INFO("%{public}s begin, permission:%{public}s", __func__, permission.c_str());
    if (!permission.empty() && AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), permission)
        != AppExecFwk::Constants::PERMISSION_GRANTED) {
        HILOG_ERROR("%{public}s permission not granted.", __func__);
        return false;
    }
    HILOG_INFO("%{public}s end.", __func__);
    return true;
}

} // namespace AbilityRuntime
} // namespace OHOS
