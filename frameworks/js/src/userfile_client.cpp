/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "userfile_client.h"

#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "ability.h"

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace Media {

shared_ptr<DataShare::DataShareHelper> UserFileClient::GetDataShareHelper(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    bool isStageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, argv[0], isStageMode);
    if (status != napi_ok || !isStageMode) {
        auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
        if (ability == nullptr) {
            NAPI_ERR_LOG("Failed to get native ability instance");
            return nullptr;
        }
        auto context = ability->GetContext();
        if (context == nullptr) {
            NAPI_ERR_LOG("Failed to get native context instance");
            return nullptr;
        }
        dataShareHelper = DataShare::DataShareHelper::Creator(context, MEDIALIBRARY_DATA_URI);
    } else {
        auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[0]);
        if (context == nullptr) {
            NAPI_ERR_LOG("Failed to get native stage context instance");
            return nullptr;
        }
        dataShareHelper = DataShare::DataShareHelper::Creator(context, MEDIALIBRARY_DATA_URI);
    }
    return dataShareHelper;
}

bool UserFileClient::IsValid()
{
    return sDataShareHelper_ != nullptr;
}

void UserFileClient::Init(napi_env env, napi_callback_info info)
{
    sDataShareHelper_ = GetDataShareHelper(env, info);
}

shared_ptr<DataShareResultSet> UserFileClient::Query(Uri &uri, const DataSharePredicates &predicates,
    std::vector<std::string> &columns)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("Query fail, helper null");
        return nullptr;
    }
    return sDataShareHelper_->Query(uri, predicates, columns);
}

int UserFileClient::Insert(Uri &uri, const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("insert fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->Insert(uri, value);
}

int UserFileClient::Delete(Uri &uri, const DataSharePredicates &predicates)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("delete fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->Delete(uri, predicates);
}

void UserFileClient::NotifyChange(const Uri &uri)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("notify change fail, helper null");
        return;
    }
    sDataShareHelper_->NotifyChange(uri);
}

void UserFileClient::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("register observer fail, helper null");
        return;
    }
    sDataShareHelper_->RegisterObserver(uri, dataObserver);
}

void UserFileClient::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("unregister observer fail, helper null");
        return;
    }
    sDataShareHelper_->UnregisterObserver(uri, dataObserver);
}

int UserFileClient::OpenFile(Uri &uri, const std::string &mode)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("unregister observer fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->OpenFile(uri, mode);
}

int UserFileClient::Update(Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("update fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->Update(uri, predicates, value);
}

}
}