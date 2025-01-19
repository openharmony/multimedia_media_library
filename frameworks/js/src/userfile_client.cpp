/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "ability.h"

#include "media_asset_rdbstore.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_helper_container.h"
#include "media_file_utils.h"

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace Media {

int32_t UserFileClient::userId_ = -1;
int32_t UserFileClient::lastUserId_ = -1;
std::string MULTI_USER_URI_FLAG = "user=";
std::string USER_STR = "user";

static std::string GetMediaLibraryDataUri()
{
    std::string mediaLibraryDataUri = MEDIALIBRARY_DATA_URI;
    if (UserFileClient::GetUserId() != -1) {
        mediaLibraryDataUri = mediaLibraryDataUri + "?" + MULTI_USER_URI_FLAG + to_string(UserFileClient::GetUserId());
    }
    return mediaLibraryDataUri;
}

static void DataShareCreator(const sptr<IRemoteObject> &token, shared_ptr<DataShare::DataShareHelper> &dataShareHelper)
{
    dataShareHelper = DataShare::DataShareHelper::Creator(token, GetMediaLibraryDataUri());
    if (dataShareHelper == nullptr) {
        NAPI_ERR_LOG("dataShareHelper Creator failed");
        dataShareHelper = DataShare::DataShareHelper::Creator(token, mediaLibraryDataUri);
    }
}

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
        DataShareCreator(context->GetToken(), dataShareHelper);
    } else {
        auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[0]);
        if (context == nullptr) {
            NAPI_ERR_LOG("Failed to get native stage context instance");
            return nullptr;
        }
        DataShareCreator(context->GetToken(), dataShareHelper);
    }
    MediaLibraryHelperContainer::GetInstance()->SetDataShareHelper(dataShareHelper);
    return dataShareHelper;
}

napi_status UserFileClient::CheckIsStage(napi_env env, napi_callback_info info, bool &result)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Failed to get cb info, status=%{public}d", (int) status);
        return status;
    }

    result = false;
    status = OHOS::AbilityRuntime::IsStageContext(env, argv[0], result);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Failed to get stage mode, status=%{public}d", (int) status);
        return status;
    }
    return napi_ok;
}

sptr<IRemoteObject> UserFileClient::ParseTokenInStageMode(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        NAPI_ERR_LOG("Failed to get cb info");
        return nullptr;
    }

    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[0]);
    if (context == nullptr) {
        NAPI_ERR_LOG("Failed to get native stage context instance");
        return nullptr;
    }
    return context->GetToken();
}

sptr<IRemoteObject> UserFileClient::ParseTokenInAbility(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        NAPI_ERR_LOG("Failed to get cb info");
        return nullptr;
    }

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
    return context->GetToken();
}

bool UserFileClient::IsValid()
{
    return sDataShareHelper_ != nullptr;
}

void UserFileClient::Init(const sptr<IRemoteObject> &token, bool isSetHelper)
{
    sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    if (isSetHelper) {
        MediaLibraryHelperContainer::GetInstance()->SetDataShareHelper(sDataShareHelper_);
    }
}

void UserFileClient::Init(napi_env env, napi_callback_info info)
{
    sDataShareHelper_ = GetDataShareHelper(env, info);
}

shared_ptr<DataShareResultSet> UserFileClient::Query(Uri &uri, const DataSharePredicates &predicates,
    std::vector<std::string> &columns, int &errCode)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("Query fail, helper null");
        return nullptr;
    }

    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        MediaLibraryNapiUtils::UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);

    shared_ptr<DataShareResultSet> resultSet = nullptr;
    OperationObject object = OperationObject::UNKNOWN_OBJECT;
    if (MediaAssetRdbStore::GetInstance()->IsQueryAccessibleViaSandBox(uri, object, predicates) &&
        !uriString.find(MULTI_USER_URI_FLAG)) {
        resultSet = MediaAssetRdbStore::GetInstance()->Query(predicates, columns, object, errCode);
    } else {
        DatashareBusinessError businessError;
        resultSet = sDataShareHelper_->Query(uri, predicates, columns, &businessError);
        errCode = businessError.GetCode();
    }
    return resultSet;
}

std::shared_ptr<NativeRdb::ResultSet> UserFileClient::QueryRdb(Uri &uri,
    const DataShare::DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    OperationObject object = OperationObject::UNKNOWN_OBJECT;
    if (MediaAssetRdbStore::GetInstance()->IsSupportSharedAssetQuery(uri, object)) {
        resultSet = MediaAssetRdbStore::GetInstance()->QueryRdb(predicates, columns, object);
    }
    return resultSet;
}

int UserFileClient::Insert(Uri &uri, const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("insert fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        MediaLibraryNapiUtils::UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    int index = sDataShareHelper_->Insert(uri, value);
    return index;
}

int UserFileClient::InsertExt(Uri &uri, const DataShareValuesBucket &value, string &result)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("insert fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        MediaLibraryNapiUtils::UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    int index = sDataShareHelper_->InsertExt(uri, value, result);
    return index;
}

int UserFileClient::BatchInsert(Uri &uri, const std::vector<DataShare::DataShareValuesBucket> &values)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("Batch insert fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        MediaLibraryNapiUtils::UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    return sDataShareHelper_->BatchInsert(uri, values);
}

int UserFileClient::Delete(Uri &uri, const DataSharePredicates &predicates)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("delete fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        MediaLibraryNapiUtils::UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
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
        NAPI_ERR_LOG("Open file fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        MediaLibraryNapiUtils::UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    return sDataShareHelper_->OpenFile(uri, mode);
}

int UserFileClient::Update(Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("update fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        MediaLibraryNapiUtils::UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    return sDataShareHelper_->Update(uri, predicates, value);
}

void UserFileClient::RegisterObserverExt(const Uri &uri,
    shared_ptr<DataShare::DataShareObserver> dataObserver, bool isDescendants)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("register observer fail, helper null");
        return;
    }
    sDataShareHelper_->RegisterObserverExt(uri, std::move(dataObserver), isDescendants);
}

void UserFileClient::UnregisterObserverExt(const Uri &uri, std::shared_ptr<DataShare::DataShareObserver> dataObserver)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("unregister observer fail, helper null");
        return;
    }
    sDataShareHelper_->UnregisterObserverExt(uri, std::move(dataObserver));
}

std::string UserFileClient::GetType(Uri &uri)
{
    if (!IsValid()) {
        NAPI_ERR_LOG("get type fail, helper null");
        return "";
    }
    return sDataShareHelper_->GetType(uri);
}

void UserFileClient::Clear()
{
    sDataShareHelper_ = nullptr;
}

void UserFileClient::SetUserId(const int32_t userId)
{
    userId_ = userId;
}

int32_t UserFileClient::GetUserId()
{
    return userId_;
}

void UserFileClient::SetLastUserId(const int32_t userId)
{
    lastUserId_ = userId;
}

int32_t UserFileClient::GetLastUserId()
{
    return lastUserId_;
}
}
}
