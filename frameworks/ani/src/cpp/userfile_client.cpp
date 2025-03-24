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

#include "userfile_client.h"

#include "ability.h"
#include "ani_base_context.h"
#include "media_asset_rdbstore.h"
#include "medialibrary_errno.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_helper_container.h"
#include "media_file_utils.h"
#include "userfilemgr_uri.h"

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace Media {
static void DataShareCreator(const sptr<IRemoteObject> &token, shared_ptr<DataShare::DataShareHelper> &dataShareHelper)
{
    dataShareHelper = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    if (dataShareHelper == nullptr) {
        ANI_ERR_LOG("dataShareHelper Creator failed");
        dataShareHelper = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
}

shared_ptr<DataShare::DataShareHelper> UserFileClient::GetDataShareHelper(ani_env *env, ani_object object)
{
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    auto context = GetStageModeContext(env, object);
    if (context == nullptr) {
        ANI_ERR_LOG("Failed to get native stage context instance");
        return nullptr;
    }
    DataShareCreator(context->GetToken(), dataShareHelper);
    MediaLibraryHelperContainer::GetInstance()->SetDataShareHelper(dataShareHelper);
    return dataShareHelper;
}

ani_status UserFileClient::CheckIsStage(ani_env *env, ani_object object, bool &result)
{
    ani_boolean isStageMode = false;
    CHECK_STATUS_RET(IsStageContext(env, object, isStageMode), "IsStageContext failed.");
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetBool(env, isStageMode, result), "GetBool failed.");
    return ANI_OK;
}

sptr<IRemoteObject> UserFileClient::ParseTokenInStageMode(ani_env *env, ani_object object)
{
    auto context = GetStageModeContext(env, object);
    if (context == nullptr) {
        ANI_ERR_LOG("Failed to get native stage context instance");
        return nullptr;
    }
    return context->GetToken();
}

sptr<IRemoteObject> UserFileClient::ParseTokenInAbility(ani_env *env, ani_object object)
{
    auto ability = GetCurrentAbility(env);
    if (ability == nullptr) {
        ANI_ERR_LOG("Failed to get native ability instance");
        return nullptr;
    }
    auto context = ability->GetContext();
    if (context == nullptr) {
        ANI_ERR_LOG("Failed to get native context instance");
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

void UserFileClient::Init(ani_env *env, ani_object object)
{
    sDataShareHelper_ = GetDataShareHelper(env, object);
}

shared_ptr<DataShareResultSet> UserFileClient::Query(Uri &uri, const DataSharePredicates &predicates,
    std::vector<std::string> &columns, int &errCode)
{
    if (!IsValid()) {
        ANI_ERR_LOG("Query fail, helper null");
        return nullptr;
    }

    shared_ptr<DataShareResultSet> resultSet = nullptr;
    OperationObject object = OperationObject::UNKNOWN_OBJECT;
    if (MediaAssetRdbStore::GetInstance()->IsQueryAccessibleViaSandBox(uri, object, predicates)) {
        resultSet = MediaAssetRdbStore::GetInstance()->Query(predicates, columns, object, errCode);
    } else {
        DatashareBusinessError businessError;
        resultSet = sDataShareHelper_->Query(uri, predicates, columns, &businessError);
        errCode = businessError.GetCode();
    }
    return resultSet;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> UserFileClient::QueryRdb(Uri &uri,
    const DataShare::DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    OperationObject object = OperationObject::UNKNOWN_OBJECT;
    if (MediaAssetRdbStore::GetInstance()->IsSupportSharedAssetQuery(uri, object)) {
        resultSet = MediaAssetRdbStore::GetInstance()->QueryRdb(predicates, columns, object);
    }
    return resultSet;
}

int UserFileClient::Insert(Uri &uri, const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        ANI_ERR_LOG("insert fail, helper null");
        return E_FAIL;
    }
    int index = sDataShareHelper_->Insert(uri, value);
    return index;
}

int UserFileClient::InsertExt(Uri &uri, const DataShareValuesBucket &value, string &result)
{
    if (!IsValid()) {
        ANI_ERR_LOG("insert fail, helper null");
        return E_FAIL;
    }
    int index = sDataShareHelper_->InsertExt(uri, value, result);
    return index;
}

int UserFileClient::BatchInsert(Uri &uri, const std::vector<DataShare::DataShareValuesBucket> &values)
{
    if (!IsValid()) {
        ANI_ERR_LOG("Batch insert fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->BatchInsert(uri, values);
}

int UserFileClient::Delete(Uri &uri, const DataSharePredicates &predicates)
{
    if (!IsValid()) {
        ANI_ERR_LOG("delete fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->Delete(uri, predicates);
}

void UserFileClient::NotifyChange(const Uri &uri)
{
    if (!IsValid()) {
        ANI_ERR_LOG("notify change fail, helper null");
        return;
    }
    sDataShareHelper_->NotifyChange(uri);
}

void UserFileClient::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    if (!IsValid()) {
        ANI_ERR_LOG("register observer fail, helper null");
        return;
    }
    sDataShareHelper_->RegisterObserver(uri, dataObserver);
}

void UserFileClient::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    if (!IsValid()) {
        ANI_ERR_LOG("unregister observer fail, helper null");
        return;
    }
    sDataShareHelper_->UnregisterObserver(uri, dataObserver);
}

int UserFileClient::OpenFile(Uri &uri, const std::string &mode)
{
    if (!IsValid()) {
        ANI_ERR_LOG("Open file fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->OpenFile(uri, mode);
}

int UserFileClient::Update(Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        ANI_ERR_LOG("update fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->Update(uri, predicates, value);
}

void UserFileClient::RegisterObserverExt(const Uri &uri,
    shared_ptr<DataShare::DataShareObserver> dataObserver, bool isDescendants)
{
    if (!IsValid()) {
        ANI_ERR_LOG("register observer fail, helper null");
        return;
    }
    sDataShareHelper_->RegisterObserverExt(uri, std::move(dataObserver), isDescendants);
}

void UserFileClient::UnregisterObserverExt(const Uri &uri, std::shared_ptr<DataShare::DataShareObserver> dataObserver)
{
    if (!IsValid()) {
        ANI_ERR_LOG("unregister observer fail, helper null");
        return;
    }
    sDataShareHelper_->UnregisterObserverExt(uri, std::move(dataObserver));
}

void UserFileClient::Clear()
{
    sDataShareHelper_ = nullptr;
}
} // namespace Media
} // namespace OHOS
