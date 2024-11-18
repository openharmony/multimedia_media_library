/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "userfile_client.h"

#include "ability_runtime/cj_ability_context.h"
#include "ffi_remote_data.h"
#include "media_asset_rdbstore.h"
#include "media_file_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_helper_container.h"
#include "medialibrary_operation.h"
#include "userfilemgr_uri.h"

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace Media {
bool UserFileClient::IsValid()
{
    return sDataShareHelper_ != nullptr;
}

void UserFileClient::Init(const sptr<IRemoteObject> &token)
{
    if (sDataShareHelper_ == nullptr) {
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
    MediaLibraryHelperContainer::GetInstance()->SetDataShareHelper(sDataShareHelper_);
}

void UserFileClient::Init(int64_t contextId)
{
    auto context = FFI::FFIData::GetData<AbilityRuntime::CJAbilityContext>(contextId);
    if (context == nullptr) {
        LOGE("Failed to get native stage context instance");
        return;
    }
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(context->GetToken(), MEDIALIBRARY_DATA_URI);
    MediaLibraryHelperContainer::GetInstance()->SetDataShareHelper(dataShareHelper);
    sDataShareHelper_ = dataShareHelper;
}

shared_ptr<DataShareResultSet> UserFileClient::Query(Uri &uri, const DataSharePredicates &predicates,
    std::vector<std::string> &columns, int &errCode)
{
    if (!IsValid()) {
        LOGE("Query fail, helper null");
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

int UserFileClient::Insert(Uri &uri, const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        LOGE("insert fail, helper null");
        return E_FAIL;
    }
    int index = sDataShareHelper_->Insert(uri, value);
    return index;
}

void UserFileClient::RegisterObserverExt(const Uri &uri,
    shared_ptr<DataShare::DataShareObserver> dataObserver, bool isDescendants)
{
    if (!IsValid()) {
        LOGE("register observer fail, helper null");
        return;
    }
    sDataShareHelper_->RegisterObserverExt(uri, std::move(dataObserver), isDescendants);
}

void UserFileClient::UnregisterObserverExt(const Uri &uri, std::shared_ptr<DataShare::DataShareObserver> dataObserver)
{
    if (!IsValid()) {
        LOGE("unregister observer fail, helper null");
        return;
    }
    sDataShareHelper_->UnregisterObserverExt(uri, std::move(dataObserver));
}

void UserFileClient::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    if (!IsValid()) {
        LOGE("register observer fail, helper null");
        return;
    }
    sDataShareHelper_->RegisterObserver(uri, dataObserver);
}

void UserFileClient::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    if (dataObserver == nullptr) {
        LOGE("Failed to obtain data observer");
        return;
    }
    if (!IsValid()) {
        LOGE("unregister observer fail, helper null");
        return;
    }
    sDataShareHelper_->UnregisterObserver(uri, dataObserver);
}

int UserFileClient::Update(Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        LOGE("update fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->Update(uri, predicates, value);
}

void UserFileClient::NotifyChange(const Uri &uri)
{
    if (!IsValid()) {
        LOGE("notify change fail, helper null");
        return;
    }
    sDataShareHelper_->NotifyChange(uri);
}

int UserFileClient::OpenFile(Uri &uri, const std::string &mode)
{
    if (!IsValid()) {
        LOGE("Open file fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->OpenFile(uri, mode);
}

int UserFileClient::Delete(Uri &uri, const DataSharePredicates &predicates)
{
    if (!IsValid()) {
        LOGE("delete fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->Delete(uri, predicates);
}

int UserFileClient::InsertExt(Uri &uri, const DataShareValuesBucket &value, string &result)
{
    if (!IsValid()) {
        LOGE("insert fail, helper null");
        return E_FAIL;
    }
    int index = sDataShareHelper_->InsertExt(uri, value, result);
    return index;
}

int UserFileClient::BatchInsert(Uri& uri, const std::vector<DataShare::DataShareValuesBucket>& values)
{
    if (!IsValid()) {
        LOGE("Batch insert fail, helper null");
        return E_FAIL;
    }
    return sDataShareHelper_->BatchInsert(uri, values);
}
}
}