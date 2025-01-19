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

#include "media_userfile_client.h"
#include "medialibrary_errno.h"
#include "medialibrary_helper_container.h"
#include "media_log.h"
#include "userfilemgr_uri.h"
#include "medialibrary_operation.h"
#include "media_asset_rdbstore.h"
#include "iservice_registry.h"

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::AppExecFwk;

static const int STORAGE_MANAGER_MANAGER_ID = 5003;

namespace OHOS {
namespace Media {

int32_t UserFileClient::userId_ = -1;
int32_t UserFileClient::lastUserId_ = -1;
std::string MULTI_USER_URI_FLAG = "user=";
std::string USER_STR = "user";
bool UserFileClient::IsValid()
{
    return sDataShareHelper_ != nullptr;
}

void UserFileClient::Init()
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("Get system ability mgr failed.");
        return;
    }
    auto remoteObj = saManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service Failed.");
        return;
    }

    Init(remoteObj);
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Create DataShareHelper failed.");
        return;
    }
}

void UserFileClient::Init(const sptr<IRemoteObject> &token, bool isSetHelper)
{
    std::string mediaLibraryDataUri = MEDIALIBRARY_DATA_URI;
    if (GetUserId() != -1) {
        mediaLibraryDataUri = mediaLibraryDataUri + "?" + MULTI_USER_URI_FLAG + to_string(GetUserId());
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, mediaLibraryDataUri);
    }
    if (sDataShareHelper_ == nullptr) {
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, mediaLibraryDataUri);
    }

    if (isSetHelper) {
        MediaLibraryHelperContainer::GetInstance()->SetDataShareHelper(sDataShareHelper_);
    }
}

shared_ptr<DataShareResultSet> UserFileClient::Query(Uri &uri, const DataSharePredicates &predicates,
    std::vector<std::string> &columns, int &errCode)
{
    if (!IsValid()) {
        MEDIA_ERR_LOG("Query fail, helper null");
        return nullptr;
    }

    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
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

int UserFileClient::Insert(Uri &uri, const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        MEDIA_ERR_LOG("insert fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    int index = sDataShareHelper_->Insert(uri, value);
    return index;
}

int UserFileClient::InsertExt(Uri &uri, const DataShareValuesBucket &value, string &result)
{
    if (!IsValid()) {
        MEDIA_ERR_LOG("insert fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    int index = sDataShareHelper_->InsertExt(uri, value, result);
    return index;
}


int UserFileClient::Delete(Uri &uri, const DataSharePredicates &predicates)
{
    if (!IsValid()) {
        MEDIA_ERR_LOG("delete fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    return sDataShareHelper_->Delete(uri, predicates);
}

int UserFileClient::OpenFile(Uri &uri, const std::string &mode)
{
    if (!IsValid()) {
        MEDIA_ERR_LOG("Open file fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    return sDataShareHelper_->OpenFile(uri, mode);
}

int UserFileClient::Update(Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    if (!IsValid()) {
        MEDIA_ERR_LOG("update fail, helper null");
        return E_FAIL;
    }
    std::string uriString = uri.ToString();
    if (GetUserId() != -1) {
        UriAppendKeyValue(uriString, USER_STR, to_string(GetUserId()));
    }
    uri = Uri(uriString);
    return sDataShareHelper_->Update(uri, predicates, value);
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

void UserFileClient::UriAppendKeyValue(string &uri, const string &key, const string &value)
{
    string uriKey = key + '=';
    if (uri.find(uriKey) != string::npos) {
        return;
    }

    char queryMark = (uri.find('?') == string::npos) ? '?' : '&';
    string append = queryMark + key + '=' + value;

    size_t posJ = uri.find('#');
    if (posJ == string::npos) {
        uri += append;
    } else {
        uri.insert(posJ, append);
    }
}
}
}
