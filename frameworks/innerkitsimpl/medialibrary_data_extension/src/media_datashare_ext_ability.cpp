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
#define MLOG_TAG "Extension"

#include "media_datashare_ext_ability.h"

#include "ability_info.h"
#include "dataobs_mgr_client.h"
#include "media_datashare_stub_impl.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "datashare_ext_ability_context.h"
#include "runtime.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_uripermission_operations.h"
#include "media_scanner_manager.h"
#include "media_log.h"
#include "system_ability_definition.h"
#include "permission_utils.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedKv;
using namespace OHOS::Media;
using namespace OHOS::DataShare;

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
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
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return;
    }
    MEDIA_INFO_LOG("%{public}s runtime language  %{public}d", __func__, runtime_.GetLanguage());

    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager != nullptr) {
        auto extensionContext = GetContext();
        dataManager->InitMediaLibraryMgr(context, extensionContext);
        dataManager->SetOwner(static_pointer_cast<MediaDataShareExtAbility>(shared_from_this()));
    }

    auto scannerManager = MediaScannerManager::GetInstance();
    if (scannerManager != nullptr) {
        scannerManager->Start();
    }
}

void MediaDataShareExtAbility::OnStart(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    Extension::OnStart(want);
    Media::MedialibrarySubscriber::Subscribe();
    MEDIA_INFO_LOG("%{public}s end.", __func__);
}

void MediaDataShareExtAbility::OnStop()
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto scannerManager = MediaScannerManager::GetInstance();
    if (scannerManager != nullptr) {
        scannerManager->Stop();
    }
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    MEDIA_INFO_LOG("%{public}s end.", __func__);
}

sptr<IRemoteObject> MediaDataShareExtAbility::OnConnect(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("%{public}s begin. ", __func__);
    Extension::OnConnect(want);
    sptr<MediaDataShareStubImpl> remoteObject = new (std::nothrow) MediaDataShareStubImpl(
        std::static_pointer_cast<MediaDataShareExtAbility>(shared_from_this()),
        nullptr);
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("%{public}s No memory allocated for DataShareStubImpl", __func__);
        return nullptr;
    }
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return remoteObject->AsObject();
}

static uint32_t TypeMaskStringToInteger(const std::string &typeMask)
{
    uint32_t mask = 0;
    for (auto &item : MEDIA_TYPE_TUPLE_VEC) {
        if (typeMask[std::get<POS_TYPE_MASK_STRING_INDEX>(item)] == TYPE_MASK_BIT_SET) {
            mask |= static_cast<uint32_t>(std::get<POS_TYPE_MASK_INTEGER>(item));
        }
    }
    return mask;
}

// Parse uri(eg. datashare::///media/image/10#key1:value1#key2:value2#key3:value3) to key-value pairs
static int32_t GetKeyValueFromUri(const std::string &uri, std::vector<std::pair<std::string, std::string>> &pairs)
{
    constexpr size_t SHARP_POS = 1;
    size_t nextPairIndex = uri.find('#');
    if (nextPairIndex == std::string::npos) {
        return E_SUCCESS;
    }
    std::string keyValueString;
    for (std::string remain = uri.substr(nextPairIndex); nextPairIndex != std::string::npos;) {
        nextPairIndex = remain.find('#', SHARP_POS);
        if (nextPairIndex == std::string::npos) {
            keyValueString = remain.substr(SHARP_POS);
        } else {
            keyValueString = remain.substr(SHARP_POS, nextPairIndex - 1);
            remain = remain.substr(nextPairIndex);
        }
        size_t splitIndex = keyValueString.find(':');
        if (splitIndex == std::string::npos) {
            MEDIA_ERR_LOG("Key-Value string should have format: #key:value");
            return -EINVAL;
        }
        pairs.push_back(std::make_pair(keyValueString.substr(0, splitIndex), keyValueString.substr(splitIndex + 1)));
    }
    return E_SUCCESS;
}

static int32_t ShouldCheckTypePermission(const std::string &uri, bool &shouldCheckType, std::string &typeMask)
{
    typeMask.resize(TYPE_MASK_STRING_SIZE, TYPE_MASK_BIT_DEFAULT);
    shouldCheckType = false;
    size_t paramIndex = uri.rfind('#');
    if (paramIndex == string::npos) {
        return E_SUCCESS;
    }

    std::vector<std::pair<std::string, std::string>> pairs;
    int err = GetKeyValueFromUri(uri, pairs);
    if (err < 0) {
        MEDIA_ERR_LOG("Failed to parse key value pair from uri: %{public}s, err: %{public}d", uri.c_str(), err);
        return err;
    }

    for (auto &item : pairs) {
        if (item.first == URI_PARAM_KEY_TYPE) {
            typeMask = item.second;
            shouldCheckType = true;
            return E_SUCCESS;
        }
    }
    return E_SUCCESS;
}

static bool CheckPerms(bool shouldCheckType, bool isWrite, const std::string &typeMask)
{
    if (!shouldCheckType) {
        string perm = isWrite ? PERMISSION_NAME_WRITE_MEDIA : PERMISSION_NAME_READ_MEDIA;
        if (PermissionUtils::CheckCallerPermission(perm)) {
            return true;
        }
        return false;
    }

    if (PermissionUtils::CheckCallerPermission((isWrite ? WRITE_PERMS : READ_PERMS),
        TypeMaskStringToInteger(typeMask))) {
        return true;
    }
    return false;
}

std::vector<std::string> MediaDataShareExtAbility::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    std::vector<std::string> ret;
    return ret;
}

static int CheckOpenFilePermission(string &uri, string &mode)
{
    bool shouldCheckType = false;
    string typeMask;
    int err = ShouldCheckTypePermission(uri, shouldCheckType, typeMask);
    if (err < 0) {
        return err;
    }
    if (shouldCheckType) {
        uri = uri.substr(0, uri.find('#'));
    }

    size_t rPos = mode.find('r');
    if (rPos != string::npos) {
        bool checkReadResult = CheckPerms(shouldCheckType, false, typeMask);
        if (!checkReadResult) {
            return E_PERMISSION_DENIED;
        }
    }
    size_t wPos = mode.find('w');
    if (wPos != string::npos) {
        bool checkWriteResult = CheckPerms(shouldCheckType, true, typeMask);
        if (!checkWriteResult) {
            return E_PERMISSION_DENIED;
        }
    }
    if ((rPos == string::npos) && (wPos == string::npos)) {
        MEDIA_INFO_LOG("Mode is invalid: %{public}s, return err: %{public}d", mode.c_str(), E_PERMISSION_DENIED);
        return E_PERMISSION_DENIED;
    }

    return E_SUCCESS;
}

static bool CheckPermFromUri(std::string &uri, bool isWrite)
{
    bool shouldCheckType = false;
    string typeMask;
    if (ShouldCheckTypePermission(uri, shouldCheckType, typeMask) < 0) {
        return false;
    }
    if (shouldCheckType) {
        /* position of '#' should not be string::npos here */
        uri = uri.substr(0, uri.find('#'));
    }
    return CheckPerms(shouldCheckType, isWrite, typeMask);
}

int MediaDataShareExtAbility::OpenFile(const Uri &uri, const std::string &mode)
{
    string uriStr = uri.ToString();
    string unifyMode = mode;
    transform(unifyMode.begin(), unifyMode.end(), unifyMode.begin(), ::tolower);

    int err = CheckOpenFilePermission(uriStr, unifyMode);
    if (err == E_PERMISSION_DENIED) {
        err = UriPermissionOperations::CheckUriPermission(uriStr, unifyMode);
        if (err != E_OK) {
            MEDIA_ERR_LOG("Permission Denied! err = %{public}d", err);
            return err;
        }
    } else if (err < 0) {
        return err;
    }
    
    return MediaLibraryDataManager::GetInstance()->OpenFile(Uri(uriStr), unifyMode);
}

int MediaDataShareExtAbility::OpenRawFile(const Uri &uri, const std::string &mode)
{
    return 0;
}

int MediaDataShareExtAbility::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    string closeUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET;
    string insertUri = uri.ToString();
    bool isWrite = (insertUri == closeUri) ? false : true;
    if ((insertUri.find(DISTRIBUTE_THU_OPRN_CREATE) == string::npos) &&
        !CheckPermFromUri(insertUri, isWrite)) {
        return E_PERMISSION_DENIED;
    }

    return MediaLibraryDataManager::GetInstance()->Insert(Uri(insertUri), value);
}

int MediaDataShareExtAbility::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    string updateUri = uri.ToString();
    if (!CheckPermFromUri(updateUri, true)) {
        return E_PERMISSION_DENIED;
    }

    return MediaLibraryDataManager::GetInstance()->Update(Uri(updateUri), value, predicates);
}

int MediaDataShareExtAbility::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    string uriStr = uri.ToString();
    int err = CheckPermFromUri(uriStr, true);
    if (err < 0) {
        return err;
    }

    return MediaLibraryDataManager::GetInstance()->Delete(Uri(uriStr), predicates);
}

std::shared_ptr<DataShareResultSet> MediaDataShareExtAbility::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    const static set<string> noPermissionCheck = {
        MEDIALIBRARY_DIRECTORY_URI,
        MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYACTIVEDEVICE,
        MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYALLDEVICE
    };

    string uriStr = uri.ToString();
    if ((noPermissionCheck.find(uriStr) == noPermissionCheck.end()) && !CheckPermFromUri(uriStr, false)) {
        return nullptr;
    }
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(Uri(uriStr), columns, predicates);
    if (queryResultSet == nullptr) {
        return nullptr;
    }
    std::shared_ptr<DataShareResultSet> resultSet = std::make_shared<DataShareResultSet>(queryResultSet);
    return resultSet;
}

std::string MediaDataShareExtAbility::GetType(const Uri &uri)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto ret = MediaLibraryDataManager::GetInstance()->GetType(uri);
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    int ret = INVALID_VALUE;
    if (!PermissionUtils::CheckCallerPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        MEDIA_ERR_LOG("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return ret;
}

bool MediaDataShareExtAbility::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->RegisterObserver(uri, dataObserver);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient->RegisterObserver error return %{public}d", __func__, ret);
        return false;
    }
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return true;
}

bool MediaDataShareExtAbility::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->UnregisterObserver(uri, dataObserver);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient->UnregisterObserver error return %{public}d", __func__, ret);
        return false;
    }
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return true;
}

bool MediaDataShareExtAbility::NotifyChange(const Uri &uri)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->NotifyChange(uri);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient->NotifyChange error return %{public}d", __func__, ret);
        return false;
    }
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return true;
}

Uri MediaDataShareExtAbility::NormalizeUri(const Uri &uri)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto ret = uri;
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return ret;
}

Uri MediaDataShareExtAbility::DenormalizeUri(const Uri &uri)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto ret = uri;
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return ret;
}
} // namespace AbilityRuntime
} // namespace OHOS
