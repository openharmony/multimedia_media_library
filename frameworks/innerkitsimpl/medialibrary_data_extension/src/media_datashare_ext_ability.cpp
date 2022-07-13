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
#include "dataobs_mgr_client.h"
#include "media_datashare_stub_impl.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "sa_mgr_client.h"
#include "datashare_ext_ability_context.h"
#include "runtime.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_subscriber.h"
#include "system_ability_definition.h"

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
constexpr int UID_FILEMANAGER = 1006;
namespace {
const std::unordered_set<int32_t> UID_FREE_CHECK {
    UID_FILEMANAGER
};
const std::unordered_set<std::string> SYSTEM_BUNDLE_FREE_CHECK {};
std::mutex bundleMgrMutex;
const std::string PERMISSION_NAME_READ_MEDIA = "ohos.permission.READ_MEDIA";
const std::string PERMISSION_NAME_WRITE_MEDIA = "ohos.permission.WRITE_MEDIA";
}

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
    Media::MedialibrarySubscriber::Subscribe();
    HILOG_INFO("%{public}s end.", __func__);
}

void MediaDataShareExtAbility::OnStop()
{
    HILOG_INFO("%{public}s begin.", __func__);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    HILOG_INFO("%{public}s end.", __func__);
}

sptr<IRemoteObject> MediaDataShareExtAbility::OnConnect(const AAFwk::Want &want)
{
    HILOG_INFO("%{public}s begin. ", __func__);
    Extension::OnConnect(want);
    sptr<MediaDataShareStubImpl> remoteObject = new (std::nothrow) MediaDataShareStubImpl(
        std::static_pointer_cast<MediaDataShareExtAbility>(shared_from_this()),
        nullptr);
    if (remoteObject == nullptr) {
        HILOG_ERROR("%{public}s No memory allocated for DataShareStubImpl", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s end.", __func__);
    return remoteObject->AsObject();
}

std::vector<std::string> MediaDataShareExtAbility::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    std::vector<std::string> ret;
    return ret;
}

int MediaDataShareExtAbility::OpenFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    if (mode == MEDIA_FILEMODE_READONLY) {
        if (!CheckCallingPermission(PERMISSION_NAME_READ_MEDIA)) {
            return E_PERMISSION_DENIED;
        }
    } else if (mode == MEDIA_FILEMODE_WRITEONLY ||
               mode == MEDIA_FILEMODE_WRITETRUNCATE ||
               mode == MEDIA_FILEMODE_WRITEAPPEND) {
        if (!CheckCallingPermission(PERMISSION_NAME_WRITE_MEDIA)) {
            return E_PERMISSION_DENIED;
        }
    } else if (mode == MEDIA_FILEMODE_READWRITETRUNCATE ||
               mode == MEDIA_FILEMODE_READWRITE) {
        if (!CheckCallingPermission(PERMISSION_NAME_READ_MEDIA) ||
            !CheckCallingPermission(PERMISSION_NAME_WRITE_MEDIA)) {
            return E_PERMISSION_DENIED;
        }
    }
    return MediaLibraryDataManager::GetInstance()->OpenFile(uri, mode);
}

int MediaDataShareExtAbility::OpenRawFile(const Uri &uri, const std::string &mode)
{
    return 0;
}

int MediaDataShareExtAbility::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    HILOG_INFO("%{public}s begin.", __func__);
    string tmpUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET;
    if (uri.ToString() == tmpUri) {
        if (!CheckCallingPermission(PERMISSION_NAME_READ_MEDIA)) {
            return E_PERMISSION_DENIED;
        }
    } else if (!CheckCallingPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        return E_PERMISSION_DENIED;
    }
    return MediaLibraryDataManager::GetInstance()->Insert(uri, value);
}

int MediaDataShareExtAbility::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    HILOG_INFO("%{public}s begin.", __func__);
    if (!CheckCallingPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return E_PERMISSION_DENIED;
    }

    return MediaLibraryDataManager::GetInstance()->Update(uri, value, predicates);
}

int MediaDataShareExtAbility::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    HILOG_INFO("%{public}s begin.", __func__);
    if (!CheckCallingPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return E_PERMISSION_DENIED;
    }

    return MediaLibraryDataManager::GetInstance()->Delete(uri, predicates);
}

std::shared_ptr<DataShareResultSet> MediaDataShareExtAbility::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    if (!CheckCallingPermission(PERMISSION_NAME_READ_MEDIA)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return nullptr;
    }
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(uri, columns, predicates);
    std::shared_ptr<DataShareResultSet> resultSet = std::make_shared<DataShareResultSet>(queryResultSet);
    return resultSet;
}

std::string MediaDataShareExtAbility::GetType(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = MediaLibraryDataManager::GetInstance()->GetType(uri);
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = INVALID_VALUE;
    if (!CheckCallingPermission(PERMISSION_NAME_WRITE_MEDIA)) {
        HILOG_ERROR("%{public}s Check calling permission failed.", __func__);
        return ret;
    }

    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

bool MediaDataShareExtAbility::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("%{public}s begin.", __func__);
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
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = uri;
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

Uri MediaDataShareExtAbility::DenormalizeUri(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    auto ret = uri;
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

std::vector<std::shared_ptr<DataShareResult>> MediaDataShareExtAbility::ExecuteBatch(
    const std::vector<std::shared_ptr<DataShareOperation>> &operations)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::vector<std::shared_ptr<DataShareResult>> ret;
    HILOG_INFO("%{public}s end.", __func__);
    return ret;
}

bool MediaDataShareExtAbility::CheckCallingPermission(const std::string &permission)
{
    int uid = IPCSkeleton::GetCallingUid();
    if (UID_FREE_CHECK.find(uid) != UID_FREE_CHECK.end()) {
        HILOG_INFO("CheckCallingPermission: Pass the uid check list");
        return true;
    }

    std::string bundleName = GetClientBundle(uid);
    auto bundleMgr = GetSysBundleManager();
    if ((bundleMgr != nullptr) && bundleMgr->CheckIsSystemAppByUid(uid) &&
        (SYSTEM_BUNDLE_FREE_CHECK.find(bundleName) != SYSTEM_BUNDLE_FREE_CHECK.end())) {
        HILOG_INFO("CheckCallingPermission: Pass the system bundle name check list");
        return true;
    }

    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int res = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller, permission);
    if (res != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        HILOG_ERROR("MediaLibraryDataManager Query: Have no media permission");
        return false;
    }

    return true;
}

std::string MediaDataShareExtAbility::GetClientBundle(int uid)
{
    auto bms = GetSysBundleManager();
    std::string bundleName = "";
    if (bms == nullptr) {
        HILOG_INFO("GetClientBundleName bms failed");
        return bundleName;
    }
    auto result = bms->GetBundleNameForUid(uid, bundleName);
    if (!result) {
        HILOG_ERROR("GetBundleNameForUid fail");
        return "";
    }
    return bundleName;
}

sptr<AppExecFwk::IBundleMgr> MediaDataShareExtAbility::GetSysBundleManager()
{
    if (bundleMgr_ == nullptr) {
        std::lock_guard<std::mutex> lock(bundleMgrMutex);
        if (bundleMgr_ == nullptr) {
            auto saMgr = OHOS::DelayedSingleton<SaMgrClient>::GetInstance();
            if (saMgr == nullptr) {
                HILOG_ERROR("failed to get SaMgrClient::GetInstance");
                return nullptr;
            }
            auto bundleObj = saMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
            if (bundleObj == nullptr) {
                HILOG_ERROR("failed to get GetSystemAbility");
                return nullptr;
            }
            auto bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(bundleObj);
            if (bundleMgr == nullptr) {
                HILOG_ERROR("failed to iface_cast");
                return nullptr;
            }
            bundleMgr_ = bundleMgr;
        }
    }
    return bundleMgr_;
}
} // namespace AbilityRuntime
} // namespace OHOS
