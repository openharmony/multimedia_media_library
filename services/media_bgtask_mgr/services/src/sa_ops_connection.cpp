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

#define MLOG_TAG "MediaBgTask_SAOpsConnection"

#include "sa_ops_connection.h"
#include <vector>
#include "media_bgtask_mgr_log.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
const std::string MML_OPS_EXTENSION = "mml_ops_task";
const int32_t SA_LOAD_SYNC_TIMEOUT = 5;

SAOpsConnection::SAOpsConnection(const int32_t systemAbilityId, SAConnectionStatusCallback callback)
    : saId_(systemAbilityId), connectionCallback_(callback), statusListener_(nullptr) {}

SAOpsConnection::~SAOpsConnection()
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr != nullptr && statusListener_ != nullptr) {
        saMgr->UnSubscribeSystemAbility(saId_, statusListener_);
    }
}

int32_t SAOpsConnection::Init()
{
    MEDIA_INFO_LOG("SAOpsConnection saId:%{public}d Init", saId_);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_INFO_LOG("SAOpsConnection saId:%{public}d Init failed, no mgr", saId_);
        return ERR_INVALID_DATA;
    }
    statusListener_ = sptr<SAStatusListener>::MakeSptr(shared_from_this());
    saMgr->SubscribeSystemAbility(saId_, statusListener_);
    return ERR_OK;
}

bool SAOpsConnection::InputParaSet(MessageParcel& data)
{
    MEDIA_INFO_LOG("SAOpsConnection saId:%{public}d Input Param", saId_);
    if (!data.WriteString(taskName_) ||
        !data.WriteString(ops_) ||
        !data.WriteString(extra_)) {
        MEDIA_ERR_LOG("error write taks info");
        return false;
    }
    return true;
}

bool SAOpsConnection::OutputParaGet(MessageParcel& reply)
{
    MEDIA_INFO_LOG("SAOpsConnection saId:%{public}d Output Param", saId_);
    return true;
}

bool SAOpsConnection::IsSAConnected()
{
    return isConnected_.load();
}

bool SAOpsConnection::IsSALoaded()
{
    return isLoaded_.load();
}

int32_t SAOpsConnection::LoadSAExtension()
{
    if (isConnected_.load()) {
        connectionCallback_(saId_, ConnectionStatus::CONNECTED);
        return ERR_OK;
    }

    // try to get extension frist if SA already running
    if (GetSAExtensionProxy(true) == ERR_OK) {
        return ERR_OK;
    }

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_ERR_LOG("saMgr is nullptr");
        return ERR_INVALID_DATA;
    }
    sptr<SALoadListener> loadCallback = sptr<SALoadListener>::MakeSptr(shared_from_this());
    if (loadCallback == nullptr) {
        MEDIA_ERR_LOG("loadCallback is nullptr");
        return ERR_INVALID_DATA;
    }
    int32_t ret = saMgr->LoadSystemAbility(saId_, loadCallback);
    MEDIA_INFO_LOG("SA:%{public}d not started, try to load SA ret:%{public}d", saId_, ret);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("load sa:%{public}d failed", saId_);
        return ERR_INVALID_DATA;
    }
    return ERR_OK;
}

int32_t SAOpsConnection::LoadSAExtensionSync()
{
    if (isConnected_.load()) {
        return ERR_OK;
    }

    // try to get extension frist if SA already running
    if (GetSAExtensionProxy(true) == ERR_OK) {
        return ERR_OK;
    }

    // try to load SA
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_ERR_LOG("saMgr is nullptr");
        return ERR_INVALID_DATA;
    }
    sptr<IRemoteObject> proxy = saMgr->LoadSystemAbility(saId_, SA_LOAD_SYNC_TIMEOUT);
    if (proxy == nullptr) {
        MEDIA_ERR_LOG("Load sa:%{public}d sync failed", saId_);
        return ERR_INVALID_DATA;
    }
    MEDIA_INFO_LOG("SA:%{public}d LoadSAExtensionSync load SA success, try to check extension correctness", saId_);
    return GetSAExtensionProxy(true);
}
 
int32_t SAOpsConnection::CallOps(const std::string& ops, const std::string& taskName, const std::string& extra)
{
    std::lock_guard<std::recursive_mutex> lock(proxyMutex_);
    if (!extensionProxy_) {
        MEDIA_ERR_LOG("CallOps failed no extensionProxy");
        return ERR_INVALID_DATA;
    }

    this->taskName_ = taskName;
    this->ops_ = ops;
    this->extra_ = extra;
    int32_t ret = extensionProxy_->SystemAbilityExtProc(MML_OPS_EXTENSION, saId_, this);
    if (ret != NO_ERROR) {
        MEDIA_ERR_LOG("CallOps failed taskName:%{public}s ops:%{public}s ret:%{public}d",
            taskName.c_str(), ops.c_str(), ret);
        return ERR_INVALID_DATA;
    }
    return ERR_OK;
}

int32_t SAOpsConnection::TaskOpsSync(const std::string& ops, const std::string& taskName, const std::string& extra)
{
    MEDIA_INFO_LOG("SA:%{public}d OpenSync taskName:%{public}s isConnected:%{public}d.",
        saId_, taskName.c_str(), isConnected_.load());
    if (isConnected_.load()) {
        return CallOps(ops, taskName, extra);
    }

    if (LoadSAExtensionSync() != ERR_OK) {
        return ERR_INVALID_DATA;
    }
 
    return CallOps(ops, taskName, extra);
}

int32_t SAOpsConnection::GetSAExtensionProxy(bool isSync)
{
    std::lock_guard<std::recursive_mutex> lock(proxyMutex_);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_ERR_LOG("saMgr is nullptr");
        return ERR_INVALID_DATA;
    }

    std::vector<ISystemAbilityManager::SaExtensionInfo> saExtentionInfos;
    int32_t ret = saMgr->GetRunningSaExtensionInfoList(MML_OPS_EXTENSION, saExtentionInfos);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("GetRunningSaExtensionInfoList err, ret %{public}d.", ret);
        return ERR_INVALID_DATA;
    }

    for (ISystemAbilityManager::SaExtensionInfo& saExtentionInfo : saExtentionInfos) {
        if (saExtentionInfo.saId == saId_) {
            MEDIA_INFO_LOG("SA:%{public}d already loaded, get proxy success.", saId_);
            extensionProxy_ = iface_cast<ILocalAbilityManager>(saExtentionInfo.processObj);
            isLoaded_.store(true);
            isConnected_.store(true);
            if (!isSync) {
                connectionCallback_(saId_, ConnectionStatus::CONNECTED);
            }
            return ERR_OK;
        }
    }
    MEDIA_INFO_LOG("SA:%{public}d extension remote obj get failed.", saId_);
    return ERR_INVALID_DATA;
}

void SAOpsConnection::OnSystemAbilityAdd(int32_t systemAbilityId, const std::string& deviceId)
{
}

void SAOpsConnection::OnSystemAbilityRemove(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId != saId_) {
        return;
    }
    MEDIA_INFO_LOG("SAOpsConnection SA:%{public}d removed.", saId_);
    std::lock_guard<std::recursive_mutex> lock(proxyMutex_);
    isLoaded_.store(false);
    isConnected_.store(false);
    extensionProxy_ = nullptr;
    connectionCallback_(systemAbilityId, ConnectionStatus::DISCONNECTED);
}

void SAOpsConnection::OnSystemAbilityLoadSuccess(int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject)
{
    if (saId_ != systemAbilityId) {
        return;
    }
    MEDIA_INFO_LOG("SA:%{public}d on SA load success, try to get proxy.", saId_);
}

void SAOpsConnection::OnSystemAbilityLoadFail(int32_t systemAbilityId)
{
    if (saId_ != systemAbilityId) {
        return;
    }
    isLoaded_.store(false);
    isConnected_.store(false);
    connectionCallback_(systemAbilityId, ConnectionStatus::DISCONNECTED);
}

SAOpsConnection::SALoadListener::SALoadListener(const std::shared_ptr<SAOpsConnection>& outer): outer(outer)
{
}

SAOpsConnection::SALoadListener::~SALoadListener()
{
}

void SAOpsConnection::SALoadListener::OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
    const sptr<IRemoteObject>& remoteObject)
{
    MEDIA_INFO_LOG("SA:%{public}d OnLoadSystemAbilitySuccess.", systemAbilityId);
    auto outerSptr = outer.lock();
    if (outerSptr) {
        outerSptr->OnSystemAbilityLoadSuccess(systemAbilityId, remoteObject);
    }
}

void SAOpsConnection::SALoadListener::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("SA:%{public}d OnLoadSystemAbilityFail.", systemAbilityId);
    auto outerSptr = outer.lock();
    if (outerSptr) {
        outerSptr->OnSystemAbilityLoadFail(systemAbilityId);
    }
}

SAOpsConnection::SAStatusListener::SAStatusListener(const std::shared_ptr<SAOpsConnection>& outer) : outer(outer)
{
}

SAOpsConnection::SAStatusListener::~SAStatusListener()
{
}

void SAOpsConnection::SAStatusListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    auto outerSptr = outer.lock();
    if (outerSptr) {
        outerSptr->OnSystemAbilityAdd(systemAbilityId, deviceId);
    }
}

void SAOpsConnection::SAStatusListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    auto outerSptr = outer.lock();
    if (outerSptr) {
        outerSptr->OnSystemAbilityRemove(systemAbilityId, deviceId);
    }
}

} // namespace MediaBgtaskSchedule
} // namespace OHOS
