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

#define MLOG_TAG "MediaBgtaskMgrClient"

#include "media_bgtask_mgr_client.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "media_bgtask_mgr_log.h"

namespace OHOS::MediaBgtaskSchedule {

static const int32_t MEDIA_BGTASK_MGR_SERVICE_ID = 3016;
static const int32_t SA_LOAD_SYNC_TIMEOUT = 5;
static const int32_t INVALID_UID = -1;
static const int32_t BASE_USER_RANGE = 200000;

std::once_flag MediaBgtaskMgrClient::instanceFlag_;
std::shared_ptr<MediaBgtaskMgrClient> MediaBgtaskMgrClient::instance_;

std::shared_ptr<MediaBgtaskMgrClient> MediaBgtaskMgrClient::GetInstance()
{
    std::call_once(instanceFlag_, []() {
        instance_ = std::make_shared<MediaBgtaskMgrClient>();
    });
    return instance_;
}

MediaBgtaskMgrClient::MediaBgtaskMgrClient()
{
}

int32_t MediaBgtaskMgrClient::ReportTaskComplete(const std::string& task_name)
{
    MEDIA_INFO_LOG("ReportTaskComplete taskName: %{public}s", task_name.c_str());
    std::lock_guard<std::mutex> lock(proxyMutex_);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = -1;
    if (callingUid <= INVALID_UID) {
        MEDIA_ERR_LOG("Get Invalid uid: %{public}d.", callingUid);
    } else {
        userId = callingUid / BASE_USER_RANGE;
    }
    sptr<IMmlTaskMgr> proxy = GetMediaBgtaskMgrProxy();
    if (proxy == nullptr) {
        MEDIA_ERR_LOG("MediaBgTaskMgr proxy not connected");
        return ERR_INVALID_DATA;
    }
    return proxy->ReportTaskComplete(task_name);
}

int32_t MediaBgtaskMgrClient::ModifyTask(const std::string& task_name, const std::string& modifyInfo)
{
    MEDIA_INFO_LOG("ModifyTask taskName: %{public}s, modifyInfo: %{public}s", task_name.c_str(), modifyInfo.c_str());
    std::lock_guard<std::mutex> lock(proxyMutex_);
    sptr<IMmlTaskMgr> proxy = GetMediaBgtaskMgrProxy();
    if (proxy == nullptr) {
        MEDIA_ERR_LOG("MediaBgTaskMgr proxy not connected");
        return ERR_INVALID_DATA;
    }
    return proxy->ModifyTask(task_name, modifyInfo);
}

sptr<IMmlTaskMgr> MediaBgtaskMgrClient::GetMediaBgtaskMgrProxy()
{
    if (proxy_ != nullptr) {
        return proxy_;
    }

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        MEDIA_ERR_LOG("saMgr is nullptr");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObj = saMgr->GetSystemAbility(MEDIA_BGTASK_MGR_SERVICE_ID);
    if (remoteObj != nullptr) {
        proxy_ = iface_cast<IMmlTaskMgr>(remoteObj);
        return proxy_;
    }

    remoteObj = saMgr->LoadSystemAbility(MEDIA_BGTASK_MGR_SERVICE_ID, SA_LOAD_SYNC_TIMEOUT);
    if (remoteObj == nullptr) {
        return nullptr;
    }
    proxy_ = iface_cast<IMmlTaskMgr>(remoteObj);
    return proxy_;
}
} // namespace OHOS::MediaBgtaskSchedule
