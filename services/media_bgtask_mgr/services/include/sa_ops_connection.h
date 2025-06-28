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

#ifndef SA_OPS_CONNECTION_H
#define SA_OPS_CONNECTION_H

#include <memory>
#include "if_local_ability_manager.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_load_callback_stub.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
class SAOpsConnection : public SystemAbilityExtensionPara, public std::enable_shared_from_this<SAOpsConnection> {
public:
    enum class ConnectionStatus {
        CONNECTED, // loaded by SAMGR & have IPC remote obj
        DISCONNECTED,
    };
    using SAConnectionStatusCallback = std::function<void(const int32_t systemAbilityId, ConnectionStatus status)>;

public:
    bool InputParaSet(MessageParcel& data) override;
    bool OutputParaGet(MessageParcel& reply) override;

    SAOpsConnection(const int32_t systemAbilityId, SAConnectionStatusCallback connectionCallback);
    ~SAOpsConnection();
    
    // add death listener to SA
    int32_t Init();
    bool IsSAConnected();
    bool IsSALoaded();
    int32_t LoadSAExtension();
    int32_t LoadSAExtensionSync();
    int32_t TaskOpsSync(const std::string& ops, const std::string& taskName, const std::string& extra);

private:
    class SALoadListener : public SystemAbilityLoadCallbackStub {
    public:
        SALoadListener(const std::shared_ptr<SAOpsConnection>& outer);
        ~SALoadListener();
        void OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject) override;
        void OnLoadSystemAbilityFail(int32_t systemAbilityId) override;
    private:
        std::weak_ptr<SAOpsConnection> outer;
    };
    friend SALoadListener;
    
    class SAStatusListener : public SystemAbilityStatusChangeStub  {
    public:
        SAStatusListener(const std::shared_ptr<SAOpsConnection>& outer);
        ~SAStatusListener();
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    private:
        std::weak_ptr<SAOpsConnection> outer;
    };
    friend SAStatusListener;

private:
    int32_t GetSAExtensionProxy(bool isSync);
    int32_t CallOps(const std::string& ops, const std::string& taskName, const std::string& extra);
    void OnSystemAbilityRemove(int32_t systemAbilityId, const std::string& deviceId);
    void OnSystemAbilityAdd(int32_t systemAbilityId, const std::string& deviceId);
    void OnSystemAbilityLoadSuccess(int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject);
    void OnSystemAbilityLoadFail(int32_t systemAbilityId);

    int32_t saId_ = -1;
    SAConnectionStatusCallback connectionCallback_;
    std::recursive_mutex proxyMutex_;
    sptr<ILocalAbilityManager> extensionProxy_;
    sptr<SAStatusListener> statusListener_;
    std::atomic<bool> isConnected_{false}; // does extensionProxy useable
    std::atomic<bool> isLoaded_{false}; // does SA process loaded
    std::string taskName_;
    std::string ops_;
    std::string extra_;
};

} // namespace MediaBgtaskSchedule
} // namespace OHOS

#endif
