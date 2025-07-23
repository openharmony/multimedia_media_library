/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef NOTIFYCHANGE_FUZZER_H
#define NOTIFYCHANGE_FUZZER_H

#define FUZZ_PROJECT_NAME "medialibrarynotification_fuzzer"

#include "notify_info_inner.h"
#include "media_datashare_stub_impl.h"
#include "media_log.h"
#include "i_observer_manager_interface.h"
#include "media_observer_manager.h"
#include "notify_register_permission.h"
#include "observer_callback_recipient.h"

namespace OHOS {
namespace Media {
const std::vector<Notification::AssetRefreshOperation> ASSET_REFRESH_OPERATION = {
    Notification::ASSET_OPERATION_UNDEFINED,
    Notification::ASSET_OPERATION_ADD,
    Notification::ASSET_OPERATION_ADD_HIDDEN,
    Notification::ASSET_OPERATION_ADD_TRASH,
    Notification::ASSET_OPERATION_REMOVE,
    Notification::ASSET_OPERATION_REMOVE_HIDDEN,
    Notification::ASSET_OPERATION_REMOVE_TRASH,
    Notification::ASSET_OPERATION_UPDATE_NORMAL,
    Notification::ASSET_OPERATION_UPDATE_ADD_NORMAL,
    Notification::ASSET_OPERATION_UPDATE_REMOVE_NORMAL,
    Notification::ASSET_OPERATION_UPDATE_HIDDEN,
    Notification::ASSET_OPERATION_UPDATE_ADD_HIDDEN,
    Notification::ASSET_OPERATION_UPDATE_REMOVE_HIDDEN,
    Notification::ASSET_OPERATION_UPDATE_TRASH,
    Notification::ASSET_OPERATION_UPDATE_ADD_TRASH,
    Notification::ASSET_OPERATION_UPDATE_REMOVE_TRASH,
    Notification::ASSET_OPERATION_TRASH,
    Notification::ASSET_OPERATION_UNTRASH,
    Notification::ASSET_OPERATION_HIDDEN,
    Notification::ASSET_OPERATION_UNHIDDEN,
    Notification::ASSET_OPERATION_RECHECK,
};
class IRemoteObjectTest : public IRemoteObject {
public:
    IRemoteObjectTest() : IRemoteObject(u"mock_i_remote_object") {}

    ~IRemoteObjectTest() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};

class IDataAbilityObserverTest : public AAFwk::DataAbilityObserverStub {
public:
    IDataAbilityObserverTest() {}
    ~IDataAbilityObserverTest() {}
    void OnChange() override {}
    sptr<IRemoteObject> AsObject() override
    {
        if (objectTest == nullptr) {
            objectTest = new (std::nothrow)IRemoteObjectTest();
        }
        return objectTest;
    }

private:
    sptr<IRemoteObjectTest> objectTest;
};

} // namespace Media
} // namespace OHOS
#endif