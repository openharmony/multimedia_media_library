/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ACTIVE_ANALYSIS_CALLBACK_H
#define OHOS_MEDIA_ACTIVE_ANALYSIS_CALLBACK_H

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS::Media {
enum class ActiveAnalysisCallbackCode : uint32_t {
    ON_ANALYSIS_FINISHED = 0,
};

class ActiveAnalysisCallbackResult {
public:
    int32_t result = 0;

    bool Marshalling(MessageParcel &parcel) const
    {
        return parcel.WriteInt32(result);
    }

    bool Unmarshalling(MessageParcel &parcel)
    {
        result = parcel.ReadInt32();
        return true;
    }
};

class IActiveAnalysisCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Media.ActiveAnalysisCallback");

    virtual int32_t OnAnalysisFinished(const ActiveAnalysisCallbackResult &result) = 0;
};

class ActiveAnalysisCallbackProxy : public IRemoteProxy<IActiveAnalysisCallback> {
public:
    explicit ActiveAnalysisCallbackProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<IActiveAnalysisCallback>(impl)
    {
    }

    int32_t OnAnalysisFinished(const ActiveAnalysisCallbackResult &result) override
    {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option(MessageOption::TF_ASYNC);
        if (!data.WriteInterfaceToken(GetDescriptor())) {
            return IPC_STUB_INVALID_DATA_ERR;
        }
        if (!result.Marshalling(data)) {
            return IPC_STUB_INVALID_DATA_ERR;
        }
        auto remote = Remote();
        if (remote == nullptr) {
            return IPC_STUB_INVALID_DATA_ERR;
        }
        return remote->SendRequest(static_cast<uint32_t>(ActiveAnalysisCallbackCode::ON_ANALYSIS_FINISHED),
            data, reply, option);
    }

private:
    static inline BrokerDelegator<ActiveAnalysisCallbackProxy> delegator_;
};

class ActiveAnalysisCallbackStub : public IRemoteStub<IActiveAnalysisCallback> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        if (data.ReadInterfaceToken() != GetDescriptor()) {
            return ERR_UNKNOWN_TRANSACTION;
        }

        if (code != static_cast<uint32_t>(ActiveAnalysisCallbackCode::ON_ANALYSIS_FINISHED)) {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }

        ActiveAnalysisCallbackResult result;
        if (!result.Unmarshalling(data)) {
            return IPC_STUB_INVALID_DATA_ERR;
        }
        return OnAnalysisFinished(result);
    }
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_ACTIVE_ANALYSIS_CALLBACK_H
