/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_NOTIFICATION_TEST_DATA_H
#define MEDIALIBRARY_NOTIFICATION_TEST_DATA_H

#include "photo_asset_change_info.h"
#include "album_change_info.h"
#include "media_change_info.h"
#include "notify_info.h"
#include "media_datashare_stub_impl.h"
#include "notify_info_inner.h"
#include "notify_task_worker.h"

namespace OHOS {
namespace Media {
class IRemoteObjectTest : public IRemoteObject {
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
namespace Notification {
    extern const AccurateRefresh::PhotoAssetChangeData deletePhotoData1;
    extern const AccurateRefresh::PhotoAssetChangeData deletePhotoData2;
    extern const AccurateRefresh::AlbumChangeData albumChangeData1;
    extern const AccurateRefresh::AlbumChangeData albumChangeData2;
class NotificationTestData {
public:
    EXPORT NotificationTestData();
    EXPORT ~NotificationTestData();
    static std::vector<Notification::MediaChangeInfo> getPhotoChangeInfos(
        const Notification::NotifyUriType& notifyUriType,
        const Notification::NotifyType& notifyType,  bool isForRecheck);
    static std::vector<Notification::MediaChangeInfo> getPhotnChangeInfosByUriType(
        const Notification::NotifyUriType& notifyUriType, bool isForRecheck);
    static std::vector<Notification::MediaChangeInfo> getAlbumChangeInfos(
        const Notification::NotifyUriType& notifyUriType,
        const Notification::NotifyType& notifyType, bool isForRecheck);
    static std::vector<Notification::MediaChangeInfo> getAlbumChangeInfosByUriType(
        const Notification::NotifyUriType& notifyUriType, bool isForRecheck);
    static std::vector<Notification::NotifyInfo> buildAssetsNotifyInfo(const std::string &testName,
        std::unordered_map<NotifyUriType, std::vector<ObserverInfo>> observerMap);
    static std::vector<Notification::MediaChangeInfo> buildAssetsMediaChangeInfo();
    static std::vector<NotifyInfoInner> buildPhotoNotifyTaskInfo(NotifyTableType tableType,
        std::vector<AccurateRefresh::PhotoAssetChangeData> infos,
        Notification::AssetRefreshOperation operationType, NotifyLevel notifyLevel);
    static std::vector<NotifyInfoInner> buildAlbumNotifyTaskInfo(NotifyTableType tableType,
        std::vector<AccurateRefresh::AlbumChangeData> infos,
        Notification::AlbumRefreshOperation operationType, NotifyLevel notifyLevel);
    static void SetHapPermission();
};
} // namespace Notification
} // namespace Media
} // namespace OHOS

#endif