/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef MEDIALIBRARY_APPSTATE_OBSERVER_H
#define MEDIALIBRARY_APPSTATE_OBSERVER_H

#include "app_mgr_interface.h"
#include "application_state_observer_stub.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
using namespace OHOS::AppExecFwk;
class MedialibraryAppStateObserverManager {
    public:
        MedialibraryAppStateObserverManager() = default;
        ~MedialibraryAppStateObserverManager() = default;
        EXPORT static MedialibraryAppStateObserverManager &GetInstance();

        EXPORT void SubscribeAppState();
        EXPORT void UnSubscribeAppState();
        EXPORT void AddTokenId(int64_t tokenId, bool needRevoke);
        EXPORT void RemoveTokenId(int64_t tokenId);
        EXPORT bool IsContainTokenId(int64_t tokenId);
        EXPORT bool NeedRevoke(int64_t tokenId);

    protected:
        sptr<ApplicationStateObserverStub> appStateObserver_ = nullptr;

    private:
        sptr<IAppMgr> GetAppManagerInstance();
        std::map<int64_t, bool> revokeMap_;
        std::mutex revokeMapMutex_;
};

class MedialibraryAppStateObserver : public AppExecFwk::ApplicationStateObserverStub {
    public:
        MedialibraryAppStateObserver() {};
        ~MedialibraryAppStateObserver() override = default;

        void OnAppStopped(const AppStateData &appStateData) override;
        void OnAppStarted(const AppStateData &appStateData) override;

    private:
        void Wait4Revoke(int64_t tokenId);
};
}  // namespace Media
}  // namespace OHOS
#endif // MEDIALIBRARY_APPSTATE_OBSERVER_H
