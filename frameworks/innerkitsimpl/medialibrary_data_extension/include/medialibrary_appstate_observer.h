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
using namespace OHOS::AppExecFwk;
class MedialibraryAppStateObserverManager {
    public:
        MedialibraryAppStateObserverManager() = default;
        ~MedialibraryAppStateObserverManager() = default;
        static MedialibraryAppStateObserverManager &GetInstance();

        void SubscribeAppState();
        void UnSubscribeAppState();

    protected:
        sptr<ApplicationStateObserverStub> appStateObserver_ = nullptr;

    private:
        sptr<IAppMgr> GetAppManagerInstance();
};

class MedialibraryAppStateObserver : public AppExecFwk::ApplicationStateObserverStub {
    public:
        MedialibraryAppStateObserver() {};
        ~MedialibraryAppStateObserver() override = default;

        void OnAppStopped(const AppStateData &appStateData) override;
};
}  // namespace Media
}  // namespace OHOS
#endif // MEDIALIBRARY_APPSTATE_OBSERVER_H
