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

#ifndef MEDIALIBRARY_NOTIFY_ASSET_MANAGER_OBSERVER_H
#define MEDIALIBRARY_NOTIFY_ASSET_MANAGER_OBSERVER_H

#include <mutex>
#include <vector>
#include "napi/native_api.h"
#include "parcel.h"
#include "uv.h"

#include "data_ability_helper.h"
#include "data_ability_observer_stub.h"
#include "datashare_helper.h"
#include "media_change_info.h"
#include "medialibrary_napi_utils.h"
#include "medialibrary_notify_utils.h"
#include "medialibrary_notify_new_observer.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class MediaOnNotifyAssetManagerObserver : public DataShare::DataShareObserver  {
public:
    MediaOnNotifyAssetManagerObserver(const Notification::NotifyUriType &uriType, const std::string &uri,
        napi_env env) : uriType_(uriType), uri_(uri), env_(env) {}

    ~MediaOnNotifyAssetManagerObserver() = default;

    void OnChange(const ChangeInfo &changeInfo) override;
    void static ReadyForCallbackEvent(const NewJsOnChangeCallbackWrapper &callbackWrapper);
    void static OnJsCallbackEvent(std::unique_ptr<NewJsOnChangeCallbackWrapper> &jsCallback);
    bool OnChangeForBatchDownloadProgress(NewJsOnChangeCallbackWrapper &callbackWrapper);
    Notification::NotifyUriType uriType_;
    std::string uri_;
    napi_env env_ = nullptr;
    std::map<Notification::NotifyUriType, std::vector<std::shared_ptr<ClientObserver>>> clientObservers_;
};

} // Media
} // OHOS
#endif // MEDIALIBRARY_NOTIFY_ASSET_MANAGER_OBSERVER_H