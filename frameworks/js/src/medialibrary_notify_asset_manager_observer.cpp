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

#define MLOG_TAG "MediaOnNotifyAssetManagerObserver"
#include "medialibrary_notify_asset_manager_observer.h"

#include "media_file_utils.h"
#include "media_notification_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"

using namespace std;

namespace OHOS {
namespace Media {
static const uint32_t MAX_PARCEL_SIZE = 200 * 1024;

void MediaOnNotifyAssetManagerObserver::OnChange(const ChangeInfo &changeInfo)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaOnNotifyAssetManagerObserver::OnChange");
    NAPI_INFO_LOG("begin MediaOnNotifyAssetManagerObserver OnChange");
    if (changeInfo.data_ == nullptr || changeInfo.size_ <= 0) {
        NAPI_ERR_LOG("changeInfo.data_ is null or changeInfo.size_ is invalid");
        return;
    }
    CHECK_AND_RETURN_LOG(changeInfo.size_ < MAX_PARCEL_SIZE, "The size of the parcel exceeds the limit.");
    uint8_t *parcelData = static_cast<uint8_t *>(malloc(changeInfo.size_));
    CHECK_AND_RETURN_LOG(parcelData != nullptr, "parcelData malloc failed");
    if (memcpy_s(parcelData, changeInfo.size_, changeInfo.data_, changeInfo.size_) != 0) {
        NAPI_ERR_LOG("parcelData copy parcel data failed");
        free(parcelData);
        return;
    }
    shared_ptr<MessageParcel> parcel = make_shared<MessageParcel>();
    // parcel析构函数中会free掉parcelData，成功调用ParseFrom后不可进行free(parcelData)
    if (!parcel->ParseFrom(reinterpret_cast<uintptr_t>(parcelData), changeInfo.size_)) {
        NAPI_ERR_LOG("Parse parcelData failed");
        free(parcelData);
        return;
    }
    NewJsOnChangeCallbackWrapper callbackWrapper;
    // 解析通知内容
    callbackWrapper.assetManagerInfo_ = NotificationUtils::UnmarshalAssetManagerNotify(*parcel);
    CHECK_AND_RETURN_LOG(callbackWrapper.assetManagerInfo_ != nullptr, "invalid assetManagerInfo");
    NAPI_INFO_LOG("assetManagerInfo is: %{public}s", callbackWrapper.assetManagerInfo_->ToString(true).c_str());

    Notification::NotifyUriType infoUriType = callbackWrapper.assetManagerInfo_->notifyUri;
    if (clientObservers_.find(infoUriType) == clientObservers_.end()) {
        NAPI_ERR_LOG("invalid infoUriType");
        NAPI_ERR_LOG("invalid assetManagerInfo_->notifyUri: %{public}d", static_cast<int32_t>(infoUriType));
        for (const auto& pair : clientObservers_) {
            NAPI_ERR_LOG("invalid clientObservers_ infoUriType: %{public}d", static_cast<int32_t>(pair.first));
        }
        return;
    }
    callbackWrapper.env_ = env_;
    callbackWrapper.observerUriType_ = infoUriType;
    callbackWrapper.clientObservers_ = clientObservers_[infoUriType];
    OnChangeForBatchDownloadProgress(callbackWrapper);
}

bool MediaOnNotifyAssetManagerObserver::OnChangeForBatchDownloadProgress(NewJsOnChangeCallbackWrapper &callbackWrapper)
{
    if (callbackWrapper.assetManagerInfo_->notifyUri == NotifyUriType::BATCH_DOWNLOAD_PROGRESS_URI) {
        MediaOnNotifyAssetManagerObserver::ReadyForCallbackEvent(callbackWrapper);
        return true;
    }
    NAPI_ERR_LOG("invalid assetManagerInfo notifyUri");
    return false;
}

void MediaOnNotifyAssetManagerObserver::ReadyForCallbackEvent(const NewJsOnChangeCallbackWrapper &callbackWrapper)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaOnNotifyAssetManagerObserver::ReadyForCallbackEvent");
    NAPI_DEBUG_LOG("start ReadyForCallbackEvent");

    std::unique_ptr<NewJsOnChangeCallbackWrapper> jsCallback = std::make_unique<NewJsOnChangeCallbackWrapper>();
    if (jsCallback == nullptr) {
        NAPI_ERR_LOG("NewJsOnChangeCallbackWrapper make_unique failed");
        return;
    }
    jsCallback->env_ = callbackWrapper.env_;
    jsCallback->clientObservers_ = callbackWrapper.clientObservers_;
    jsCallback->observerUriType_ = callbackWrapper.observerUriType_;
    jsCallback->assetManagerInfo_ = callbackWrapper.assetManagerInfo_;

    OnJsCallbackEvent(jsCallback);
}

static void OnChangeNotifyDetail(NewJsOnChangeCallbackWrapper* wrapper)
{
    MediaLibraryTracer tracer;
    tracer.Start("OnChangeNotifyDetail");
    std::shared_ptr<Notification::AssetManagerNotifyInfo> assetManagerInfo = wrapper->assetManagerInfo_;
    napi_env env = wrapper->env_;
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    napi_value buildResult = nullptr;
    switch (wrapper->observerUriType_) {
        case Notification::BATCH_DOWNLOAD_PROGRESS_URI:
            buildResult = MediaLibraryNotifyUtils::BuildBatchDownloadProgressInfos(env, assetManagerInfo);
            break;
        default:
            NAPI_ERR_LOG("Invalid registerUriType");
    }
    if (buildResult == nullptr) {
        NAPI_ERR_LOG("Failed to build result");
        napi_close_handle_scope(env, scope);
        return;
    }
    napi_value result[ARGS_ONE];
    result[PARAM0] = buildResult;
    for (auto &observer : wrapper->clientObservers_) {
        napi_value jsCallback = nullptr;
        napi_status status = napi_get_reference_value(env, observer->ref_, &jsCallback);
        if (status != napi_ok) {
            NAPI_ERR_LOG("Create reference fail, status: %{public}d", status);
            continue;
        }
        napi_value retVal = nullptr;
        status = napi_call_function(env, nullptr, jsCallback, ARGS_ONE, result, &retVal);
        if (status != napi_ok) {
            NAPI_ERR_LOG("CallJs napi_call_function fail, status: %{public}d", status);
            continue;
        }
    }
    napi_close_handle_scope(env, scope);
}

void MediaOnNotifyAssetManagerObserver::OnJsCallbackEvent(std::unique_ptr<NewJsOnChangeCallbackWrapper> &jsCallback)
{
    if (jsCallback.get() == nullptr) {
        NAPI_ERR_LOG("jsCallback.get() is nullptr");
        return;
    }

    napi_env env = jsCallback->env_;
    NewJsOnChangeCallbackWrapper *event = jsCallback.release();
    auto task = [event] () {
        std::shared_ptr<NewJsOnChangeCallbackWrapper> context(
            static_cast<NewJsOnChangeCallbackWrapper*>(event),
            [](NewJsOnChangeCallbackWrapper* ptr) {
                delete ptr;
        });
        CHECK_AND_RETURN_LOG(event != nullptr, "event is nullptr");
        OnChangeNotifyDetail(event);
    };
    if (napi_send_event(env, task, napi_eprio_immediate) != napi_ok) {
        NAPI_ERR_LOG("failed to execute task");
        delete event;
    }
}
}  // namespace Media
}  // namespace OHOS
