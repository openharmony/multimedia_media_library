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

#include "medialibrary_notify_new_observer.h"

#include "media_file_utils.h"
#include "media_notification_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"

using namespace std;

namespace OHOS {
namespace Media {
shared_ptr<ChangeInfoTaskWorker> ChangeInfoTaskWorker::changeInfoTaskWorker_{nullptr};
mutex ChangeInfoTaskWorker::instanceMtx_;
mutex ChangeInfoTaskWorker::vectorMutex_;

static const int64_t MAX_NOTIFY_MILLISECONDS = 10;
static const int32_t START_NOTIFY_TASK_COUNT = 3;
static const int32_t MAX_NOTIFY_TASK_COUNT = 23;
static const int32_t MAX_NOTIFY_TASK_INFO_SIZE = 5000;

void MediaOnNotifyNewObserver::OnChange(const ChangeInfo &changeInfo)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaOnNotifyNewObserver::OnChange");
    NAPI_DEBUG_LOG("begin OnChange");
    if (changeInfo.data_ == nullptr || changeInfo.size_ <= 0) {
        NAPI_ERR_LOG("changeInfo.data_ is null or changeInfo.size_ is invalid");
        return;
    }
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
    callbackWrapper.mediaChangeInfo_ = NotificationUtils::UnmarshalInMultiMode(*parcel);
    CHECK_AND_RETURN_LOG(callbackWrapper.mediaChangeInfo_ != nullptr, "invalid mediaChangeInfo");
    Notification::NotifyUriType infoUriType = callbackWrapper.mediaChangeInfo_->notifyUri;
    if (clientObservers_.find(infoUriType) == clientObservers_.end()) {
        NAPI_ERR_LOG("invalid mediaChangeInfo_->notifyUri: %{public}d", static_cast<int32_t>(infoUriType));
        for (const auto& pair : clientObservers_) {
            NAPI_ERR_LOG("invalid clientObservers_ infoUriType: %{public}d", static_cast<int32_t>(pair.first));
        }
        return;
    }
    callbackWrapper.env_ = env_;
    callbackWrapper.observerUriType_ = infoUriType;
    callbackWrapper.clientObservers_ = clientObservers_[infoUriType];

    auto worker = ChangeInfoTaskWorker::GetInstance();
    if (worker == nullptr) {
        NAPI_ERR_LOG("Get ChangeInfoTaskWorker instance failed");
        return;
    }
    worker->AddTaskInfo(callbackWrapper);
    if (!worker->IsRunning()) {
        worker->StartWorker();
    }
}

void MediaOnNotifyNewObserver::ReadyForUvWork(const NewJsOnChangeCallbackWrapper &callbackWrapper)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaOnNotifyNewObserver::ReadyForUvWork");
    NAPI_DEBUG_LOG("start ReadyForUvWork");
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(callbackWrapper.env_, &loop);
    if (loop == nullptr) {
        NAPI_ERR_LOG("Failed to get loop");
        return;
    }
    uv_work_t *work = new (nothrow) uv_work_t;
    if (work == nullptr) {
        NAPI_ERR_LOG("Failed to new uv_work");
        return;
    }

    NewJsOnChangeCallbackWrapper* wrapper = new (std::nothrow) NewJsOnChangeCallbackWrapper();
    if (wrapper == nullptr) {
        NAPI_ERR_LOG("NewJsOnChangeCallbackWrapper allocation failed");
        delete work;
        return;
    }
    wrapper->env_ = callbackWrapper.env_;
    wrapper->clientObservers_ = callbackWrapper.clientObservers_;
    if (callbackWrapper.mediaChangeInfo_ == nullptr) {
        work->data = reinterpret_cast<void *>(wrapper);
        SendRecheckUvWork(loop, work);
        return;
    }
    wrapper->observerUriType_ = callbackWrapper.observerUriType_;
    wrapper->mediaChangeInfo_ = callbackWrapper.mediaChangeInfo_;
    NAPI_INFO_LOG("mediaChangeInfo_ is: %{public}s", wrapper->mediaChangeInfo_->ToString(true).c_str());
    work->data = reinterpret_cast<void *>(wrapper);
    UvQueueWork(loop, work);
}

static void OnChangeNotifyDetail(NewJsOnChangeCallbackWrapper* wrapper)
{
    MediaLibraryTracer tracer;
    tracer.Start("OnChangeNotifyDetail");
    std::shared_ptr<Notification::MediaChangeInfo> mediaChangeInfo = wrapper->mediaChangeInfo_;

    napi_env env = wrapper->env_;
    napi_value buildResult = nullptr;
    switch (wrapper->observerUriType_) {
        case Notification::PHOTO_URI:
        case Notification::HIDDEN_PHOTO_URI:
        case Notification::TRASH_PHOTO_URI:
            buildResult = MediaLibraryNotifyUtils::BuildPhotoAssetChangeInfos(env, mediaChangeInfo);
            break;
        case Notification::PHOTO_ALBUM_URI:
        case Notification::HIDDEN_ALBUM_URI:
        case Notification::TRASH_ALBUM_URI:
            buildResult = MediaLibraryNotifyUtils::BuildAlbumAlbumChangeInfos(env, mediaChangeInfo);
            break;
        default:
            NAPI_ERR_LOG("Invalid registerUriType");
    }
    if (buildResult == nullptr) {
        NAPI_ERR_LOG("Failed to build result");
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
}

void MediaOnNotifyNewObserver::UvQueueWork(uv_loop_s *loop, uv_work_t *work)
{
    uv_queue_work(loop, work, [](uv_work_t *work) {}, [](uv_work_t *work, int status) {
        if (work == nullptr) {
            return;
        }
        NewJsOnChangeCallbackWrapper* wrapper = reinterpret_cast<NewJsOnChangeCallbackWrapper *>(work->data);
        napi_env env = wrapper->env_;
        NapiScopeHandler scopeHandler(env);
        if (!scopeHandler.IsValid()) {
            delete wrapper;
            delete work;
            return;
        }
        MediaLibraryTracer tracer;
        tracer.Start("MediaOnNotifyNewObserver::UvQueueWork");
        OnChangeNotifyDetail(wrapper);
        delete wrapper;
        delete work;
    });
}

void MediaOnNotifyNewObserver::SendRecheckUvWork(uv_loop_s *loop, uv_work_t *work)
{
    uv_queue_work(loop, work, [](uv_work_t *work) {}, [](uv_work_t *work, int status) {
        if (work == nullptr) {
            return;
        }
        NewJsOnChangeCallbackWrapper* wrapper = reinterpret_cast<NewJsOnChangeCallbackWrapper *>(work->data);
        napi_env env = wrapper->env_;
        NapiScopeHandler scopeHandler(env);
        if (!scopeHandler.IsValid()) {
            delete wrapper;
            delete work;
            return;
        }
        MediaLibraryTracer tracer;
        tracer.Start("MediaOnNotifyNewObserver::SendRecheckUvWork");
        napi_value jsResults = nullptr;
        napi_create_object(env, &jsResults);
        napi_status jsStatus = napi_ok;
        jsStatus = MediaLibraryNotifyUtils::SetValueBool(env, "isForReCheck", true, jsResults);
        if (jsStatus != napi_ok) {
            NAPI_ERR_LOG("set array named property error: isForReCheck");
            delete wrapper;
            delete work;
            return;
        }
        napi_value result[ARGS_ONE];
        result[PARAM0] = jsResults;

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
        delete wrapper;
        delete work;
    });
}

shared_ptr<ChangeInfoTaskWorker> ChangeInfoTaskWorker::GetInstance()
{
    if (changeInfoTaskWorker_ == nullptr) {
        lock_guard<mutex> lockGuard(instanceMtx_);
        if (changeInfoTaskWorker_ == nullptr) {
            changeInfoTaskWorker_ = make_shared<ChangeInfoTaskWorker>();
        }
    }
    return changeInfoTaskWorker_;
}

ChangeInfoTaskWorker::ChangeInfoTaskWorker() {}

ChangeInfoTaskWorker::~ChangeInfoTaskWorker() {}

void ChangeInfoTaskWorker::StartWorker()
{
    if (!isThreadRunning_.load()) {
        isThreadRunning_.store(true);
        std::thread([this]() { this->HandleNotifyTaskPeriod(); }).detach();
    }
}

void ChangeInfoTaskWorker::GetTaskInfos()
{
    // taskMap key: 注册给服务端的uriType  value: uriType对应的clientObservers_
    map<Notification::NotifyUriType, NewJsOnChangeCallbackWrapper> taskMap;
    for (const auto& taskInfo : taskInfos_) {
        const auto& clientObservers = taskInfo.clientObservers_;
        if (clientObservers.empty()) {
            continue;
        }
        Notification::NotifyUriType observerUriType = taskInfo.observerUriType_;
        napi_env env = taskInfo.env_;

        if (taskMap.find(observerUriType) == taskMap.end()) {
            NewJsOnChangeCallbackWrapper newCallbackWrapper;
            newCallbackWrapper.env_ = env;
            newCallbackWrapper.clientObservers_ = clientObservers;
            taskMap[observerUriType] = newCallbackWrapper;
        }
    }

    taskInfos_.clear();
    for (const auto& task : taskMap) {
        const NewJsOnChangeCallbackWrapper& callbackWrapper = task.second;
        taskInfos_.push_back(callbackWrapper);
    }
    return;
}
void ChangeInfoTaskWorker::AddTaskInfo(NewJsOnChangeCallbackWrapper callbackWrapper)
{
    NAPI_DEBUG_LOG("enter AddTaskInfo");
    lock_guard<mutex> lock(vectorMutex_);
    int64_t currentTime = MediaFileUtils::UTCTimeMilliSeconds();
    if (currentTime - lastTaskTime_ < MAX_NOTIFY_MILLISECONDS) {
        notifyTaskCount_++;
        if (notifyTaskCount_ > START_NOTIFY_TASK_COUNT && callbackWrapper.mediaChangeInfo_ != nullptr) {
            notifyTaskInfoSize_ += callbackWrapper.mediaChangeInfo_->changeInfos.size();
        }
        lastTaskTime_ = currentTime;
        taskInfos_.push_back(callbackWrapper);
        NAPI_DEBUG_LOG("taskInfos_ size: %{public}zu, notifyTaskCount_: %{public}d, notifyTaskInfoSize_: %{public}d",
            taskInfos_.size(), notifyTaskCount_, notifyTaskInfoSize_);
        return;
    }
    if ((notifyTaskCount_ > MAX_NOTIFY_TASK_COUNT || notifyTaskInfoSize_ > MAX_NOTIFY_TASK_INFO_SIZE) &&
        !taskInfos_.empty()) {
        GetTaskInfos();
    } else {
        taskInfos_.push_back(callbackWrapper);
    }
    notifyTaskCount_ = 0;
    notifyTaskInfoSize_ = 0;
    lastTaskTime_ = currentTime;
    NAPI_DEBUG_LOG("taskInfos_ size: %{public}zu, notifyTaskCount_: %{public}d, notifyTaskInfoSize_: %{public}d",
        taskInfos_.size(), notifyTaskCount_, notifyTaskInfoSize_);
}

bool ChangeInfoTaskWorker::IsTaskInfosEmpty()
{
    lock_guard<mutex> lock(vectorMutex_);
    return taskInfos_.empty();
}

bool ChangeInfoTaskWorker::IsRunning()
{
    return isThreadRunning_.load();
}

void ChangeInfoTaskWorker::WaitForTask()
{
    if (IsTaskInfosEmpty()) {
        isThreadRunning_.store(false);
    }
}

void ChangeInfoTaskWorker::HandleTimeoutNotifyTask()
{
    lock_guard<mutex> lock(vectorMutex_);
    int64_t currentTime = MediaFileUtils::UTCTimeMilliSeconds();
    if (taskInfos_.empty() || currentTime - lastTaskTime_ < MAX_NOTIFY_MILLISECONDS) {
        return;
    }
    // taskInfos_非空，并且距离上一个加入队列的任务超过10ms
    if ((notifyTaskCount_ > MAX_NOTIFY_TASK_COUNT || notifyTaskInfoSize_ > MAX_NOTIFY_TASK_INFO_SIZE)) {
        GetTaskInfos();
    }
    notifyTaskCount_ = 0;
    notifyTaskInfoSize_ = 0;
    lastTaskTime_ = currentTime;
    NAPI_DEBUG_LOG("taskInfos_ size: %{public}zu, notifyTaskCount_: %{public}d, notifyTaskInfoSize_: %{public}d",
        taskInfos_.size(), notifyTaskCount_, notifyTaskInfoSize_);
}

void ChangeInfoTaskWorker::HandleNotifyTask()
{
    lock_guard<mutex> lock(vectorMutex_);
    if (notifyTaskCount_ > START_NOTIFY_TASK_COUNT) {
        NAPI_DEBUG_LOG("taskInfos_ size: %{public}zu, notifyTaskCount_: %{public}d, notifyTaskInfoSize_: %{public}d",
            taskInfos_.size(), notifyTaskCount_, notifyTaskInfoSize_);
        return;
    }
    if (taskInfos_.empty()) {
        NAPI_INFO_LOG("taskInfos_ is empty");
        return;
    }
    NewJsOnChangeCallbackWrapper callbackWrapper = taskInfos_.front();
    taskInfos_.erase(taskInfos_.begin());
    MediaOnNotifyNewObserver::ReadyForUvWork(callbackWrapper);
}

void ChangeInfoTaskWorker::HandleNotifyTaskPeriod()
{
    MediaLibraryTracer tracer;
    tracer.Start("ChangeInfoTaskWorker::HandleNotifyTaskPeriod");
    NAPI_INFO_LOG("start changeInfo notify worker");
    string name("NewNotifyThread");
    pthread_setname_np(pthread_self(), name.c_str());
    while (isThreadRunning_.load()) {
        WaitForTask();
        if (!isThreadRunning_.load()) {
            break;
        }
        HandleNotifyTask();
        HandleTimeoutNotifyTask();
    }
    NAPI_INFO_LOG("end changeInfo notify worker");
}
}  // namespace Media
}  // namespace OHOS
