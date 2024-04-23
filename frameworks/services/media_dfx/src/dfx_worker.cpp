/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "DfxWorker"

#include "dfx_worker.h"

#include <pthread.h>

#include "media_file_utils.h"
#include "media_log.h"
#include "dfx_manager.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "parameters.h"

using namespace std;
namespace OHOS {
namespace Media {
shared_ptr<DfxWorker> DfxWorker::dfxWorkerInstance_{nullptr};

shared_ptr<DfxWorker> DfxWorker::GetInstance()
{
    if (dfxWorkerInstance_ == nullptr) {
        dfxWorkerInstance_ = make_shared<DfxWorker>();
    }
    return dfxWorkerInstance_;
}

DfxWorker::DfxWorker() : isThreadRunning_(false)
{
    shortTime_ = stoi(system::GetParameter("persist.multimedia.medialibrary.dfx.shorttime", FIVE_MINUTE)) *
        TO_MILLION * ONE_MINUTE;
    middleTime_ = stoi(system::GetParameter("persist.multimedia.medialibrary.dfx.middletime", SIX_HOUR)) *
        ONE_MINUTE * ONE_MINUTE;
    longTime_ = stoi(system::GetParameter("persist.multimedia.medialibrary.dfx.longtime", ONE_DAY)) * ONE_MINUTE *
        ONE_MINUTE;
}

DfxWorker::~DfxWorker()
{
    MEDIA_INFO_LOG("DfxWorker deconstructor");
    isThreadRunning_ = false;
    workCv_.notify_all();
    if (delayThread_.joinable()) {
        delayThread_.join();
    }
    dfxWorkerInstance_ = nullptr;
}

void DfxWorker::Init()
{
    MEDIA_INFO_LOG("init");
    cycleThread_ = thread(bind(&DfxWorker::InitCycleThread, this));
    cycleThread_.detach();
    isThreadRunning_ = true;
    delayThread_ = thread(bind(&DfxWorker::InitDelayThread, this));
}

void DfxWorker::InitCycleThread()
{
    MEDIA_INFO_LOG("InitCycleThread");
    string name("DfxCycleThread");
    pthread_setname_np(pthread_self(), name.c_str());
    Prepare();
    InitLoop();
}

void DfxWorker::Prepare()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    lastReportTime_ = prefs->GetLong(LAST_REPORT_TIME, 0);
    lastMiddleReportTime_ = prefs->GetInt(LAST_MIDDLE_REPORT_TIME, 0);
    thumbnailVersion_ = prefs->GetInt(THUMBNAIL_ERROR_VERSION, 0);
    deleteStatisticVersion_ = prefs->GetInt(DELETE_STATISTIC_VERSION, 0);
    if (IsThumbnailUpdate()) {
        thumbnailVersion_ = LATEST_THUMBNAIL_ERROR_VERSION;
        prefs->PutInt(THUMBNAIL_ERROR_VERSION, LATEST_THUMBNAIL_ERROR_VERSION);
    }
    if (IsDeleteStatisticUpdate()) {
        deleteStatisticVersion_ = LATEST_DELETE_STATISTIC_VERSION;
        prefs->PutInt(DELETE_STATISTIC_VERSION, LATEST_DELETE_STATISTIC_VERSION);
    }
    prefs->FlushSync();
}

bool DfxWorker::IsThumbnailUpdate()
{
    if (thumbnailVersion_ < LATEST_THUMBNAIL_ERROR_VERSION) {
        MEDIA_INFO_LOG("update thumbnail version from %{public}d to %{public}d", thumbnailVersion_,
            LATEST_THUMBNAIL_ERROR_VERSION);
        int32_t errCode;
        shared_ptr<NativePreferences::Preferences> prefs =
            NativePreferences::PreferencesHelper::GetPreferences(THUMBNAIL_ERROR_XML, errCode);
        if (!prefs) {
            MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
            return false;
        }
        prefs->Clear();
        prefs->FlushSync();
        return true;
    }
    return false;
}

bool DfxWorker::IsDeleteStatisticUpdate()
{
    if (deleteStatisticVersion_ < LATEST_DELETE_STATISTIC_VERSION) {
        MEDIA_INFO_LOG("update delete statistic version from %{public}d to %{public}d", deleteStatisticVersion_,
            LATEST_DELETE_STATISTIC_VERSION);
        int32_t errCode;
        shared_ptr<NativePreferences::Preferences> prefs =
            NativePreferences::PreferencesHelper::GetPreferences(DELETE_BEHAVIOR_XML, errCode);
        if (!prefs) {
            MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
            return false;
        }
        prefs->Clear();
        prefs->FlushSync();
        return true;
    }
    return false;
}

void DfxWorker::InitLoop()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    while (!isEnd_) {
        DfxManager::GetInstance()->HandleFiveMinuteTask();
        if (MediaFileUtils::UTCTimeSeconds() - lastMiddleReportTime_ > middleTime_) {
            MEDIA_INFO_LOG("Report Middle Xml");
            lastMiddleReportTime_ = DfxManager::GetInstance()->HandleMiddleReport();
            prefs->PutLong(LAST_MIDDLE_REPORT_TIME, lastMiddleReportTime_);
            prefs->FlushSync();
        }
        if (MediaFileUtils::UTCTimeSeconds() - lastReportTime_ > longTime_) {
            MEDIA_INFO_LOG("Report Xml");
            lastReportTime_ = DfxManager::GetInstance()->HandleReportXml();
            prefs->PutLong(LAST_REPORT_TIME, lastReportTime_);
            prefs->FlushSync();
        }
        this_thread::sleep_for(chrono::milliseconds(shortTime_));
    }
}

void DfxWorker::InitDelayThread()
{
    MEDIA_INFO_LOG("InitDelayThread");
    string name("DfxDelayThread");
    pthread_setname_np(pthread_self(), name.c_str());
    while (isThreadRunning_) {
        WaitForTask();
        if (!isThreadRunning_) {
            break;
        }
        if (!IsTaskQueueEmpty()) {
            shared_ptr<DfxTask> task = GetTask();
            if (task != nullptr) {
                task->executor_(task->data_);
                task = nullptr;
            }
        }
    }
}

void DfxWorker::AddTask(const shared_ptr<DfxTask> &task)
{
    lock_guard<mutex> lockGuard(taskLock_);
    taskQueue_.push(task);
    workCv_.notify_one();
}

bool DfxWorker::IsTaskQueueEmpty()
{
    lock_guard<mutex> lock_Guard(taskLock_);
    return taskQueue_.empty();
}

void DfxWorker::WaitForTask()
{
    std::unique_lock<std::mutex> lock(workLock_);
    workCv_.wait(lock,
        [this]() { return !isThreadRunning_ || !IsTaskQueueEmpty(); });
}

shared_ptr<DfxTask> DfxWorker::GetTask()
{
    lock_guard<mutex> lockGuard(taskLock_);
    if (taskQueue_.empty()) {
        return nullptr;
    }
    shared_ptr<DfxTask> task = taskQueue_.front();
    taskQueue_.pop();
    return task;
}

void DfxWorker::End()
{
    isEnd_ = true;
}
} // namespace Media
} // namespace OHOS