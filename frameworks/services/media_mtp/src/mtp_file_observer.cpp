/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "mtp_file_observer.h"
#include <memory>
#include <securec.h>
#include <string>
#include <sys/inotify.h>
#include <unistd.h>
#include "media_log.h"

using namespace std;
namespace OHOS {
namespace Media {
bool MtpFileObserver::isRunning_ = false;
int MtpFileObserver::inotifyFd_ = 0;
std::map<int, std::string> MtpFileObserver::watchMap_;
std::mutex MtpFileObserver::eventLock_;
const int BUF_SIZE = 1024;
#ifdef HAS_BATTERY_MANAGER_PART
const int LOW_BATTERY = 50;
#endif
void MtpFileObserver::SendEvent(const inotify_event &event, const std::string &path, const ContextSptr &context)
{
    string fileName;
    std::shared_ptr<MtpEvent> eventPtr = std::make_shared<OHOS::Media::MtpEvent>(context);
    if ((event.mask & IN_CREATE) || (event.mask & IN_MOVED_TO)) {
        fileName = path + "/" + event.name;
        MEDIA_DEBUG_LOG("MtpFileObserver AddInotifyEvents create/MOVED_TO: path:%{private}s", fileName.c_str());
        eventPtr->SendObjectAdded(fileName);
    } else if ((event.mask & IN_DELETE) || (event.mask & IN_MOVED_FROM)) {
        fileName = path + "/" + event.name;
        MEDIA_DEBUG_LOG("MtpFileObserver AddInotifyEvents delete/MOVED_FROM: path:%{private}s", fileName.c_str());
        eventPtr->SendObjectRemoved(fileName);
    } else if (event.mask & IN_CLOSE_WRITE) {
        fileName = path + "/" + event.name;
        MEDIA_DEBUG_LOG("MtpFileObserver AddInotifyEvents IN_CLOSE_WRITE : path:%{private}s", fileName.c_str());
        eventPtr->SendObjectInfoChanged(fileName);
    }
}

bool MtpFileObserver::AddInotifyEvents(const int &inotifyFd, const ContextSptr &context)
{
    char eventBuf[BUF_SIZE] = {0};

    int ret = read(inotifyFd, eventBuf, sizeof(eventBuf));
    if (ret < (int)sizeof(struct inotify_event)) {
        MEDIA_ERR_LOG("MtpFileObserver AddInotifyEvents no event");
        return false;
    }

    struct inotify_event *positionEvent = (struct inotify_event *)eventBuf;
    struct inotify_event *event;
    while (ret >= (int)sizeof(struct inotify_event)) {
        event = positionEvent;
        if (event->len) {
            bool isFind;
            map<int, string>::iterator iter;
            {
                lock_guard<mutex> lock(eventLock_);
                iter = watchMap_.find(event->wd);
                isFind = iter != watchMap_.end();
            }
            if (isFind) {
                string path = iter->second;
                SendEvent(*event, path, context);
            }
        }
        positionEvent++;
        ret -= (int)sizeof(struct inotify_event);
    }
    return true;
}

void MtpFileObserver::SendBattery(const ContextSptr &context)
{
#ifdef HAS_BATTERY_MANAGER_PART
    std::shared_ptr<MtpEvent> eventPtr = std::make_shared<OHOS::Media::MtpEvent>(context);
    auto battery = make_shared<MtpOperationUtils>(context);
    if (LOW_BATTERY >= battery->GetBatteryLevel()) {
        eventPtr->SendDevicePropertyChanged();
    }
#endif
}

bool MtpFileObserver::StopFileInotify()
{
    isRunning_ = false;
    lock_guard<mutex> lock(eventLock_);
    for (auto ret : watchMap_) {
        if (inotify_rm_watch(inotifyFd_, ret.first) == -1) {
            MEDIA_ERR_LOG("MtpFileObserver StopFileInotify inotify_rm_watch error");
            return false;
        }
    }
    close(inotifyFd_);
    watchMap_.clear();
    startThread_ = false;
    inotifySuccess_ = false;
    inotifyFd_ = 0;
    return true;
}

bool MtpFileObserver::StartFileInotify()
{
    isRunning_ = true;
    inotifyFd_ = inotify_init();
    if (inotifyFd_ == -1) {
        MEDIA_ERR_LOG("MtpFileObserver inotify_init false");
        return false;
    } else {
        inotifySuccess_ = true;
        return true;
    }
}

bool MtpFileObserver::WatchPathThread(const ContextSptr &context)
{
    while (isRunning_) {
        SendBattery(context);
        size_t size;
        {
            lock_guard<mutex> lock(eventLock_);
            size = watchMap_.size();
        }
        if (size > 0) {
            AddInotifyEvents(inotifyFd_, context);
        }
    }
    return true;
}

void MtpFileObserver::AddFileInotify(const std::string &path, const std::string &realPath, const ContextSptr &context)
{
    if (inotifySuccess_) {
        lock_guard<mutex> lock(eventLock_);
        if (!path.empty() && !realPath.empty()) {
            int ret = inotify_add_watch(inotifyFd_, realPath.c_str(),
                IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE);
            watchMap_.insert(make_pair(ret, path));
        }
        if (!startThread_) {
            std::thread watchThread(WatchPathThread, context);
            watchThread.detach();
            startThread_ = true;
        }
    }
}
} // namespace Media
} // namespace OHOS
