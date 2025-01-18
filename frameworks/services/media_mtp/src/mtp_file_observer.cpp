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

#define MLOG_TAG "MtpFileObserver"
#include "mtp_file_observer.h"
#include <memory>
#include <securec.h>
#include <string>
#include <sys/inotify.h>
#include <unistd.h>
#include "media_log.h"
#include "mtp_media_library.h"

using namespace std;
namespace OHOS {
namespace Media {
bool MtpFileObserver::isRunning_ = false;
int MtpFileObserver::inotifyFd_ = 0;
std::map<int, std::string> MtpFileObserver::watchMap_;
std::mutex MtpFileObserver::eventLock_;
const int BUF_SIZE = 1024;
const int32_t SIZE_ONE = 1;
#ifdef HAS_BATTERY_MANAGER_PART
const int LOW_BATTERY = 50;
#endif
const std::string PATH_SEPARATOR = "/";
struct MoveInfo {
    uint32_t cookie;
    std::string path;
} g_moveInfo;

void MtpFileObserver::EraseFromWatchMap(const std::string &path)
{
    CHECK_AND_RETURN_LOG(!path.empty(), "EraseFromWatchMap path is empty");
    {
        lock_guard<mutex> lock(eventLock_);
        std::vector<int> eraseList;
        std::string separatorPath = path + PATH_SEPARATOR;
        for (const auto &item : watchMap_) {
            // remove the path in watchMap_ which is the subdirectory of the deleted path
            if (separatorPath.compare(item.second.substr(0, separatorPath.size())) == 0) {
                eraseList.push_back(item.first);
            } else if (item.second.compare(path) == 0) {
                // remove the path in watchMap_
                eraseList.push_back(item.first);
            }
        }
        for (const auto &i : eraseList) {
            inotify_rm_watch(inotifyFd_, i);
            watchMap_.erase(i);
        }
        std::vector<int>().swap(eraseList);
    }
}

void MtpFileObserver::UpdateWatchMap(const std::string &path)
{
    CHECK_AND_RETURN_LOG(!path.empty(), "UpdateWatchMap path is empty");
    CHECK_AND_RETURN_LOG(!g_moveInfo.path.empty(), "UpdateWatchMap removeInfo.path is empty");
    {
        lock_guard<mutex> lock(eventLock_);
        std::string separatorPath = g_moveInfo.path + PATH_SEPARATOR;
        for (auto &item : watchMap_) {
            // update the path in watchMap_ which is the subdirectory of the moved path
            if (separatorPath.compare(item.second.substr(0, separatorPath.size())) == 0) {
                item.second = path + PATH_SEPARATOR + item.second.substr(separatorPath.size());
            } else if (item.second.compare(g_moveInfo.path) == 0) {
                // update the path in watchMap_
                item.second = path;
            }
        }
    }
}

void MtpFileObserver::DealWatchMap(const inotify_event &event, const std::string &path)
{
    CHECK_AND_RETURN_LOG(!path.empty(), "DealWatchMap path is empty");
    CHECK_AND_RETURN_LOG((event.mask & IN_ISDIR), "DealWatchMap path is not dir");
    if (event.mask & IN_DELETE) {
        // if the path is deleted, remove it from watchMap_
        EraseFromWatchMap(path);
    } else if (event.mask & IN_MOVED_FROM) {
        // if the path is moved from, record the cookie and path
        g_moveInfo = {
            .cookie = event.cookie,
            .path = path
        };
    } else if (event.mask & IN_MOVED_TO) {
        // if the path is moved to, update the path in watchMap_
        if (g_moveInfo.cookie == event.cookie) {
            UpdateWatchMap(path);
        }
    }
}

void MtpFileObserver::SendEvent(const inotify_event &event, const std::string &path, const ContextSptr &context)
{
    string fileName = path + "/" + event.name;
    std::shared_ptr<MtpEvent> eventPtr = std::make_shared<OHOS::Media::MtpEvent>(context);
    CHECK_AND_RETURN_LOG(eventPtr != nullptr, "MtpFileObserver SendEvent eventPtr is null");
    if ((event.mask & IN_CREATE) || (event.mask & IN_MOVED_TO)) {
        MEDIA_DEBUG_LOG("MtpFileObserver AddInotifyEvents create/MOVED_TO: path:%{private}s", fileName.c_str());
        MtpMediaLibrary::GetInstance()->ObserverAddPathToMap(fileName);
        eventPtr->SendObjectAdded(fileName);
    } else if ((event.mask & IN_DELETE) || (event.mask & IN_MOVED_FROM)) {
        MEDIA_DEBUG_LOG("MtpFileObserver AddInotifyEvents delete/MOVED_FROM: path:%{private}s", fileName.c_str());
        uint32_t id = 0;
        if (MtpMediaLibrary::GetInstance()->GetIdByPath(fileName, id) == 0) {
            MtpMediaLibrary::GetInstance()->ObserverDeletePathToMap(fileName);
            eventPtr->SendObjectRemovedByHandle(id);
        }
    } else if (event.mask & IN_CLOSE_WRITE) {
        MEDIA_DEBUG_LOG("MtpFileObserver AddInotifyEvents IN_CLOSE_WRITE : path:%{private}s", fileName.c_str());
        eventPtr->SendObjectInfoChanged(fileName);
    }
    // if the path is a directory and it is moved or deleted, deal with the watchMap_
    if ((event.mask & IN_ISDIR) && (event.mask & (IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO))) {
        DealWatchMap(event, fileName);
    }
}

bool MtpFileObserver::AddInotifyEvents(const int &inotifyFd, const ContextSptr &context)
{
    char eventBuf[BUF_SIZE] = {0};

    int ret = read(inotifyFd, eventBuf, sizeof(eventBuf) - SIZE_ONE);
    bool cond = (ret < static_cast<int>(sizeof(struct inotify_event)));
    CHECK_AND_RETURN_RET_LOG(!cond, false, "MtpFileObserver AddInotifyEvents no event");

    struct inotify_event *positionEvent = (struct inotify_event *)eventBuf;
    struct inotify_event *event;
    while (ret >= static_cast<int>(sizeof(struct inotify_event))) {
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
        ret -= static_cast<int>(sizeof(struct inotify_event));
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
    CHECK_AND_RETURN_RET_LOG(isRunning_, false, "MtpFileObserver FileInotify is not running");
    isRunning_ = false;
    lock_guard<mutex> lock(eventLock_);
    for (auto ret : watchMap_) {
        CHECK_AND_RETURN_RET_LOG(inotify_rm_watch(inotifyFd_, ret.first) != -1, false,
            "MtpFileObserver StopFileInotify inotify_rm_watch error = [%{public}d]", errno);
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
    CHECK_AND_RETURN_RET_LOG(inotifyFd_ != -1, false, "MtpFileObserver inotify_init false");
    inotifySuccess_ = true;
    return true;
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
            int ret = inotify_add_watch(inotifyFd_, path.c_str(),
                IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_ISDIR);
            watchMap_.insert(make_pair(ret, path));
        }
        if (!startThread_) {
            std::thread watchThread([&context] { WatchPathThread(context); });
            watchThread.detach();
            startThread_ = true;
        }
    }
}

void MtpFileObserver::AddPathToWatchMap(const std::string &path)
{
    CHECK_AND_RETURN_LOG(!path.empty(), "AddPathToWatchMap path is empty");
    {
        lock_guard<mutex> lock(eventLock_);
        int ret = inotify_add_watch(inotifyFd_, path.c_str(),
            IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_ISDIR);
        if (ret > 0) {
            watchMap_.insert(make_pair(ret, path));
        }
    }
}
} // namespace Media
} // namespace OHOS
