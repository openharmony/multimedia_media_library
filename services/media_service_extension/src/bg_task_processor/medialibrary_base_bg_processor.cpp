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

#define MLOG_TAG "MediaBgTask_MediaLibraryBaseBgProcessor"

#include "medialibrary_base_bg_processor.h"

#include "media_bgtask_mgr_client.h"
#include "media_log.h"
#include "medialibrary_errno.h"

using namespace OHOS::MediaBgtaskSchedule;
namespace OHOS {
namespace Media {
static const std::string BUNDLE_NAME = "com.ohos.medialibrary.medialibrarydata:";

std::mutex MediaLibraryBaseBgProcessor::removeTaskNameMutex_;
std::function<void(const std::string &)> MediaLibraryBaseBgProcessor::removeTaskNameCallback_;

std::mutex MediaLibraryBaseBgProcessor::ipcMutex_;

const std::unordered_map<std::string, std::vector<std::string>> KEY_VALUE_MAP = {
    { "taskRun", { "true", "false", "skipToday" } },
};

void MediaLibraryBaseBgProcessor::RemoveTaskName(const std::string &taskName)
{
    if (removeTaskNameCallback_) {
        removeTaskNameCallback_(taskName);
    }
}

void MediaLibraryBaseBgProcessor::AddRemoveTaskNameCallback(std::function<void(const std::string &)> callback)
{
    std::lock_guard<std::mutex> lock(removeTaskNameMutex_);
    if (callback) {
        removeTaskNameCallback_ = std::move(callback);
    }
}

void MediaLibraryBaseBgProcessor::WriteModifyInfo(const std::string &key, const std::string &value,
    std::string &modifyInfo)
{
    MEDIA_INFO_LOG("key: %{public}s, value: %{public}s, modifyInfo: %{public}s",
        key.c_str(), value.c_str(), modifyInfo.c_str());

    auto it = KEY_VALUE_MAP.find(key);
    if (it == KEY_VALUE_MAP.end()) {
        MEDIA_INFO_LOG("key: %{public}s, is not exist", key.c_str());
        return;
    }
    if (find((it->second).begin(), (it->second).end(), value) == (it->second).end()) {
        MEDIA_INFO_LOG("value: %{public}s, is not exist", value.c_str());
        return;
    }

    if (modifyInfo.empty()) {
        modifyInfo = key + ":" + value;
    } else {
        modifyInfo = modifyInfo + "," + key + ":" + value;
    }
}

void MediaLibraryBaseBgProcessor::ReportTaskComplete(const std::string &taskName)
{
    std::lock_guard<std::mutex> lock(ipcMutex_);
    std::shared_ptr<MediaBgtaskSchedule::MediaBgtaskMgrClient> bgtaskMgr = MediaBgtaskMgrClient::GetInstance();
    CHECK_AND_RETURN_LOG(bgtaskMgr != nullptr, "bgtaskMgr is nullptr.");
    std::string taskId = BUNDLE_NAME + taskName;
    bgtaskMgr->ReportTaskComplete(taskId);
}

void MediaLibraryBaseBgProcessor::ModifyTask(const std::string &taskName, const std::string& modifyInfo)
{
    std::lock_guard<std::mutex> lock(ipcMutex_);
    std::shared_ptr<MediaBgtaskSchedule::MediaBgtaskMgrClient> bgtaskMgr = MediaBgtaskMgrClient::GetInstance();
    CHECK_AND_RETURN_LOG(bgtaskMgr != nullptr, "bgtaskMgr is nullptr.");
    std::string taskId = BUNDLE_NAME + taskName;
    bgtaskMgr->ModifyTask(taskId, modifyInfo);
}
} // namespace Media
} // namespace OHOS
