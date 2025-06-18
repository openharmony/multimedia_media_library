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

#ifndef MEDIA_BGTASK_MGR_CLIENT_H
#define MEDIA_BGTASK_MGR_CLIENT_H

#include <memory>
#include <mutex>
#include "imml_task_mgr.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
class MediaBgtaskMgrClient {
public:
    static std::shared_ptr<MediaBgtaskMgrClient> GetInstance();

    MediaBgtaskMgrClient();
    MediaBgtaskMgrClient(const MediaBgtaskMgrClient&) = delete;  // 禁止拷贝
    MediaBgtaskMgrClient& operator=(const MediaBgtaskMgrClient&) = delete;  // 禁止赋值
    int32_t ReportTaskComplete(const std::string& task_name);
    int32_t ModifyTask(const std::string& task_name, const std::string& modifyInfo);

private:
    sptr<IMmlTaskMgr> GetMediaBgtaskMgrProxy();

    static std::once_flag instanceFlag_;
    static std::shared_ptr<MediaBgtaskMgrClient> instance_;
    sptr<IMmlTaskMgr> proxy_;
    std::mutex proxyMutex_;
};
} // MediaBgtaskSchedule
} // OHOS
#endif // MEDIA_BGTASK_MGR_CLIENT_H
