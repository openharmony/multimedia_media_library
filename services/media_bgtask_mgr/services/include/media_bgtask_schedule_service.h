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

#ifndef MEDIA_BGTASK_MGR_SERVICES_INCLUDE_MEDIA_BGTASK_SCHEDULE_SERVICE_H
#define MEDIA_BGTASK_MGR_SERVICES_INCLUDE_MEDIA_BGTASK_SCHEDULE_SERVICE_H

#include <time.h>

#include <string>
#include <mutex>

#include "ffrt.h"

#include "schedule_policy.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

class MediaBgtaskScheduleService {
public:
    static MediaBgtaskScheduleService &GetInstance()
    {
        static MediaBgtaskScheduleService inst;
        return inst;
    }

    // 当有调度策略更新的时候，参数管理模块调用这个接口
    void HandleScheduleParamUpdate();

    // 当系统状态有变化时，调用这个重新计算
    void HandleSystemStateChange();

    // 当任务状态有变化时，调用这个重新计算
    void HandleTaskStateChange();

    // 当定时到的时候，调用这个重新计算
    static void HandleTimerCome();

    // 任务名字不符合要求，不应该出现在解析后的信息中
    static std::string GetTaskNameFromId(std::string taskId);

    void Init();

    bool reportTaskComplete(const std::string &task_name, int32_t &funcResult);
    bool modifyTask(const std::string &task_name, const std::string &modifyInfo, int32_t &funcResult);
    // 所有调度，都要加这个锁。只用这一个锁，避免多个锁造成死锁
    std::recursive_mutex scheduleLock_;
    void AddDelaySchedule(time_t delaySec);

private:
    std::shared_ptr<ffrt::queue> queue_ = nullptr;
    void ClearAllSchedule();
    void HandleReschedule();
    void HandleStopTask(TaskScheduleResult &compResult);
    void HandleStartTask(TaskScheduleResult &compResult);
};

// 注意：因为涉及作用域，不能用函数
#define LOCK_SCHEDULE_AND_CHANGE() std::lock_guard<std::recursive_mutex> \
        lock_macro_(MediaBgtaskScheduleService::GetInstance().scheduleLock_)
#define SCHEDULE_DELAY_DEFAULT_SEC 2
#define SCHEDULE_DELAY_TASK_CHANGE_SEC 3

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS

#endif  // MEDIA_BGTASK_MGR_SERVICES_INCLUDE_MEDIA_BGTASK_SCHEDULE_SERVICE_H
