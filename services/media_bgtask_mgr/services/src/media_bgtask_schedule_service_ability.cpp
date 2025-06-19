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

#define MLOG_TAG "MediaBgtaskScheduleService"

constexpr int MEDIA_TASK_SCHEDULE_SERVICE_ID = 3016;
#include "media_bgtask_schedule_service_ability.h"

#include "system_ability_definition.h"
#include "media_bgtask_mgr_log.h"
#include "media_bgtask_schedule_service.h"
#include "media_bgtask_utils.h"
#include "task_info_mgr.h"
#include "task_runner.h"

namespace OHOS {
namespace MediaBgtaskSchedule {
REGISTER_SYSTEM_ABILITY_BY_ID(MediaBgtaskScheduleServiceAbility, MEDIA_TASK_SCHEDULE_SERVICE_ID, true);

MediaBgtaskScheduleServiceAbility::MediaBgtaskScheduleServiceAbility(const int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{}

MediaBgtaskScheduleServiceAbility::~MediaBgtaskScheduleServiceAbility()
{}

void MediaBgtaskScheduleServiceAbility::OnStart(const SystemAbilityOnDemandReason &activeReason)
{
    std::lock_guard<std::mutex> lock(systemAbilityMutex_);
    MEDIA_INFO_LOG("MediaBgtaskScheduleServiceAbility OnStart, reason %{public}d", activeReason.GetId());

    if (!registerToService_) {
        MediaBgtaskScheduleService::GetInstance().Init();
        if (!Publish(this)) {
            MEDIA_ERR_LOG("publish failed.");
            return;
        }
        registerToService_ = true;
    }

    MEDIA_INFO_LOG("MediaBgtaskScheduleServiceAbility start succeed");
}

void MediaBgtaskScheduleServiceAbility::OnStop()
{
    std::lock_guard<std::mutex> lock(systemAbilityMutex_);
    MEDIA_INFO_LOG("MediaBgtaskScheduleServiceAbility onStop");
    TaskInfoMgr::GetInstance().SaveTaskState(false);
    registerToService_ = false;
}

void MediaBgtaskScheduleServiceAbility::OnActive(const SystemAbilityOnDemandReason &activeReason)
{
    std::lock_guard<std::mutex> lock(systemAbilityMutex_);
    MEDIA_INFO_LOG("MediaBgtaskScheduleServiceAbility OnActive ,reason %{public}d", activeReason.GetId());
    // 如果上次卸载后，在被unload又被active了，要重新触发下任务调度
    MediaBgtaskScheduleService::GetInstance().HandleSystemStateChange();
    MEDIA_INFO_LOG("MediaBgtaskScheduleServiceAbility active succeed");
}

int32_t MediaBgtaskScheduleServiceAbility::OnIdle(const SystemAbilityOnDemandReason &idleReason)
{
    std::lock_guard<std::mutex> lock(systemAbilityMutex_);
    MEDIA_INFO_LOG("MediaBgtaskScheduleServiceAbility OnIdle");
    return 0;
}

int32_t MediaBgtaskScheduleServiceAbility::OnSvcCmd(int32_t fd, const std::vector<std::u16string> &args)
{
    std::lock_guard<std::mutex> lock(systemAbilityMutex_);
    MEDIA_INFO_LOG("OnSvcCmd OnActive called....");
    return 0;
}

int32_t MediaBgtaskScheduleServiceAbility::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    MEDIA_INFO_LOG("Dump called....");
    dprintf(fd, "Enter MediaBgtaskScheduleServiceAbility::Dump.\n");
    CHECK_AND_RETURN_RET_LOG(fd > 0, OHOS::INVALID_OPERATION, "Failed to check fd.");
    MEDIA_INFO_LOG("Dump called....");

    int32_t ret = OHOS::NO_ERROR;
    int argSize = args.size();
    std::string arg0 = (argSize == 0) ? "" : Str16ToStr8(args[0]);
    // -test sa|app start|stop $(said)|$(bundle/abilityName) $(taskName)
    constexpr int TEST_ARGS_CNT = 5;
    if (arg0 == "-test" && argSize == TEST_ARGS_CNT) {
        std::string type = Str16ToStr8(args[1]);
        std::string ops = Str16ToStr8(args[2]);
        std::string startInfo = Str16ToStr8(args[3]);
        std::string taskName = Str16ToStr8(args[4]);
        dprintf(fd,
            "Enter test: %{public}s %{public}s task in [%{public}s], name %{public}s.\n",
            type.c_str(),
            ops.c_str(),
            startInfo.c_str(),
            taskName.c_str());
        if (type == "sa") {
            // call ops on sa task
            uint32_t saId = static_cast<uint32_t>(std::strtoul(startInfo.c_str(), nullptr, 10));
            TaskOps taskOps = MediaBgTaskUtils::StringToTaskOps(ops);
            if (taskOps == NONE) {
                dprintf(fd, "Bad ops type:%{public}s", ops.c_str());
                return OHOS::INVALID_OPERATION;
            }
            TaskRunner::OpsSaTask(taskOps, saId, taskName, "");
        } else if (type == "app") {
            // call ops on app task
            TaskOps taskOps = MediaBgTaskUtils::StringToTaskOps(ops);
            if (taskOps == NONE) {
                dprintf(fd, "Bad ops type:%{public}s", ops.c_str());
                return OHOS::INVALID_OPERATION;
            }
            AppSvcInfo svcInfo{"com.ohos.medialibrary.medialibrarydata", "ServiceExtAbility"};
            TaskRunner::OpsAppTask(taskOps, svcInfo, taskName, "");
        }
    }
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR, OHOS::INVALID_OPERATION, "Failed to call MediaServerManager::Dump.");
    return OHOS::NO_ERROR;
}

ErrCode MediaBgtaskScheduleServiceAbility::ReportTaskComplete(const std::string &task_name, int32_t &funcResult)
{
    bool success = MediaBgtaskScheduleService::GetInstance().reportTaskComplete(task_name, funcResult);
    return success ? 0 : 1;
}
ErrCode MediaBgtaskScheduleServiceAbility::ModifyTask(
    const std::string &task_name, const std::string &modifyInfo, int32_t &funcResult)
{
    bool success = MediaBgtaskScheduleService::GetInstance().modifyTask(task_name, modifyInfo, funcResult);
    return success ? 0 : 1;
}

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS
