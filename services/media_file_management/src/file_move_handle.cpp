/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "FileMoveHandle"
#include <sys/stat.h>
#include "file_move_handle.h"

#include <string>
#include <map>
#include "progress_observer_manager.h"

namespace OHOS::Media {
FileMoveHandle::~FileMoveHandle()
{
    if (progressTimerId_ != 0) {
        EndProgressTimer();
    }
}

void FileMoveHandle::StartProgressTimer(uint32_t preSetimeMs, bool once)
{
    Utils::Timer::TimerCallback callBack = [this]() {
        int32_t ret = this->CalculateProgress();
        CHECK_AND_RETURN_LOG(ret == E_OK, "failed to CalculateProgress");
        this->OnMoveProgressTimer();
    };
    progressTimer_.Setup();
    progressTimerId_ = progressTimer_.Register(callBack, preSetimeMs, once); // 1000ms = 1秒
}

void FileMoveHandle::EndProgressTimer()
{
    progressTimer_.Unregister(progressTimerId_);
    progressTimer_.Shutdown();
    progressTimerId_ = 0;
}

int32_t FileMoveHandle::OnMoveProgressTimer()
{
    std::lock_guard<std::mutex> lock(progressStateMutex_);
    CHECK_AND_RETURN_RET_LOG(progressChangeInfo_->requestId > 0, E_ERR, "current requestId is invaild");
    auto &progressManager = Notification::ProgressObserverManager::GetInstance();
    progressManager.NotifyProgress(progressChangeInfo_);
    return E_OK;
}

int32_t FileMoveHandle::CalculateProgress()
{
    MEDIA_DEBUG_LOG("start CalculateProgress");
    std::lock_guard<std::mutex> lock(progressStateMutex_);
    int32_t ret;
    if (targetPath_ != "") {
        struct stat statInfo {};
        ret = stat(targetPath_.c_str(), &statInfo);
        CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, E_ERR, "fail to stat. ret: %{public}d", ret);
        progressChangeInfo_->realTimeprocessSize = progressChangeInfo_->processedSize + statInfo.st_size; //定时回调时计算
    } else {
        progressChangeInfo_->realTimeprocessSize = progressChangeInfo_->processedSize;
    }
    progressChangeInfo_->remainSize = progressChangeInfo_->totalSize - progressChangeInfo_->realTimeprocessSize;
    progressChangeInfo_->remainCount = (progressChangeInfo_->remainSize != 0) ?
        (progressChangeInfo_->totalCount - progressChangeInfo_->processedCount) : 0;
    return E_OK;
}
} //OHOS::Media