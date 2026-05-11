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
 
#ifndef FILE_MOVE_HANDLE_H
#define FILE_MOVE_HANDLE_H

#include <string>
#include <mutex>
#include <timer.h>

#include "medialibrary_errno.h"
#include "user_define_notify_info.h"
#include "media_progress_change_info.h"
#include "file_management_utils.h"

namespace OHOS {
namespace Media {
using namespace Notification;

class FileMoveHandle {
public:
    FileMoveHandle(std::shared_ptr<MediaProgressChangeInfo> changeInfo, std::string timerName)
        : progressTimer_(timerName), progressTimerId_(0), progressStateMutex_(), progressChangeInfo_(changeInfo) {}
    ~FileMoveHandle();
    // 定时器回调函数
    int32_t OnMoveProgressTimer();
    void StartProgressTimer(uint32_t preSetimeMs, bool once);
    void EndProgressTimer();
    int32_t CalculateProgress();
public:
    std::string targetPath_;
    Utils::Timer progressTimer_;
    uint32_t progressTimerId_{0};
private:
    std::mutex progressStateMutex_;
    std::shared_ptr<MediaProgressChangeInfo>  progressChangeInfo_;
};
}} //OHOS:Media
#endif