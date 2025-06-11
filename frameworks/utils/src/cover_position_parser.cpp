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

#include "cover_position_parser.h"

#include <fcntl.h>

#include "dfx_utils.h"
#include "directory_ex.h"
#include "ffrt_inner.h"
#include "media_column.h"
#include "medialibrary_notify.h"
#include "medialibrary_unistore_manager.h"
#include "moving_photo_file_utils.h"
#include "unique_fd.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::NativeRdb;

const int32_t MAX_TASK_NUM = 100;

CoverPositionParser &CoverPositionParser::GetInstance()
{
    static CoverPositionParser instance_;
    return instance_;
}

bool CoverPositionParser::AddTask(const string &path, const string &fileUri)
{
    lock_guard<mutex> lock(mtx_);
    if (tasks_.size() >= MAX_TASK_NUM) {
        MEDIA_INFO_LOG("The max queue length has been reached, ignore current task: %{public}s",
                       DfxUtils::GetSafePath(path).c_str());
        return false;
    }
    tasks_.push(make_pair(path, fileUri));
    if (tasks_.size() == 1 && !processing_) {
        MEDIA_DEBUG_LOG("queue has task, start process");
        processing_ = true;
        StartTask();
    }
    return true;
}

void CoverPositionParser::StartTask()
{
    ffrt::submit([this]() { ProcessCoverPosition(); });
}

void CoverPositionParser::ProcessCoverPosition()
{
    bool hasTask = true;
    while (hasTask) {
        pair<string, string> task = GetNextTask();
        if (task.first.empty()) {
            hasTask = false;
            continue;
        }
        UpdateCoverPosition(task.first);
        SendUpdateNotify(task.second);
    }
}

pair<string, string> CoverPositionParser::GetNextTask()
{
    lock_guard<mutex> lock(mtx_);
    if (tasks_.empty()) {
        MEDIA_DEBUG_LOG("queue is empty, stop process");
        processing_ = false;
        return make_pair("", "");
    }
    pair<string, string> task = tasks_.front();
    tasks_.pop();
    return task;
}

void CoverPositionParser::UpdateCoverPosition(const string &path)
{
    string extraDataPath = MovingPhotoFileUtils::GetMovingPhotoExtraDataPath(path);
    string absExtraDataPath;
    if (!PathToRealPath(extraDataPath, absExtraDataPath)) {
        MEDIA_ERR_LOG("realpath fail: %{public}s, errno: %{public}d", DfxUtils::GetSafePath(extraDataPath).c_str(),
                      errno);
        return;
    }

    uint64_t coverPosition = 0;
    uint32_t version = 0;
    uint32_t frameIndex = 0;
    bool hasCinemagraphInfo = false;
    UniqueFd extraDataFd(open(absExtraDataPath.c_str(), O_RDONLY));
    (void)MovingPhotoFileUtils::GetVersionAndFrameNum(extraDataFd.Get(), version, frameIndex, hasCinemagraphInfo);
    if (frameIndex != 0) {
        string videoPath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(path);
        (void)MovingPhotoFileUtils::GetCoverPosition(videoPath, frameIndex, coverPosition);
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr!");

    AbsRdbPredicates predicates = AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::MEDIA_FILE_PATH, path);
    ValuesBucket values;
    values.PutLong(PhotoColumn::PHOTO_COVER_POSITION, coverPosition);
    values.PutInt(PhotoColumn::PHOTO_IS_RECTIFICATION_COVER, 1);

    int32_t changeRows = -1;
    int32_t ret = rdbStore->Update(changeRows, values, predicates);
    CHECK_AND_PRINT_LOG(ret == E_OK, "execute update cover_position failed, ret = %{public}d", ret);
}

void CoverPositionParser::SendUpdateNotify(const string &fileUri)
{
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("Can not get MediaLibraryNotify, fail to send new asset notify.");
        return;
    }
    watch->Notify(fileUri, NotifyType::NOTIFY_UPDATE);
}
} // namespace Media
} // namespace OHOS