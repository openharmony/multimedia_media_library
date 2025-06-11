/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "AccurateRefresh::ALbumChangeNotifyExecution"

#include "album_change_notify_execution.h"
#include "accurate_debug_log.h"
#include "medialibrary_notify_new.h"

using namespace std;
using namespace OHOS::Media::Notification;
namespace OHOS {
namespace Media::AccurateRefresh {

void ALbumChangeNotifyExecution::Notify(vector<AlbumChangeData> changeDatas)
{
    for (auto &changeData : changeDatas) {
        if (changeData.operation_ == RDB_OPERATION_ADD) {
            InsertNotifyInfo(ALBUM_OPERATION_ADD, changeData);
        } else if (changeData.operation_ == RDB_OPERATION_REMOVE) {
            InsertNotifyInfo(ALBUM_OPERATION_REMOVE, changeData);
        } else if (changeData.operation_ == RDB_OPERATION_UPDATE) {
            auto subType = changeData.infoAfterChange_.albumSubType_;
            // 隐藏相册
            if (subType == static_cast<int32_t>(PhotoAlbumSubType::HIDDEN)) {
                InsertNotifyInfo(ALBUM_OPERATION_UPDATE_HIDDEN, changeData);
                continue;
            }
            // 回收站相册
            if (subType == static_cast<int32_t>(PhotoAlbumSubType::TRASH)) {
                InsertNotifyInfo(ALBUM_OPERATION_UPDATE_TRASH, changeData);
                continue;
            }

            // TOBE 确认逻辑
            bool isDelete = changeData.infoAfterChange_.dirty_ == static_cast<int32_t>(DirtyType::TYPE_DELETED) &&
                changeData.infoBeforeChange_.dirty_ != static_cast<int32_t>(DirtyType::TYPE_DELETED);
            if (isDelete) {
                changeData.isDelete_ = true;
                InsertNotifyInfo(ALBUM_OPERATION_REMOVE, changeData);
                continue;
            }
            InsertNotifyInfo(ALBUM_OPERATION_UPDATE, changeData);
        }
    }

    for (auto &item : notifyInfos_) {
        NotifyInfoInner notifyInfo;
        notifyInfo.tableType = NotifyTableType::PHOTO_ALBUM;
        notifyInfo.operationType = item.first;
        NotifyLevel level;
        notifyInfo.notifyLevel = level;
        auto &changeDatas = item.second;
        for (auto &changeData : changeDatas) {
            notifyInfo.infos.push_back(changeData);
            ACCURATE_INFO("notify PHOTO_ALBUM info: operationType(0x%{public}x), level(%{public}d), info(%{public}s)",
                static_cast<int32_t>(item.first),
                static_cast<int32_t>(notifyInfo.notifyLevel.priority), changeData.ToString().c_str());
        }
        // 调用发送通知接口
        Notification::MediaLibraryNotifyNew::AddItem(notifyInfo);
    }
}

void ALbumChangeNotifyExecution::InsertNotifyInfo(AlbumRefreshOperation operation, const AlbumChangeData &changeData)
{
    auto iter = notifyInfos_.find(operation);
    if (iter == notifyInfos_.end()) {
        vector<AlbumChangeData> infos;
        infos.push_back(changeData);
        notifyInfos_.emplace(operation, infos);
        return;
    } else {
        auto &infos = iter->second;
        infos.push_back(changeData);
    }
}

} // namespace Media
} // namespace OHOS