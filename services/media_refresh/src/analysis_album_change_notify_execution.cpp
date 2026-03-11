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

#define MLOG_TAG "AccurateRefresh::AlbumChangeNotifyExecution"

#include "analysis_album_change_notify_execution.h"

#include "accurate_common_data.h"
#include "accurate_debug_log.h"
#include "medialibrary_notify_new.h"
#include "notify_info_inner.h"

using namespace std;
using namespace OHOS::Media::Notification;

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

void AnalysisAlbumChangeNotifyExecution::Notify(vector<AlbumChangeData> &changeDatas)
{
    albumNotifyInfos_.clear();
    for (auto &changeData : changeDatas) {
        if (changeData.operation_ == RDB_OPERATION_ADD) {
            changeData.infoBeforeChange_ = AlbumChangeInfo();
            InsertNotifyInfo(ANALYSIS_ALBUM_OPERATION_ADD, changeData);
        } else if (changeData.operation_ == RDB_OPERATION_REMOVE) {
            changeData.infoAfterChange_ = AlbumChangeInfo();
            changeData.isDelete_ = true;
            InsertNotifyInfo(ANALYSIS_ALBUM_OPERATION_REMOVE, changeData);
        } else if (changeData.operation_ == RDB_OPERATION_UPDATE) {
            CHECK_AND_CONTINUE(changeData.IsAlbumInfoChange());
            InsertNotifyInfo(ANALYSIS_ALBUM_OPERATION_UPDATE, changeData);
        }
    }
    AddAlbumInfosToNewNotify();
}

void AnalysisAlbumChangeNotifyExecution::InsertNotifyInfo(AlbumRefreshOperation operation,
    const AlbumChangeData &changeData)
{
    AlbumChangeData albumChangeData = changeData;
    ACCURATE_DEBUG("origin data: %{public}s", changeData.ToString(true).c_str());
    if (operation == ANALYSIS_ALBUM_OPERATION_ADD) {
        ACCURATE_DEBUG("modify add data: %{public}s", albumChangeData.ToString(true).c_str());
    } else if (operation == ANALYSIS_ALBUM_OPERATION_REMOVE) {
        ACCURATE_DEBUG("modify remove data: %{public}s", albumChangeData.ToString(true).c_str());
    }
    auto &vec = albumNotifyInfos_.try_emplace(operation, std::vector<AlbumChangeData>{}).first->second;
    vec.push_back(albumChangeData);
}

void AnalysisAlbumChangeNotifyExecution::AddAlbumInfosToNewNotify()
{
    for (auto &item : albumNotifyInfos_) {
        NotifyInfoInner notifyInfo;
        notifyInfo.tableType = NotifyTableType::ANALYSIS_ALBUM;
        notifyInfo.operationType = item.first;
        NotifyLevel level;
        notifyInfo.notifyLevel = level;
        auto &changeDatas = item.second;
        for (auto &changeData : changeDatas) {
            notifyInfo.infos.push_back(changeData);
            ACCURATE_INFO("notify ANALYSIS ALBUM info: operType(0x%{public}x), level(%{public}d), info(%{public}s)",
                static_cast<int32_t>(item.first),
                static_cast<int32_t>(notifyInfo.notifyLevel.priority), changeData.ToString().c_str());
        }
        // 调用发送通知接口
        Notification::MediaLibraryNotifyNew::AddItem(notifyInfo);
    }
}

void AnalysisAlbumChangeNotifyExecution::HandleUpdateNotify(PhotoAssetChangeData &changeData)
{
    auto &infoBefore = changeData.infoBeforeChange_;
    auto &infoAfter = changeData.infoAfterChange_;

    size_t sizeBefore = infoBefore.albumChangeInfos_.size();
    size_t sizeAfter = infoAfter.albumChangeInfos_.size();
    if (sizeBefore == 0 && sizeAfter == 0) {
        return;
    }

    if (sizeBefore == 0) {
        infoBefore = PhotoAssetChangeInfo();
        InsertNotifyInfo(ASSET_OPERATION_ADD_WITH_ANALYSIS, changeData);
    } else if (sizeAfter == 0) {
        infoAfter = PhotoAssetChangeInfo();
        InsertNotifyInfo(ASSET_OPERATION_REMOVE_WITH_ANALYSIS, changeData);
    } else {
        InsertNotifyInfo(ASSET_OPERATION_UPDATE_WITH_ANALYSIS, changeData);
    }
}


void AnalysisAlbumChangeNotifyExecution::Notify(vector<PhotoAssetChangeData> &changeDatas)
{
    assetNotifyInfos_.clear();
    for (auto &changeData : changeDatas) {
        auto &infoBefore = changeData.infoBeforeChange_;
        auto &infoAfter = changeData.infoAfterChange_;
        auto rdbOperation = changeData.operation_;
        switch (rdbOperation) {
            case RDB_OPERATION_ADD:
                infoBefore = PhotoAssetChangeInfo();
                InsertNotifyInfo(ASSET_OPERATION_ADD_WITH_ANALYSIS, changeData);
                break;
            case RDB_OPERATION_REMOVE:
                infoAfter = PhotoAssetChangeInfo();
                InsertNotifyInfo(ASSET_OPERATION_REMOVE_WITH_ANALYSIS, changeData);
                break;
            case RDB_OPERATION_ADD_ANALYSIS:
                infoBefore = PhotoAssetChangeInfo();
                InsertNotifyInfo(ANALYSIS_ASSET_OPERATION_ADD, changeData);
                break;
            case RDB_OPERATION_REMOVE_ANALYSIS:
                infoAfter = PhotoAssetChangeInfo();
                InsertNotifyInfo(ANALYSIS_ASSET_OPERATION_REMOVE, changeData);
                break;
            case RDB_OPERATION_UPDATE:
                HandleUpdateNotify(changeData);
                break;
            default:
                break;
        }
    }
    AddAssetInfosToNewNotify();
}

void AnalysisAlbumChangeNotifyExecution::AddAssetInfosToNewNotify()
{
    for (auto &item : assetNotifyInfos_) {
        NotifyInfoInner notifyInfo;
        notifyInfo.tableType = NotifyTableType::PHOTOS;
        notifyInfo.operationType = item.first;
        NotifyLevel level;
        notifyInfo.notifyLevel = level;
        auto &changeDatas = item.second;
        for (auto &changeData : changeDatas) {
            notifyInfo.infos.push_back(changeData);
            ACCURATE_INFO("notify ANALYSIS PHOTO info: operType(0x%{public}x), level(%{public}d), info(%{public}s)",
                static_cast<int32_t>(item.first), static_cast<int32_t>(notifyInfo.notifyLevel.priority),
                changeData.ToString().c_str());
        }
        // 调用发送通知接口
        Notification::MediaLibraryNotifyNew::AddItem(notifyInfo);
    }
}

void AnalysisAlbumChangeNotifyExecution::InsertNotifyInfo(AssetRefreshOperation operation,
    const PhotoAssetChangeData &changeData)
{
    auto &vec = assetNotifyInfos_.try_emplace(operation, std::vector<PhotoAssetChangeData>{}).first->second;
    vec.push_back(changeData);
}

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
