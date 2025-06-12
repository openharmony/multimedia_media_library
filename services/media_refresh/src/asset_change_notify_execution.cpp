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

#define MLOG_TAG "AccurateRefresh::AssetChangeNotifyExecution"
#include "asset_change_notify_execution.h"

#include "trash_asset_helper.h"
#include "hidden_asset_helper.h"
#include "accurate_debug_log.h"
#include "medialibrary_notify_new.h"

namespace OHOS {
namespace Media::AccurateRefresh {
using namespace std;
using namespace OHOS::Media::Notification;

const std::vector<std::pair<std::function<bool(std::pair<AssetType, AssetType>)>, Notification::AssetRefreshOperation>>
    NORMAL_ASSET_OPERATION_CALS = {
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return info.first != ASSET_NORMAL && info.second == ASSET_NORMAL;
        },
        Notification::ASSET_OPERATION_UPDATE_ADD_NORMAL
    },
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return info.first == ASSET_NORMAL && info.second != ASSET_NORMAL;
        },
        Notification::ASSET_OPERATION_UPDATE_REMOVE_NORMAL
    },
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return info.first == ASSET_NORMAL && info.second == ASSET_NORMAL;
        },
        Notification::ASSET_OPERATION_UPDATE_NORMAL
    },
};
const std::vector<std::pair<std::function<bool(std::pair<AssetType, AssetType>)>, Notification::AssetRefreshOperation>>
    HIDDEN_ASSET_OPERATION_CALS = {
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return info.first != ASSET_HIDDEN && info.second == ASSET_HIDDEN;
        },
        Notification::ASSET_OPERATION_UPDATE_ADD_HIDDEN
    },
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return info.first == ASSET_HIDDEN && info.second != ASSET_HIDDEN;
        },
        Notification::ASSET_OPERATION_UPDATE_REMOVE_HIDDEN
    },
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return info.first == ASSET_HIDDEN && info.second == ASSET_HIDDEN;
        },
        Notification::ASSET_OPERATION_UPDATE_HIDDEN
    },
};
const std::vector<std::pair<std::function<bool(std::pair<AssetType, AssetType>)>, Notification::AssetRefreshOperation>>
    TRASH_ASSET_OPERATION_CALS = {
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return (info.first & ASSET_TRASH) != ASSET_TRASH && (info.second & ASSET_TRASH) == ASSET_TRASH;
        },
        Notification::ASSET_OPERATION_UPDATE_ADD_TRASH
    },
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return (info.first & ASSET_TRASH) == ASSET_TRASH && (info.second & ASSET_TRASH) != ASSET_TRASH;
        },
        Notification::ASSET_OPERATION_UPDATE_REMOVE_TRASH
    },
    {
        [](std::pair<AssetType, AssetType> info) -> bool {
            return (info.first & ASSET_TRASH) == ASSET_TRASH && (info.second & ASSET_TRASH) == ASSET_TRASH;
        },
        Notification::ASSET_OPERATION_UPDATE_TRASH
    },
};

void AssetChangeNotifyExecution::Notify(vector<PhotoAssetChangeData> changeDatas)
{
    // 轮询所有的changeDatas
    for (auto &changeData : changeDatas) {
        auto &infoBefore = changeData.infoBeforeChange_;
        auto &infoAfter = changeData.infoAfterChange_;
        auto rdbOperation = changeData.operation_;
        if (rdbOperation == RDB_OPERATION_ADD) {
            AssetRefreshOperation operateionType = GetAddOperation(infoAfter);
            if (operateionType != ASSET_OPERATION_UNDEFINED) {
                InsertNotifyInfo(operateionType, changeData);
            } else {
                MEDIA_WARN_LOG("invalid after asset info:%{public}s", infoAfter.ToString().c_str());
            }
        } else if (rdbOperation == RDB_OPERATION_REMOVE) {
            AssetRefreshOperation operateionType = GetRemoveOperation(infoBefore);
            if (operateionType != ASSET_OPERATION_UNDEFINED) {
                InsertNotifyInfo(operateionType, changeData);
            } else {
                MEDIA_WARN_LOG("invalid before asset info:%{public}s", infoBefore.ToString().c_str());
            }
        } else if (rdbOperation == RDB_OPERATION_UPDATE) {
            InsertNormalAssetOperation(changeData);
            InsertTrashAssetOperation(changeData);
            InsertHiddenlAssetOperation(changeData);
        }
    }

    for (auto &item : notifyInfos_) {
        NotifyInfoInner notifyInfo;
        notifyInfo.tableType = NotifyTableType::PHOTOS;
        notifyInfo.operationType = item.first;
        NotifyLevel level;
        notifyInfo.notifyLevel = level;
        auto &changeDatas = item.second;
        for (auto &changeData : changeDatas) {
            notifyInfo.infos.push_back(changeData);
            ACCURATE_INFO("notify PHOTOS info: operationType(0x%{public}x), level(%{public}d), info(%{public}s)",
                static_cast<int32_t>(item.first),
                static_cast<int32_t>(notifyInfo.notifyLevel.priority), changeData.ToString().c_str());
        }
        // 调用发送通知接口
        Notification::MediaLibraryNotifyNew::AddItem(notifyInfo);
    }
}

void AssetChangeNotifyExecution::InsertNotifyInfo(AssetRefreshOperation operateionType,
    const PhotoAssetChangeData &changeData)
{
    auto iter = notifyInfos_.find(operateionType);
    if (iter == notifyInfos_.end()) {
        vector<PhotoAssetChangeData> infos;
        infos.push_back(changeData);
        notifyInfos_.emplace(operateionType, infos);
    } else {
        auto &infos = iter->second;
        infos.push_back(changeData);
    }
}

AssetRefreshOperation AssetChangeNotifyExecution::GetAddOperation(const PhotoAssetChangeInfo &changeInfo)
{
    if (TrashAssetHelper::IsAsset(changeInfo)) {
        return ASSET_OPERATION_ADD_TRASH;
    }
    if (HiddenAssetHelper::IsAsset(changeInfo)) {
        return ASSET_OPERATION_ADD_HIDDEN;
    }
    if (AlbumAssetHelper::IsCommonSystemAsset(changeInfo)) {
        return ASSET_OPERATION_ADD;
    }
    return ASSET_OPERATION_UNDEFINED;
}

AssetRefreshOperation AssetChangeNotifyExecution::GetRemoveOperation(const PhotoAssetChangeInfo &changeInfo)
{
    if (TrashAssetHelper::IsAsset(changeInfo)) {
        return ASSET_OPERATION_REMOVE_TRASH;
    }
    if (HiddenAssetHelper::IsAsset(changeInfo)) {
        return ASSET_OPERATION_REMOVE_HIDDEN;
    }
    if (AlbumAssetHelper::IsCommonSystemAsset(changeInfo)) {
        return ASSET_OPERATION_REMOVE;
    }
    return ASSET_OPERATION_UNDEFINED;
}

void AssetChangeNotifyExecution::InsertNormalAssetOperation(const PhotoAssetChangeData &changeData)
{
    AssetType before =
        AlbumAssetHelper::IsCommonSystemAsset(changeData.infoBeforeChange_) ? ASSET_NORMAL : ASSET_INVALID;
    AssetType after =
        AlbumAssetHelper::IsCommonSystemAsset(changeData.infoAfterChange_) ? ASSET_NORMAL : ASSET_INVALID;
    ACCURATE_DEBUG("before: 0x%{public}x, after: 0x%{public}x", static_cast<int32_t>(before),
        static_cast<int32_t>(after));
    for (auto &operationCal : NORMAL_ASSET_OPERATION_CALS) {
        if (operationCal.first({before, after})) {
            InsertNotifyInfo(operationCal.second, changeData);
            ACCURATE_DEBUG("insert normal operation: %{public}x", operationCal.second);
        }
    }
}

void AssetChangeNotifyExecution::InsertTrashAssetOperation(const PhotoAssetChangeData &changeData)
{
    AssetType before = TrashAssetHelper::IsAsset(changeData.infoBeforeChange_) ? ASSET_TRASH : ASSET_INVALID;
    AssetType after = TrashAssetHelper::IsAsset(changeData.infoAfterChange_) ? ASSET_TRASH : ASSET_INVALID;
    ACCURATE_DEBUG("before: 0x%{public}x, after: 0x%{public}x", static_cast<int32_t>(before),
        static_cast<int32_t>(after));
    for (auto &operationCal : TRASH_ASSET_OPERATION_CALS) {
        if (operationCal.first({before, after})) {
            InsertNotifyInfo(operationCal.second, changeData);
            ACCURATE_DEBUG("insert trash operation: %{public}x", operationCal.second);
        }
    }
}

void AssetChangeNotifyExecution::InsertHiddenlAssetOperation(const PhotoAssetChangeData &changeData)
{
    AssetType before = HiddenAssetHelper::IsAsset(changeData.infoBeforeChange_) ? ASSET_HIDDEN : ASSET_INVALID;
    AssetType after = HiddenAssetHelper::IsAsset(changeData.infoAfterChange_) ? ASSET_HIDDEN : ASSET_INVALID;
    ACCURATE_DEBUG("before: 0x%{public}x, after: 0x%{public}x", static_cast<int32_t>(before),
        static_cast<int32_t>(after));
    for (auto &operationCal : HIDDEN_ASSET_OPERATION_CALS) {
        if (operationCal.first({before, after})) {
            InsertNotifyInfo(operationCal.second, changeData);
            ACCURATE_DEBUG("insert hidden operation: %{public}x", operationCal.second);
        }
    }
}

} // namespace Media
} // namespace OHOS