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

#ifndef OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_CHANGE_NOTIFY_EXECUTION_H
#define OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_CHANGE_NOTIFY_EXECUTION_H

#include <unordered_map>
#include <vector>

#include "album_change_info.h"
#include "notify_info_inner.h"
#include "photo_asset_change_info.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

class AnalysisAlbumChangeNotifyExecution {
public:
    AnalysisAlbumChangeNotifyExecution() = default;
    ~AnalysisAlbumChangeNotifyExecution() = default;

    // 智慧相册（ANALYSIS_ALBUM）表的增删改通知
    void Notify(std::vector<AlbumChangeData> &changeDatas);

    // 资产对智慧相册映射关系（albumChangeInfos_）的变化通知
    void Notify(std::vector<PhotoAssetChangeData> &changeDatas);

private:
    void InsertNotifyInfo(Notification::AlbumRefreshOperation operation,
        const AlbumChangeData &changeData);
    void AddAlbumInfosToNewNotify();

    void InsertNotifyInfo(Notification::AssetRefreshOperation operation,
        const PhotoAssetChangeData &changeData);
    void AddAssetInfosToNewNotify();

    void HandleUpdateNotify(PhotoAssetChangeData &changeData);

private:
    std::unordered_map<Notification::AlbumRefreshOperation,
        std::vector<AlbumChangeData>> albumNotifyInfos_;

    std::unordered_map<Notification::AssetRefreshOperation,
        std::vector<PhotoAssetChangeData>> assetNotifyInfos_;
};

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_CHANGE_NOTIFY_EXECUTION_H
