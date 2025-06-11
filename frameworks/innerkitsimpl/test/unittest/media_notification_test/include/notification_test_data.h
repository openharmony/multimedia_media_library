/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MEDIALIBRARY_NOTIFICATION_TEST_DATA_H
#define MEDIALIBRARY_NOTIFICATION_TEST_DATA_H

#include "photo_asset_change_info.h"
#include "album_change_info.h"
#include "media_change_info.h"
#include "notify_info.h"
#include "media_datashare_stub_impl.h"
#include "notify_info_inner.h"
#include "notify_task_worker.h"

namespace OHOS {
namespace Media {
namespace Notification {
    extern const AccurateRefresh::PhotoAssetChangeData deletePhotoData1;
    extern const AccurateRefresh::PhotoAssetChangeData deletePhotoData2;
    extern const AccurateRefresh::AlbumChangeData albumChangeData1;
    extern const AccurateRefresh::AlbumChangeData albumChangeData2;
    extern const AccurateRefresh::AlbumChangeData albumChangeData3;
class NotificationTestData {
public:
    static std::vector<Notification::MediaChangeInfo> getPhotoChangeInfos(
        const Notification::NotifyUriType& notifyUriType,
        const Notification::NotifyType& notifyType,  bool isForRecheck);
    static std::vector<Notification::MediaChangeInfo> getPhotnChangeInfosByUriType(
        const Notification::NotifyUriType& notifyUriType, bool isForRecheck);
    static std::vector<Notification::MediaChangeInfo> getAlbumChangeInfos(
        const Notification::NotifyUriType& notifyUriType,
        const Notification::NotifyType& notifyType, bool isForRecheck);
    static std::vector<Notification::MediaChangeInfo> getAlbumChangeInfosByUriType(
        const Notification::NotifyUriType& notifyUriType, bool isForRecheck);
    static std::vector<Notification::NotifyInfo> buildAssetsNotifyInfo(const std::string &testName);
    static std::vector<Notification::MediaChangeInfo> buildAssetsMediaChangeInfo();
    static std::vector<NotifyInfoInner> buildPhotoNotifyTaskInfo(NotifyTableType tableType,
        std::vector<AccurateRefresh::PhotoAssetChangeData> infos,
        Notification::AssetRefreshOperation operationType, NotifyLevel notifyLevel);
    static std::vector<NotifyInfoInner> buildAlbumNotifyTaskInfo(NotifyTableType tableType,
        std::vector<AccurateRefresh::AlbumChangeData> infos,
        Notification::AlbumRefreshOperation operationType, NotifyLevel notifyLevel);
};
} // namespace Notification
} // namespace Media
} // namespace OHOS

#endif