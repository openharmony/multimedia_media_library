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
#ifndef OHOS_FILEMGMT_MEDIA_GALLERY_SYNC_NOTIFI_H
#define OHOS_FILEMGMT_MEDIA_GALLERY_SYNC_NOTIFI_H

#include <list>
#include <memory>
#include <mutex>

#include "dataobs_mgr_client.h"
#include "uri.h"

namespace OHOS::Media::CloudSync {

enum NotifyTaskType : uint32_t {
    NOTIFY_BEGIN,
    NOTIFY_END
};

enum NotifySyncType : uint32_t {
    NOTIFY_FULL_SYNC,
    NOTIFY_INCREMENTAL_SYNC
};

class MediaGallerySyncNotify : public NoCopyable {
using ChangeType = AAFwk::ChangeInfo::ChangeType;

public:
    ~MediaGallerySyncNotify() = default;

public:
    static MediaGallerySyncNotify &GetInstance();
    int32_t AddNotify(const std::string &uri, const ChangeType changeType, const std::string &fileAssetId);
    int32_t TryNotify(const std::string &uri, const ChangeType changeType, const std::string &fileAssetId);
    int32_t NotifyProgress(NotifyTaskType taskType, const std::string &syncId, NotifySyncType syncType,
        uint32_t totalAlbums = 0, uint32_t totalAssets = 0);
    int32_t FinalNotify();
    void NotifyProgressBegin();
    void NotifyProgressEnd();

public:
    static std::unordered_map<ChangeType, std::list<Uri>> notifyListMap_;
    static int32_t recordAdded_;
    static std::mutex mtx_;

private:
    MediaGallerySyncNotify() = default;
    std::string syncId_;
};
}
#endif // OHOS_FILEMGMT_MEDIA_GALLERY_SYNC_NOTIFI_H