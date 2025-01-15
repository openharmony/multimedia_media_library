/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_MEDIA_ALBUMS_REFRESH_INCLUDE_ALBUMS_REFRESH_NOTIFY_H
#define FRAMEWORKS_SERVICES_MEDIA_ALBUMS_REFRESH_INCLUDE_ALBUMS_REFRESH_NOTIFY_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <list>

#include "userfile_manager_types.h"
#include "uri.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
enum class ForceRefreshType {
    NONE = 0,
    CYCLE,
    EXCEPTION
};

static const uint8_t ALBUM_URI_TYPE = 0;
static const uint8_t PHOTO_URI_TYPE = 1;

struct SyncNotifyInfo {
    uint16_t taskType;      // 任务类型，0表示开始，1表示结束
    uint16_t syncType;      // 同步类型，0表示全量同步，1表示增量同步
    NotifyType notifyType;  // 对应ChangeType的类型
    uint32_t syncId;        // 唯一标识一次端云同步id
    uint32_t totalAssets;   // 资产个数，获取uris的总个数
    uint32_t totalAlbums;   // 保留字段
    uint8_t uriType;        // 标识当前是资产通知(PHOTO_URI_TYPE)还是相册通知(ALBUM_URI_TYPE)
    uint8_t reserve;        // 保留字段
    uint16_t urisSize;      // uris的size大小， add最多150，delete/remove最多50
    std::list<Uri> uris;         // 原始ChangeInfo里面的uris
    std::list<Uri> extraUris;    // 相册列表，填充更新相册
    std::unordered_set<std::string> uriIds; // id，不做cloudId和fieldId区分
    bool notifyAssets;
    bool notifyAlbums;
    int32_t refershResult;
    ForceRefreshType forceRefreshType = ForceRefreshType::NONE;
};

class AlbumsRefreshNotify {
public:
    AlbumsRefreshNotify();
    ~AlbumsRefreshNotify();

    static void SendBatchUris(const NotifyType type, std::list<Uri> &uris, std::list<Uri> &extraUris);
    static void SendBatchUris(const NotifyType type, std::list<Uri> &uris);
};
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_ALBUMS_REFRESH_INCLUDE_ALBUMS_REFRESH_NOTIFY_H