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

#ifndef FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUD_SYNC_NOTIFY_HANDLER_H
#define FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUD_SYNC_NOTIFY_HANDLER_H

#include "datashare_helper.h"
#include "cloud_sync_observer.h"
#include "medialibrary_type_const.h"

namespace OHOS {
namespace Media {

#define EXPORT __attribute__ ((visibility ("default")))

/**
 * @brief 云同步状态枚举
 */
enum CloudSyncStatus : int32_t {
    BEGIN = 0,                                   // 退出华为账号
    FIRST_FIVE_HUNDRED,                          // 端云下行前500张
    INCREMENT_DOWNLOAD,                          // 增量任务
    TOTAL_DOWNLOAD,                              // 全量任务
    TOTAL_DOWNLOAD_FINISH,                       // 全量下行云缩略图任务结束
    SYNC_SWITCHED_OFF,                           // 关闭同步开关
    CLOUD_CLEANING,                              // 关云退云场景清理本地的云数据
};

const std::string CLOUDSYNC_STATUS_KEY = "persist.kernel.cloudsync.status";

class CloudSyncNotifyHandler {
public:
    CloudSyncNotifyHandler(const CloudSyncNotifyInfo &info):notifyInfo_(info) {};
    ~CloudSyncNotifyHandler() = default;
    
    EXPORT void MakeResponsibilityChain();
    void ThumbnailObserverOnChange(const std::list<Uri> &uris, const DataShare::DataShareObserver::ChangeType &type);

    CloudSyncNotifyInfo notifyInfo_;

private:
    static std::string GetfileIdFromPastDirtyDataFixUri(std::string uriString);
    static int32_t QueryFilePathFromFileId(const std::string &id, std::string &filePath);
    static int32_t QueryAlbumLpathFromFileId(const std::string &id, std::string &lpath);
    void HandleInsertEvent(const std::list<Uri> &uris);
    void HandleDeleteEvent(const std::list<Uri> &uris);
    void HandleTimeUpdateEvent(const std::list<Uri> &uris);
    void HandleExtraEvent(const std::list<Uri> &uris, const DataShare::DataShareObserver::ChangeType &type);
    EXPORT void HandleDirtyDataFix(const std::list<Uri> &uris, const CloudSyncErrType &type);
    void HandleContentNotFound(const std::list<Uri> &uris);
    void HandleThumbnailNotFound(const std::list<Uri> &uris);
    void HandleLCDNotFound(const std::list<Uri> &uris);
    void HandleLCDSizeTooLarge(const std::list<Uri> &uris);
    void HandleContentSizeIsZero(const std::list<Uri> &uris);
    void HandleAlbumNotFound(const std::list<Uri> &uris);
    void HandleThumbnailGenerateFailed(const std::list<Uri> &uris);
};
} //namespace Media
} //namespace OHOS

#endif //FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_CLOUD_SYNC_NOTIFY_HANDLER_H
