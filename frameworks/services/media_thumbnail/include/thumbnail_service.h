/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_SERVICE_H
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_SERVICE_H

#include <mutex>

#include "ability_context.h"
#include "media_file_uri.h"
#include "medialibrary_rdbstore.h"
#include "pixel_map.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "result_set_bridge.h"
#include "single_kvstore.h"
#include "userfile_manager_types.h"
#include "thumbnail_const.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class ThumbnailService {
public:
    EXPORT virtual ~ThumbnailService() = default;
    EXPORT static std::shared_ptr<ThumbnailService> GetInstance();
    EXPORT void ReleaseService();

    EXPORT int GetThumbnailFd(const std::string &uri, bool isAstc = false);
    EXPORT int32_t LcdAging();
#ifdef DISTRIBUTED
    EXPORT int32_t LcdDistributeAging(const std::string &udid);
#endif
    EXPORT int32_t GenerateThumbnailBackground();
    EXPORT int32_t UpgradeThumbnailBackground(bool isWifiConnected);
    EXPORT int32_t RestoreThumbnailDualFrame();
    EXPORT void InterruptBgworker();
    EXPORT void StopAllWorker();
#ifdef DISTRIBUTED
    EXPORT int32_t InvalidateDistributeThumbnail(const std::string &udid);
#endif
    EXPORT int32_t CreateThumbnailFileScaned(const std::string &uri, const std::string &path,
        bool isSync = false);
    bool HasInvalidateThumbnail(const std::string &id, const std::string &tableName,
        const std::string &path = "", const std::string &dateTaken = "");
    EXPORT int32_t CreateThumbnailPastDirtyDataFix(const std::string &fileId);
    EXPORT int32_t CreateLcdPastDirtyDataFix(const std::string &fileId, const uint8_t quality = THUMBNAIL_MID);
    EXPORT void Init(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
#ifdef DISTRIBUTED
        const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore,
#endif
        const std::shared_ptr<OHOS::AbilityRuntime::Context> &context);
    int32_t GetAgingDataSize(const int64_t &time, int &count);
    int32_t QueryNewThumbnailCount(const int64_t &time, int &count);
    void DeleteAstcWithFileIdAndDateTaken(const std::string &fileId, const std::string &dateTaken);
    int32_t CreateAstcCloudDownload(const std::string &id, bool isCloudInsertTaskPriorityHigh = false);
    EXPORT int32_t CreateAstcBatchOnDemand(NativeRdb::RdbPredicates &rdbPredicate, int32_t requestId);
    EXPORT void CancelAstcBatchTask(int32_t requestId);
    void UpdateAstcWithNewDateTaken(const std::string &fileId, const std::string &newDateTaken,
        const std::string &formerDateTaken);
    EXPORT int32_t CheckCloudThumbnailDownloadFinish();
    EXPORT void AstcChangeKeyFromDateAddedToDateTaken();
    EXPORT void UpdateCurrentStatusForTask(const bool &currentStatusForTask);
    EXPORT bool GetCurrentStatusForTask();
    EXPORT void NotifyTempStatusForReady(const int32_t &currentTemperatureLevel);
    EXPORT int32_t GetCurrentTemperatureLevel();
    EXPORT void CheckLcdSizeAndUpdateStatus();
private:
    EXPORT ThumbnailService();
    bool CheckSizeValid();
    int32_t ParseThumbnailParam(const std::string &uri, std::string &fileId, std::string &networkId,
        std::string &tableName);
    int GetThumbFd(const std::string &path, const std::string &table, const std::string &id,
        const std::string &uri, const Size &size, bool isAstc = false);
    static std::shared_ptr<ThumbnailService> thumbnailServiceInstance_;
    static std::mutex instanceLock_;
#ifdef DISTRIBUTED
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
#endif
    std::shared_ptr<MediaLibraryRdbStore> rdbStorePtr_;
    std::shared_ptr<OHOS::AbilityRuntime::Context> context_;
    std::shared_ptr<NativeRdb::RdbPredicates> rdbPredicatePtr_;
    Size screenSize_;
    int32_t currentRequestId_ = 0;
    int32_t currentTemperatureLevel_ = 0;
    bool isScreenSizeInit_ = false;
    bool currentStatusForTask_ = false;
    bool isTemperatureHighForReady_ = false;
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_SERVICE_H
