/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_ITHUMBNAIL_HELPER_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_ITHUMBNAIL_HELPER_H_

#include <map>
#include <memory>
#include <shared_mutex>

#include "ability_connect_callback_stub.h"
#include "ability_context.h"
#include "datashare_proxy.h"
#include "datashare_values_bucket.h"
#include "medialibrary_sync_operation.h"
#include "result_set_bridge.h"
#include "thumbnail_const.h"
#include "thumbnail_generate_worker.h"
#include "thumbnail_utils.h"
#include "pixel_map.h"

namespace OHOS {
namespace Media {
enum WaitStatus {
    INSERT,
    WAIT_SUCCESS,
    WAIT_FAILED,
    TIMEOUT,
};

class ThumbnailSyncStatus {
public:
    std::condition_variable cond_;
    std::mutex mtx_;
    bool isSyncComplete_{false};
    bool isCreateThumbnailSuccess_{false};
};

using ThumbnailMap = std::map<std::string, std::shared_ptr<ThumbnailSyncStatus>>;
class ThumbnailWait {
public:
    ThumbnailWait(bool release);
    ~ThumbnailWait();

    WaitStatus InsertAndWait(const std::string &id, bool isLcd);
    void CheckAndWait(const std::string &id, bool isLcd);
    void UpdateThumbnailMap();

private:
    void Notify();
    std::string id_;
    bool needRelease_{false};
    static ThumbnailMap thumbnailMap_;
    static std::shared_mutex mutex_;
};

class IThumbnailHelper {
public:
    IThumbnailHelper() = default;
    virtual ~IThumbnailHelper() = default;
    static void CreateThumbnails(std::shared_ptr<ThumbnailTaskData> &data);
    static bool DoCreateThumbnails(ThumbRdbOpt &opts, ThumbnailData &data);
    static void CreateLcd(std::shared_ptr<ThumbnailTaskData> &data);
    static void CreateThumbnail(std::shared_ptr<ThumbnailTaskData> &data);
    static void CreateAstc(std::shared_ptr<ThumbnailTaskData> &data);
    static void AddThumbnailGenerateTask(ThumbnailGenerateExecute executor, ThumbRdbOpt &opts, ThumbnailData &thumbData,
        const ThumbnailTaskType &taskType, const ThumbnailTaskPriority &priority);
    static std::unique_ptr<PixelMap> GetPixelMap(const std::vector<uint8_t> &image, Size &size);
    static bool DoCreateLcd(ThumbRdbOpt &opts, ThumbnailData &data);
    static bool DoCreateThumbnail(ThumbRdbOpt &opts, ThumbnailData &data);
    static bool DoCreateAstc(ThumbRdbOpt &opts, ThumbnailData &data);
    static bool IsPureCloudImage(ThumbRdbOpt &opts);
private:
    static bool GenThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, const ThumbnailType type);
    static bool TryLoadSource(ThumbRdbOpt &opts, ThumbnailData &data);
    static bool GenMonthAndYearAstcData(ThumbnailData &data, const ThumbnailType type);
    static bool UpdateThumbnailState(const ThumbRdbOpt &opts, const ThumbnailData &data);
    static int32_t UpdateAstcState(const ThumbRdbOpt &opts, const ThumbnailData &data);
    static bool IsCreateThumbnailSuccess(ThumbRdbOpt &opts, ThumbnailData &data);
    static bool IsCreateLcdSuccess(ThumbRdbOpt &opts, ThumbnailData &data);
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_ITHUMBNAIL_HELPER_H_
