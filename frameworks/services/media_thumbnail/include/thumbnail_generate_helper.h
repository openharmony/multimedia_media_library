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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_HELPER_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_HELPER_H_

#include "cloud_sync_manager.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "single_kvstore.h"
#include "thumbnail_utils.h"

namespace OHOS {
namespace Media {
enum DownloadFileType {
    TYPE_CONTENT = 1 << 0,
    TYPE_THUMB = 1 << 1,
    TYPE_LCD = 1 << 2,
};

using namespace OHOS::FileManagement::CloudSync;
class ThumbnailCloudDownloadCallback : public CloudDownloadCallback {
public:
    virtual ~ThumbnailCloudDownloadCallback() override = default;
    void OnDownloadProcess(const DownloadProgressObj &progress) override;
};

class ThumbnailGenerateHelper {
public:
    ThumbnailGenerateHelper() = delete;
    virtual ~ThumbnailGenerateHelper() = delete;
    EXPORT static int32_t CreateThumbnailFileScaned(ThumbRdbOpt &opts, bool isSync);
    EXPORT static int32_t CreateThumbnailBackground(ThumbRdbOpt &opts);
    EXPORT static int32_t CreateAstcBackground(ThumbRdbOpt &opts);
    EXPORT static int32_t CreateAstcCloudDownload(ThumbRdbOpt &opts, bool isCloudInsertTaskPriorityHigh = false);
    EXPORT static int32_t CreateLcdBackground(ThumbRdbOpt &opts);
    EXPORT static int32_t GenerateHighlightThumbnailBackground(ThumbRdbOpt &opts);
    EXPORT static int32_t TriggerHighlightThumbnail(ThumbRdbOpt &opts, std::string &id, std::string &tracks,
        std::string &trigger, std::string &genType);
    EXPORT static int32_t UpgradeThumbnailBackground(ThumbRdbOpt &opts, bool isWifiConnected);
    EXPORT static int32_t RestoreAstcDualFrame(ThumbRdbOpt &opts);
    EXPORT static int32_t CreateAstcBatchOnDemand(ThumbRdbOpt &opts, NativeRdb::RdbPredicates &predicate,
        int32_t requestId);
    EXPORT static int32_t GetNewThumbnailCount(ThumbRdbOpt &opts, const int64_t &time, int &count);
    EXPORT static int32_t GetThumbnailPixelMap(ThumbRdbOpt &opts, ThumbnailType thumbType);
    EXPORT static int32_t GetKeyFrameThumbnailPixelMap(ThumbRdbOpt &opts, int32_t &timeStamp,
        int32_t &type);
    EXPORT static void CreateAstcAfterDownloadThumbOnDemand(const std::string &path);
    EXPORT static void StopDownloadThumbBatchOnDemand(int32_t requestId);
    EXPORT static void CreateAstcBatchOnDemandTaskFinish();
    EXPORT static void HandleDownloadBatch();

private:
    EXPORT static int32_t GetLcdCount(ThumbRdbOpt &opts, int &outLcdCount);
    EXPORT static int32_t GetNoLcdData(ThumbRdbOpt &opts, std::vector<ThumbnailData> &outDatas);
    EXPORT static int32_t GetNoThumbnailData(ThumbRdbOpt &opts, std::vector<ThumbnailData> &outDatas);
    EXPORT static int32_t GetNoAstcData(ThumbRdbOpt &opts, std::vector<ThumbnailData> &outDatas);
    EXPORT static int32_t GetAvailableFile(ThumbRdbOpt &opts, ThumbnailData &data, ThumbnailType thumbType,
        std::string &fileName);
    EXPORT static int32_t GetNoHighlightData(ThumbRdbOpt &opts, std::vector<ThumbnailData> &outDatas);
    EXPORT static int32_t GetAvailableKeyFrameFile(ThumbRdbOpt &opts, ThumbnailData &data, int32_t thumbType,
        std::string &fileName);
    EXPORT static int32_t GetThumbnailDataNeedUpgrade(ThumbRdbOpt &opts, std::vector<ThumbnailData> &outDatas,
        bool isWifiConnected);
    EXPORT static void CheckMonthAndYearKvStoreValid(ThumbRdbOpt &opts);
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_HELPER_H_
