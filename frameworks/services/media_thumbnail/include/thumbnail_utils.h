/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_UTILS_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_UTILS_H_

#include <mutex>
#include <condition_variable>

#include "ability_context.h"
#include "avmetadatahelper.h"
#include "datashare_result_set.h"
#include "image_source.h"
#include "rdb_helper.h"
#include "single_kvstore.h"
#include "thumbnail_const.h"
#include "thumbnail_data.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
struct ThumbRdbOpt {
    EXPORT std::shared_ptr<NativeRdb::RdbStore> store;
#ifdef DISTRIBUTED
    EXPORT std::shared_ptr<DistributedKv::SingleKvStore> kvStore;
#endif
    EXPORT std::shared_ptr<AbilityRuntime::Context> context;
    EXPORT std::string networkId;
    EXPORT std::string path;
    EXPORT std::string table;
    EXPORT std::string udid;
    EXPORT std::string row;
    EXPORT std::string uri;
    EXPORT std::string dateAdded;
    EXPORT std::string fileUri;
    EXPORT Size screenSize;
};

class ThumbnailUtils {
public:
    EXPORT ThumbnailUtils() = delete;
    EXPORT ~ThumbnailUtils() = delete;
    // utils
    EXPORT static bool ResizeImage(const std::vector<uint8_t> &data, const Size &size,
        std::unique_ptr<PixelMap> &pixelMap);
    EXPORT static bool CompressImage(std::shared_ptr<PixelMap> &pixelMap, std::vector<uint8_t> &data,
        bool isHigh = false, std::shared_ptr<std::string> pathPtr = nullptr, bool isAstc = false);
    EXPORT static bool CleanThumbnailInfo(ThumbRdbOpt &opts, bool withThumb, bool withLcd = false);

    // RDB Store Query
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> QueryThumbnailInfo(ThumbRdbOpt &opts,
        ThumbnailData &data, int &err);
#ifdef DISTRIBUTED
    static bool QueryRemoteThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
    // KV Store
    static bool RemoveDataFromKv(const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore, const std::string &key);
    static bool IsImageExist(const std::string &key, const std::string &networkId,
        const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore);
    static bool DeleteDistributeLcdData(ThumbRdbOpt &opts, ThumbnailData &thumbnailData);
#endif
    static bool DeleteThumbFile(ThumbnailData &data, ThumbnailType type);
#ifdef DISTRIBUTED
    static bool DeleteDistributeThumbnailInfo(ThumbRdbOpt &opts);
#endif

    EXPORT static bool DeleteOriginImage(ThumbRdbOpt &opts);
    // Steps
    EXPORT static bool LoadSourceImage(ThumbnailData &data);
    static bool GenTargetPixelmap(ThumbnailData &data, const Size &desiredSize);

    static int TrySaveFile(ThumbnailData &Data, ThumbnailType type);
    EXPORT static bool UpdateLcdInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
    EXPORT static bool UpdateVisitTime(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
#ifdef DISTRIBUTED
    static bool DoUpdateRemoteThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
#endif

    // RDB Store generate and aging
    EXPORT static bool QueryLcdCount(ThumbRdbOpt &opts, int &outLcdCount, int &err);
    EXPORT static bool QueryDistributeLcdCount(ThumbRdbOpt &opts, int &outLcdCount, int &err);
    EXPORT static bool QueryAgingLcdInfos(ThumbRdbOpt &opts, int LcdLimit,
        std::vector<ThumbnailData> &infos, int &err);
#ifdef DISTRIBUTED
    static bool QueryAgingDistributeLcdInfos(ThumbRdbOpt &opts, int LcdLimit,
        std::vector<ThumbnailData> &infos, int &err);
#endif
    EXPORT static bool QueryNoLcdInfos(ThumbRdbOpt &opts, int LcdLimit, std::vector<ThumbnailData> &infos, int &err);
    EXPORT static bool QueryNoThumbnailInfos(ThumbRdbOpt &opts, std::vector<ThumbnailData> &infos, int &err);
    static bool QueryNoAstcInfos(ThumbRdbOpt &opts, std::vector<ThumbnailData> &infos, int &err);
    static bool QueryNewThumbnailCount(ThumbRdbOpt &opts, const int64_t &time, int &count, int &err);
#ifdef DISTRIBUTED
    static bool QueryDeviceThumbnailRecords(ThumbRdbOpt &opts, std::vector<ThumbnailData> &infos, int &err);
#endif
    static bool QueryLcdCountByTime(const int64_t &time, const bool &before, ThumbRdbOpt &opts, int &outLcdCount,
        int &err);
    EXPORT static bool ResizeThumb(int& width, int& height);
    EXPORT static bool ResizeLcd(int& width, int& height);
    static bool IsSupportGenAstc();
    EXPORT static void QueryThumbnailDataFromFileId(ThumbRdbOpt &opts, const std::string &id,
        ThumbnailData &data, int &err);
    static bool CheckDateAdded(ThumbRdbOpt &opts, ThumbnailData &data);
    static void GetThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &outData);
    static bool ScaleThumbnailEx(ThumbnailData &data);
    EXPORT static bool ScaleTargetPixelMap(ThumbnailData &data, const Size &targetSize);

    static void RecordStartGenerateStats(ThumbnailData::GenerateStats &stats, GenerateScene scene,
        LoadSourceType sourceType);
    static void RecordCostTimeAndReport(ThumbnailData::GenerateStats &stats);

private:
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> QueryThumbnailSet(ThumbRdbOpt &opts);
    static int SaveThumbDataToLocalDir(ThumbnailData &data,
        const ThumbnailType &type, const std::string &suffix, uint8_t *output, const int writeSize);
    static int ToSaveFile(ThumbnailData &data, const ThumbnailType &type, const std::string &fileName,
        uint8_t *output, const int &writeSize);
    static int SaveFileCreateDir(const std::string &path, const std::string &suffix, std::string &fileName);
    EXPORT static int32_t SetSource(std::shared_ptr<AVMetadataHelper> avMetadataHelper, const std::string &path);
    EXPORT static int64_t UTCTimeMilliSeconds();
    EXPORT static void ParseQueryResult(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        ThumbnailData &data, int &err);
    EXPORT static void ParseStringResult(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        int index, std::string &data, int &err);

    EXPORT static bool CheckResultSetCount(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, int &err);
    // utils
    EXPORT static bool LoadImageFile(ThumbnailData &data, Size &desiredSize);
    EXPORT static bool LoadVideoFile(ThumbnailData &data, Size &desiredSize);
    static bool LoadAudioFileInfo(std::shared_ptr<AVMetadataHelper> avMetadataHelper, ThumbnailData &data,
        Size &desiredSize, uint32_t &errCode);
    EXPORT static bool LoadAudioFile(ThumbnailData &data, Size &desiredSize);

#ifdef DISTRIBUTED
    // RDB Store
    static bool GetUdidByNetworkId(ThumbRdbOpt &opts, const std::string &networkId,
        std::string &outUdid, int &err);
    static bool UpdateRemoteThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
    static bool InsertRemoteThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
    static bool CleanDistributeLcdInfo(ThumbRdbOpt &opts);
#endif

    // scale
    static bool ScaleFastThumb(ThumbnailData &data, const Size &size);

    static int SaveAstcDataToKvStore(ThumbnailData &data, const ThumbnailType &type);
    static bool GenerateKvStoreKey(const std::string &fieldId, const std::string &dateAdded, std::string &key);
    static bool DeleteAstcDataFromKvStore(ThumbRdbOpt &opts, const ThumbnailType &type);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_UTILS_H_
