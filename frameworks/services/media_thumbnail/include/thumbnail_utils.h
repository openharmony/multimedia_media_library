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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_UTILS_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_UTILS_H_

#include <mutex>
#include <condition_variable>

#include "ability_context.h"
#include "avmetadatahelper.h"
#include "rdb_helper.h"
#include "single_kvstore.h"
#include "thumbnail_datashare_bridge.h"

namespace OHOS {
namespace Media {
struct ThumbRdbOpt {
    std::shared_ptr<NativeRdb::RdbStore> store;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStore;
    std::shared_ptr<AbilityRuntime::Context> context;
    std::string networkId;
    std::string table;
    std::string udid;
    std::string row;
    std::string uri;
    int32_t size{0};
};

struct ThumbnailData {
    ThumbnailData() {}
    virtual ~ThumbnailData()
    {
        source = nullptr;
        thumbnail.clear();
        lcd.clear();
    }
    int mediaType{0};
    int64_t dateModified{0};
    float degrees;
    std::shared_ptr<PixelMap> source;
    std::vector<uint8_t> thumbnail;
    std::vector<uint8_t> lcd;
    std::string id;
    std::string udid;
    std::string path;
    std::string hashKey;
    std::string thumbnailKey;
    std::string lcdKey;
    std::string suffix;
};

struct ThumbnailRdbData {
    int mediaType;
    int64_t dateModified{0};
    std::string id;
    std::string path;
    std::string thumbnailKey;
    std::string lcdKey;
};

class ThumbnailUtils {
public:
    ThumbnailUtils() = delete;
    ~ThumbnailUtils() = delete;
    // utils
    static bool ResizeImage(const std::vector<uint8_t> &data, const Size &size, std::unique_ptr<PixelMap> &pixelMap);
    static bool CompressImage(std::shared_ptr<PixelMap> &pixelMap, const Size &size, std::vector<uint8_t> &data,
        float degrees);
    static void ThumbnailDataCopy(ThumbnailData &data, ThumbnailRdbData &rdbData);
    static bool CleanThumbnailInfo(ThumbRdbOpt &opts, bool withThumb, bool withLcd = false);

    // URI utils
    std::string GetDeviceIdByUri(const std::string &uri);
    static bool UpdateRemotePath(std::string &path, const std::string &networkId);

    // RDB Store Query
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryThumbnailSet(ThumbRdbOpt &opts);
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryThumbnailInfo(ThumbRdbOpt &opts,
        ThumbnailData &data, int &err);
    static bool QueryRemoteThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, int &err);

    // KV Store
    static bool RemoveDataFromKv(const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore, const std::string &key);
    static bool IsImageExist(const std::string &key, const std::string &networkId,
        const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore);
    static bool DeleteLcdData(ThumbRdbOpt &opts, ThumbnailData &data);
    static bool DeleteDistributeLcdData(ThumbRdbOpt &opts, ThumbnailData &thumbnailData);
    static bool ClearThumbnailAllRecord(ThumbRdbOpt &opts, ThumbnailData &thumbnailData);
    static bool GetKvResultSet(const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore, const std::string &key,
        const std::string &networkId, std::shared_ptr<DataShare::ResultSetBridge> &outResultSet);
    static bool DeleteOriginImage(ThumbRdbOpt &opts, ThumbnailData &thumbnailData);
    // Steps
    static bool LoadSourceImage(ThumbnailData &data);
    static bool GenThumbnailKey(ThumbnailData &data);
    static bool CreateThumbnailData(ThumbnailData &data);
    static DistributedKv::Status SaveThumbnailData(ThumbnailData &data, const std::string &networkId,
        const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore);

    static bool GenLcdKey(ThumbnailData &data);
    static bool CreateLcdData(ThumbnailData &data, int32_t lcdSize);
    static DistributedKv::Status SaveLcdData(ThumbnailData &data, const std::string &networkId,
        const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore);
    static bool UpdateThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
    static bool UpdateVisitTime(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
    static bool DoUpdateRemoteThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, int &err);

    // RDB Store generate and aging
    static bool QueryHasLcdFiles(ThumbRdbOpt &opts, std::vector<ThumbnailRdbData> &infos, int &err);
    static bool QueryHasThumbnailFiles(ThumbRdbOpt &opts, std::vector<ThumbnailRdbData> &infos, int &err);
    static bool QueryLcdCount(ThumbRdbOpt &opts, int &outLcdCount, int &err);
    static bool QueryDistributeLcdCount(ThumbRdbOpt &opts, int &outLcdCount, int &err);
    static bool QueryAgingLcdInfos(ThumbRdbOpt &opts, int LcdLimit,
        std::vector<ThumbnailRdbData> &infos, int &err);
    static bool QueryAgingDistributeLcdInfos(ThumbRdbOpt &opts, int LcdLimit,
        std::vector<ThumbnailRdbData> &infos, int &err);
    static bool QueryNoLcdInfos(ThumbRdbOpt &opts, int LcdLimit, std::vector<ThumbnailRdbData> &infos, int &err);
    static bool QueryNoThumbnailInfos(ThumbRdbOpt &opts, std::vector<ThumbnailRdbData> &infos, int &err);
    static bool QueryDeviceThumbnailRecords(ThumbRdbOpt &opts, std::vector<ThumbnailRdbData> &infos, int &err);

    static bool SyncPushTable(ThumbRdbOpt &opts, std::vector<std::string> &devices, bool isBlock = false);
    static bool SyncPullTable(ThumbRdbOpt &opts, std::vector<std::string> &devices, bool isBlock = false);
    static DistributedKv::Status SyncPushKvstore(const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore,
        const std::string key, const std::string &networkId);
    static DistributedKv::Status SyncPullKvstore(const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore,
        const std::string key, const std::string &networkId);
private:
    const int RETRY_COUNT = 3;
    static int32_t SetSource(std::shared_ptr<AVMetadataHelper> avMetadataHelper, const std::string &path);
    static int64_t UTCTimeSeconds();
    static void ParseQueryResult(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        ThumbnailRdbData &data, int &err);
    static void ParseStringResult(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        int index, std::string &data, int &err);

    static bool CheckResultSetCount(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, int &err);
    static bool CheckResultSetColumn(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, int &err);
    // utils
    static bool LoadImageFile(const std::string &path, std::shared_ptr<PixelMap> &pixelMap, float &degrees);
    static bool LoadVideoFile(const std::string &path, std::shared_ptr<PixelMap> &pixelMap, float &degrees);
    static bool LoadAudioFile(const std::string &path, std::shared_ptr<PixelMap> &pixelMap, float &degrees);
    static bool GenKey(ThumbnailData &data, std::string &key);
    static std::string GetUdid();
    // KV Store
    static DistributedKv::Status SaveImage(const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore,
        const std::string &key, const std::vector<uint8_t> &image);

    // RDB Store
    static bool GetRemoteThumbnailInfo(ThumbRdbOpt &opts, const std::string &id,
        const std::string &udid, int &err);
    static bool GetUdidByNetworkId(ThumbRdbOpt &opts, const std::string &networkId,
        std::string &outUdid, int &err);
    static bool UpdateRemoteThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
    static bool InsertRemoteThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &err);
    static bool CleanDistributeLcdInfo(ThumbRdbOpt &opts);
    static bool DeleteDistributeThumbnailInfo(ThumbRdbOpt &opts);
};

class SyncStatus {
public:
    std::condition_variable cond_;
    std::mutex mtx_;
    bool isSyncComplete_{false};
};

class MediaLibrarySyncCallback : public DistributedKv::KvStoreSyncCallback {
public:
    MediaLibrarySyncCallback() = default;
    ~MediaLibrarySyncCallback() override {}
    void SyncCompleted(const std::map<std::string, DistributedKv::Status> &results) override;
    bool WaitFor();
private:
    SyncStatus status_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_UTILS_H_
