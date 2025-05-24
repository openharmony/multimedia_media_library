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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DATA_CLIENT_HANDLER_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DATA_CLIENT_HANDLER_H

#include <string>
#include <vector>

#include "i_cloud_media_data_client.h"
#include "get_aging_file_vo.h"

namespace OHOS::Media::CloudSync {
class CloudMediaDataClientHandler : public ICloudMediaDataClient {
public:  // constructors & destructors
    CloudMediaDataClientHandler() = default;
    virtual ~CloudMediaDataClientHandler() = default;

public:  // getter & setter
    void SetTraceId(const std::string &traceId) override;
    std::string GetTraceId() const override;

public:
    // 核查
    int32_t UpdateDirty(const std::string &cloudId, DirtyTypes dirtyType) override;
    int32_t UpdatePosition(const std::vector<std::string> &cloudIds, int32_t position) override;
    int32_t UpdateThmStatus(const std::string &cloudId, int32_t thmStatus) override;
    int32_t GetAgingFile(const int64_t time, int32_t mediaType, int32_t sizeLimit, int32_t offset,
        std::vector<CloudMetaData> &metaData) override;
    int32_t GetActiveAgingFile(const int64_t time, int32_t mediaType, int32_t sizeLimit, int32_t offset,
        std::vector<CloudMetaData> &metaData) override;
    // 下载
    int32_t GetDownloadAsset(
        const std::vector<std::string> &uris, std::vector<CloudMetaData> &cloudMetaDataVec) override;
    int32_t GetDownloadThmsByUri(
        const std::vector<std::string> &uri, int32_t type, std::vector<CloudMetaData> &metaData) override;
    int32_t OnDownloadAsset(const std::vector<std::string> &cloudIds, std::vector<MediaOperateResult> &result) override;
    int32_t GetDownloadThms(std::vector<CloudMetaData> &cloudMetaDataVec, const DownloadThumPara &param) override;
    int32_t OnDownloadThms(const std::unordered_map<std::string, int32_t> &resMap, int32_t &failSize) override;
    int32_t GetDownloadThmNum(int32_t &totalNum, int32_t type) override;
    // 缓存视频
    int32_t GetVideoToCache(std::vector<CloudMetaData> &cloudMetaDataVec, int32_t size) override;
    // 大数据
    int32_t GetFilePosStat(std::vector<uint64_t> &filePosStat) override;
    int32_t GetCloudThmStat(std::vector<uint64_t> &cloudThmStat) override;
    int32_t GetDirtyTypeStat(std::vector<uint64_t> &dirtyTypeStat) override;
    int32_t UpdateLocalFileDirty(std::vector<MDKRecord> &records) override;
    int32_t UpdateSyncStatus(const std::string &cloudId, int32_t syncStatus) override;

private:
    int32_t GetAgingFile(uint32_t operationCode, GetAgingFileReqBody &reqBody, std::vector<CloudMetaData> &metaData);

private:
    enum {
        SIZE_FILE_POSITION_LEN = 3,
        SIZE_CLOUD_THM_STAT_LEN = 4,
        SIZE_DIRTY_TYPE_LEN = 5,
    };

private:
    std::string traceId_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DATA_CLIENT_HANDLER_H