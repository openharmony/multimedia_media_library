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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DOWNLOAD_SERVICE_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DOWNLOAD_SERVICE_H

#include <string>
#include <vector>

#include "cloud_media_download_service_processor.h"
#include "cloud_media_download_dao.h"
#include "photos_dto.h"
#include "photos_po.h"
#include "download_thumbnail_query_dto.h"
#include "media_operate_result_dto.h"
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
class EXPORT CloudMediaDownloadService {
public:
    int32_t GetDownloadThmNum(const int32_t type, int32_t &totalNum);
    int32_t GetDownloadThms(const DownloadThumbnailQueryDto &queryDto, std::vector<PhotosDto> &photosDtos);
    std::vector<PhotosDto> GetDownloadThmsByUri(const std::vector<int32_t> &fileIds, const int32_t type);
    int32_t OnDownloadThms(const std::unordered_map<std::string, int32_t> &downloadThumbnailMap,
        std::vector<MediaOperateResultDto> &result);
    std::vector<PhotosDto> GetDownloadAsset(const std::vector<int32_t> &fileIds);
    int32_t OnDownloadAsset(const std::vector<std::string> &cloudIds, std::vector<MediaOperateResultDto> &result);

private:
    struct OnDownloadAssetData {
        bool fixFileType;
        bool needSliceContent;
        bool needSliceRaw;
        std::string path;
        int64_t dateModified;
        std::string localPath;
        int32_t err;
        std::string errorMsg;
        std::string fileUri;
        bool needParseCover;
    };

private:
    bool IsCloudInsertTaskPriorityHigh();
    // functions for OnDownloadThms API
    int32_t OnDownloadThm(const std::vector<std::string> &thmVector, std::vector<MediaOperateResultDto> &result);
    int32_t OnDownloadLcd(const std::vector<std::string> &lcdVector, std::vector<MediaOperateResultDto> &result);
    int32_t OnDownloadThmAndLcd(const std::vector<std::string> &bothVector, std::vector<MediaOperateResultDto> &result);
    OnDownloadAssetData GetOnDownloadAssetData(PhotosPo &photosPo);
    void UnlinkAsset(OnDownloadAssetData &assetData);
    void ResetAssetModifyTime(OnDownloadAssetData &assetData);
    int32_t SliceAssetFile(const std::string &originalFile, const std::string &path,
        const std::string &videoPath, const std::string &extraDataPath);
    int32_t SliceAsset(const OnDownloadAssetData &assetData, const PhotosPo &photo);
    void HandlePhoto(const ORM::PhotosPo &photo, OnDownloadAssetData &assetData);
    std::string PrintOnDownloadAssetData(const OnDownloadAssetData &assetData);
    void NotifyDownloadLcd(const std::vector<std::string> &cloudIds);

private:
    const uint32_t TYPE_THM_MASK = 0x1;
    const uint32_t TYPE_LCD_MASK = 0x2;
    enum {
        // Index of Download Thumbnail Type Statistic Info.
        TYPE_THM = 1,
        TYPE_LCD = 2,
        TYPE_THM_AND_LCD = 3,
        TYPE_ASTC = 4,
    };

private:
    CloudMediaDownloadDao dao_;
    CloudMediaDownloadServiceProcessor processor_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DOWNLOAD_SERVICE_H