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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DOWNLOAD_SERVICE_PROCESSOR_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DOWNLOAD_SERVICE_PROCESSOR_H

#include <vector>
#include <unordered_map>

#include "photos_po.h"
#include "photos_dto.h"
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
using namespace OHOS::Media::ORM;
class EXPORT CloudMediaDownloadServiceProcessor {
public:
    std::vector<PhotosDto> GetPhotosDto(std::vector<PhotosPo> photosPos);
    void GetDownloadAssetData(
        const std::vector<PhotosPo> &photosPos, std::vector<DownloadAssetData> &downloadAssetDatas);

private:
    bool CheckPhotosPo(const PhotosPo &photosPo);
    void GetDownloadAssetData(const PhotosPo &photosPo, DownloadAssetData &downloadAssetData);
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_DOWNLOAD_SERVICE_PROCESSOR_H
