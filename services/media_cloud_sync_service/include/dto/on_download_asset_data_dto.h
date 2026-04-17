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

#ifndef OHOS_MEDIA_CLOUD_SYNC_ON_DOWNLOAD_ASSET_DATA_DTO_H
#define OHOS_MEDIA_CLOUD_SYNC_ON_DOWNLOAD_ASSET_DATA_DTO_H

#include <string>
#include <vector>
#include <sstream>
#include "cloud_media_define.h"
#include "cloud_lake_info.h"
#include "photos_po.h"

namespace OHOS::Media::CloudSync {
using namespace OHOS::Media::ORM;
class EXPORT AssetFileNode {
public:
    AssetFileNode() = default;
    AssetFileNode(const std::string &filePath, const std::string &liveVideoPath)
        : filePath(filePath), liveVideoPath(liveVideoPath)
    {}

public:  // fields
    std::string filePath;
    std::string liveVideoPath;

public:  // basic functions
    std::string ToString() const;
};
class EXPORT OnDownloadAssetData {
public:
    bool fixFileType;
    bool needSliceContent;
    bool needSliceRaw;
    // Photos.data, pattern: /storage/cloud/files/Photo/${bucketId}/${fileName}.${suffix}
    std::string path;
    int64_t dateModified;
    // pattern: /storage/media/local/files/Photo/${bucketId}/${fileName}.${suffix}
    std::string localPath;
    int32_t err;
    std::string errorMsg;
    std::string fileUri;
    bool needParseCover;
    bool needScanShootingMode;
    bool needScanSubtype{false};
    AdditionFileInfo lakeInfo;
    bool needScanHdrMode{false};
    bool needParseDuration{false};
    AssetFileNode fileInfo;
    AssetFileNode editedFileInfo;
    std::string cloudId;
    std::optional<PhotosPo> localPhotosPoOp;

public:  // basic functions
    std::string ToString() const;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_ON_DOWNLOAD_ASSET_DATA_DTO_H