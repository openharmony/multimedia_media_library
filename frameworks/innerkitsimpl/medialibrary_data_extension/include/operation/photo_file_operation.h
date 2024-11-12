/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_PHOTO_FILE_OPERATIOIN_H
#define OHOS_MEDIA_PHOTO_FILE_OPERATIOIN_H

#include <string>

#include "rdb_store.h"

namespace OHOS::Media {
class PhotoFileOperation {
private:
    struct PhotoAssetInfo {
        std::string displayName;
        std::string filePath;
        int64_t dateModified{0};
        int32_t subtype{0};
        std::string videoFilePath;
        std::string editDataFolder;
    };

public:
    int32_t CopyPhoto(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::string &targetPath);

private:
    std::string GetVideoFilePath(const PhotoAssetInfo &photoInfo);
    std::string FindVideoFilePath(const PhotoAssetInfo &photoInfo);
    std::string FindRelativePath(const std::string &filePath);
    std::string FindPrefixOfEditDataFolder(const std::string &filePath);
    std::string BuildEditDataFolder(const PhotoFileOperation::PhotoAssetInfo &photoInfo);
    std::string FindEditDataFolder(const PhotoAssetInfo &photoInfo);
    int32_t CopyPhotoFile(const PhotoAssetInfo &sourcePhotoInfo, const PhotoAssetInfo &targetPhotoInfo);
    int32_t CopyPhotoRelatedVideoFile(const PhotoAssetInfo &sourcePhotoInfo, const PhotoAssetInfo &targetPhotoInfo);
    int32_t CopyPhotoRelatedExtraData(const PhotoAssetInfo &sourcePhotoInfo, const PhotoAssetInfo &targetPhotoInfo);
    int32_t CopyPhoto(const PhotoAssetInfo &sourcePhotoInfo, const PhotoAssetInfo &targetPhotoInfo);
    int32_t CopyFile(const std::string &srcPath, std::string &targetPath);
    std::string ToString(const PhotoAssetInfo &photoInfo);
};
}  // namespace OHOS::Media
#endif  // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_PHOTO_FILE_H_