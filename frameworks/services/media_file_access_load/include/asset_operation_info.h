/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_ASSET_OPERATION_INFO_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_ASSET_OPERATION_INFO_H_

#include <string>

#include "medialibrary_db_const.h"
#include "userfile_manager_types.h"
#include "file_asset.h"
#include "asset_accurate_refresh.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
using namespace AccurateRefresh;
enum class AssetOperationStatus : int32_t {
    NOT_INIT = 0,
    INIT_SUCCESS = 1,
    INFO_NOT_AVAILABLE = 2,  // check empty before use data or fileId
};

enum class AssetPathType : int32_t {
    ASSET_PATH,
    NORMAL_PATH
};

class AssetOperationInfo {
public:
    EXPORT static AssetOperationInfo CreateFromFileId(const std::string &fileId);
    // If pathType is NORMAL_PATH, not query db and set status to INFO_NOT_AVAILABLE. Otherwise, query db and fill info.
    EXPORT static AssetOperationInfo CreateFromPath(const std::string &path,
        AssetPathType pathType = AssetPathType::ASSET_PATH);

    EXPORT bool Init();
    EXPORT void Reset();
    // True means asset info can be used. False means asset info (except data_) is not available.
    EXPORT bool IsInfoAvailable() const;
    // True means asset operation info contains valid fileId_ or data_. False means both fileId_ and data_ are empty.
    EXPORT bool IsValid() const;

    EXPORT std::string GetFileId() const;
    EXPORT void SetFileId(const std::string &fileId);

    EXPORT std::string GetAssetPath() const;
    EXPORT void SetAssetPath(const std::string &assetPath);

    EXPORT std::string GetStoragePath() const;
    EXPORT void SetStoragePath(const std::string &storagePath);

    EXPORT FileSourceType GetFileSourceType() const;
    EXPORT void SetFileSourceType(FileSourceType sourceType);

    EXPORT PhotoSubType GetSubType() const;
    EXPORT void SetSubType(PhotoSubType subType);

    EXPORT std::string GetOwnerAlbumId() const;
    EXPORT void SetOwnerAlbumId(const std::string &ownerAlbumId);

    EXPORT BurstCoverLevelType GetBurstCoverLevel() const;
    EXPORT void SetBurstCoverLevel(BurstCoverLevelType burstCoverLevel);

    EXPORT std::string GetBurstKey() const;
    EXPORT void SetBurstKey(const std::string &burstKey);

    EXPORT std::shared_ptr<FileAsset> GetAssetInfo() const;
    EXPORT void SetAssetInfo(const std::shared_ptr<FileAsset> &assetInfo);

    EXPORT const std::shared_ptr<AssetAccurateRefresh>& GetAssetRefresh() const;
    EXPORT void SetAssetRefresh(const std::shared_ptr<AssetAccurateRefresh> &assetRefresh);

private:
    struct FileIdTag {};
    struct PathTag {};

    AssetOperationInfo(const std::string &fileId, FileIdTag);
    AssetOperationInfo(const std::string &path, PathTag);
    AssetOperationInfo() = default;

    void HandleSubType(int32_t subtype, int32_t effectMode);
    void SetInitStatus(AssetOperationStatus status)
    {
        initStatus_ = status;
    }

    AssetOperationStatus initStatus_ {AssetOperationStatus::NOT_INIT};
    std::string data_;
    std::string storagePath_;
    std::string fileId_;
    std::string photoOwnerAlbumId_;
    std::shared_ptr<FileAsset> assetInfo_;
    std::string burstKey_;
    BurstCoverLevelType burstCoverLevel_ {BurstCoverLevelType::DEFAULT};
    FileSourceType sourceType_ {FileSourceType::MEDIA};
    PhotoSubType subType_ {PhotoSubType::DEFAULT};
    std::shared_ptr<AssetAccurateRefresh> assetRefresh_;
};
} // namespace OHOS::Media
#endif // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_ASSET_OPERATION_INFO_H_
