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
#define MLOG_TAG "AssetOperationInfo"

#include "asset_operation_info.h"

#include "medialibrary_errno.h"
#include "media_file_access_utils.h"
#include "media_file_utils.h"
#include "media_log.h"

namespace OHOS::Media {
AssetOperationInfo::AssetOperationInfo(const std::string &fileId, FileIdTag) : fileId_(fileId) {}

AssetOperationInfo::AssetOperationInfo(const std::string &path, PathTag) : data_(path) {}

AssetOperationInfo AssetOperationInfo::CreateFromFileId(const std::string &fileId)
{
    AssetOperationInfo info(fileId, FileIdTag {});
    info.Init();
    return info;
}

AssetOperationInfo AssetOperationInfo::CreateFromPath(const std::string &path, AssetPathType pathType)
{
    AssetOperationInfo info(path, PathTag {});
    if (pathType == AssetPathType::NORMAL_PATH) {
        info.SetInitStatus(AssetOperationStatus::INFO_NOT_AVAILABLE);
    } else {
        info.Init();
    }
    return info;
}

void AssetOperationInfo::Reset()
{
    SetInitStatus(AssetOperationStatus::NOT_INIT);
}

std::string AssetOperationInfo::GetFileId() const
{
    return fileId_;
}

void AssetOperationInfo::SetFileId(const std::string &fileId)
{
    fileId_ = fileId;
}

std::string AssetOperationInfo::GetAssetPath() const
{
    return data_;
}

void AssetOperationInfo::SetAssetPath(const std::string &assetPath)
{
    data_ = assetPath;
}

std::string AssetOperationInfo::GetStoragePath() const
{
    return storagePath_;
}

void AssetOperationInfo::SetStoragePath(const std::string &storagePath)
{
    storagePath_ = storagePath;
}

FileSourceType AssetOperationInfo::GetFileSourceType() const
{
    return sourceType_;
}

void AssetOperationInfo::SetFileSourceType(FileSourceType sourceType)
{
    sourceType_ = sourceType;
}

PhotoSubType AssetOperationInfo::GetSubType() const
{
    return subType_;
}

void AssetOperationInfo::SetSubType(PhotoSubType subType)
{
    subType_ = subType;
}

bool AssetOperationInfo::Init()
{
    CHECK_AND_RETURN_RET_INFO_LOG(initStatus_ == AssetOperationStatus::NOT_INIT, IsInfoAvailable(),
        "has been initialized");
    SetInitStatus(AssetOperationStatus::INFO_NOT_AVAILABLE);
    std::shared_ptr<FileAsset> fileAsset;
    if (!data_.empty()) {
        fileAsset = MediaFileAccessUtils::GetFileAssetFromDb(MediaColumn::MEDIA_FILE_PATH, data_);
    } else if (!fileId_.empty()) {
        fileAsset = MediaFileAccessUtils::GetFileAssetFromDb(MediaColumn::MEDIA_ID, fileId_);
    } else {
        SetInitStatus(AssetOperationStatus::INFO_NOT_AVAILABLE);
        MEDIA_ERR_LOG("no valid data to init");
        return false;
    }
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, IsInfoAvailable(), "get file asset from db failed");
    SetFileId(std::to_string(fileAsset->GetId()));
    SetAssetPath(fileAsset->GetFilePath());
    SetStoragePath(fileAsset->GetStoragePath());
    SetFileSourceType(static_cast<FileSourceType>(fileAsset->GetFileSourceType()));
    SetOwnerAlbumId(std::to_string(fileAsset->GetOwnerAlbumId()));
    SetAssetInfo(fileAsset);
    HandleSubType(fileAsset->GetPhotoSubType(), fileAsset->GetMovingPhotoEffectMode());
    if (GetSubType() == PhotoSubType::BURST) {
        SetBurstCoverLevel(static_cast<BurstCoverLevelType>(fileAsset->GetBurstCoverLevel()));
        SetBurstKey(fileAsset->GetBurstKey());
    }
    SetInitStatus(AssetOperationStatus::INIT_SUCCESS);
    return true;
}

bool AssetOperationInfo::IsInfoAvailable() const
{
    return initStatus_ == AssetOperationStatus::INIT_SUCCESS;
}

bool AssetOperationInfo::IsValid() const
{
    return !GetAssetPath().empty() || !GetFileId().empty();
}

void AssetOperationInfo::HandleSubType(int32_t subtype, int32_t effectMode)
{
    if (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO) ||
        effectMode == static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY)) {
        SetSubType(PhotoSubType::MOVING_PHOTO);
    } else if (subtype == static_cast<int32_t>(PhotoSubType::BURST)) {
        SetSubType(PhotoSubType::BURST);
    }
}

std::string AssetOperationInfo::GetOwnerAlbumId() const
{
    return photoOwnerAlbumId_;
}

void AssetOperationInfo::SetAssetInfo(const std::shared_ptr<FileAsset> &assetInfo)
{
    assetInfo_ = assetInfo;
}

std::shared_ptr<FileAsset> AssetOperationInfo::GetAssetInfo() const
{
    return assetInfo_;
}

void AssetOperationInfo::SetOwnerAlbumId(const std::string &ownerAlbumId)
{
    photoOwnerAlbumId_ = ownerAlbumId;
}

BurstCoverLevelType AssetOperationInfo::GetBurstCoverLevel() const
{
    return burstCoverLevel_;
}

void AssetOperationInfo::SetBurstCoverLevel(BurstCoverLevelType burstCoverLevel)
{
    burstCoverLevel_ = burstCoverLevel;
}

std::string AssetOperationInfo::GetBurstKey() const
{
    return burstKey_;
}

void AssetOperationInfo::SetBurstKey(const std::string &burstKey)
{
    burstKey_ = burstKey;
}

const std::shared_ptr<AssetAccurateRefresh>& AssetOperationInfo::GetAssetRefresh() const
{
    return assetRefresh_;
}

void AssetOperationInfo::SetAssetRefresh(const std::shared_ptr<AssetAccurateRefresh> &assetRefresh)
{
    assetRefresh_ = assetRefresh;
}
} // namespace OHOS::Media