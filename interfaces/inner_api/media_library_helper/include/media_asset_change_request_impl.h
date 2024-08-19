/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_IMPL_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_IMPL_H

#include <fstream>
#include <vector>
#include <mutex>

#include "media_asset_base_capi.h"
#include "media_asset_types.h"
#include "unique_fd.h"
#include "media_asset_edit_data.h"
#include "values_bucket.h"
#include "datashare_helper.h"
#include "media_data_source.h"

constexpr int32_t YES = 1;
constexpr int32_t NO = 0;

/*
 * MediaDataSource
 */
class MediaDataSource : public OHOS::Media::IMediaDataSource {
public:
    MediaDataSource(void* buffer, int64_t size) : buffer_(buffer), size_(size), readPos_(0) {}
    ~MediaDataSource() = default;

    int32_t ReadAt(const std::shared_ptr<OHOS::Media::AVSharedMemory>& mem, uint32_t length, int64_t pos = -1) override;
    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<OHOS::Media::AVSharedMemory>& mem) override;
    int32_t ReadAt(uint32_t length, const std::shared_ptr<OHOS::Media::AVSharedMemory>& mem) override;
    int32_t GetSize(int64_t& size) override;

private:
    int32_t ReadData(const std::shared_ptr<OHOS::Media::AVSharedMemory>& mem, uint32_t length);

    void* buffer_;
    int64_t size_;
    int64_t readPos_;
};

struct OH_MediaAssetChangeRequest {
public:
    OH_MediaAssetChangeRequest(OH_MediaAsset* mediaAsset);
    ~OH_MediaAssetChangeRequest();

    MediaLibrary_ErrorCode AddResourceWithBuffer(MediaLibrary_ResourceType resourceType, uint8_t* buffer,
        uint32_t length);
    MediaLibrary_ErrorCode SaveCameraPhoto(MediaLibrary_ImageFileType imageFileType);
    MediaLibrary_ErrorCode DiscardCameraPhoto();
    MediaLibrary_ErrorCode ApplyChanges();

private:
    bool IsMovingPhoto();
    bool CheckWriteOperation(MediaLibrary_ResourceType resourceType);
    bool CheckMovingPhotoResource(MediaLibrary_ResourceType resourceType);
    bool ContainsResource(MediaLibrary_ResourceType resourceType);
    bool Contains(OHOS::Media::AssetChangeOperation changeOperation);
    int32_t OpenWriteCacheHandler(bool isMovingPhotoVideo = false);
    uint32_t FetchAddCacheFileId();
    void RecordChangeOperation(OHOS::Media::AssetChangeOperation changeOperation);
    bool CheckMovingPhotoVideo(void* dataBuffer, size_t size);
    bool ChangeOperationExecute(OHOS::Media::AssetChangeOperation option);
    bool CheckChangeOperations();
    bool CheckMovingPhotoWriteOperation();
    bool SubmitCacheExecute();
    bool AddResourceExecute();
    bool SaveCameraPhotoExecute();
    bool DiscardCameraPhotoExecute();
    bool HasWritePermission();
    bool WriteBySecurityComponent();
    bool IsCreation();
    int32_t CopyToMediaLibrary(bool isCreation, OHOS::Media::AddResourceMode mode);
    int32_t CreateAssetBySecurityComponent(std::string& assetUri);
    int32_t CopyMovingPhotoVideo(const std::string& assetUri);
    int32_t CopyFileToMediaLibrary(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo = false);
    int32_t CopyDataBufferToMediaLibrary(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo = false);
    void SetNewFileAsset(int32_t id, const std::string& uri);
    bool SendToCacheFile(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo = false);
    bool IsSetEffectMode();
    int32_t SubmitCache(bool isCreation, bool isSetEffectMode);
    int32_t SendFile(const OHOS::UniqueFd& srcFd, const OHOS::UniqueFd& destFd);
    int32_t PutMediaAssetEditData(OHOS::DataShare::DataShareValuesBucket& valuesBucket);
    bool HasAddResource(MediaLibrary_ResourceType resourceType);
    bool AddMovingPhotoVideoExecute();
    bool AddResourceByMode(const OHOS::UniqueFd& uniqueFd, OHOS::Media::AddResourceMode mode,
        bool isMovingPhotoVideo = false);
    bool WriteCacheByArrayBuffer(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo = false);
    void DiscardHighQualityPhoto();

private:
    OH_MediaAsset* mediaAsset_;
    std::vector<MediaLibrary_ResourceType> addResourceTypes_;
    std::vector<OHOS::Media::AssetChangeOperation> assetChangeOperations_;
    std::string cacheMovingPhotoVideoName_;
    std::string cacheFileName_;
    static std::atomic<uint32_t> cacheFileId_;
    std::mutex mutex_;
    uint8_t* dataBuffer_;
    uint8_t* movingPhotoVideoDataBuffer_;
    OHOS::DataShare::DataShareValuesBucket creationValuesBucket_;
    OHOS::Media::AddResourceMode movingPhotoVideoResourceMode_;
    std::string realPath_;
    std::string movingPhotoVideoRealPath_;
    uint32_t movingPhotoVideoBufferSize_;
    uint32_t dataBufferSize_;
    OHOS::Media::AddResourceMode addResourceMode_;
    std::shared_ptr<OHOS::Media::MediaAssetEditData> editData_ = nullptr;
};

#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_IMPL_H
