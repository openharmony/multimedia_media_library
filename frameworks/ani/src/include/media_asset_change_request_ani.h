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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_ANI_H

#include <ani.h>
#include <memory>
#include "avmetadatahelper.h"
#include "datashare_helper.h"
#include "file_asset_ani.h"
#include "media_asset_edit_data.h"
#include "media_change_request_ani.h"
#include "photo_proxy.h"
#include "unique_fd.h"

namespace OHOS {
namespace Media {
enum class AssetChangeOperation {
    CREATE_FROM_SCRATCH,
    CREATE_FROM_URI,
    GET_WRITE_CACHE_HANDLER,
    ADD_RESOURCE,
    SET_EDIT_DATA,
    SET_FAVORITE,
    SET_HIDDEN,
    SET_TITLE,
    SET_USER_COMMENT,
    SET_MOVING_PHOTO_EFFECT_MODE,
    SET_PHOTO_QUALITY_AND_PHOTOID,
    SET_LOCATION,
    SET_CAMERA_SHOT_KEY,
    SAVE_CAMERA_PHOTO,
    ADD_FILTERS,
    DISCARD_CAMERA_PHOTO,
    SET_ORIENTATION,
    SET_SUPPORTED_WATERMARK_TYPE,
    SET_VIDEO_ENHANCEMENT_ATTR,
};

enum class AddResourceMode {
    DATA_BUFFER,
    FILE_URI,
    PHOTO_PROXY,
};

class MediaDataSource : public IMediaDataSource {
public:
    MediaDataSource(void* buffer, int64_t size) : buffer_(buffer), size_(size), readPos_(0) {}
    ~MediaDataSource() = default;

    int32_t ReadAt(const std::shared_ptr<AVSharedMemory>& mem, uint32_t length, int64_t pos = -1) override;
    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory>& mem) override;
    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory>& mem) override;
    int32_t GetSize(int64_t& size) override;

private:
    int32_t ReadData(const std::shared_ptr<AVSharedMemory>& mem, uint32_t length);

    void* buffer_;
    int64_t size_;
    int64_t readPos_;
};

struct MediaAssetChangeRequestAniContext;

class MediaAssetChangeRequestAni : public MediaChangeRequestAni {
public:
    MediaAssetChangeRequestAni(FileAssetAni* fileAssetAni);
    ~MediaAssetChangeRequestAni();
    static ani_status MediaAssetChangeRequestAniInit(ani_env *env);
    static ani_object Constructor(ani_env *env, [[maybe_unused]] ani_class clazz, ani_object fileAssetAni);
    static ani_object Wrap(ani_env *env, MediaAssetChangeRequestAni* changeRequest);
    static MediaAssetChangeRequestAni* Unwrap(ani_env *env, ani_object aniObject);
    virtual ani_status ApplyChanges(ani_env *env, ani_object aniObject) override;

    static ani_object createAssetRequestSystem(ani_env *env, ani_object context, ani_string displayName,
        ani_object photoCreateOptions);
    static ani_object createAssetRequest(ani_env *env, ani_object context, ani_enum_item photoTypeItem,
        ani_string extension, ani_object createOptions);

    static ani_object createImageAssetRequest(ani_env *env, ani_object context, ani_string fileUri);
    static ani_object createVideoAssetRequest(ani_env *env, ani_object context, ani_string fileUri);
    static ani_object CreateAssetRequestFromRealPath(ani_env *env, const std::string &realPath);

    static ani_object addResourceByFileUri(ani_env *env, ani_object aniObject, ani_enum_item resourceTypeItem,
        ani_string fileUri);
    static ani_object addResourceByArrayBuffer(ani_env *env, ani_object aniObject,
        ani_enum_item resourceType, ani_object arrayBuffer);
    static ani_object addResourceByPhotoProxy(ani_env *env, ani_object aniObject, ani_enum_item resourceTypeItem,
        ani_object proxy);
    static ani_object AddMovingPhotoVideoResourceByFileUri(ani_env *env, ani_object aniObject, ani_string fileUri);
    static ani_object AddMovingPhotoVideoResourceByArrayBuffer(ani_env *env, ani_object aniObject,
        ani_object arrayBuffer);

    static ani_object getAsset(ani_env *env, ani_object aniObject);
    static ani_object deleteAssetsByPhotoAsset(ani_env *env, ani_object context, ani_object assets);
    static ani_object deleteAssetsByUriList(ani_env *env, ani_object context, ani_object uriList);

    void RecordChangeOperation(AssetChangeOperation changeOperation);
    bool Contains(AssetChangeOperation changeOperation) const;
    bool ContainsResource(ResourceType resourceType) const;
    bool IsMovingPhoto() const;
    bool CheckMovingPhotoResource(ResourceType resourceType) const;
    bool CheckEffectModeWriteOperation();
    bool CheckMovingPhotoWriteOperation();
    bool CheckChangeOperations(ani_env *env);
    int32_t CreateAssetBySecurityComponent(std::string &assetUri);
    int32_t CopyToMediaLibrary(bool isCreation, AddResourceMode mode);
    int32_t PutMediaAssetEditData(DataShare::DataShareValuesBucket& valuesBucket);
    void SetNewFileAsset(int32_t id, const std::string& uri);
    int32_t CopyFileToMediaLibrary(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo = false);
    int32_t CopyDataBufferToMediaLibrary(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo = false);
    int32_t CopyMovingPhotoVideo(const std::string& assetUri);
    int32_t SubmitCache(bool isCreation, bool isSetEffectMode);

    std::shared_ptr<FileAsset> GetFileAssetInstance() const;
    sptr<PhotoProxy> GetPhotoProxyObj();
    void ReleasePhotoProxyObj();
    uint32_t FetchAddCacheFileId();
    void SetCacheFileName(std::string& fileName);
    void SetCacheMovingPhotoVideoName(std::string& fileName);
    std::string GetFileRealPath() const;
    AddResourceMode GetAddResourceMode() const;
    void* GetDataBuffer() const;
    size_t GetDataBufferSize() const;
    std::string GetMovingPhotoVideoPath() const;
    AddResourceMode GetMovingPhotoVideoMode() const;
    void* GetMovingPhotoVideoBuffer() const;
    size_t GetMovingPhotoVideoSize() const;

private:
    static ani_object CreateAssetRequestCommon(ani_env *env,
        std::unique_ptr<MediaAssetChangeRequestAniContext>& context);

    static std::atomic<uint32_t> cacheFileId_;
    sptr<PhotoProxy> photoProxy_ = nullptr;
    std::shared_ptr<FileAsset> fileAsset_;
    std::shared_ptr<MediaAssetEditData> editData_ = nullptr;
    std::string cacheFileName_;
    DataShare::DataShareValuesBucket creationValuesBucket_;
    std::vector<AssetChangeOperation> assetChangeOperations_;
    std::string realPath_;
    void* dataBuffer_;
    size_t dataBufferSize_;
    AddResourceMode addResourceMode_;
    std::string movingPhotoVideoRealPath_;
    std::string cacheMovingPhotoVideoName_;
    void* movingPhotoVideoDataBuffer_;
    size_t movingPhotoVideoBufferSize_;
    AddResourceMode movingPhotoVideoResourceMode_;
    std::vector<ResourceType> addResourceTypes_; // support adding resource multiple times
};

struct MediaAssetChangeRequestAniContext : public AniError {
    MediaAssetChangeRequestAni* objectInfo;
    std::vector<AssetChangeOperation> assetChangeOperations;
    std::vector<ResourceType> addResourceTypes;
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    std::vector<std::string> uris;
    std::string appName;
    std::string realPath;
    int32_t fd;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_ANI_H