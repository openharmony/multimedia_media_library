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

#include "media_asset_change_request_impl.h"

#include <fcntl.h>
#include <sys/sendfile.h>

#include "media_asset_impl.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "media_column.h"
#include "file_uri.h"
#include "directory_ex.h"
#include "medialibrary_db_const.h"
#include "avmetadatahelper.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "image_packer.h"
#include "permission_utils.h"
#include "media_userfile_client.h"
#include "userfilemgr_uri.h"

using namespace std;
using namespace OHOS::Media;
using namespace OHOS::Security::AccessToken;

atomic<uint32_t> OH_MediaAssetChangeRequest::cacheFileId_(0);
const string MOVING_PHOTO_VIDEO_EXTENSION = "mp4";
const string API_VERSION = "api_version";

OH_MediaAssetChangeRequest::OH_MediaAssetChangeRequest(OH_MediaAsset* mediaAsset)
{
    mediaAsset_ = mediaAsset;
    movingPhotoVideoDataBuffer_ = nullptr;
    dataBuffer_ = nullptr;
    movingPhotoVideoResourceMode_ = AddResourceMode::DEFAULT;
    addResourceMode_ = AddResourceMode::DEFAULT;
    movingPhotoVideoBufferSize_ = 0;
    dataBufferSize_ = 0;
}

OH_MediaAssetChangeRequest::~OH_MediaAssetChangeRequest()
{
    mediaAsset_ = nullptr;
    if (movingPhotoVideoDataBuffer_ != nullptr) {
        delete[] movingPhotoVideoDataBuffer_;
        movingPhotoVideoDataBuffer_ = nullptr;
    }

    if (dataBuffer_ != nullptr) {
        delete[] dataBuffer_;
        dataBuffer_ = nullptr;
    }

    if (editData_ != nullptr) {
        editData_ = nullptr;
    }

    addResourceTypes_.clear();
    assetChangeOperations_.clear();
}

MediaLibrary_ErrorCode OH_MediaAssetChangeRequest::SaveCameraPhoto(MediaLibrary_ImageFileType imageFileType)
{
    CHECK_AND_RETURN_RET_LOG(imageFileType == MEDIA_LIBRARY_IMAGE_JPEG, MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED,
        "imageFileType not support");

    unique_lock<mutex> ulock(mutex_);
    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "fileAsset get failed!");

    RecordChangeOperation(AssetChangeOperation::SAVE_CAMERA_PHOTO);
    return MEDIA_LIBRARY_OK;
}

MediaLibrary_ErrorCode OH_MediaAssetChangeRequest::DiscardCameraPhoto()
{
    unique_lock<mutex> ulock(mutex_);
    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "fileAsset get failed!");

    RecordChangeOperation(AssetChangeOperation::DISCARD_CAMERA_PHOTO);
    return MEDIA_LIBRARY_OK;
}

MediaLibrary_ErrorCode OH_MediaAssetChangeRequest::AddResourceWithBuffer(MediaLibrary_ResourceType resourceType,
    uint8_t* buffer, uint32_t length)
{
    unique_lock<mutex> ulock(mutex_);
    CHECK_AND_RETURN_RET_LOG(CheckWriteOperation(resourceType), MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED,
        "operation not support");

    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "fileAsset get failed!");

    if ((fileAsset->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) &&
        resourceType == static_cast<int32_t>(MediaLibrary_ResourceType::MEDIA_LIBRARY_VIDEO_RESOURCE)) {
        if (movingPhotoVideoDataBuffer_ != nullptr) {
            delete[] movingPhotoVideoDataBuffer_;
        }
        movingPhotoVideoDataBuffer_ = new uint8_t[length + 1];
        CHECK_AND_RETURN_RET_LOG(movingPhotoVideoDataBuffer_ != nullptr, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "create movingPhotoVideoDataBuffer_ failed!");

        movingPhotoVideoBufferSize_ = length;
        if (length > 0) {
            int ret = memcpy_s(movingPhotoVideoDataBuffer_, length + 1, buffer, length);
            CHECK_AND_RETURN_RET_LOG(ret == EOK, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
                "memcpy buffer failed!");
        }

        if (!(CheckMovingPhotoVideo(static_cast<void*>(movingPhotoVideoDataBuffer_),
            static_cast<uint32_t>(length)))) {
            MEDIA_ERR_LOG("invalid param code");
            return MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR;
        }

        movingPhotoVideoResourceMode_ = AddResourceMode::DATA_BUFFER;
        RecordChangeOperation(AssetChangeOperation::ADD_RESOURCE);
        addResourceTypes_.push_back(MediaLibrary_ResourceType::MEDIA_LIBRARY_VIDEO_RESOURCE);
        return MEDIA_LIBRARY_OK;
    }

    if (dataBuffer_ != nullptr) {
        delete[] dataBuffer_;
    }
    dataBuffer_ = new uint8_t[length + 1];
    CHECK_AND_RETURN_RET_LOG(dataBuffer_ != nullptr, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
        "create dataBuffer_ failed!");

    dataBufferSize_ = length;
    if (length > 0) {
        int ret = memcpy_s(dataBuffer_, length + 1, buffer, length);
        CHECK_AND_RETURN_RET_LOG(ret == EOK, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "memcpy buffer failed!");
    }
    addResourceMode_ = AddResourceMode::DATA_BUFFER;
    RecordChangeOperation(AssetChangeOperation::ADD_RESOURCE);
    addResourceTypes_.push_back(resourceType);
    return MEDIA_LIBRARY_OK;
}

MediaLibrary_ErrorCode OH_MediaAssetChangeRequest::ApplyChanges()
{
    unique_lock<mutex> ulock(mutex_);
    bool result = CheckChangeOperations();
    CHECK_AND_RETURN_RET_LOG(result, MEDIA_LIBRARY_PARAMETER_ERROR, "Failed to check asset change request operations");

    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR, "fileAsset is nullptr");

    unordered_set<AssetChangeOperation> appliedOperations;
    for (const auto& changeOperation : assetChangeOperations_) {
        if (appliedOperations.find(changeOperation) != appliedOperations.end()) {
            continue;
        }

        bool valid = false;
        if (changeOperation == AssetChangeOperation::CREATE_FROM_SCRATCH ||
            changeOperation == AssetChangeOperation::SET_EDIT_DATA) {
            valid = true;
        } else {
            valid = ChangeOperationExecute(changeOperation);
        }

        if (!valid) {
            MEDIA_ERR_LOG("Failed to apply asset change request, operation: %{public}d", changeOperation);
            return MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED;
        }
        appliedOperations.insert(changeOperation);
    }
    assetChangeOperations_.clear();
    addResourceTypes_.clear();
    return MEDIA_LIBRARY_OK;
}

bool OH_MediaAssetChangeRequest::IsMovingPhoto()
{
    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, false, "fileAsset is nullptr");

    return fileAsset->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO);
}

bool OH_MediaAssetChangeRequest::CheckWriteOperation(MediaLibrary_ResourceType resourceType)
{
    if (IsMovingPhoto()) {
        CHECK_AND_RETURN_RET_LOG(CheckMovingPhotoResource(resourceType), false,
            "Failed to check resource to add for moving photo");
        return true;
    }

    if (Contains(AssetChangeOperation::CREATE_FROM_URI) ||
        Contains(AssetChangeOperation::GET_WRITE_CACHE_HANDLER) ||
        Contains(AssetChangeOperation::ADD_RESOURCE)) {
        MEDIA_ERR_LOG("The previous asset creation/modification request has not been applied");
        return false;
    }
    return true;
}

bool OH_MediaAssetChangeRequest::CheckMovingPhotoResource(MediaLibrary_ResourceType resourceType)
{
    bool isResourceTypeVaild = !ContainsResource(resourceType);
    int addResourceTimes =
        count(assetChangeOperations_.begin(), assetChangeOperations_.end(), AssetChangeOperation::ADD_RESOURCE);
    return isResourceTypeVaild && addResourceTimes <= 1;
}

bool OH_MediaAssetChangeRequest::ContainsResource(MediaLibrary_ResourceType resourceType)
{
    return find(addResourceTypes_.begin(), addResourceTypes_.end(), resourceType) != addResourceTypes_.end();
}

bool OH_MediaAssetChangeRequest::Contains(AssetChangeOperation changeOperation)
{
    return find(assetChangeOperations_.begin(), assetChangeOperations_.end(), changeOperation) !=
           assetChangeOperations_.end();
}

int32_t OH_MediaAssetChangeRequest::OpenWriteCacheHandler(bool isMovingPhotoVideo)
{
    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_FAIL, "fileAsset is null");

    // specify mp4 extension for cache file of moving photo video
    string extension = isMovingPhotoVideo ? MOVING_PHOTO_VIDEO_EXTENSION
        : MediaFileUtils::GetExtensionFromPath(fileAsset->GetDisplayName());
    int64_t currentTimestamp = MediaFileUtils::UTCTimeNanoSeconds();
    uint32_t cacheFileId = FetchAddCacheFileId();
    string cacheFileName = to_string(currentTimestamp) + "_" + to_string(cacheFileId) + "." + extension;
    string uri = PhotoColumn::PHOTO_CACHE_URI_PREFIX + cacheFileName;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri openCacheUri(uri);
    int32_t ret = UserFileClient::OpenFile(openCacheUri, MEDIA_FILEMODE_WRITEONLY);
    CHECK_AND_RETURN_RET_LOG(ret != E_PERMISSION_DENIED, ret, "Open cache file failed, permission denied");

    if (ret < 0) {
        MEDIA_ERR_LOG("Open cache file failed, ret: %{public}d", ret);
    }

    if (isMovingPhotoVideo) {
        cacheMovingPhotoVideoName_ = cacheFileName;
    } else {
        cacheFileName_ = cacheFileName;
    }
    return ret;
}

uint32_t OH_MediaAssetChangeRequest::FetchAddCacheFileId()
{
    return cacheFileId_.fetch_add(1);
}

void OH_MediaAssetChangeRequest::RecordChangeOperation(AssetChangeOperation changeOperation)
{
    if ((changeOperation == AssetChangeOperation::GET_WRITE_CACHE_HANDLER ||
        changeOperation == AssetChangeOperation::ADD_RESOURCE ||
        changeOperation == AssetChangeOperation::ADD_FILTERS) &&
        Contains(AssetChangeOperation::CREATE_FROM_SCRATCH)) {
        assetChangeOperations_.insert(assetChangeOperations_.begin() + 1, changeOperation);
        return;
    }
    assetChangeOperations_.push_back(changeOperation);
}

bool OH_MediaAssetChangeRequest::CheckMovingPhotoVideo(void* dataBuffer, size_t size)
{
    auto dataSource = make_shared<MediaDataSource>(dataBuffer, static_cast<int64_t>(size));
    auto avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    CHECK_AND_RETURN_RET_LOG(avMetadataHelper != nullptr, true,
        "Failed to create AVMetadataHelper, ignore checking duration of moving photo video");

    int32_t err = avMetadataHelper->SetSource(dataSource);
    if (err != E_OK) {
        MEDIA_ERR_LOG("SetSource failed for dataSource, err = %{public}d", err);
        return false;
    }

    unordered_map<int32_t, string> resultMap = avMetadataHelper->ResolveMetadata();
    if (resultMap.find(AV_KEY_DURATION) == resultMap.end()) {
        MEDIA_ERR_LOG("AV_KEY_DURATION does not exist");
        return false;
    }

    string durationStr = resultMap.at(AV_KEY_DURATION);
    int32_t duration = atoi(durationStr.c_str());
    if (!MediaFileUtils::CheckMovingPhotoVideoDuration(duration)) {
        MEDIA_ERR_LOG("Failed to check duration of moving photo video");
        return false;
    }
    return true;
}

bool OH_MediaAssetChangeRequest::CheckChangeOperations()
{
    CHECK_AND_RETURN_RET_LOG(assetChangeOperations_.size() != 0, false, "None request to apply");

    bool isCreateFromScratch = Contains(AssetChangeOperation::CREATE_FROM_SCRATCH);
    bool isCreateFromUri = Contains(AssetChangeOperation::CREATE_FROM_URI);
    bool containsEdit = Contains(AssetChangeOperation::SET_EDIT_DATA);
    bool containsGetHandler = Contains(AssetChangeOperation::GET_WRITE_CACHE_HANDLER);
    bool containsAddResource = Contains(AssetChangeOperation::ADD_RESOURCE);
    bool isSaveCameraPhoto = Contains(AssetChangeOperation::SAVE_CAMERA_PHOTO);
    if ((isCreateFromScratch || containsEdit) && !containsGetHandler && !containsAddResource && !isSaveCameraPhoto) {
        MEDIA_ERR_LOG("Cannot create or edit asset without data to write");
        return false;
    }

    if (containsEdit && (isCreateFromScratch || isCreateFromUri)) {
        MEDIA_ERR_LOG("Cannot create together with edit");
        return false;
    }

    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, false, "fileAsset is null");

    AssetChangeOperation firstOperation = assetChangeOperations_.front();
    if (fileAsset->GetId() <= 0 && firstOperation != AssetChangeOperation::CREATE_FROM_SCRATCH &&
        firstOperation != AssetChangeOperation::CREATE_FROM_URI) {
        MEDIA_ERR_LOG("Invalid asset change request");
        return false;
    }

    bool isMovingPhoto = IsMovingPhoto();
    if (isMovingPhoto && !CheckMovingPhotoWriteOperation()) {
        MEDIA_ERR_LOG("Invalid write operation for moving photo");
        return false;
    }
    return true;
}

bool OH_MediaAssetChangeRequest::CheckMovingPhotoWriteOperation()
{
    if (!Contains(AssetChangeOperation::ADD_RESOURCE)) {
        return true;
    }

    if (!Contains(AssetChangeOperation::CREATE_FROM_SCRATCH)) {
        MEDIA_ERR_LOG("Moving photo is not supported to edit now");
        return false;
    }

    int addResourceTimes =
        count(assetChangeOperations_.begin(), assetChangeOperations_.end(), AssetChangeOperation::ADD_RESOURCE);
    bool isImageExist = ContainsResource(MediaLibrary_ResourceType::MEDIA_LIBRARY_IMAGE_RESOURCE);
    bool isVideoExist = ContainsResource(MediaLibrary_ResourceType::MEDIA_LIBRARY_VIDEO_RESOURCE);
    return addResourceTimes == 2 && isImageExist && isVideoExist; // must add resource 2 times with image and video
}

bool OH_MediaAssetChangeRequest::ChangeOperationExecute(AssetChangeOperation option)
{
    bool ret = false;
    switch (option) {
        case AssetChangeOperation::GET_WRITE_CACHE_HANDLER:
            ret = SubmitCacheExecute();
            break;
        case AssetChangeOperation::ADD_RESOURCE:
            ret = AddResourceExecute();
            break;
        case AssetChangeOperation::SAVE_CAMERA_PHOTO:
            ret = SaveCameraPhotoExecute();
            break;
        case AssetChangeOperation::DISCARD_CAMERA_PHOTO:
            ret = DiscardCameraPhotoExecute();
            break;
        default:
            break;
    }
    return ret;
}

bool OH_MediaAssetChangeRequest::SubmitCacheExecute()
{
    bool isCreation = IsCreation();
    bool isSetEffectMode = IsSetEffectMode();
    int32_t ret = SubmitCache(isCreation, isSetEffectMode);
    if (ret < 0) {
        MEDIA_ERR_LOG("Failed to write cache, ret: %{public}d", ret);
        return false;
    }
    return true;
}

bool OH_MediaAssetChangeRequest::AddResourceExecute()
{
    if (!HasWritePermission()) {
        return WriteBySecurityComponent();
    }

    if (IsMovingPhoto() && HasAddResource(MediaLibrary_ResourceType::MEDIA_LIBRARY_VIDEO_RESOURCE) &&
        !AddMovingPhotoVideoExecute()) {
        MEDIA_ERR_LOG("Faild to write cache file for video of moving photo");
        return false;
    }

    if (IsMovingPhoto() && !HasAddResource(MediaLibrary_ResourceType::MEDIA_LIBRARY_IMAGE_RESOURCE)) {
        return SubmitCacheExecute();
    }
    int32_t cacheFd = OpenWriteCacheHandler();
    if (cacheFd < 0) {
        MEDIA_ERR_LOG("Failed to open write cache handler, err: %{public}d", cacheFd);
        return false;
    }
    OHOS::UniqueFd uniqueFd(cacheFd);
    AddResourceMode mode = addResourceMode_;
    if (!AddResourceByMode(uniqueFd, mode)) {
        MEDIA_ERR_LOG("Faild to write cache file");
        return false;
    }
    return SubmitCacheExecute();
}

bool OH_MediaAssetChangeRequest::SaveCameraPhotoExecute()
{
    bool containsAddResource = find(assetChangeOperations_.begin(), assetChangeOperations_.end(),
        AssetChangeOperation::ADD_RESOURCE) != assetChangeOperations_.end();
    if (containsAddResource && !PermissionUtils::IsSystemApp()) {
        // remove high quality photo
        MEDIA_INFO_LOG("discard high quality photo because add resource by third app");
        DiscardHighQualityPhoto();
    }

    // The watermark will trigger the scan. If the watermark is turned on, there is no need to trigger the scan again.
    bool needScan = std::find(assetChangeOperations_.begin(), assetChangeOperations_.end(),
        AssetChangeOperation::ADD_FILTERS) == assetChangeOperations_.end();

    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, false, "fileAsset is nullptr");

    std::string uriStr = PAH_SAVE_CAMERA_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    MediaFileUtils::UriAppendKeyValue(uriStr, MEDIA_OPERN_KEYWORD, to_string(needScan));
    MediaFileUtils::UriAppendKeyValue(uriStr, PhotoColumn::MEDIA_FILE_PATH, fileAsset->GetUri());
    MediaFileUtils::UriAppendKeyValue(uriStr, PhotoColumn::MEDIA_ID, to_string(fileAsset->GetId()));
    MediaFileUtils::UriAppendKeyValue(uriStr, PhotoColumn::PHOTO_SUBTYPE,
        to_string(fileAsset->GetPhotoSubType()));
    Uri uri(uriStr);
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_IS_TEMP, false);
    OHOS::DataShare::DataSharePredicates predicates;
    bool ret = UserFileClient::Update(uri, predicates, valuesBucket);
    CHECK_AND_RETURN_RET_LOG(ret, false, "save camera photo fail");

    return true;
}

bool OH_MediaAssetChangeRequest::DiscardCameraPhotoExecute()
{
    OHOS::DataShare::DataSharePredicates predicates;
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_IS_TEMP, true);

    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileAsset->GetId()));

    string uri = PAH_DISCARD_CAMERA_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        MEDIA_ERR_LOG("Failed to update property of asset, err: %{public}d", changedRows);
        return false;
    }
    return true;
}

bool OH_MediaAssetChangeRequest::HasWritePermission()
{
    AccessTokenID tokenCaller = OHOS::IPCSkeleton::GetSelfTokenID();
    int result = AccessTokenKit::VerifyAccessToken(tokenCaller, PERM_WRITE_IMAGEVIDEO);
    return result == PermissionState::PERMISSION_GRANTED;
}

bool OH_MediaAssetChangeRequest::WriteBySecurityComponent()
{
    bool isCreation = IsCreation();
    int32_t ret = E_FAIL;
    bool isCreateFromUri = find(assetChangeOperations_.begin(), assetChangeOperations_.end(),
        AssetChangeOperation::CREATE_FROM_URI) != assetChangeOperations_.end();
    if (isCreateFromUri) {
        ret = CopyToMediaLibrary(isCreation, AddResourceMode::FILE_URI);
    } else {
        ret = CopyToMediaLibrary(isCreation, addResourceMode_);
    }
    if (ret < 0) {
        MEDIA_ERR_LOG("Failed to write by security component, ret: %{public}d", ret);
        return false;
    }
    return true;
}

bool OH_MediaAssetChangeRequest::IsCreation()
{
    bool isCreateFromScratch = find(assetChangeOperations_.begin(), assetChangeOperations_.end(),
        AssetChangeOperation::CREATE_FROM_SCRATCH) != assetChangeOperations_.end();
    bool isCreateFromUri = find(assetChangeOperations_.begin(), assetChangeOperations_.end(),
        AssetChangeOperation::CREATE_FROM_URI) != assetChangeOperations_.end();
    return isCreateFromScratch || isCreateFromUri;
}

int32_t OH_MediaAssetChangeRequest::CopyToMediaLibrary(bool isCreation, AddResourceMode mode)
{
    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_FAIL, "fileAsset is null");

    int32_t ret = E_ERR;
    int32_t id = 0;
    string assetUri;
    if (isCreation) {
        ret = CreateAssetBySecurityComponent(assetUri);
        CHECK_AND_RETURN_RET_LOG(ret > 0, (ret == 0 ? E_ERR : ret), "Failed to create asset by security component");
        id = ret;
    } else {
        assetUri = fileAsset->GetUri();
    }
    CHECK_AND_RETURN_RET_LOG(!assetUri.empty(), E_ERR, "Failed to check empty asset uri");

    if (IsMovingPhoto()) {
        ret = CopyMovingPhotoVideo(assetUri);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Failed to copy data to moving photo video with error: %{public}d", ret);
            return ret;
        }
    }

    Uri uri(assetUri);
    OHOS::UniqueFd destFd(UserFileClient::OpenFile(uri, MEDIA_FILEMODE_WRITEONLY));
    if (destFd.Get() < 0) {
        MEDIA_ERR_LOG("Failed to open %{private}s with error: %{public}d", assetUri.c_str(), destFd.Get());
        return destFd.Get();
    }

    if (mode == AddResourceMode::FILE_URI) {
        ret = CopyFileToMediaLibrary(destFd);
    } else if (mode == AddResourceMode::DATA_BUFFER) {
        ret = CopyDataBufferToMediaLibrary(destFd);
    } else {
        MEDIA_ERR_LOG("Invalid mode: %{public}d", mode);
        return E_INVALID_VALUES;
    }

    if (ret == E_OK && isCreation) {
        SetNewFileAsset(id, assetUri);
    }
    return ret;
}

int32_t OH_MediaAssetChangeRequest::CreateAssetBySecurityComponent(string& assetUri)
{
    bool isValid = false;
    string title = creationValuesBucket_.Get(PhotoColumn::MEDIA_TITLE, isValid);
    CHECK_AND_RETURN_RET_LOG(isValid, E_FAIL, "Failed to get title");

    string extension = creationValuesBucket_.Get(ASSET_EXTENTION, isValid);
    CHECK_AND_RETURN_RET_LOG(isValid && MediaFileUtils::CheckDisplayName(title + "." + extension) == E_OK, E_FAIL,
        "Failed to check displayName");

    creationValuesBucket_.valuesMap.erase(MEDIA_DATA_DB_NAME);
    string uri = PAH_CREATE_PHOTO_COMPONENT;
    OHOS::Media::MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri createAssetUri(uri);
    return UserFileClient::InsertExt(createAssetUri, creationValuesBucket_, assetUri);
}

int32_t OH_MediaAssetChangeRequest::CopyMovingPhotoVideo(const string& assetUri)
{
    CHECK_AND_RETURN_RET_LOG(!assetUri.empty(), E_INVALID_URI, "Failed to check empty asset uri");

    string videoUri = assetUri;
    MediaFileUtils::UriAppendKeyValue(videoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, OPEN_MOVING_PHOTO_VIDEO);
    Uri uri(videoUri);
    int videoFd = UserFileClient::OpenFile(uri, MEDIA_FILEMODE_WRITEONLY);
    CHECK_AND_RETURN_RET_LOG(videoFd >= 0, videoFd, "Failed to open video of moving photo with write-only mode");

    int32_t ret = E_ERR;
    OHOS::UniqueFd uniqueFd(videoFd);
    if (movingPhotoVideoResourceMode_ == AddResourceMode::FILE_URI) {
        ret = CopyFileToMediaLibrary(uniqueFd, true);
    } else if (movingPhotoVideoResourceMode_ == AddResourceMode::DATA_BUFFER) {
        ret = CopyDataBufferToMediaLibrary(uniqueFd, true);
    } else {
        MEDIA_ERR_LOG("Invalid mode: %{public}d", movingPhotoVideoResourceMode_);
        return E_INVALID_VALUES;
    }
    return ret;
}

int32_t OH_MediaAssetChangeRequest::CopyFileToMediaLibrary(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo)
{
    string srcRealPath = isMovingPhotoVideo ? movingPhotoVideoRealPath_ : realPath_;
    CHECK_AND_RETURN_RET_LOG(!srcRealPath.empty(), E_FAIL, "Failed to check real path of source");

    string absFilePath;
    CHECK_AND_RETURN_RET_LOG(OHOS::PathToRealPath(srcRealPath, absFilePath), E_FAIL, "Not real path %{private}s",
        srcRealPath.c_str());

    OHOS::UniqueFd srcFd(open(absFilePath.c_str(), O_RDONLY));
    if (srcFd.Get() < 0) {
        MEDIA_ERR_LOG("Failed to open %{private}s, errno=%{public}d", absFilePath.c_str(), errno);
        return srcFd.Get();
    }

    int32_t err = SendFile(srcFd, destFd);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to send file from %{public}d to %{public}d", srcFd.Get(), destFd.Get());
    }
    return err;
}

int32_t OH_MediaAssetChangeRequest::CopyDataBufferToMediaLibrary(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo)
{
    size_t offset = 0;
    size_t length = isMovingPhotoVideo ? movingPhotoVideoBufferSize_ : dataBufferSize_;
    void* dataBuffer = isMovingPhotoVideo ? movingPhotoVideoDataBuffer_ : dataBuffer_;
    while (offset < length) {
        ssize_t written = write(destFd.Get(), (char*)dataBuffer + offset, length - offset);
        if (written < 0) {
            MEDIA_ERR_LOG("Failed to copy data buffer, return %{public}d", static_cast<int>(written));
            return written;
        }
        offset += static_cast<size_t>(written);
    }
    return E_OK;
}

void OH_MediaAssetChangeRequest::SetNewFileAsset(int32_t id, const string& uri)
{
    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("fileAsset is nullptr");
        return;
    }

    if (id <= 0 || uri.empty()) {
        MEDIA_ERR_LOG("Failed to check file_id: %{public}d and uri: %{public}s", id, uri.c_str());
        return;
    }
    fileAsset->SetId(id);
    fileAsset->SetUri(uri);
    fileAsset->SetTimePending(0);
}

bool OH_MediaAssetChangeRequest::SendToCacheFile(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo)
{
    string realPath = isMovingPhotoVideo ? movingPhotoVideoRealPath_ : realPath_;
    string absFilePath;
    if (!OHOS::PathToRealPath(realPath, absFilePath)) {
        MEDIA_ERR_LOG("Not real path %{private}s, errno=%{public}d", realPath.c_str(), errno);
        return false;
    }

    OHOS::UniqueFd srcFd(open(absFilePath.c_str(), O_RDONLY));
    if (srcFd.Get() < 0) {
        MEDIA_ERR_LOG("Failed to open file, errno=%{public}d", errno);
        return false;
    }

    int32_t err = SendFile(srcFd, destFd);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to send file from %{public}d to %{public}d", srcFd.Get(), destFd.Get());
        return false;
    }
    return true;
}

bool OH_MediaAssetChangeRequest::IsSetEffectMode()
{
    return find(assetChangeOperations_.begin(), assetChangeOperations_.end(),
        AssetChangeOperation::SET_MOVING_PHOTO_EFFECT_MODE) != assetChangeOperations_.end();
}

int32_t OH_MediaAssetChangeRequest::SubmitCache(bool isCreation, bool isSetEffectMode)
{
    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_FAIL, "fileAsset is null");
    CHECK_AND_RETURN_RET_LOG(!cacheFileName_.empty() || !cacheMovingPhotoVideoName_.empty(), E_FAIL,
        "Failed to check cache file");

    string uri = PAH_SUBMIT_CACHE;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri submitCacheUri(uri);
    string assetUri;
    int32_t ret;
    if (isCreation) {
        bool isValid = false;
        string displayName = creationValuesBucket_.Get(MEDIA_DATA_DB_NAME, isValid);
        CHECK_AND_RETURN_RET_LOG(
            isValid && MediaFileUtils::CheckDisplayName(displayName) == E_OK, E_FAIL, "Failed to check displayName");

        creationValuesBucket_.Put(CACHE_FILE_NAME, cacheFileName_);
        if (IsMovingPhoto()) {
            creationValuesBucket_.Put(CACHE_MOVING_PHOTO_VIDEO_NAME, cacheMovingPhotoVideoName_);
        }
        ret = UserFileClient::InsertExt(submitCacheUri, creationValuesBucket_, assetUri);
    } else {
        OHOS::DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.Put(PhotoColumn::MEDIA_ID, fileAsset->GetId());
        valuesBucket.Put(CACHE_FILE_NAME, cacheFileName_);
        ret = PutMediaAssetEditData(valuesBucket);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Failed to put editData");

        if (isSetEffectMode) {
            valuesBucket.Put(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, fileAsset->GetMovingPhotoEffectMode());
            valuesBucket.Put(CACHE_MOVING_PHOTO_VIDEO_NAME, cacheMovingPhotoVideoName_);
        }
        ret = UserFileClient::Insert(submitCacheUri, valuesBucket);
    }

    if (ret > 0 && isCreation) {
        SetNewFileAsset(ret, assetUri);
    }
    cacheFileName_.clear();
    cacheMovingPhotoVideoName_.clear();
    return ret;
}

int32_t OH_MediaAssetChangeRequest::SendFile(const OHOS::UniqueFd& srcFd, const OHOS::UniqueFd& destFd)
{
    if (srcFd.Get() < 0 || destFd.Get() < 0) {
        MEDIA_ERR_LOG("Failed to check srcFd: %{public}d and destFd: %{public}d", srcFd.Get(), destFd.Get());
        return E_ERR;
    }

    struct stat statSrc {};
    int32_t status = fstat(srcFd.Get(), &statSrc);
    if (status != 0) {
        MEDIA_ERR_LOG("Failed to get file stat, errno=%{public}d", errno);
        return status;
    }

    off_t offset = 0;
    off_t fileSize = statSrc.st_size;
    while (offset < fileSize) {
        ssize_t sent = sendfile(destFd.Get(), srcFd.Get(), &offset, fileSize - offset);
        if (sent < 0) {
            MEDIA_ERR_LOG("Failed to sendfile with errno=%{public}d, srcFd=%{private}d, destFd=%{private}d", errno,
                srcFd.Get(), destFd.Get());
            return sent;
        }
    }

    return E_OK;
}

int32_t OH_MediaAssetChangeRequest::PutMediaAssetEditData(OHOS::DataShare::DataShareValuesBucket& valuesBucket)
{
    if (editData_ == nullptr) {
        return E_OK;
    }

    string compatibleFormat = editData_->GetCompatibleFormat();
    CHECK_AND_RETURN_RET_LOG(!compatibleFormat.empty(), E_FAIL, "Failed to check compatibleFormat");

    string formatVersion = editData_->GetFormatVersion();
    CHECK_AND_RETURN_RET_LOG(!formatVersion.empty(), E_FAIL, "Failed to check formatVersion");

    string data = editData_->GetData();
    CHECK_AND_RETURN_RET_LOG(!data.empty(), E_FAIL, "Failed to check data");

    valuesBucket.Put(COMPATIBLE_FORMAT, compatibleFormat);
    valuesBucket.Put(FORMAT_VERSION, formatVersion);
    valuesBucket.Put(EDIT_DATA, data);
    return E_OK;
}

bool OH_MediaAssetChangeRequest::HasAddResource(MediaLibrary_ResourceType resourceType)
{
    return find(addResourceTypes_.begin(), addResourceTypes_.end(), resourceType) !=
        addResourceTypes_.end();
}

bool OH_MediaAssetChangeRequest::AddMovingPhotoVideoExecute()
{
    int32_t cacheVideoFd = OpenWriteCacheHandler(true);
    if (cacheVideoFd < 0) {
        MEDIA_ERR_LOG("Failed to open cache moving photo video, err: %{public}d", cacheVideoFd);
        return false;
    }
    OHOS::UniqueFd uniqueFd(cacheVideoFd);
    AddResourceMode mode = movingPhotoVideoResourceMode_;
    if (!AddResourceByMode(uniqueFd, mode, true)) {
        MEDIA_ERR_LOG("Faild to write cache file");
        return false;
    }
    return true;
}

bool OH_MediaAssetChangeRequest::AddResourceByMode(const OHOS::UniqueFd& uniqueFd,
    AddResourceMode mode, bool isMovingPhotoVideo)
{
    bool isWriteSuccess = false;
    if (mode == AddResourceMode::DATA_BUFFER) {
        isWriteSuccess = WriteCacheByArrayBuffer(uniqueFd, isMovingPhotoVideo);
    } else if (mode == AddResourceMode::FILE_URI) {
        isWriteSuccess = SendToCacheFile(uniqueFd, isMovingPhotoVideo);
    } else {
        MEDIA_ERR_LOG("Unsupported addResource mode");
    }
    return isWriteSuccess;
}

bool OH_MediaAssetChangeRequest::WriteCacheByArrayBuffer(const OHOS::UniqueFd& destFd, bool isMovingPhotoVideo)
{
    size_t offset = 0;
    size_t length = isMovingPhotoVideo ? movingPhotoVideoBufferSize_ : dataBufferSize_;
    void* dataBuffer = isMovingPhotoVideo ? movingPhotoVideoDataBuffer_ : dataBuffer_;
    while (offset < length) {
        ssize_t written = write(destFd.Get(), (char*)dataBuffer + offset, length - offset);
        if (written < 0) {
            MEDIA_ERR_LOG("Failed to write data buffer to cache file, return %{public}d", static_cast<int>(written));
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return true;
}

void OH_MediaAssetChangeRequest::DiscardHighQualityPhoto()
{
    string uriStr = PAH_REMOVE_MSC_TASK;
    OHOS::Media::MediaFileUtils::UriAppendKeyValue(uriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(uriStr);
    OHOS::DataShare::DataSharePredicates predicates;
    int errCode = 0;

    auto fileAsset = mediaAsset_->GetFileAssetInstance();
    vector<string> columns { to_string(fileAsset->GetId()) };
    UserFileClient::Query(uri, predicates, columns, errCode);
}

int32_t MediaDataSource::ReadData(const shared_ptr<AVSharedMemory>& mem, uint32_t length)
{
    if (readPos_ >= size_) {
        MEDIA_ERR_LOG("Failed to check read position");
        return SOURCE_ERROR_EOF;
    }

    if (memcpy_s(mem->GetBase(), mem->GetSize(), (char*)buffer_ + readPos_, length) != E_OK) {
        MEDIA_ERR_LOG("Failed to copy buffer to mem");
        return SOURCE_ERROR_IO;
    }
    readPos_ += static_cast<int64_t>(length);
    return static_cast<int32_t>(length);
}

int32_t MediaDataSource::ReadAt(const shared_ptr<AVSharedMemory>& mem, uint32_t length, int64_t pos)
{
    readPos_ = pos;
    return ReadData(mem, length);
}

int32_t MediaDataSource::ReadAt(int64_t pos, uint32_t length, const shared_ptr<AVSharedMemory>& mem)
{
    readPos_ = pos;
    return ReadData(mem, length);
}

int32_t MediaDataSource::ReadAt(uint32_t length, const shared_ptr<AVSharedMemory>& mem)
{
    return ReadData(mem, length);
}

int32_t MediaDataSource::GetSize(int64_t& size)
{
    size = size_;
    return E_OK;
}
