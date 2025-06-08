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

#include <array>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "directory_ex.h"
#include "file_uri.h"
#include "ani_class_name.h"
#include "image_packer.h"
#include "ipc_skeleton.h"
#include "media_asset_change_request_ani.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_db_const.h"
#include "medialibrary_tracer.h"
#include "permission_utils.h"
#include "photo_proxy_ani.h"
#ifdef HAS_ACE_ENGINE_PART
#include "ui_content.h"
#endif
#include "userfile_client.h"
#include "userfile_manager_types.h"
#include "want.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
using UniqueFd = OHOS::UniqueFd;

namespace OHOS::Media {
std::atomic<uint32_t> MediaAssetChangeRequestAni::cacheFileId_ = 0;
constexpr int64_t CREATE_ASSET_REQUEST_PENDING = -4;

const std::string PAH_SUBTYPE = "subtype";
const std::string CAMERA_SHOT_KEY = "cameraShotKey";
const std::map<std::string, std::string> PHOTO_CREATE_OPTIONS_PARAM = {
    { PAH_SUBTYPE, PhotoColumn::PHOTO_SUBTYPE },
    { CAMERA_SHOT_KEY, PhotoColumn::CAMERA_SHOT_KEY },
};

const std::string TITLE = "title";
const std::map<std::string, std::string> CREATE_OPTIONS_PARAM = {
    { TITLE, PhotoColumn::MEDIA_TITLE },
    { PAH_SUBTYPE, PhotoColumn::PHOTO_SUBTYPE },
};

const std::string DEFAULT_TITLE_TIME_FORMAT = "%Y%m%d_%H%M%S";
const std::string DEFAULT_TITLE_IMG_PREFIX = "IMG_";
const std::string DEFAULT_TITLE_VIDEO_PREFIX = "VID_";
const std::string MOVING_PHOTO_VIDEO_EXTENSION = "mp4";

int32_t MediaDataSource::ReadData(const shared_ptr<AVSharedMemory>& mem, uint32_t length)
{
    if (readPos_ >= size_) {
        ANI_ERR_LOG("Failed to check read position");
        return SOURCE_ERROR_EOF;
    }

    if (memcpy_s(mem->GetBase(), mem->GetSize(), (char*)buffer_ + readPos_, length) != E_OK) {
        ANI_ERR_LOG("Failed to copy buffer to mem");
        return SOURCE_ERROR_IO;
    }
    readPos_ += static_cast<int64_t>(length);
    return static_cast<int32_t>(length);
}

int32_t MediaDataSource::ReadAt(const std::shared_ptr<AVSharedMemory>& mem, uint32_t length, int64_t pos)
{
    readPos_ = pos;
    return ReadData(mem, length);
}

int32_t MediaDataSource::ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory>& mem)
{
    readPos_ = pos;
    return ReadData(mem, length);
}

int32_t MediaDataSource::ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory>& mem)
{
    return ReadData(mem, length);
}

int32_t MediaDataSource::GetSize(int64_t& size)
{
    size = size_;
    return E_OK;
}

ani_status MediaAssetChangeRequestAni::MediaAssetChangeRequestAniInit(ani_env *env)
{
    static const char *className = ANI_CLASS_MEDIA_ASSET_CHANGE_REQUEST.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"create", nullptr, reinterpret_cast<void *>(Constructor)},
        ani_native_function {"addResource", nullptr, reinterpret_cast<void *>(addResourceByFileUri)},
        ani_native_function {"addResource", nullptr, reinterpret_cast<void *>(addResourceByArrayBuffer)},
        ani_native_function {"addResource", nullptr, reinterpret_cast<void *>(addResourceByPhotoProxy)},
        ani_native_function {"createAssetRequest", nullptr, reinterpret_cast<void *>(createAssetRequestSystem)},
        ani_native_function {"createAssetRequest", nullptr, reinterpret_cast<void *>(createAssetRequest)},
        ani_native_function {"createImageAssetRequest", nullptr, reinterpret_cast<void *>(createImageAssetRequest)},
        ani_native_function {"createVideoAssetRequest", nullptr, reinterpret_cast<void *>(createVideoAssetRequest)},
        ani_native_function {"getAsset", nullptr, reinterpret_cast<void *>(getAsset)},
        ani_native_function {"deleteAssetsByPhotoAssetSync", nullptr,
            reinterpret_cast<void *>(deleteAssetsByPhotoAsset)},
        ani_native_function {"deleteAssetsByUriListSync", nullptr, reinterpret_cast<void *>(deleteAssetsByUriList)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_object MediaAssetChangeRequestAni::Constructor(ani_env *env, [[maybe_unused]] ani_class clazz,
    ani_object fileAssetAni)
{
    FileAssetAni* fileAssetAniPtr = FileAssetAni::Unwrap(env, fileAssetAni);
    CHECK_COND_WITH_RET_MESSAGE(env, fileAssetAniPtr != nullptr, nullptr, "fileAssetAniPtr is null");
    auto fileAssetPtr = fileAssetAniPtr->GetFileAssetInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, fileAssetPtr != nullptr, nullptr, "fileAssetPtr is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        fileAssetPtr->GetResultNapiType() == ResultNapiType::TYPE_PHOTOACCESS_HELPER &&
            (fileAssetPtr->GetMediaType() == MEDIA_TYPE_IMAGE || fileAssetPtr->GetMediaType() == MEDIA_TYPE_VIDEO),
        nullptr, "Unsupported type of fileAsset");

    auto nativeHandle = std::make_unique<MediaAssetChangeRequestAni>(fileAssetAniPtr);
    nativeHandle->fileAsset_ = fileAssetPtr;

    static const char *className = ANI_CLASS_MEDIA_ASSET_CHANGE_REQUEST.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    // wrap nativeHandle to aniObject
    ani_object aniObject;
    if (ANI_OK !=env->Object_New(cls, ctor, &aniObject, reinterpret_cast<ani_long>(nativeHandle.release()))) {
        ANI_ERR_LOG("New MediaAssetChangeRequest Fail");
        return nullptr;
    }

    return aniObject;
}

ani_object MediaAssetChangeRequestAni::Wrap(ani_env *env, MediaAssetChangeRequestAni* changeRequest)
{
    static const char *className = ANI_CLASS_MEDIA_ASSET_CHANGE_REQUEST.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return nullptr;
    }

    // wrap nativeHandle to aniObject
    ani_object aniObject;
    if (ANI_OK !=env->Object_New(cls, ctor, &aniObject, reinterpret_cast<ani_long>(changeRequest))) {
        ANI_ERR_LOG("New MediaAssetChangeRequest Fail");
        return nullptr;
    }
    return aniObject;
}

MediaAssetChangeRequestAni* MediaAssetChangeRequestAni::Unwrap(ani_env *env, ani_object aniObject)
{
    ani_long context;
    if (ANI_OK != env->Object_GetFieldByName_Long(aniObject, "nativeHandle", &context)) {
        return nullptr;
    }
    return reinterpret_cast<MediaAssetChangeRequestAni*>(context);
}

MediaAssetChangeRequestAni::MediaAssetChangeRequestAni(FileAssetAni* fileAssetAni)
{
    if (fileAssetAni == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }
    auto fileAsset = fileAssetAni->GetFileAssetInstance();
    if (fileAsset == nullptr) {
        ANI_ERR_LOG("fileAsset is nullptr");
        return;
    }
    if (fileAsset->GetResultNapiType() != ResultNapiType::TYPE_PHOTOACCESS_HELPER ||
        (fileAsset->GetMediaType() != MEDIA_TYPE_IMAGE && fileAsset->GetMediaType() != MEDIA_TYPE_VIDEO)) {
        ANI_ERR_LOG("Unsupported type of fileAsset");
        return;
    }
    fileAsset_ = fileAsset;
}

static void DeleteCache(const std::string& cacheFileName)
{
    if (cacheFileName.empty()) {
        return;
    }

    std::string uri = PhotoColumn::PHOTO_CACHE_URI_PREFIX + cacheFileName;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, std::to_string(MEDIA_API_VERSION_V10));
    Uri deleteCacheUri(uri);
    DataShare::DataSharePredicates predicates;
    int32_t ret = UserFileClient::Delete(deleteCacheUri, predicates);
    if (ret < 0) {
        ANI_ERR_LOG("Failed to delete cache: %{private}s, error: %{public}d", cacheFileName.c_str(), ret);
    }
}

MediaAssetChangeRequestAni::~MediaAssetChangeRequestAni()
{
    DeleteCache(cacheFileName_);
    DeleteCache(cacheMovingPhotoVideoName_);
}

static bool ParseCreateOptions(std::unique_ptr<MediaAssetChangeRequestAniContext>& context,
    const std::unordered_map<std::string, std::variant<int32_t, bool, std::string>>& optionsMap,
    const std::map<std::string, std::string>& createOptionsMap)
{
    if (optionsMap.empty()) {
        ANI_INFO_LOG("optionsMap is empty. There is no need to parse create options.");
        return true;
    }
    for (const auto& [key, value] : optionsMap) {
        auto iter = createOptionsMap.find(key);
        if (iter != createOptionsMap.end()) {
            std::string column = iter->second;
            if (std::holds_alternative<int32_t>(value)) {
                context->valuesBucket.Put(column, std::get<int32_t>(value));
            } else if (std::holds_alternative<bool>(value)) {
                context->valuesBucket.Put(column, std::get<bool>(value));
            } else if (std::holds_alternative<std::string>(value)) {
                context->valuesBucket.Put(column, std::get<std::string>(value));
            } else {
                ANI_ERR_LOG("value type of key: %{public}s not supported", key.c_str());
                continue;
            }
        } else {
            ANI_ERR_LOG("key %{public}s not found in createOptionsMap", key.c_str());
            continue;
        }
    }

    return true;
}

static ResourceType GetResourceType(int32_t value)
{
    ResourceType result = ResourceType::INVALID_RESOURCE;
    switch (value) {
        case static_cast<int32_t>(ResourceType::IMAGE_RESOURCE):
        case static_cast<int32_t>(ResourceType::VIDEO_RESOURCE):
        case static_cast<int32_t>(ResourceType::PHOTO_PROXY):
            result = static_cast<ResourceType>(value);
            break;
        default:
            break;
    }
    return result;
}

static bool CheckWriteOperation(ani_env *env, MediaAssetChangeRequestAni* changeRequest,
    ResourceType resourceType = ResourceType::INVALID_RESOURCE)
{
    if (changeRequest == nullptr) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "changeRequest is null");
        return false;
    }

    if (changeRequest->IsMovingPhoto()) {
        if (!changeRequest->CheckMovingPhotoResource(resourceType)) {
            AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Failed to check resource to add for moving photo");
            return false;
        }
        return true;
    }

    if (changeRequest->Contains(AssetChangeOperation::CREATE_FROM_URI) ||
        changeRequest->Contains(AssetChangeOperation::GET_WRITE_CACHE_HANDLER) ||
        changeRequest->Contains(AssetChangeOperation::ADD_RESOURCE)) {
        AniError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT,
            "The previous asset creation/modification request has not been applied");
        return false;
    }
    return true;
}

static bool HasWritePermission()
{
    AccessTokenID tokenCaller = IPCSkeleton::GetSelfTokenID();
    int result = AccessTokenKit::VerifyAccessToken(tokenCaller, PERM_WRITE_IMAGEVIDEO);
    return result == PermissionState::PERMISSION_GRANTED;
}

static bool CheckMovingPhotoCreationArgs(std::unique_ptr<MediaAssetChangeRequestAniContext>& context)
{
    ANI_CHECK_RETURN_RET_LOG(context != nullptr, false, "context is null");
    bool isValid = false;
    int32_t mediaType = context->valuesBucket.Get(MEDIA_DATA_DB_MEDIA_TYPE, isValid);
    if (!isValid) {
        ANI_ERR_LOG("Failed to get media type");
        return false;
    }

    if (mediaType != static_cast<int32_t>(MEDIA_TYPE_IMAGE)) {
        ANI_ERR_LOG("Failed to check media type (%{public}d) for moving photo", mediaType);
        return false;
    }

    std::string extension = context->valuesBucket.Get(ASSET_EXTENTION, isValid);
    if (isValid) {
        return MediaFileUtils::CheckMovingPhotoExtension(extension);
    }

    std::string displayName = context->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
    return isValid && MediaFileUtils::CheckMovingPhotoExtension(MediaFileUtils::GetExtensionFromPath(displayName));
}

static bool CheckCreateOption(std::unique_ptr<MediaAssetChangeRequestAniContext>& context, bool isSystemApi)
{
    ANI_CHECK_RETURN_RET_LOG(context != nullptr, false, "context is null");
    bool isValid = false;
    int32_t subtype = context->valuesBucket.Get(PhotoColumn::PHOTO_SUBTYPE, isValid);
    if (isValid) {
        if (subtype < static_cast<int32_t>(PhotoSubType::DEFAULT) ||
            subtype >= static_cast<int32_t>(PhotoSubType::SUBTYPE_END)) {
            ANI_ERR_LOG("Failed to check subtype: %{public}d", subtype);
            return false;
        }

        // check media type and extension for moving photo
        if (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO) &&
            !CheckMovingPhotoCreationArgs(context)) {
            ANI_ERR_LOG("Failed to check creation args for moving photo");
            return false;
        }

        // check subtype for public api
        if (!isSystemApi && subtype != static_cast<int32_t>(PhotoSubType::DEFAULT) &&
            subtype != static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            ANI_ERR_LOG("Failed to check subtype: %{public}d", subtype);
            return false;
        }
    }

    std::string cameraShotKey = context->valuesBucket.Get(PhotoColumn::CAMERA_SHOT_KEY, isValid);
    if (isValid) {
        if (cameraShotKey.size() < CAMERA_SHOT_KEY_SIZE) {
            ANI_ERR_LOG("cameraShotKey is not null but is less than CAMERA_SHOT_KEY_SIZE");
            return false;
        }
        if (subtype == static_cast<int32_t>(PhotoSubType::SCREENSHOT)) {
            ANI_ERR_LOG("cameraShotKey is not null with subtype is SCREENSHOT");
            return false;
        } else {
            context->valuesBucket.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::CAMERA));
        }
    }
    return true;
}

static const unordered_map<MovingPhotoEffectMode, unordered_map<ResourceType, bool>> EFFECT_MODE_RESOURCE_CHECK = {
    { MovingPhotoEffectMode::DEFAULT,
        { { ResourceType::IMAGE_RESOURCE, false }, { ResourceType::VIDEO_RESOURCE, false } } },
    { MovingPhotoEffectMode::BOUNCE_PLAY,
        { { ResourceType::IMAGE_RESOURCE, false }, { ResourceType::VIDEO_RESOURCE, true } } },
    { MovingPhotoEffectMode::LOOP_PLAY,
        { { ResourceType::IMAGE_RESOURCE, false }, { ResourceType::VIDEO_RESOURCE, true } } },
    { MovingPhotoEffectMode::CINEMA_GRAPH,
        { { ResourceType::IMAGE_RESOURCE, false }, { ResourceType::VIDEO_RESOURCE, true } } },
    { MovingPhotoEffectMode::LONG_EXPOSURE,
        { { ResourceType::IMAGE_RESOURCE, true }, { ResourceType::VIDEO_RESOURCE, false } } },
    { MovingPhotoEffectMode::MULTI_EXPOSURE,
        { { ResourceType::IMAGE_RESOURCE, true }, { ResourceType::VIDEO_RESOURCE, false } } },
    { MovingPhotoEffectMode::IMAGE_ONLY,
        { { ResourceType::IMAGE_RESOURCE, false }, { ResourceType::VIDEO_RESOURCE, false } } },
};

bool MediaAssetChangeRequestAni::CheckEffectModeWriteOperation()
{
    if (fileAsset_ == nullptr) {
        ANI_ERR_LOG("fileAsset is nullptr");
        return false;
    }

    if (fileAsset_->GetTimePending() != 0) {
        ANI_ERR_LOG("Failed to check pending of fileAsset: %{public}" PRId64, fileAsset_->GetTimePending());
        return false;
    }

    MovingPhotoEffectMode effectMode = static_cast<MovingPhotoEffectMode>(fileAsset_->GetMovingPhotoEffectMode());
    auto iter = EFFECT_MODE_RESOURCE_CHECK.find(effectMode);
    if (iter == EFFECT_MODE_RESOURCE_CHECK.end()) {
        ANI_ERR_LOG("Failed to check effect mode: %{public}d", static_cast<int32_t>(effectMode));
        return false;
    }

    bool isImageExist = ContainsResource(ResourceType::IMAGE_RESOURCE);
    bool isVideoExist = ContainsResource(ResourceType::VIDEO_RESOURCE);
    if (iter->second.at(ResourceType::IMAGE_RESOURCE) && !isImageExist) {
        ANI_ERR_LOG("Failed to check image resource for effect mode: %{public}d", static_cast<int32_t>(effectMode));
        return false;
    }
    if (iter->second.at(ResourceType::VIDEO_RESOURCE) && !isVideoExist) {
        ANI_ERR_LOG("Failed to check video resource for effect mode: %{public}d", static_cast<int32_t>(effectMode));
        return false;
    }
    return true;
}

bool MediaAssetChangeRequestAni::CheckMovingPhotoWriteOperation()
{
    if (Contains(AssetChangeOperation::SET_MOVING_PHOTO_EFFECT_MODE)) {
        return CheckEffectModeWriteOperation();
    }

    bool containsAddResource = Contains(AssetChangeOperation::ADD_RESOURCE);
    if (!containsAddResource) {
        return true;
    }

    bool isCreation = Contains(AssetChangeOperation::CREATE_FROM_SCRATCH);
    if (!isCreation) {
        return true;
    }

    int addResourceTimes =
        std::count(assetChangeOperations_.begin(), assetChangeOperations_.end(), AssetChangeOperation::ADD_RESOURCE);
    bool isImageExist = ContainsResource(ResourceType::IMAGE_RESOURCE);
    bool isVideoExist = ContainsResource(ResourceType::VIDEO_RESOURCE);
    return addResourceTimes == 2 && isImageExist && isVideoExist; // must add resource 2 times with image and video
}

bool MediaAssetChangeRequestAni::CheckChangeOperations(ani_env *env)
{
    if (assetChangeOperations_.empty()) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "None request to apply");
        return false;
    }

    bool isCreateFromScratch = Contains(AssetChangeOperation::CREATE_FROM_SCRATCH);
    bool isCreateFromUri = Contains(AssetChangeOperation::CREATE_FROM_URI);
    bool containsEdit = Contains(AssetChangeOperation::SET_EDIT_DATA);
    bool containsGetHandler = Contains(AssetChangeOperation::GET_WRITE_CACHE_HANDLER);
    bool containsAddResource = Contains(AssetChangeOperation::ADD_RESOURCE);
    bool isSaveCameraPhoto = Contains(AssetChangeOperation::SAVE_CAMERA_PHOTO);
    if ((isCreateFromScratch || containsEdit) && !containsGetHandler && !containsAddResource && !isSaveCameraPhoto) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Cannot create or edit asset without data to write");
        return false;
    }

    if (containsEdit && (isCreateFromScratch || isCreateFromUri)) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Cannot create together with edit");
        return false;
    }

    auto fileAsset = GetFileAssetInstance();
    if (fileAsset == nullptr) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "fileAsset is null");
        return false;
    }

    AssetChangeOperation firstOperation = assetChangeOperations_.front();
    if (fileAsset->GetId() <= 0 && firstOperation != AssetChangeOperation::CREATE_FROM_SCRATCH &&
        firstOperation != AssetChangeOperation::CREATE_FROM_URI) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid asset change request");
        return false;
    }

    bool isMovingPhoto = IsMovingPhoto();
    if (isMovingPhoto && !CheckMovingPhotoWriteOperation()) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid write operation for moving photo");
        return false;
    }

    return true;
}

std::shared_ptr<FileAsset> MediaAssetChangeRequestAni::GetFileAssetInstance() const
{
    return fileAsset_;
}

sptr<PhotoProxy> MediaAssetChangeRequestAni::GetPhotoProxyObj()
{
    return photoProxy_;
}

void MediaAssetChangeRequestAni::ReleasePhotoProxyObj()
{
    photoProxy_->Release();
    photoProxy_ = nullptr;
}

uint32_t MediaAssetChangeRequestAni::FetchAddCacheFileId()
{
    uint32_t id = cacheFileId_.fetch_add(1);
    return id;
}

void MediaAssetChangeRequestAni::SetCacheFileName(string& fileName)
{
    cacheFileName_ = fileName;
}

void MediaAssetChangeRequestAni::SetCacheMovingPhotoVideoName(string& fileName)
{
    cacheMovingPhotoVideoName_ = fileName;
}

string MediaAssetChangeRequestAni::GetFileRealPath() const
{
    return realPath_;
}
AddResourceMode MediaAssetChangeRequestAni::GetAddResourceMode() const
{
    return addResourceMode_;
}

void* MediaAssetChangeRequestAni::GetDataBuffer() const
{
    return dataBuffer_;
}

size_t MediaAssetChangeRequestAni::GetDataBufferSize() const
{
    return dataBufferSize_;
}

string MediaAssetChangeRequestAni::GetMovingPhotoVideoPath() const
{
    return movingPhotoVideoRealPath_;
}

AddResourceMode MediaAssetChangeRequestAni::GetMovingPhotoVideoMode() const
{
    return movingPhotoVideoResourceMode_;
}

void* MediaAssetChangeRequestAni::GetMovingPhotoVideoBuffer() const
{
    return movingPhotoVideoDataBuffer_;
}

size_t MediaAssetChangeRequestAni::GetMovingPhotoVideoSize() const
{
    return movingPhotoVideoBufferSize_;
}

void MediaAssetChangeRequestAni::RecordChangeOperation(AssetChangeOperation changeOperation)
{
    if ((changeOperation == AssetChangeOperation::GET_WRITE_CACHE_HANDLER ||
            changeOperation == AssetChangeOperation::ADD_RESOURCE ||
            changeOperation == AssetChangeOperation::ADD_FILTERS) &&
        Contains(AssetChangeOperation::CREATE_FROM_SCRATCH)) {
        assetChangeOperations_.insert(assetChangeOperations_.begin() + 1, changeOperation);
        return;
    }
    if (changeOperation == AssetChangeOperation::ADD_RESOURCE &&
        Contains(AssetChangeOperation::SET_MOVING_PHOTO_EFFECT_MODE)) {
        assetChangeOperations_.insert(assetChangeOperations_.begin(), changeOperation);
        return;
    }
    assetChangeOperations_.push_back(changeOperation);
}

bool MediaAssetChangeRequestAni::Contains(AssetChangeOperation changeOperation) const
{
    return std::find(assetChangeOperations_.begin(), assetChangeOperations_.end(), changeOperation) !=
        assetChangeOperations_.end();
}

bool MediaAssetChangeRequestAni::ContainsResource(ResourceType resourceType) const
{
    return std::find(addResourceTypes_.begin(), addResourceTypes_.end(), resourceType) != addResourceTypes_.end();
}

bool MediaAssetChangeRequestAni::IsMovingPhoto() const
{
    return fileAsset_ != nullptr &&
        (fileAsset_->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO) ||
        (fileAsset_->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::DEFAULT) &&
        fileAsset_->GetMovingPhotoEffectMode() == static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY)));
}

bool MediaAssetChangeRequestAni::CheckMovingPhotoResource(ResourceType resourceType) const
{
    if (resourceType == ResourceType::INVALID_RESOURCE) {
        ANI_ERR_LOG("Invalid resource type");
        return false;
    }

    bool isResourceTypeVaild = !ContainsResource(resourceType);
    int addResourceTimes =
        std::count(assetChangeOperations_.begin(), assetChangeOperations_.end(), AssetChangeOperation::ADD_RESOURCE);
    return isResourceTypeVaild && addResourceTimes <= 1; // currently, add resource no more than once
}

static bool ParseArgsCreateAssetSystem(ani_env *env, ani_string displayName,
    ani_object photoCreateOptions, std::unique_ptr<MediaAssetChangeRequestAniContext>& context)
{
    std::string displayNameStr;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetParamStringPathMax(env, displayName, displayNameStr) == ANI_OK, false,
        "Failed to get displayName");
    CHECK_COND_WITH_RET_MESSAGE(env, MediaFileUtils::CheckDisplayName(displayNameStr) == E_OK, false,
        "Failed to check displayName");
    MediaType mediaType = MediaFileUtils::GetMediaType(displayNameStr);
    CHECK_COND_WITH_RET_MESSAGE(env, mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO, false,
        "Invalid file type");
    context->valuesBucket.Put(MEDIA_DATA_DB_NAME, displayNameStr);
    context->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));

    ani_boolean isUndefined;
    env->Reference_IsUndefined(photoCreateOptions, &isUndefined);
    if (isUndefined) {
        ANI_INFO_LOG("PhotoCreateOptions is undefined. There is no need to parse create options");
        return true;
    }
    auto optionsMap = MediaLibraryAniUtils::GetPhotoCreateOptions(env, photoCreateOptions);
    // parse photo create options
    if (ParseCreateOptions(context, optionsMap, PHOTO_CREATE_OPTIONS_PARAM)) {
        CheckCreateOption(context, false);
    }
    return true;
}

static bool ParseArgsCreateAssetCommon(ani_env *env, ani_enum_item photoType, ani_string extension,
    ani_object createOptions, std::unique_ptr<MediaAssetChangeRequestAniContext>& context)
{
    // Parse photoType.
    MediaType mediaType;
    int32_t mediaTypeInt;
    ANI_CHECK_RETURN_RET_LOG(MediaLibraryEnumAni::EnumGetValueInt32(
        env, photoType, mediaTypeInt) == ANI_OK, false, "Failed to get photoType");
    mediaType = static_cast<MediaType>(mediaTypeInt);
    ANI_CHECK_RETURN_RET_LOG(mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO,
        false, "Invalid photoType");

    // Parse extension.
    std::string extensionStr;
    ANI_CHECK_RETURN_RET_LOG(
        MediaLibraryAniUtils::GetParamStringPathMax(env, extension, extensionStr) == ANI_OK, false,
        "Failed to get extension");
    ANI_CHECK_RETURN_RET_LOG(mediaType == MediaFileUtils::GetMediaType("." + extensionStr), false,
        "Failed to check extension");
    context->valuesBucket.Put(ASSET_EXTENTION, extensionStr);
    context->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));

    // Parse options if exists.
    ani_boolean isUndefined;
    env->Reference_IsUndefined(createOptions, &isUndefined);
    if (!isUndefined) {
        auto optionsMap = MediaLibraryAniUtils::GetCreateOptions(env, createOptions);
        ParseCreateOptions(context, optionsMap, CREATE_OPTIONS_PARAM);
        CheckCreateOption(context, true);
    }

    bool isValid = false;
    std::string title = context->valuesBucket.Get(PhotoColumn::MEDIA_TITLE, isValid);
    if (!isValid) {
        title = mediaType == MEDIA_TYPE_IMAGE ? DEFAULT_TITLE_IMG_PREFIX : DEFAULT_TITLE_VIDEO_PREFIX;
        title += MediaFileUtils::StrCreateTime(DEFAULT_TITLE_TIME_FORMAT, MediaFileUtils::UTCTimeSeconds());
        context->valuesBucket.Put(PhotoColumn::MEDIA_TITLE, title);
    }

    std::string displayName = title + "." + extensionStr;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaFileUtils::CheckDisplayName(displayName) == E_OK, false,
        "Failed to check displayName");
    context->valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    return true;
}

ani_object MediaAssetChangeRequestAni::CreateAssetRequestCommon(
    ani_env *env, std::unique_ptr<MediaAssetChangeRequestAniContext>& context)
{
    bool isValid = false;
    std::string displayName = context->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
    int32_t subtype = context->valuesBucket.Get(PhotoColumn::PHOTO_SUBTYPE, isValid); // default is 0
    auto emptyFileAsset = std::make_unique<FileAsset>();
    emptyFileAsset->SetDisplayName(displayName);
    emptyFileAsset->SetTitle(MediaFileUtils::GetTitleFromDisplayName(displayName));
    emptyFileAsset->SetMediaType(MediaFileUtils::GetMediaType(displayName));
    emptyFileAsset->SetPhotoSubType(subtype);
    emptyFileAsset->SetTimePending(CREATE_ASSET_REQUEST_PENDING);
    emptyFileAsset->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    FileAssetAni* fileAssetAni = FileAssetAni::CreateFileAsset(env, emptyFileAsset);
    CHECK_COND_WITH_RET_MESSAGE(env, fileAssetAni != nullptr, nullptr, "Failed to create file asset");

    auto changeRequest = std::make_unique<MediaAssetChangeRequestAni>(fileAssetAni);
    changeRequest->creationValuesBucket_ = std::move(context->valuesBucket);
    changeRequest->RecordChangeOperation(AssetChangeOperation::CREATE_FROM_SCRATCH);
    return Wrap(env, changeRequest.release());
}

ani_object MediaAssetChangeRequestAni::createAssetRequestSystem(ani_env *env, ani_object context,
    ani_string displayName, ani_object photoCreateOptions)
{
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryAniUtils::IsSystemApp(), nullptr,
        "This interface can be called only by system apps");
    auto aniContext = std::make_unique<MediaAssetChangeRequestAniContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, ParseArgsCreateAssetSystem(
        env, displayName, photoCreateOptions, aniContext), nullptr, "Failed to parse create options");
    return CreateAssetRequestCommon(env, aniContext);
}

ani_object MediaAssetChangeRequestAni::createAssetRequest(ani_env *env, ani_object context,
    ani_enum_item photoType, ani_string extension, ani_object createOptions)
{
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryAniUtils::IsSystemApp(), nullptr,
        "This interface can be called only by system apps");
    auto aniContext = std::make_unique<MediaAssetChangeRequestAniContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, ParseArgsCreateAssetCommon(
        env, photoType, extension, createOptions, aniContext), nullptr, "Failed to parse create options");
    return CreateAssetRequestCommon(env, aniContext);
}

static ani_object ParseFileUri(ani_env *env, ani_object fileUriAni, MediaType mediaType,
    std::unique_ptr<MediaAssetChangeRequestAniContext>& context)
{
    std::string fileUriStr;
    CHECK_COND_WITH_MESSAGE(env, MediaLibraryAniUtils::GetParamStringPathMax(env, fileUriAni, fileUriStr) == ANI_OK,
        "Failed to get fileUri");
    OHOS::AppFileService::ModuleFileUri::FileUri fileUri(fileUriStr);
    std::string path = fileUri.GetRealPath();
    CHECK_COND(env, OHOS::PathToRealPath(path, context->realPath), JS_ERR_NO_SUCH_FILE);

    CHECK_COND_WITH_MESSAGE(env, mediaType == MediaFileUtils::GetMediaType(context->realPath), "Invalid file type");
    return reinterpret_cast<ani_object>(true);
}

static ani_object ParseArgsCreateAssetFromFileUri(ani_env *env, ani_object fileUriAni, MediaType mediaType,
    std::unique_ptr<MediaAssetChangeRequestAniContext>& context)
{
    return ParseFileUri(env, fileUriAni, mediaType, context);
}

ani_object MediaAssetChangeRequestAni::CreateAssetRequestFromRealPath(ani_env *env, const std::string &realPath)
{
    std::string displayName = MediaFileUtils::GetFileName(realPath);
    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckDisplayName(displayName) == E_OK, "Invalid fileName");
    std::string title = MediaFileUtils::GetTitleFromDisplayName(displayName);
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    auto emptyFileAsset = std::make_unique<FileAsset>();
    emptyFileAsset->SetDisplayName(displayName);
    emptyFileAsset->SetTitle(title);
    emptyFileAsset->SetMediaType(mediaType);
    emptyFileAsset->SetPhotoSubType(static_cast<int32_t>(PhotoSubType::DEFAULT));
    emptyFileAsset->SetTimePending(CREATE_ASSET_REQUEST_PENDING);
    emptyFileAsset->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    FileAssetAni* fileAssetAni = FileAssetAni::CreateFileAsset(env, emptyFileAsset);
    ANI_CHECK_RETURN_RET_LOG(fileAssetAni != nullptr, nullptr, "context is null");
    auto changeRequest = std::make_unique<MediaAssetChangeRequestAni>(fileAssetAni);
    changeRequest->realPath_ = realPath;
    changeRequest->creationValuesBucket_.Put(MEDIA_DATA_DB_NAME, displayName);
    changeRequest->creationValuesBucket_.Put(ASSET_EXTENTION, MediaFileUtils::GetExtensionFromPath(displayName));
    changeRequest->creationValuesBucket_.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));
    changeRequest->creationValuesBucket_.Put(PhotoColumn::MEDIA_TITLE, title);
    changeRequest->RecordChangeOperation(AssetChangeOperation::CREATE_FROM_URI);
    return Wrap(env, changeRequest.release());
}

ani_object MediaAssetChangeRequestAni::createImageAssetRequest(ani_env *env, ani_object context, ani_string fileUri)
{
    auto aniContext = std::make_unique<MediaAssetChangeRequestAniContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsCreateAssetFromFileUri(env,
        fileUri, MediaType::MEDIA_TYPE_IMAGE, aniContext), "Failed to parse args");
    return CreateAssetRequestFromRealPath(env, aniContext->realPath);
}

ani_object MediaAssetChangeRequestAni::createVideoAssetRequest(ani_env *env, ani_object context, ani_string fileUri)
{
    auto aniContext = std::make_unique<MediaAssetChangeRequestAniContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsCreateAssetFromFileUri(env,
        fileUri, MediaType::MEDIA_TYPE_VIDEO, aniContext), "Failed to parse args");
    return CreateAssetRequestFromRealPath(env, aniContext->realPath);
}

ani_object MediaAssetChangeRequestAni::getAsset(ani_env *env, ani_object aniObject)
{
    auto aniContext = std::make_unique<MediaAssetChangeRequestAniContext>();
    aniContext->objectInfo = Unwrap(env, aniObject);
    auto changeRequest = aniContext->objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    CHECK_COND(env, fileAsset != nullptr, JS_INNER_FAIL);
 
    if (fileAsset->GetId() > 0) {
        return FileAssetAni::Wrap(env, FileAssetAni::CreatePhotoAsset(env, fileAsset));
    }
    return nullptr;
}

#ifdef HAS_ACE_ENGINE_PART
static napi_value initDeleteRequest(napi_env env, MediaAssetChangeRequestAniContext& context,
    OHOS::AAFwk::Want& request, shared_ptr<DeleteCallback>& callback)
{
    request.SetElementName(DELETE_UI_PACKAGE_NAME, DELETE_UI_EXT_ABILITY_NAME);
    request.SetParam(DELETE_UI_EXTENSION_TYPE, DELETE_UI_REQUEST_TYPE);

    CHECK_COND(env, !context.appName.empty(), JS_INNER_FAIL);
    request.SetParam(DELETE_UI_APPNAME, context.appName);

    request.SetParam(DELETE_UI_URIS, context.uris);
    callback->SetUris(context.uris);

    napi_valuetype valueType = napi_undefined;
    CHECK_COND_WITH_MESSAGE(env, context.argc >= ARGS_THREE && context.argc <= ARGS_FOUR, "Failed to check args");
    napi_value func = context.argv[PARAM1];
    if (ANI_OK != napi_typeof(env, func, &valueType)) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }
    CHECK_COND_WITH_MESSAGE(env, valueType == napi_function, "Failed to check args");
    callback->SetFunc(func);
    RETURN_NAPI_TRUE(env);
}
#endif

static void DeleteAssetsExecute(ani_env *env, std::unique_ptr<MediaAssetChangeRequestAniContext>& context)
{
    MediaLibraryTracer tracer;
    tracer.Start("DeleteAssetsExecute");

    string trashUri = PAH_TRASH_PHOTO;
    MediaLibraryAniUtils::UriAppendKeyValue(trashUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(trashUri);
    int32_t changedRows = UserFileClient::Update(updateAssetUri, context->predicates, context->valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        ANI_ERR_LOG("Failed to delete assets, err: %{public}d", changedRows);
    }
}

static ani_object DeleteAssetsCommon(ani_env *env, std::unique_ptr<MediaAssetChangeRequestAniContext>& aniContext,
    std::vector<std::string>& uris)
{
    CHECK_COND_WITH_MESSAGE(env, !uris.empty(), "Failed to check empty array");
    for (const auto& uri : uris) {
        CHECK_COND(env, uri.find(PhotoColumn::PHOTO_URI_PREFIX) != string::npos, JS_E_URI);
    }

    ANI_INFO_LOG("DeleteAssetsExecute size:%{public}zu", uris.size());
    aniContext->predicates.In(PhotoColumn::MEDIA_ID, uris);
    aniContext->valuesBucket.Put(PhotoColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());
    aniContext->uris.assign(uris.begin(), uris.end());

    // Delete assets
    if (MediaLibraryAniUtils::IsSystemApp()) {
        DeleteAssetsExecute(env, aniContext);
        return nullptr;
    }
#ifdef HAS_ACE_ENGINE_PART
    // Deletion control by ui extension
    CHECK_COND(env, HasWritePermission(), OHOS_PERMISSION_DENIED_CODE);
    CHECK_COND_WITH_MESSAGE(
        env, aniContext->uris.size() <= MAX_DELETE_NUMBER, "No more than 300 assets can be deleted at one time");
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, aniContext->argv[PARAM0]);
    CHECK_COND_WITH_MESSAGE(env, context != nullptr, "Failed to get stage mode context");
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    CHECK_COND(env, abilityContext != nullptr, JS_INNER_FAIL);
    auto abilityInfo = abilityContext->GetAbilityInfo();
    abilityContext->GetResourceManager()->GetStringById(abilityInfo->labelId, aniContext->appName);
    auto uiContent = abilityContext->GetUIContent();
    CHECK_COND(env, uiContent != nullptr, JS_INNER_FAIL);

    auto callback = std::make_shared<DeleteCallback>(env, uiContent);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallback = {
        ([callback](auto arg) { callback->OnRelease(arg); }),
        ([callback](auto arg1, auto arg2) { callback->OnResult(arg1, arg2); }),
        ([callback](auto arg) { callback->OnReceive(arg); }),
        ([callback](auto arg1, auto arg2, auto arg3) { callback->OnError(arg1, arg2, arg3); }),
    };
    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    OHOS::AAFwk::Want request;
    CHECK_COND(env, initDeleteRequest(env, *aniContext, request, callback), JS_INNER_FAIL);

    int32_t sessionId = uiContent->CreateModalUIExtension(request, extensionCallback, config);
    CHECK_COND(env, sessionId != 0, JS_INNER_FAIL);
    callback->SetSessionId(sessionId);
    RETURN_NAPI_UNDEFINED(env);
#else
    AniError::ThrowError(env, JS_INNER_FAIL, "ace_engine is not support");
    return nullptr;
#endif
}

ani_object MediaAssetChangeRequestAni::deleteAssetsByPhotoAsset(ani_env *env, ani_object context, ani_object assets)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteAssets");

    auto aniContext = make_unique<MediaAssetChangeRequestAniContext>();
    std::vector<std::string> uris;
    CHECK_COND(env, MediaAssetChangeRequestAni::InitUserFileClient(env, context), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, MediaLibraryAniUtils::GetUriArrayFromAssets(env, assets, uris) == ANI_OK,
        "Failed to get uri array from assets");
    return DeleteAssetsCommon(env, aniContext, uris);
}

ani_object MediaAssetChangeRequestAni::deleteAssetsByUriList(ani_env *env, ani_object context, ani_object uriList)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteAssets");

    auto aniContext = make_unique<MediaAssetChangeRequestAniContext>();
    std::vector<std::string> uris;
    CHECK_COND(env, MediaAssetChangeRequestAni::InitUserFileClient(env, context), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, MediaLibraryAniUtils::GetStringArray(env, uriList, uris) == ANI_OK,
        "Failed to get uri array from uriList");
    return DeleteAssetsCommon(env, aniContext, uris);
}

static bool CheckMovingPhotoVideo(void* dataBuffer, size_t size)
{
    MediaLibraryTracer tracer;
    tracer.Start("CheckMovingPhotoVideo");

    auto dataSource = make_shared<MediaDataSource>(dataBuffer, static_cast<int64_t>(size));
    auto avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (avMetadataHelper == nullptr) {
        ANI_WARN_LOG("Failed to create AVMetadataHelper, ignore checking duration of moving photo video");
        return true;
    }

    int32_t err = avMetadataHelper->SetSource(dataSource);
    if (err != E_OK) {
        ANI_ERR_LOG("SetSource failed for dataSource, err = %{public}d", err);
        return false;
    }

    unordered_map<int32_t, string> resultMap = avMetadataHelper->ResolveMetadata();
    if (resultMap.find(AV_KEY_DURATION) == resultMap.end()) {
        ANI_ERR_LOG("AV_KEY_DURATION does not exist");
        return false;
    }

    string durationStr = resultMap.at(AV_KEY_DURATION);
    int32_t duration = std::atoi(durationStr.c_str());
    if (!MediaFileUtils::CheckMovingPhotoVideoDuration(duration)) {
        ANI_ERR_LOG("Failed to check duration of moving photo video: %{public}d ms", duration);
        return false;
    }
    return true;
}

ani_object MediaAssetChangeRequestAni::AddMovingPhotoVideoResourceByFileUri(ani_env *env, ani_object aniObject,
    ani_string fileUri)
{
    MediaLibraryTracer tracer;
    tracer.Start("AddMovingPhotoVideoResource");

    auto aniContext = make_unique<MediaAssetChangeRequestAniContext>();
    aniContext->objectInfo = MediaAssetChangeRequestAni::Unwrap(env, aniObject);
    auto changeRequest = aniContext->objectInfo;

    CHECK_COND(env, ParseFileUri(env, fileUri, MediaType::MEDIA_TYPE_VIDEO, aniContext), OHOS_INVALID_PARAM_CODE);
    if (!MediaFileUtils::CheckMovingPhotoVideo(aniContext->realPath)) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Failed to check video resource of moving photo");
        return nullptr;
    }
    changeRequest->movingPhotoVideoRealPath_ = aniContext->realPath;
    changeRequest->movingPhotoVideoResourceMode_ = AddResourceMode::FILE_URI;
    changeRequest->RecordChangeOperation(AssetChangeOperation::ADD_RESOURCE);
    changeRequest->addResourceTypes_.push_back(ResourceType::VIDEO_RESOURCE);
    return nullptr;
}

ani_object MediaAssetChangeRequestAni::AddMovingPhotoVideoResourceByArrayBuffer(ani_env *env, ani_object aniObject,
    ani_object arrayBuffer)
{
    MediaLibraryTracer tracer;
    tracer.Start("AddMovingPhotoVideoResource");

    auto aniContext = make_unique<MediaAssetChangeRequestAniContext>();
    aniContext->objectInfo = MediaAssetChangeRequestAni::Unwrap(env, aniObject);
    auto changeRequest = aniContext->objectInfo;

    std::unique_ptr<uint8_t[]> buffer;
    CHECK_COND_WITH_MESSAGE(env, MediaLibraryAniUtils::GetArrayBuffer(
        env, arrayBuffer, buffer, changeRequest->movingPhotoVideoBufferSize_) == ANI_OK, "Failed to get data buffer");
    changeRequest->movingPhotoVideoDataBuffer_ = buffer.release();
    CHECK_COND_WITH_MESSAGE(env, changeRequest->movingPhotoVideoBufferSize_ > 0,
        "Failed to check size of data buffer");
    if (!CheckMovingPhotoVideo(changeRequest->movingPhotoVideoDataBuffer_,
        changeRequest->movingPhotoVideoBufferSize_)) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Failed to check video resource of moving photo");
        return nullptr;
    }
    changeRequest->movingPhotoVideoResourceMode_ = AddResourceMode::DATA_BUFFER;

    changeRequest->RecordChangeOperation(AssetChangeOperation::ADD_RESOURCE);
    changeRequest->addResourceTypes_.push_back(ResourceType::VIDEO_RESOURCE);
    return nullptr;
}

ani_object MediaAssetChangeRequestAni::addResourceByFileUri(ani_env *env, ani_object aniObject,
    ani_enum_item resourceTypeItem, ani_string fileUri)
{
    auto aniContext = make_unique<MediaAssetChangeRequestAniContext>();
    aniContext->objectInfo = MediaAssetChangeRequestAni::Unwrap(env, aniObject);
    auto changeRequest = aniContext->objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    CHECK_COND(env, fileAsset != nullptr, JS_INNER_FAIL);

    int32_t resourceType = static_cast<int32_t>(ResourceType::INVALID_RESOURCE);
    CHECK_COND_WITH_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(
        env, resourceTypeItem, resourceType) == ANI_OK, "Failed to get resourceType");
    CHECK_COND(env,
        CheckWriteOperation(env, changeRequest, GetResourceType(resourceType)), JS_E_OPERATION_NOT_SUPPORT);
    if (changeRequest->IsMovingPhoto() && resourceType == static_cast<int32_t>(ResourceType::VIDEO_RESOURCE)) {
        return AddMovingPhotoVideoResourceByFileUri(env, aniObject, fileUri);
    }
    CHECK_COND_WITH_MESSAGE(env, resourceType == static_cast<int32_t>(fileAsset->GetMediaType()),
        "Failed to check resourceType");

    CHECK_COND(env, ParseFileUri(env, fileUri, fileAsset->GetMediaType(), aniContext), OHOS_INVALID_PARAM_CODE);
    changeRequest->realPath_ = aniContext->realPath;
    changeRequest->addResourceMode_ = AddResourceMode::FILE_URI;

    changeRequest->RecordChangeOperation(AssetChangeOperation::ADD_RESOURCE);
    changeRequest->addResourceTypes_.push_back(GetResourceType(resourceType));
    return nullptr;
}

ani_object MediaAssetChangeRequestAni::addResourceByArrayBuffer(ani_env *env, ani_object aniObject,
    ani_enum_item resourceTypeItem, ani_object arrayBuffer)
{
    auto aniContext = make_unique<MediaAssetChangeRequestAniContext>();
    aniContext->objectInfo = MediaAssetChangeRequestAni::Unwrap(env, aniObject);
    auto changeRequest = aniContext->objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    CHECK_COND(env, fileAsset != nullptr, JS_INNER_FAIL);

    int32_t resourceType = static_cast<int32_t>(ResourceType::INVALID_RESOURCE);
    CHECK_COND_WITH_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(
        env, resourceTypeItem, resourceType) == ANI_OK, "Failed to get resourceType");
    CHECK_COND(env,
        CheckWriteOperation(env, changeRequest, GetResourceType(resourceType)), JS_E_OPERATION_NOT_SUPPORT);
    if (changeRequest->IsMovingPhoto() && resourceType == static_cast<int32_t>(ResourceType::VIDEO_RESOURCE)) {
        return AddMovingPhotoVideoResourceByArrayBuffer(env, aniObject, arrayBuffer);
    }
    CHECK_COND_WITH_MESSAGE(env, resourceType == static_cast<int32_t>(fileAsset->GetMediaType()),
        "Failed to check resourceType");

    std::unique_ptr<uint8_t[]> buffer;
    CHECK_COND_WITH_MESSAGE(env, MediaLibraryAniUtils::GetArrayBuffer(
        env, arrayBuffer, buffer, changeRequest->dataBufferSize_) == ANI_OK, "Failed to get data buffer");
    changeRequest->dataBuffer_ = buffer.release();
    CHECK_COND_WITH_MESSAGE(env, changeRequest->dataBufferSize_ > 0, "Failed to check size of data buffer");
    changeRequest->addResourceMode_ = AddResourceMode::DATA_BUFFER;

    changeRequest->RecordChangeOperation(AssetChangeOperation::ADD_RESOURCE);
    changeRequest->addResourceTypes_.push_back(GetResourceType(resourceType));
    return nullptr;
}

ani_object MediaAssetChangeRequestAni::addResourceByPhotoProxy(ani_env *env, ani_object aniObject,
    ani_enum_item resourceTypeItem, ani_object proxy)
{
    auto aniContext = make_unique<MediaAssetChangeRequestAniContext>();
    aniContext->objectInfo = MediaAssetChangeRequestAni::Unwrap(env, aniObject);
    auto changeRequest = aniContext->objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    CHECK_COND(env, fileAsset != nullptr, JS_INNER_FAIL);

    int32_t resourceType = static_cast<int32_t>(ResourceType::INVALID_RESOURCE);
    CHECK_COND_WITH_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(
        env, resourceTypeItem, resourceType) == ANI_OK, "Failed to get resourceType");
    CHECK_COND(env,
        CheckWriteOperation(env, changeRequest, GetResourceType(resourceType)), JS_E_OPERATION_NOT_SUPPORT);
    CHECK_COND_WITH_MESSAGE(env, resourceType == static_cast<int32_t>(ResourceType::PHOTO_PROXY),
        "Failed to check resourceType");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    auto photoProxyAni = std::make_unique<PhotoProxyAni>();
    changeRequest->photoProxy_ = photoProxyAni->photoProxy_;
    changeRequest->addResourceMode_ = AddResourceMode::PHOTO_PROXY;

    changeRequest->RecordChangeOperation(AssetChangeOperation::ADD_RESOURCE);
    changeRequest->addResourceTypes_.push_back(GetResourceType(resourceType));
    return nullptr;
}

void MediaAssetChangeRequestAni::SetNewFileAsset(int32_t id, const string& uri)
{
    if (fileAsset_ == nullptr) {
        ANI_ERR_LOG("fileAsset_ is nullptr");
        return;
    }

    if (id <= 0 || uri.empty()) {
        ANI_ERR_LOG("Failed to check file_id: %{public}d and uri: %{public}s", id, uri.c_str());
        return;
    }
    fileAsset_->SetId(id);
    fileAsset_->SetUri(uri);
    fileAsset_->SetTimePending(0);
}

static bool IsCreation(MediaAssetChangeRequestAniContext& context)
{
    auto assetChangeOperations = context.assetChangeOperations;
    bool isCreateFromScratch = std::find(assetChangeOperations.begin(), assetChangeOperations.end(),
                                         AssetChangeOperation::CREATE_FROM_SCRATCH) != assetChangeOperations.end();
    bool isCreateFromUri = std::find(assetChangeOperations.begin(), assetChangeOperations.end(),
                                     AssetChangeOperation::CREATE_FROM_URI) != assetChangeOperations.end();
    return isCreateFromScratch || isCreateFromUri;
}

static bool IsSetEffectMode(MediaAssetChangeRequestAniContext& context)
{
    auto assetChangeOperations = context.assetChangeOperations;
    return std::find(assetChangeOperations.begin(), assetChangeOperations.end(),
        AssetChangeOperation::SET_MOVING_PHOTO_EFFECT_MODE) != assetChangeOperations.end();
}

static int32_t SendFile(const UniqueFd& srcFd, const UniqueFd& destFd)
{
    if (srcFd.Get() < 0 || destFd.Get() < 0) {
        ANI_ERR_LOG("Failed to check srcFd: %{public}d and destFd: %{public}d", srcFd.Get(), destFd.Get());
        return E_ERR;
    }

    struct stat statSrc {};
    int32_t status = fstat(srcFd.Get(), &statSrc);
    if (status != 0) {
        ANI_ERR_LOG("Failed to get file stat, errno=%{public}d", errno);
        return status;
    }

    off_t offset = 0;
    off_t fileSize = statSrc.st_size;
    while (offset < fileSize) {
        ssize_t sent = sendfile(destFd.Get(), srcFd.Get(), &offset, fileSize - offset);
        if (sent < 0) {
            ANI_ERR_LOG("Failed to sendfile with errno=%{public}d, srcFd=%{private}d, destFd=%{private}d", errno,
                srcFd.Get(), destFd.Get());
            return sent;
        }
    }

    return E_OK;
}

int32_t MediaAssetChangeRequestAni::CopyFileToMediaLibrary(const UniqueFd& destFd, bool isMovingPhotoVideo)
{
    string srcRealPath = isMovingPhotoVideo ? movingPhotoVideoRealPath_ : realPath_;
    CHECK_COND_RET(!srcRealPath.empty(), E_FAIL, "Failed to check real path of source");

    string absFilePath;
    CHECK_COND_RET(OHOS::PathToRealPath(srcRealPath, absFilePath), E_FAIL,
        "Not real path %{private}s", srcRealPath.c_str());
    UniqueFd srcFd(open(absFilePath.c_str(), O_RDONLY));
    if (srcFd.Get() < 0) {
        ANI_ERR_LOG("Failed to open %{private}s, errno=%{public}d", absFilePath.c_str(), errno);
        return srcFd.Get();
    }

    int32_t err = SendFile(srcFd, destFd);
    if (err != E_OK) {
        ANI_ERR_LOG("Failed to send file from %{public}d to %{public}d", srcFd.Get(), destFd.Get());
    }
    return err;
}

int32_t MediaAssetChangeRequestAni::CopyDataBufferToMediaLibrary(const UniqueFd& destFd, bool isMovingPhotoVideo)
{
    size_t offset = 0;
    size_t length = isMovingPhotoVideo ? movingPhotoVideoBufferSize_ : dataBufferSize_;
    void* dataBuffer = isMovingPhotoVideo ? movingPhotoVideoDataBuffer_ : dataBuffer_;
    while (offset < length) {
        ssize_t written = write(destFd.Get(), (char*)dataBuffer + offset, length - offset);
        if (written < 0) {
            ANI_ERR_LOG("Failed to copy data buffer, return %{public}d", static_cast<int>(written));
            return written;
        }
        offset += static_cast<size_t>(written);
    }
    return E_OK;
}

int32_t MediaAssetChangeRequestAni::CopyMovingPhotoVideo(const string& assetUri)
{
    if (assetUri.empty()) {
        ANI_ERR_LOG("Failed to check empty asset uri");
        return E_INVALID_URI;
    }

    string videoUri = assetUri;
    MediaFileUtils::UriAppendKeyValue(videoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, OPEN_MOVING_PHOTO_VIDEO);
    Uri uri(videoUri);
    int videoFd = UserFileClient::OpenFile(uri, MEDIA_FILEMODE_WRITEONLY);
    if (videoFd < 0) {
        ANI_ERR_LOG("Failed to open video of moving photo with write-only mode");
        return videoFd;
    }

    int32_t ret = E_ERR;
    UniqueFd uniqueFd(videoFd);
    if (movingPhotoVideoResourceMode_ == AddResourceMode::FILE_URI) {
        ret = CopyFileToMediaLibrary(uniqueFd, true);
    } else if (movingPhotoVideoResourceMode_ == AddResourceMode::DATA_BUFFER) {
        ret = CopyDataBufferToMediaLibrary(uniqueFd, true);
    } else {
        ANI_ERR_LOG("Invalid mode: %{public}d", movingPhotoVideoResourceMode_);
        return E_INVALID_VALUES;
    }
    return ret;
}

int32_t MediaAssetChangeRequestAni::CreateAssetBySecurityComponent(string& assetUri)
{
    bool isValid = false;
    string title = creationValuesBucket_.Get(PhotoColumn::MEDIA_TITLE, isValid);
    CHECK_COND_RET(isValid, E_FAIL, "Failed to get title");
    string extension = creationValuesBucket_.Get(ASSET_EXTENTION, isValid);
    CHECK_COND_RET(isValid && MediaFileUtils::CheckDisplayName(title + "." + extension) == E_OK, E_FAIL,
        "Failed to check displayName");
    creationValuesBucket_.valuesMap.erase(MEDIA_DATA_DB_NAME);

    std::string uri = PAH_CREATE_PHOTO_COMPONENT; // create asset by security component
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, std::to_string(MEDIA_API_VERSION_V10));
    Uri createAssetUri(uri);
    return UserFileClient::InsertExt(createAssetUri, creationValuesBucket_, assetUri);
}

int32_t MediaAssetChangeRequestAni::CopyToMediaLibrary(bool isCreation, AddResourceMode mode)
{
    CHECK_COND_RET(fileAsset_ != nullptr, E_FAIL, "Failed to check fileAsset_");
    int32_t ret = E_ERR;
    int32_t id = 0;
    string assetUri;
    if (isCreation) {
        ret = CreateAssetBySecurityComponent(assetUri);
        CHECK_COND_RET(ret > 0, (ret == 0 ? E_ERR : ret), "Failed to create asset by security component");
        id = ret;
    } else {
        assetUri = fileAsset_->GetUri();
    }
    CHECK_COND_RET(!assetUri.empty(), E_ERR, "Failed to check empty asset uri");

    if (IsMovingPhoto()) {
        ret = CopyMovingPhotoVideo(assetUri);
        if (ret != E_OK) {
            ANI_ERR_LOG("Failed to copy data to moving photo video with error: %{public}d", ret);
            return ret;
        }
    }

    Uri uri(assetUri);
    UniqueFd destFd(UserFileClient::OpenFile(uri, MEDIA_FILEMODE_WRITEONLY));
    if (destFd.Get() < 0) {
        ANI_ERR_LOG("Failed to open %{private}s with error: %{public}d", assetUri.c_str(), destFd.Get());
        return destFd.Get();
    }

    if (mode == AddResourceMode::FILE_URI) {
        ret = CopyFileToMediaLibrary(destFd);
    } else if (mode == AddResourceMode::DATA_BUFFER) {
        ret = CopyDataBufferToMediaLibrary(destFd);
    } else {
        ANI_ERR_LOG("Invalid mode: %{public}d", mode);
        return E_INVALID_VALUES;
    }

    if (ret == E_OK && isCreation) {
        SetNewFileAsset(id, assetUri);
    }
    return ret;
}

static bool WriteBySecurityComponent(MediaAssetChangeRequestAniContext& context)
{
    bool isCreation = IsCreation(context);
    int32_t ret = E_FAIL;
    auto assetChangeOperations = context.assetChangeOperations;
    bool isCreateFromUri = std::find(assetChangeOperations.begin(), assetChangeOperations.end(),
                                     AssetChangeOperation::CREATE_FROM_URI) != assetChangeOperations.end();
    auto changeRequest = context.objectInfo;
    if (isCreateFromUri) {
        ret = changeRequest->CopyToMediaLibrary(isCreation, AddResourceMode::FILE_URI);
    } else {
        ret = changeRequest->CopyToMediaLibrary(isCreation, changeRequest->GetAddResourceMode());
    }

    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to write by security component, ret: %{public}d", ret);
        return false;
    }
    return true;
}

int32_t MediaAssetChangeRequestAni::PutMediaAssetEditData(DataShare::DataShareValuesBucket& valuesBucket)
{
    if (editData_ == nullptr) {
        return E_OK;
    }

    string compatibleFormat = editData_->GetCompatibleFormat();
    CHECK_COND_RET(!compatibleFormat.empty(), E_FAIL, "Failed to check compatibleFormat");
    string formatVersion = editData_->GetFormatVersion();
    CHECK_COND_RET(!formatVersion.empty(), E_FAIL, "Failed to check formatVersion");
    string data = editData_->GetData();
    CHECK_COND_RET(!data.empty(), E_FAIL, "Failed to check data");

    valuesBucket.Put(COMPATIBLE_FORMAT, compatibleFormat);
    valuesBucket.Put(FORMAT_VERSION, formatVersion);
    valuesBucket.Put(EDIT_DATA, data);
    return E_OK;
}

int32_t MediaAssetChangeRequestAni::SubmitCache(bool isCreation, bool isSetEffectMode)
{
    CHECK_COND_RET(fileAsset_ != nullptr, E_FAIL, "Failed to check fileAsset_");
    CHECK_COND_RET(!cacheFileName_.empty() || !cacheMovingPhotoVideoName_.empty(), E_FAIL,
        "Failed to check cache file");

    string uri = PAH_SUBMIT_CACHE;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri submitCacheUri(uri);

    string assetUri;
    int32_t ret;
    if (isCreation) {
        bool isValid = false;
        string displayName = creationValuesBucket_.Get(MEDIA_DATA_DB_NAME, isValid);
        CHECK_COND_RET(
            isValid && MediaFileUtils::CheckDisplayName(displayName) == E_OK, E_FAIL, "Failed to check displayName");
        creationValuesBucket_.Put(CACHE_FILE_NAME, cacheFileName_);
        if (IsMovingPhoto()) {
            creationValuesBucket_.Put(CACHE_MOVING_PHOTO_VIDEO_NAME, cacheMovingPhotoVideoName_);
        }
        ret = UserFileClient::InsertExt(submitCacheUri, creationValuesBucket_, assetUri);
    } else {
        DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.Put(PhotoColumn::MEDIA_ID, fileAsset_->GetId());
        valuesBucket.Put(CACHE_FILE_NAME, cacheFileName_);
        ret = PutMediaAssetEditData(valuesBucket);
        CHECK_COND_RET(ret == E_OK, ret, "Failed to put editData");
        if (IsMovingPhoto()) {
            valuesBucket.Put(CACHE_MOVING_PHOTO_VIDEO_NAME, cacheMovingPhotoVideoName_);
        }
        if (isSetEffectMode) {
            valuesBucket.Put(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, fileAsset_->GetMovingPhotoEffectMode());
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

static bool SubmitCacheExecute(MediaAssetChangeRequestAniContext& context)
{
    MediaLibraryTracer tracer;
    tracer.Start("SubmitCacheExecute");

    bool isCreation = IsCreation(context);
    bool isSetEffectMode = IsSetEffectMode(context);
    auto changeRequest = context.objectInfo;
    int32_t ret = changeRequest->SubmitCache(isCreation, isSetEffectMode);
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to write cache, ret: %{public}d", ret);
        return false;
    }
    return true;
}

static int SavePhotoProxyImage(const UniqueFd& destFd, sptr<PhotoProxy> photoProxyPtr)
{
    void* imageAddr = photoProxyPtr->GetFileDataAddr();
    size_t imageSize = photoProxyPtr->GetFileSize();
    if (imageAddr == nullptr || imageSize == 0) {
        ANI_ERR_LOG("imageAddr is nullptr or imageSize(%{public}zu)==0", imageSize);
        return E_ERR;
    }

    ANI_INFO_LOG("start pack PixelMap");
    Media::InitializationOptions opts;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.size = {
        .width = photoProxyPtr->GetWidth(),
        .height = photoProxyPtr->GetHeight()
    };
    auto pixelMap = Media::PixelMap::Create(opts);
    if (pixelMap == nullptr) {
        ANI_ERR_LOG("Create pixelMap failed.");
        return E_ERR;
    }
    pixelMap->SetPixelsAddr(imageAddr, nullptr, imageSize, Media::AllocatorType::SHARE_MEM_ALLOC, nullptr);
    auto pixelSize = static_cast<uint32_t>(pixelMap->GetByteCount());

    // encode rgba to jpeg
    auto buffer = new (std::nothrow) uint8_t[pixelSize];
    int64_t packedSize = 0L;
    Media::ImagePacker imagePacker;
    Media::PackOption packOption;
    packOption.format = "image/jpeg";
    imagePacker.StartPacking(buffer, pixelSize, packOption);
    imagePacker.AddImage(*pixelMap);
    imagePacker.FinalizePacking(packedSize);
    if (buffer == nullptr) {
        ANI_ERR_LOG("packet pixelMap failed");
        return E_ERR;
    }
    ANI_INFO_LOG("pack pixelMap success, packedSize: %{public}" PRId64, packedSize);

    int ret = write(destFd, buffer, packedSize);
    if (ret < 0) {
        ANI_ERR_LOG("Failed to write photo proxy to cache file, return %{public}d", ret);
        return ret;
    }
    delete[] buffer;
    return ret;
}

static int32_t OpenWriteCacheHandler(MediaAssetChangeRequestAniContext& context, bool isMovingPhotoVideo = false)
{
    auto changeRequest = context.objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    if (fileAsset == nullptr) {
        context.SaveError(E_FAIL);
        ANI_ERR_LOG("fileAsset is null");
        return E_FAIL;
    }

    // specify mp4 extension for cache file of moving photo video
    string extension = isMovingPhotoVideo ? MOVING_PHOTO_VIDEO_EXTENSION
                                          : MediaFileUtils::GetExtensionFromPath(fileAsset->GetDisplayName());
    int64_t currentTimestamp = MediaFileUtils::UTCTimeNanoSeconds();
    uint32_t cacheFileId = changeRequest->FetchAddCacheFileId();
    string cacheFileName = to_string(currentTimestamp) + "_" + to_string(cacheFileId) + "." + extension;
    string uri = PhotoColumn::PHOTO_CACHE_URI_PREFIX + cacheFileName;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri openCacheUri(uri);
    int32_t ret = UserFileClient::OpenFile(openCacheUri, MEDIA_FILEMODE_WRITEONLY);
    if (ret == E_PERMISSION_DENIED) {
        context.error = OHOS_PERMISSION_DENIED_CODE;
        ANI_ERR_LOG("Open cache file failed, permission denied");
        return ret;
    }
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Open cache file failed, ret: %{public}d", ret);
    }

    if (isMovingPhotoVideo) {
        changeRequest->SetCacheMovingPhotoVideoName(cacheFileName);
    } else {
        changeRequest->SetCacheFileName(cacheFileName);
    }
    return ret;
}

static bool WriteCacheByArrayBuffer(MediaAssetChangeRequestAniContext& context,
    const UniqueFd& destFd, bool isMovingPhotoVideo = false)
{
    auto changeRequest = context.objectInfo;
    size_t offset = 0;
    size_t length = isMovingPhotoVideo ? changeRequest->GetMovingPhotoVideoSize() : changeRequest->GetDataBufferSize();
    void* dataBuffer = isMovingPhotoVideo ? changeRequest->GetMovingPhotoVideoBuffer() : changeRequest->GetDataBuffer();
    while (offset < length) {
        ssize_t written = write(destFd.Get(), (char*)dataBuffer + offset, length - offset);
        if (written < 0) {
            context.SaveError(written);
            ANI_ERR_LOG("Failed to write data buffer to cache file, return %{public}d", static_cast<int>(written));
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return true;
}

static bool SendToCacheFile(MediaAssetChangeRequestAniContext& context,
    const UniqueFd& destFd, bool isMovingPhotoVideo = false)
{
    auto changeRequest = context.objectInfo;
    string realPath = isMovingPhotoVideo ? changeRequest->GetMovingPhotoVideoPath() : changeRequest->GetFileRealPath();

    string absFilePath;
    if (!OHOS::PathToRealPath(realPath, absFilePath)) {
        ANI_ERR_LOG("Not real path %{private}s, errno=%{public}d", realPath.c_str(), errno);
        return false;
    }

    UniqueFd srcFd(open(absFilePath.c_str(), O_RDONLY));
    if (srcFd.Get() < 0) {
        context.SaveError(srcFd.Get());
        ANI_ERR_LOG("Failed to open file, errno=%{public}d", errno);
        return false;
    }

    int32_t err = SendFile(srcFd, destFd);
    if (err != E_OK) {
        context.SaveError(err);
        ANI_ERR_LOG("Failed to send file from %{public}d to %{public}d", srcFd.Get(), destFd.Get());
        return false;
    }
    return true;
}

static bool AddPhotoProxyResourceExecute(MediaAssetChangeRequestAniContext& context, const UniqueFd& destFd)
{
    string uri = PAH_ADD_IMAGE;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);

    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(PhotoColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ to_string(fileAsset->GetId()) });

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_ID, context.objectInfo->GetPhotoProxyObj()->GetPhotoId());
    ANI_INFO_LOG("photoId: %{public}s", context.objectInfo->GetPhotoProxyObj()->GetPhotoId().c_str());
    valuesBucket.Put(PhotoColumn::PHOTO_DEFERRED_PROC_TYPE,
        static_cast<int32_t>(context.objectInfo->GetPhotoProxyObj()->GetDeferredProcType()));
    valuesBucket.Put(MediaColumn::MEDIA_ID, fileAsset->GetId());
    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context.SaveError(changedRows);
        ANI_ERR_LOG("Failed to set, err: %{public}d", changedRows);
        return false;
    }

    int err = SavePhotoProxyImage(destFd, context.objectInfo->GetPhotoProxyObj());
    context.objectInfo->ReleasePhotoProxyObj();
    if (err < 0) {
        context.SaveError(err);
        ANI_ERR_LOG("Failed to saveImage , err: %{public}d", err);
        return false;
    }
    return true;
}

static bool AddResourceByMode(MediaAssetChangeRequestAniContext& context,
    const UniqueFd& uniqueFd, AddResourceMode mode, bool isMovingPhotoVideo = false)
{
    bool isWriteSuccess = false;
    if (mode == AddResourceMode::DATA_BUFFER) {
        isWriteSuccess = WriteCacheByArrayBuffer(context, uniqueFd, isMovingPhotoVideo);
    } else if (mode == AddResourceMode::FILE_URI) {
        isWriteSuccess = SendToCacheFile(context, uniqueFd, isMovingPhotoVideo);
    } else if (mode == AddResourceMode::PHOTO_PROXY) {
        isWriteSuccess = AddPhotoProxyResourceExecute(context, uniqueFd);
    } else {
        context.SaveError(E_FAIL);
        ANI_ERR_LOG("Unsupported addResource mode");
    }
    return isWriteSuccess;
}

static bool AddMovingPhotoVideoExecute(MediaAssetChangeRequestAniContext& context)
{
    MediaLibraryTracer tracer;
    tracer.Start("AddMovingPhotoVideoExecute");

    int32_t cacheVideoFd = OpenWriteCacheHandler(context, true);
    if (cacheVideoFd < 0) {
        ANI_ERR_LOG("Failed to open cache moving photo video, err: %{public}d", cacheVideoFd);
        return false;
    }

    UniqueFd uniqueFd(cacheVideoFd);
    AddResourceMode mode = context.objectInfo->GetMovingPhotoVideoMode();
    if (!AddResourceByMode(context, uniqueFd, mode, true)) {
        ANI_ERR_LOG("Faild to write cache file");
        return false;
    }
    return true;
}

static bool HasAddResource(MediaAssetChangeRequestAniContext& context, ResourceType resourceType)
{
    return std::find(context.addResourceTypes.begin(), context.addResourceTypes.end(), resourceType) !=
        context.addResourceTypes.end();
}

static bool AddResourceExecute(MediaAssetChangeRequestAniContext& context)
{
    MediaLibraryTracer tracer;
    tracer.Start("AddResourceExecute");

    if (!HasWritePermission()) {
        return WriteBySecurityComponent(context);
    }

    auto changeRequest = context.objectInfo;
    if (changeRequest->IsMovingPhoto() && HasAddResource(context, ResourceType::VIDEO_RESOURCE) &&
        !AddMovingPhotoVideoExecute(context)) {
        ANI_ERR_LOG("Faild to write cache file for video of moving photo");
        return false;
    }

    // image resource is not mandatory when setting effect mode of moving photo
    if (changeRequest->IsMovingPhoto() && !HasAddResource(context, ResourceType::IMAGE_RESOURCE)) {
        return SubmitCacheExecute(context);
    }

    int32_t cacheFd = OpenWriteCacheHandler(context);
    if (cacheFd < 0) {
        ANI_ERR_LOG("Failed to open write cache handler, err: %{public}d", cacheFd);
        return false;
    }

    UniqueFd uniqueFd(cacheFd);
    AddResourceMode mode = changeRequest->GetAddResourceMode();
    if (!AddResourceByMode(context, uniqueFd, mode)) {
        ANI_ERR_LOG("Faild to write cache file");
        return false;
    }
    return SubmitCacheExecute(context);
}

static const unordered_map<AssetChangeOperation, bool (*)(MediaAssetChangeRequestAniContext&)> EXECUTE_MAP = {
    { AssetChangeOperation::ADD_RESOURCE, AddResourceExecute },
};

static ani_status ApplyAssetChangeRequestExecute(ani_env *env,
    std::unique_ptr<MediaAssetChangeRequestAniContext>& context)
{
    MediaLibraryTracer tracer;
    tracer.Start("ApplyAssetChangeRequestExecute");

    if (context == nullptr || context->objectInfo == nullptr ||
        context->objectInfo->GetFileAssetInstance() == nullptr) {
        context->SaveError(E_FAIL);
        ANI_ERR_LOG("Failed to check async context of MediaAssetChangeRequest object");
        return ANI_INVALID_ARGS;
    }

    unordered_set<AssetChangeOperation> appliedOperations;
    for (const auto& changeOperation : context->assetChangeOperations) {
        // Keep the final result of each operation, and commit it only once.
        if (appliedOperations.find(changeOperation) != appliedOperations.end()) {
            continue;
        }

        bool valid = false;
        auto iter = EXECUTE_MAP.find(changeOperation);
        if (iter != EXECUTE_MAP.end()) {
            tracer.Start("ApplyAssetChangeRequestExecute " + to_string(static_cast<int32_t>(changeOperation)));
            valid = iter->second(*context);
            tracer.Finish();
        } else if (changeOperation == AssetChangeOperation::CREATE_FROM_SCRATCH ||
                   changeOperation == AssetChangeOperation::SET_EDIT_DATA) {
            // Perform CREATE_FROM_SCRATCH and SET_EDIT_DATA during GET_WRITE_CACHE_HANDLER or ADD_RESOURCE.
            valid = true;
        } else {
            ANI_ERR_LOG("Invalid asset change operation: %{public}d", changeOperation);
            context->error = OHOS_INVALID_PARAM_CODE;
            return ANI_INVALID_ARGS;
        }

        if (!valid) {
            ANI_ERR_LOG("Failed to apply asset change request, operation: %{public}d", changeOperation);
            return ANI_ERROR;
        }
        appliedOperations.insert(changeOperation);
    }
    return ANI_OK;
}

ani_status MediaAssetChangeRequestAni::ApplyChanges(ani_env *env, ani_object aniObject)
{
    auto aniContext = make_unique<MediaAssetChangeRequestAniContext>();
    aniContext->objectInfo = this;

    ANI_CHECK_RETURN_RET_LOG(CheckChangeOperations(env), ANI_INVALID_ARGS,
        "Failed to check asset change request operations");
    aniContext->assetChangeOperations = assetChangeOperations_;
    aniContext->addResourceTypes = addResourceTypes_;
    assetChangeOperations_.clear();
    addResourceTypes_.clear();
    ANI_CHECK_RETURN_RET_LOG(ApplyAssetChangeRequestExecute(env, aniContext), ANI_ERROR,
        "Failed to apply asset change request");
    return ANI_OK;
}
} // namespace Media