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
#include "media_album_change_request_ani.h"
#include "result_set_utils.h"
#include "media_log.h"
#include "ani_class_name.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include <iostream>
#include "userfile_client.h"
#include "photo_album_ani.h"
#include "vision_photo_map_column.h"
#include "album_operation_uri.h"

using namespace std;
namespace OHOS::Media {
ani_status MediaAlbumChangeRequestAni::Init(ani_env *env)
{
    static const char *className = PAH_ANI_CLASS_MEDIA_ALBUM_CHANGE_REQUEST.c_str();
    ani_class cls;
    auto status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        MEDIA_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"nativeConstructor", nullptr, reinterpret_cast<void *>(Constructor)},
        ani_native_function {"placeBefore", nullptr, reinterpret_cast<void *>(PlaceBefore)},
        ani_native_function {"dismissAssets", nullptr, reinterpret_cast<void *>(DismissAssets)},
        ani_native_function {"addAssets", nullptr, reinterpret_cast<void *>(AddAssets)},
        ani_native_function {"moveAssets", nullptr, reinterpret_cast<void *>(MoveAssets)},
        ani_native_function {"mergeAlbum", nullptr, reinterpret_cast<void *>(MergeAlbum)},
        ani_native_function {"setAlbumName", nullptr, reinterpret_cast<void *>(SetAlbumName)},
        ani_native_function {"setCoverUri", nullptr, reinterpret_cast<void *>(SetCoverUri)},
        ani_native_function {"recoverAssets", nullptr, reinterpret_cast<void *>(RecoverAssets)},
        ani_native_function {"setDisplayLevel", nullptr, reinterpret_cast<void *>(SetDisplayLevel)},
        ani_native_function {"deleteAssets", nullptr, reinterpret_cast<void *>(DeleteAssets)},
        ani_native_function {"deleteAlbumsSync", nullptr, reinterpret_cast<void *>(DeleteAlbums)},
        ani_native_function {"setIsMe", nullptr, reinterpret_cast<void *>(SetIsMe)},
    };
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        MEDIA_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    };

    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::Constructor([[maybe_unused]] ani_env *env, ani_object object,
    [[maybe_unused]] ani_object albumHandle)
{
    auto albumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, albumHandle);
    CHECK_COND_RET(albumAni != nullptr, ANI_ERROR, "albumAni is nullptr");

    auto nativeHandle = std::make_unique<MediaAlbumChangeRequestAni>();
    nativeHandle->photoAlbum_ = albumAni->GetPhotoAlbumInstance();

    if (ANI_OK != env->Object_CallMethodByName_Void(object, "create", nullptr,
        reinterpret_cast<ani_long>(nativeHandle.release()))) {
        MEDIA_ERR_LOG("New PhotoAccessHelper Fail");
        return ANI_ERROR;
    }
    return ANI_OK;
}

MediaAlbumChangeRequestAni* MediaAlbumChangeRequestAni::Unwrap(ani_env *env, ani_object mediaAlbumChangeRequestHandle)
{
    ani_long mediaAlbumChangeRequestLong;
    if (ANI_OK != env->Object_GetFieldByName_Long(mediaAlbumChangeRequestHandle, "nativeHandle",
        &mediaAlbumChangeRequestLong)) {
        return nullptr;
    }
    return reinterpret_cast<MediaAlbumChangeRequestAni *>(mediaAlbumChangeRequestLong);
}

shared_ptr<PhotoAlbum> MediaAlbumChangeRequestAni::GetPhotoAlbumInstance() const
{
    return photoAlbum_;
}

shared_ptr<PhotoAlbum> MediaAlbumChangeRequestAni::GetReferencePhotoAlbumInstance() const
{
    return referencePhotoAlbum_;
}

shared_ptr<PhotoAlbum> MediaAlbumChangeRequestAni::GetTargetPhotoAlbumInstance() const
{
    return targetAlbum_;
}


ani_status MediaAlbumChangeRequestAni::PlaceBefore([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    [[maybe_unused]] ani_object albumHandle)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto albumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, albumHandle);
    CHECK_COND_RET(albumAni != nullptr, ANI_INVALID_ARGS, "albumAni is nullptr");
    aniContext->objectInfo->referencePhotoAlbum_ = albumAni->GetPhotoAlbumInstance();
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::ORDER_ALBUM);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::SetAlbumName(ani_env *env, ani_object object, ani_string name)
{
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");

    string albumName;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetParamStringPathMax(env, name, albumName) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get name");
    auto photoAlbum = aniContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, MediaFileUtils::CheckAlbumName(albumName) == E_OK, ANI_INVALID_ARGS,
        "Invalid album name");
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()) ||
        PhotoAlbum::IsSmartPortraitPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()) ||
        PhotoAlbum::IsSmartGroupPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only user album, smart portrait album and group photo can set album name");
    photoAlbum->SetAlbumName(albumName);
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_ALBUM_NAME);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::SetCoverUri(ani_env *env, ani_object object, ani_string coverUri)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto photoAlbum = aniContext->objectInfo->GetPhotoAlbumInstance();
    string coverUriStr;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetParamStringPathMax(env, coverUri, coverUriStr) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get coverUri");
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()) ||
        PhotoAlbum::IsSmartPortraitPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()) ||
        PhotoAlbum::IsSmartGroupPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only user album, smart portrait album and group photo can set album name");
    photoAlbum->SetCoverUri(coverUriStr);
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_COVER_URI);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::MergeAlbum(ani_env *env, ani_object object, ani_object albumHandle)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto albumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, albumHandle);
    CHECK_COND_RET(albumAni != nullptr, ANI_INVALID_ARGS, "albumAni is nullptr");
    aniContext->objectInfo->targetAlbum_ = albumAni->GetPhotoAlbumInstance();
    auto photoAlbum = aniContext->objectInfo->photoAlbum_;
    auto targetAlbum = aniContext->objectInfo->targetAlbum_;
    CHECK_COND_WITH_RET_MESSAGE(env,
        (photoAlbum != nullptr) && (targetAlbum != nullptr), ANI_INVALID_ARGS, "PhotoAlbum or TargetAlbum is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env,
        (PhotoAlbum::IsSmartPortraitPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) &&
        (PhotoAlbum::IsSmartPortraitPhotoAlbum(targetAlbum->GetPhotoAlbumType(), targetAlbum->GetPhotoAlbumSubType())),
        ANI_INVALID_ARGS, "Only portrait album can merge");
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::MERGE_ALBUM);
    return ANI_OK;
}

bool MediaAlbumChangeRequestAni::CheckDismissAssetVaild(std::vector<std::string> &dismissAssets,
    std::vector<std::string> &newAssetArray)
{
    if (newAssetArray.empty()) {
        return false;
    }
    unordered_set<string> assetSet(dismissAssets.begin(), dismissAssets.end());
    unordered_set<string> tempSet;
    for (const auto& newAsset : newAssetArray) {
        if (assetSet.find(newAsset) != assetSet.end()) {
            return false;
        }
        tempSet.insert(newAsset);
    }
    for (const auto& tmp : tempSet) {
        dismissAssets.push_back(tmp);
    }
    return true;
}


ani_status MediaAlbumChangeRequestAni::DismissAssets(ani_env *env, ani_object object, ani_object arrayPhotoAssetStr)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    vector<std::string> newAssetArray;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetUriArrayFromAssets(env, arrayPhotoAssetStr, newAssetArray) == ANI_OK,
        ANI_INVALID_ARGS, "Failed to get arrayPhotoAssetStr");
    if (!CheckDismissAssetVaild(aniContext->objectInfo->dismissAssets_, newAssetArray)) {
        AniError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT, "This dismissAssets is not support");
        return ANI_INVALID_ARGS;
    }
    auto photoAlbum = aniContext->objectInfo->GetPhotoAlbumInstance();
    auto type = photoAlbum->GetPhotoAlbumType();
    auto subtype = photoAlbum->GetPhotoAlbumSubType();
    CHECK_COND_WITH_RET_MESSAGE(env, PhotoAlbum::IsSmartPortraitPhotoAlbum(type, subtype) ||
        PhotoAlbum::IsSmartGroupPhotoAlbum(type, subtype) || PhotoAlbum::IsSmartClassifyAlbum(type, subtype),
        ANI_INVALID_ARGS, "Only portrait, group photo and classify album can dismiss asset");
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::DISMISS_ASSET);
    return ANI_OK;
}

static bool CheckDuplicatedAssetArray(const vector<string>& arrayToCheck, const vector<string>& currentArray)
{
    if (currentArray.empty()) {
        return true;
    }

    for (const auto& element : arrayToCheck) {
        if (std::find(currentArray.begin(), currentArray.end(), element) != currentArray.end()) {
            return false;
        }
    }
    return true;
}

ani_status MediaAlbumChangeRequestAni::AddAssets(ani_env *env, ani_object object, ani_object arrayPhotoAsset)
{
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");

    auto changeRequest = aniContext->objectInfo;
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only user album can add assets");
    vector<string> assetUriArray;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetUriArrayFromAssets(env, arrayPhotoAsset, assetUriArray) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get assetUriArray");
    if (!CheckDuplicatedAssetArray(assetUriArray, changeRequest->assetsToAdd_)) {
        AniError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT,
            "The previous addAssets operation has contained the same asset");
        return ANI_OK;
    }
    changeRequest->assetsToAdd_.insert(changeRequest->assetsToAdd_.end(), assetUriArray.begin(), assetUriArray.end());
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::ADD_ASSETS);
    return ANI_OK;
}

void MediaAlbumChangeRequestAni::RecordMoveAssets(vector<string>& assetArray, shared_ptr<PhotoAlbum>& targetAlbum)
{
    if (targetAlbum == nullptr || assetArray.empty()) {
        return;
    }

    auto iter = moveMap_.find(targetAlbum);
    if (iter != moveMap_.end()) {
        iter->second.insert(iter->second.end(), assetArray.begin(), assetArray.end());
    } else {
        moveMap_.insert(make_pair(targetAlbum, assetArray));
    }
}

static bool ParsePhotoAlbum(ani_env *env, ani_object targetAblum, shared_ptr<PhotoAlbum>& photoAlbum)
{
    auto albumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, targetAblum);
    CHECK_COND_WITH_RET_MESSAGE(env, albumAni != nullptr, false, "Failed to get albumAni object");

    auto photoAlbumPtr = albumAni->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbumPtr != nullptr, false, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        photoAlbumPtr->GetResultNapiType() == ResultNapiType::TYPE_PHOTOACCESS_HELPER &&
        PhotoAlbum::CheckPhotoAlbumType(photoAlbumPtr->GetPhotoAlbumType()) &&
        PhotoAlbum::CheckPhotoAlbumSubType(photoAlbumPtr->GetPhotoAlbumSubType()),
        false, "Unsupported type of photoAlbum");
    photoAlbum = photoAlbumPtr;
    return true;
}

ani_status MediaAlbumChangeRequestAni::MoveAssets(ani_env *env, ani_object object, ani_object arrayPhotoAsset,
    ani_object targetAblum)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto changeRequest = aniContext->objectInfo;
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");

    shared_ptr<PhotoAlbum> targetPhotoAlbum = nullptr;
    CHECK_COND_WITH_RET_MESSAGE(env, ParsePhotoAlbum(env, targetAblum, targetPhotoAlbum), ANI_INVALID_ARGS,
        "Failed to parse album");
    CHECK_COND_RET(targetPhotoAlbum != nullptr, ANI_INVALID_ARGS, "targetPhotoAlbum is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum->GetAlbumId() != targetPhotoAlbum->GetAlbumId(),
        ANI_INVALID_ARGS, "targetAlbum cannot be self");
    vector<string> assetUriArray;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetUriArrayFromAssets(env, arrayPhotoAsset, assetUriArray) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get assetUriArray");
    auto moveMap = changeRequest->GetMoveMap();
    for (auto iter = moveMap.begin(); iter != moveMap.end(); iter++) {
        if (!CheckDuplicatedAssetArray(assetUriArray, iter->second)) {
            AniError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT,
                "The previous moveAssets operation has contained the same asset");
            return ANI_OK;
        }
    }
    changeRequest->RecordMoveAssets(assetUriArray, targetPhotoAlbum);
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::MOVE_ASSETS);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::RecoverAssets(ani_env *env, ani_object object, ani_object arrayPhotoAsset)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto changeRequest = aniContext->objectInfo;
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsTrashAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only trash album can recover assets");
    vector<string> assetUriArray;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetUriArrayFromAssets(env, arrayPhotoAsset, assetUriArray) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get assetUriArray");
    if (!CheckDuplicatedAssetArray(assetUriArray, changeRequest->assetsToRecover_)) {
        AniError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT,
            "The previous recoverAssets operation has contained the same asset");
        return ANI_OK;
    }
    changeRequest->assetsToRecover_.insert(
        changeRequest->assetsToRecover_.end(), assetUriArray.begin(), assetUriArray.end());
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::RECOVER_ASSETS);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::SetDisplayLevel(ani_env *env, ani_object object, ani_int displayLevel)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env, MediaFileUtils::CheckDisplayLevel(displayLevel),
        ANI_INVALID_ARGS, "Invalid display level");
    auto photoAlbum = aniContext->objectInfo->photoAlbum_;
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "PhotoAlbum is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsSmartPortraitPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only portrait album can set album display level");
    photoAlbum->SetDisplayLevel(displayLevel);
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_DISPLAY_LEVEL);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::SetIsMe(ani_env *env, ani_object object)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto photoAlbum = aniContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsSmartPortraitPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only portrait album can set is me");
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_IS_ME);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::DeleteAssets(ani_env *env, ani_object object, ani_object arrayPhotoAsset)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto changeRequest = aniContext->objectInfo;
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsTrashAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only trash album can delete assets permanently");
    vector<string> assetUriArray;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetUriArrayFromAssets(env, arrayPhotoAsset, assetUriArray) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get assetUriArray");
    if (!CheckDuplicatedAssetArray(assetUriArray, changeRequest->assetsToDelete_)) {
        AniError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT,
            "The previous deleteAssets operation has contained the same asset");
        return ANI_ERROR;
    }
    changeRequest->assetsToDelete_.insert(
        changeRequest->assetsToDelete_.end(), assetUriArray.begin(), assetUriArray.end());
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::DELETE_ASSETS);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::DeleteAlbums(ani_env *env, ani_class clazz, ani_object context,
    ani_object arrayAlbum)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, MediaAlbumChangeRequestAni::InitUserFileClient(env, context), ANI_INVALID_ARGS,
        "DeleteAlbums InitUserFileClient failed");
    std::vector<PhotoAlbumAni*> array;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetPhotoAlbumAniArray(env, arrayAlbum, array) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get arrayAlbum");

    vector<string> deleteIds;
    for (const auto& obj : array) {
        CHECK_COND_WITH_RET_MESSAGE(env,
            PhotoAlbum::IsUserPhotoAlbum(obj->GetPhotoAlbumInstance()->GetPhotoAlbumType(),
            obj->GetPhotoAlbumInstance()->GetPhotoAlbumSubType()), ANI_INVALID_ARGS, "Only user album can be deleted");
        deleteIds.push_back(to_string(obj->GetPhotoAlbumInstance()->GetAlbumId()));
    }
    aniContext->predicates.In(PhotoAlbumColumns::ALBUM_ID, deleteIds);
    Uri deleteAlbumUri(PAH_DELETE_PHOTO_ALBUM);
    int ret = UserFileClient::Delete(deleteAlbumUri, aniContext->predicates);
    if (ret < 0) {
        ANI_ERR_LOG("Failed to delete albums, err: %{public}d", ret);
        aniContext->ThrowError(env, ret, "Failed to delete albums");
        return ANI_ERROR;
    }
    ANI_INFO_LOG("Delete %{public}d album(s)", ret);
    return ANI_OK;
}

void MediaAlbumChangeRequestAni::ClearAddAssetArray()
{
    assetsToAdd_.clear();
}

void MediaAlbumChangeRequestAni::ClearRemoveAssetArray()
{
    assetsToRemove_.clear();
}

void MediaAlbumChangeRequestAni::ClearRecoverAssetArray()
{
    assetsToRecover_.clear();
}

void MediaAlbumChangeRequestAni::ClearDeleteAssetArray()
{
    assetsToDelete_.clear();
}

void MediaAlbumChangeRequestAni::ClearDismissAssetArray()
{
    dismissAssets_.clear();
}

void MediaAlbumChangeRequestAni::ClearMoveMap()
{
    moveMap_.clear();
}

vector<string> MediaAlbumChangeRequestAni::GetAddAssetArray() const
{
    return assetsToAdd_;
}

vector<string> MediaAlbumChangeRequestAni::GetRemoveAssetArray() const
{
    return assetsToRemove_;
}

vector<string> MediaAlbumChangeRequestAni::GetRecoverAssetArray() const
{
    return assetsToRecover_;
}

vector<string> MediaAlbumChangeRequestAni::GetDeleteAssetArray() const
{
    return assetsToDelete_;
}

vector<string> MediaAlbumChangeRequestAni::GetDismissAssetArray() const
{
    return dismissAssets_;
}

map<shared_ptr<PhotoAlbum>, vector<string>, PhotoAlbumPtrCompare> MediaAlbumChangeRequestAni::GetMoveMap() const
{
    return moveMap_;
}

static bool CreateAlbumExecute(MediaAlbumChangeRequestContext& context)
{
    auto changeRequest = context.objectInfo;
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();

    Uri createAlbumUri(PAH_CREATE_PHOTO_ALBUM);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_NAME, photoAlbum->GetAlbumName());
    int32_t ret = UserFileClient::Insert(createAlbumUri, valuesBucket);
    if (ret == -1) {
        context.SaveError(-EEXIST);
        ANI_ERR_LOG("Album exists");
        return false;
    }
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to create album, ret: %{public}d", ret);
        return false;
    }

    photoAlbum->SetAlbumId(ret);
    photoAlbum->SetAlbumUri(PhotoAlbumColumns::ALBUM_URI_PREFIX + to_string(ret));
    return true;
}

static bool FetchNewCount(MediaAlbumChangeRequestContext& context, shared_ptr<PhotoAlbum>& album)
{
    if (album == nullptr) {
        ANI_ERR_LOG("Album is null");
        context.SaveError(E_FAIL);
        return false;
    }

    Uri queryUri(PAH_QUERY_PHOTO_ALBUM);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, album->GetAlbumId());
    vector<string> fetchColumns = { PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT, PhotoAlbumColumns::ALBUM_VIDEO_COUNT };
    int errCode = 0;
    auto resultSet = UserFileClient::Query(queryUri, predicates, fetchColumns, errCode);
    if (resultSet == nullptr) {
        ANI_ERR_LOG("resultSet == nullptr, errCode is %{public}d", errCode);
        context.SaveError(E_HAS_DB_ERROR);
        return false;
    }
    if (resultSet->GoToFirstRow() != 0) {
        ANI_ERR_LOG("go to first row failed when fetch new count");
        context.SaveError(E_HAS_DB_ERROR);
        return false;
    }

    bool hiddenOnly = album->GetHiddenOnly();
    int imageCount = hiddenOnly ? -1 :
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet, TYPE_INT32));
    int videoCount = hiddenOnly ? -1 :
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet, TYPE_INT32));
    album->SetCount(
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT, resultSet, TYPE_INT32)));
    album->SetImageCount(imageCount);
    album->SetVideoCount(videoCount);
    return true;
}

static bool AddAssetsExecute(MediaAlbumChangeRequestContext& context)
{
    auto changeRequest = context.objectInfo;
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    int32_t albumId = photoAlbum->GetAlbumId();
    vector<DataShare::DataShareValuesBucket> valuesBuckets;
    for (const auto& asset : changeRequest->GetAddAssetArray()) {
        DataShare::DataShareValuesBucket pair;
        pair.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
        pair.Put(PhotoColumn::MEDIA_ID, asset);
        valuesBuckets.push_back(pair);
    }

    Uri addAssetsUri(PAH_PHOTO_ALBUM_ADD_ASSET);
    int ret = UserFileClient::BatchInsert(addAssetsUri, valuesBuckets);
    changeRequest->ClearAddAssetArray();
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to add assets into album %{public}d, err: %{public}d", albumId, ret);
        return false;
    }

    ANI_INFO_LOG("Add %{public}d asset(s) into album %{public}d", ret, albumId);
    FetchNewCount(context, photoAlbum);
    return true;
}

static bool RemoveAssetsExecute(MediaAlbumChangeRequestContext& context)
{
    auto changeRequest = context.objectInfo;
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    int32_t albumId = photoAlbum->GetAlbumId();
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(albumId));
    predicates.And()->In(PhotoColumn::MEDIA_ID, changeRequest->GetRemoveAssetArray());

    Uri removeAssetsUri(PAH_PHOTO_ALBUM_REMOVE_ASSET);
    int ret = UserFileClient::Delete(removeAssetsUri, predicates);
    changeRequest->ClearRemoveAssetArray();
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to remove assets from album %{public}d, err: %{public}d", albumId, ret);
        return false;
    }

    ANI_INFO_LOG("Remove %{public}d asset(s) from album %{public}d", ret, albumId);
    FetchNewCount(context, photoAlbum);
    return true;
}

static bool MoveAssetsExecute(MediaAlbumChangeRequestContext& context)
{
    auto changeRequest = context.objectInfo;
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    int32_t albumId = photoAlbum->GetAlbumId();
    auto moveMap = changeRequest->GetMoveMap();
    changeRequest->ClearMoveMap();

    for (auto iter = moveMap.begin(); iter != moveMap.end(); iter++) {
        auto targetPhotoAlbum = iter->first;
        int32_t targetAlbumId = targetPhotoAlbum->GetAlbumId();
        vector<string> moveAssetArray = iter->second;
        DataShare::DataSharePredicates predicates;
        predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(albumId));
        predicates.And()->In(PhotoColumn::MEDIA_ID, moveAssetArray);

        DataShare::DataShareValuesBucket valuesBuckets;
        valuesBuckets.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, targetAlbumId);
        string uri = PAH_BATCH_UPDATE_OWNER_ALBUM_ID;
        MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri moveAssetsUri(uri);
        int ret = UserFileClient::Update(moveAssetsUri, predicates, valuesBuckets);
        if (ret < 0) {
            context.SaveError(ret);
            ANI_ERR_LOG("Failed to move assets into album %{public}d, err: %{public}d", targetAlbumId, ret);
            return false;
        }
        ANI_INFO_LOG("Move %{public}d asset(s) into album %{public}d", ret, targetAlbumId);
        FetchNewCount(context, targetPhotoAlbum);
    }
    FetchNewCount(context, photoAlbum);
    return true;
}

static bool RecoverAssetsExecute(MediaAlbumChangeRequestContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    predicates.In(PhotoColumn::MEDIA_ID, context.objectInfo->GetRecoverAssetArray());
    valuesBucket.Put(PhotoColumn::MEDIA_DATE_TRASHED, 0);

    Uri recoverAssetsUri(PAH_RECOVER_PHOTOS);
    int ret = UserFileClient::Update(recoverAssetsUri, predicates, valuesBucket);
    context.objectInfo->ClearRecoverAssetArray();
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to recover assets, err: %{public}d", ret);
        return false;
    }

    ANI_INFO_LOG("Recover %{public}d assets from trash album", ret);
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    int32_t currentCount = photoAlbum->GetCount() - ret;
    photoAlbum->SetCount(currentCount > 0 ? currentCount : 0);
    return true;
}

static bool DeleteAssetsExecute(MediaAlbumChangeRequestContext& context)
{
    DataShare::DataSharePredicates predicates;
    predicates.In(PhotoColumn::MEDIA_ID, context.objectInfo->GetDeleteAssetArray());
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::MEDIA_DATE_TRASHED, 0);

    Uri deleteAssetsUri(PAH_DELETE_PHOTOS);
    int ret = UserFileClient::Update(deleteAssetsUri, predicates, valuesBucket);
    context.objectInfo->ClearDeleteAssetArray();
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to delete assets from trash album permanently, err: %{public}d", ret);
        return false;
    }

    ANI_INFO_LOG("Delete %{public}d assets permanently from trash album", ret);
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    int32_t currentCount = photoAlbum->GetCount() - ret;
    photoAlbum->SetCount(currentCount > 0 ? currentCount : 0);
    return true;
}

static bool OrderAlbumExecute(MediaAlbumChangeRequestContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    auto referenceAlum = context.objectInfo->GetReferencePhotoAlbumInstance();
    Uri updateAlbumUri(PAH_ORDER_ALBUM);
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_ID, photoAlbum->GetAlbumId());
    int32_t referenceAlbumId = -1;
    if (referenceAlum != nullptr) {
        referenceAlbumId = referenceAlum->GetAlbumId();
    }
    valuesBucket.Put(PhotoAlbumColumns::REFERENCE_ALBUM_ID, referenceAlbumId);
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_TYPE, photoAlbum->GetPhotoAlbumType());
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_SUBTYPE, photoAlbum->GetPhotoAlbumSubType());
    int32_t result = UserFileClient::Update(updateAlbumUri, predicates, valuesBucket);
    if (result < 0) {
        context.SaveError(result);
        ANI_ERR_LOG("Failed to order albums err: %{public}d", result);
        return false;
    }
    return true;
}

static bool MergeAlbumExecute(MediaAlbumChangeRequestContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    auto targetAlum = context.objectInfo->GetTargetPhotoAlbumInstance();
    Uri updateAlbumUri(PAH_PORTRAIT_MERGE_ALBUM);
    valuesBucket.Put(ALBUM_ID, photoAlbum->GetAlbumId());
    int32_t targetAlbumId = -1;
    if (targetAlum != nullptr) {
        targetAlbumId = targetAlum->GetAlbumId();
    }
    valuesBucket.Put(TARGET_ALBUM_ID, targetAlbumId);
    int32_t result = UserFileClient::Update(updateAlbumUri, predicates, valuesBucket);
    if (result < 0) {
        context.SaveError(result);
        ANI_ERR_LOG("Failed to merge albums err: %{public}d", result);
        return false;
    }
    return true;
}

static void UpdateTabAnalysisImageFace(std::shared_ptr<PhotoAlbum>& photoAlbum,
    MediaAlbumChangeRequestContext& context)
{
    if (photoAlbum->GetPhotoAlbumSubType() != PhotoAlbumSubType::PORTRAIT) {
        return;
    }

    std::string updateUri = PAH_UPDATE_ANA_FACE;
    MediaLibraryAniUtils::UriAppendKeyValue(updateUri, API_VERSION, std::to_string(MEDIA_API_VERSION_V10));
    MediaLibraryAniUtils::UriAppendKeyValue(updateUri, MEDIA_OPERN_KEYWORD, UPDATE_DISMISS_ASSET);
    Uri updateFaceUri(updateUri);

    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(MediaAlbumChangeRequestAni::TAG_ID,
        std::to_string(MediaAlbumChangeRequestAni::PORTRAIT_REMOVED));

    DataShare::DataSharePredicates updatePredicates;
    std::vector<std::string> dismissAssetArray = context.objectInfo->GetDismissAssetArray();
    std::string selection = std::to_string(photoAlbum->GetAlbumId());
    for (size_t i = 0; i < dismissAssetArray.size(); ++i) {
        selection += "," + dismissAssetArray[i];
    }
    updatePredicates.SetWhereClause(selection);
    int updatedRows = UserFileClient::Update(updateFaceUri, updatePredicates, updateValues);
    if (updatedRows <= 0) {
        ANI_WARN_LOG("Failed to update tab_analysis_image_face, err: %{public}d", updatedRows);
    }
}

static bool DismissAssetExecute(MediaAlbumChangeRequestContext& context)
{
    string disMissAssetAssetsUri = PAH_DISMISS_ASSET;
    Uri uri(disMissAssetAssetsUri);

    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MAP_ALBUM, to_string(photoAlbum->GetAlbumId()));
    predicates.And()->In(MAP_ASSET, context.objectInfo->GetDismissAssetArray());
    predicates.And()->EqualTo(ALBUM_SUBTYPE, to_string(photoAlbum->GetPhotoAlbumSubType()));

    auto deletedRows = UserFileClient::Delete(uri, predicates);
    if (deletedRows < 0) {
        context.SaveError(deletedRows);
        ANI_ERR_LOG("Failed to dismiss asset err: %{public}d", deletedRows);
        return false;
    }

    if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::PORTRAIT) {
        UpdateTabAnalysisImageFace(photoAlbum, context);
    }

    context.objectInfo->ClearDismissAssetArray();
    return true;
}

static const unordered_map<AlbumChangeOperation, bool (*)(MediaAlbumChangeRequestContext&)> EXECUTE_MAP = {
    { AlbumChangeOperation::CREATE_ALBUM, CreateAlbumExecute },
    { AlbumChangeOperation::ADD_ASSETS, AddAssetsExecute },
    { AlbumChangeOperation::REMOVE_ASSETS, RemoveAssetsExecute },
    { AlbumChangeOperation::MOVE_ASSETS, MoveAssetsExecute },
    { AlbumChangeOperation::RECOVER_ASSETS, RecoverAssetsExecute },
    { AlbumChangeOperation::DELETE_ASSETS, DeleteAssetsExecute },
    { AlbumChangeOperation::ORDER_ALBUM, OrderAlbumExecute },
    { AlbumChangeOperation::MERGE_ALBUM, MergeAlbumExecute },
    { AlbumChangeOperation::DISMISS_ASSET, DismissAssetExecute },
};

static bool GetAlbumUpdateValue(shared_ptr<PhotoAlbum>& photoAlbum, const AlbumChangeOperation changeOperation,
    string& uri, DataShare::DataShareValuesBucket& valuesBucket, string& property)
{
    if (photoAlbum == nullptr) {
        ANI_ERR_LOG("photoAlbum is null");
        return false;
    }

    switch (changeOperation) {
        case AlbumChangeOperation::SET_ALBUM_NAME:
            if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::PORTRAIT) {
                uri = PAH_PORTRAIT_ANAALBUM_ALBUM_NAME;
            } else if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::GROUP_PHOTO) {
                uri = PAH_GROUP_ANAALBUM_ALBUM_NAME;
            } else {
                uri = PAH_SET_PHOTO_ALBUM_NAME;
            }
            property = PhotoAlbumColumns::ALBUM_NAME;
            valuesBucket.Put(property, photoAlbum->GetAlbumName());
            break;
        case AlbumChangeOperation::SET_COVER_URI:
            if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::PORTRAIT) {
                uri = PAH_PORTRAIT_ANAALBUM_COVER_URI;
            } else if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::GROUP_PHOTO) {
                uri = PAH_GROUP_ANAALBUM_COVER_URI;
            } else {
                uri = PAH_UPDATE_PHOTO_ALBUM;
            }
            property = PhotoAlbumColumns::ALBUM_COVER_URI;
            valuesBucket.Put(property, photoAlbum->GetCoverUri());
            break;
        case AlbumChangeOperation::SET_DISPLAY_LEVEL:
            uri = PAH_PORTRAIT_DISPLAY_LEVLE;
            property = USER_DISPLAY_LEVEL;
            valuesBucket.Put(property, photoAlbum->GetDisplayLevel());
            break;
        case AlbumChangeOperation::SET_IS_ME:
            uri = PAH_PORTRAIT_IS_ME;
            property = IS_ME;
            valuesBucket.Put(property, 1);
            break;
        case AlbumChangeOperation::DISMISS:
            uri = PAH_GROUP_ANAALBUM_DISMISS;
            property = IS_REMOVED;
            valuesBucket.Put(property, 1);
            break;
        default:
            return false;
    }
    return true;
}

static bool SetAlbumPropertyExecute(
    std::unique_ptr<MediaAlbumChangeRequestContext> &aniContext, const AlbumChangeOperation changeOperation)
{
    // In the scenario of creation, the new name will be applied when the album is created.
    if (changeOperation == AlbumChangeOperation::SET_ALBUM_NAME &&
        aniContext->albumChangeOperations.front() == AlbumChangeOperation::CREATE_ALBUM) {
        return true;
    }

    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto photoAlbum = aniContext->objectInfo->GetPhotoAlbumInstance();
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    string uri;
    string property;
    if (!GetAlbumUpdateValue(photoAlbum, changeOperation, uri, valuesBucket, property)) {
        aniContext->SaveError(E_FAIL);
        ANI_ERR_LOG("Failed to parse album change operation: %{public}d", changeOperation);
        return false;
    }
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_SUBTYPE, photoAlbum->GetPhotoAlbumSubType());
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAlbumUri(uri);
    int32_t changedRows = UserFileClient::Update(updateAlbumUri, predicates, valuesBucket);
    if (changedRows < 0) {
        aniContext->SaveError(changedRows);
        ANI_ERR_LOG("Failed to set %{public}s, err: %{public}d", property.c_str(), changedRows);
        return false;
    }
    return true;
}

static void ApplyAlbumChangeRequestExecute(std::unique_ptr<MediaAlbumChangeRequestContext> &aniContext)
{
    unordered_set<AlbumChangeOperation> appliedOperations;
    for (const auto& changeOperation : aniContext->albumChangeOperations) {
        // Keep the final result(s) of each operation, and commit only once.
        if (appliedOperations.find(changeOperation) != appliedOperations.end()) {
            continue;
        }

        bool valid = false;
        auto iter = EXECUTE_MAP.find(changeOperation);
        if (iter != EXECUTE_MAP.end()) {
            valid = iter->second(*aniContext);
        } else if (changeOperation == AlbumChangeOperation::SET_ALBUM_NAME ||
                   changeOperation == AlbumChangeOperation::SET_COVER_URI ||
                   changeOperation == AlbumChangeOperation::SET_IS_ME ||
                   changeOperation == AlbumChangeOperation::SET_DISPLAY_LEVEL ||
                   changeOperation == AlbumChangeOperation::DISMISS) {
            valid = SetAlbumPropertyExecute(aniContext, changeOperation);
        } else {
            ANI_ERR_LOG("Invalid album change operation: %{public}d", changeOperation);
            aniContext->error = OHOS_INVALID_PARAM_CODE;
            return;
        }

        if (!valid) {
            ANI_ERR_LOG("Failed to apply album change request, operation: %{public}d", changeOperation);
            return;
        }
        appliedOperations.insert(changeOperation);
    }
}

ani_status MediaAlbumChangeRequestAni::ApplyChanges(ani_env *env)
{
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    aniContext->objectInfo = this;
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    aniContext->objectInfo->CheckChangeOperations(env);
    aniContext->albumChangeOperations = aniContext->objectInfo->albumChangeOperations_;
    aniContext->objectInfo->albumChangeOperations_.clear();
    ApplyAlbumChangeRequestExecute(aniContext);
    ani_object err = {};
    aniContext->HandleError(env, err);
    return ANI_OK;
}

bool MediaAlbumChangeRequestAni::CheckChangeOperations(ani_env *env)
{
    if (albumChangeOperations_.empty()) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "None request to apply");
        return false;
    }

    auto photoAlbum = GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "photoAlbum is null");
        return false;
    }

    if (albumChangeOperations_.front() != AlbumChangeOperation::CREATE_ALBUM && photoAlbum->GetAlbumId() <= 0) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid album change request");
        return false;
    }

    return true;
}

} // namespace OHOS::Media