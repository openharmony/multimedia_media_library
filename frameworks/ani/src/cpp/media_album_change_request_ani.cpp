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

#include "media_album_change_request_ani.h"
#include <array>
#include <iostream>
#include <sstream>
#include "result_set_utils.h"
#include "ani_class_name.h"
#include "medialibrary_ani_utils.h"
#include "media_file_utils.h"
#include "userfile_client.h"
#include "photo_album_ani.h"
#include "vision_photo_map_column.h"
#include "album_operation_uri.h"

namespace OHOS::Media {
ani_status MediaAlbumChangeRequestAni::Init(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    static const char *className = PAH_ANI_CLASS_MEDIA_ALBUM_CHANGE_REQUEST.c_str();
    ani_class cls;
    auto status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"getAlbum", nullptr, reinterpret_cast<void *>(GetAlbum)},
        ani_native_function {"createAlbumRequest", nullptr, reinterpret_cast<void *>(CreateAlbumRequest)},
        ani_native_function {"nativeConstructor", nullptr, reinterpret_cast<void *>(Constructor)},
        ani_native_function {"placeBefore", nullptr, reinterpret_cast<void *>(PlaceBefore)},
        ani_native_function {"dismissAssets", nullptr, reinterpret_cast<void *>(DismissAssets)},
        ani_native_function {"addAssets", nullptr, reinterpret_cast<void *>(AddAssets)},
        ani_native_function {"moveAssets", nullptr, reinterpret_cast<void *>(MoveAssets)},
        ani_native_function {"mergeAlbum", nullptr, reinterpret_cast<void *>(MergeAlbum)},
        ani_native_function {"setAlbumName", nullptr, reinterpret_cast<void *>(SetAlbumName)},
        ani_native_function {"setCoverUri", nullptr, reinterpret_cast<void *>(SetCoverUri)},
        ani_native_function {"removeAssets", nullptr, reinterpret_cast<void *>(RemoveAssets)},
        ani_native_function {"recoverAssets", nullptr, reinterpret_cast<void *>(RecoverAssets)},
        ani_native_function {"setDisplayLevel", nullptr, reinterpret_cast<void *>(SetDisplayLevel)},
        ani_native_function {"deleteAssets", nullptr, reinterpret_cast<void *>(DeleteAssets)},
        ani_native_function {"deleteAlbumsSync", nullptr, reinterpret_cast<void *>(DeleteAlbums)},
        ani_native_function {"setIsMe", nullptr, reinterpret_cast<void *>(SetIsMe)},
        ani_native_function {"dismiss", nullptr, reinterpret_cast<void *>(Dismiss)},
    };
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::MediaAnalysisAlbumChangeRequestInit(ani_env *env)
{
    static const char *className = PAH_ANI_CLASS_MEDIA_ANALYSIS_ALBUM_CHANGE_REQUEST.c_str();
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    ani_class cls;
    auto status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"setOrderPosition", nullptr, reinterpret_cast<void *>(SetOrderPosition)},
    };
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::Constructor([[maybe_unused]] ani_env *env, ani_object object,
    [[maybe_unused]] ani_object albumHandle)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    auto albumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, albumHandle);
    CHECK_COND_RET(albumAni != nullptr, ANI_ERROR, "albumAni is nullptr");

    auto nativeHandle = std::make_unique<MediaAlbumChangeRequestAni>();
    CHECK_COND_RET(nativeHandle != nullptr, ANI_ERROR, "nativeHandle is nullptr");
    nativeHandle->photoAlbum_ = albumAni->GetPhotoAlbumInstance();

    if (ANI_OK != env->Object_CallMethodByName_Void(object, "create", nullptr,
        reinterpret_cast<ani_long>(nativeHandle.get()))) {
        ANI_ERR_LOG("New PhotoAccessHelper Fail");
        return ANI_ERROR;
    }
    (void)nativeHandle.release();
    return ANI_OK;
}

MediaAlbumChangeRequestAni* MediaAlbumChangeRequestAni::Unwrap(ani_env *env, ani_object mediaAlbumChangeRequestHandle)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is null");
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

ani_object MediaAlbumChangeRequestAni::GetAlbum(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env, nullptr, "object is null");
    auto asyncContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND(env, asyncContext != nullptr, JS_INNER_FAIL);
    asyncContext->objectInfo = Unwrap(env, object);
    auto changeRequest = asyncContext->objectInfo;
    CHECK_COND(env, changeRequest != nullptr, JS_INNER_FAIL);
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND(env, photoAlbum != nullptr, JS_INNER_FAIL);
    if (photoAlbum->GetAlbumId() > 0) {
        return PhotoAlbumAni::CreatePhotoAlbumAni(env, photoAlbum);
    }
    // PhotoAlbum object has not been actually created, return null.
    return nullptr;
}

static ani_object ParseArgsCreateAlbum(ani_env *env, ani_object aniContext,
    ani_string aniName, unique_ptr<MediaAlbumChangeRequestContext>& context)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    CHECK_COND(env, MediaAlbumChangeRequestAni::InitUserFileClient(env, aniContext), JS_INNER_FAIL);

    string albumName;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryAniUtils::GetParamStringPathMax(env, aniName, albumName) == ANI_OK,
        "Failed to get album name");
    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckAlbumName(albumName) == E_OK, "Invalid album name");
    CHECK_COND_WITH_MESSAGE(env, context != nullptr, "context is nullptr");
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_NAME, albumName);
    ani_object ret;
    MediaLibraryAniUtils::ToAniBooleanObject(env, true, ret);
    return ret;
}

ani_object CreateMediaAlbumChangeRequestAni(ani_env *env, ani_object object)
{
    static const char *className = PAH_ANI_CLASS_MEDIA_ALBUM_CHANGE_REQUEST.c_str();
    ani_class cls;
    auto status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }
    ani_method ctor;
    status = env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find constructor for class: %{public}s", className);
        return nullptr;
    }
    ani_object ret;
    status = env->Object_New(cls, ctor, &ret, object);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to create MediaAlbumChangeRequestAni object");
        return nullptr;
    }
    return ret;
}

ani_object MediaAlbumChangeRequestAni::CreateAlbumRequest(ani_env *env, ani_object object, ani_object aniContext,
    ani_string aniName)
{
    auto asyncContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND(env, asyncContext != nullptr, JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, ParseArgsCreateAlbum(env, aniContext, aniName, asyncContext) != nullptr,
        "Failed to parse args");

    bool isValid = false;
    string albumName = asyncContext->valuesBucket.Get(PhotoAlbumColumns::ALBUM_NAME, isValid);
    auto photoAlbum = make_unique<PhotoAlbum>();
    CHECK_COND(env, photoAlbum != nullptr, JS_INNER_FAIL);
    photoAlbum->SetAlbumName(albumName);
    photoAlbum->SetPhotoAlbumType(USER);
    photoAlbum->SetPhotoAlbumSubType(USER_GENERIC);
    photoAlbum->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    ani_object photoAlbumAni = PhotoAlbumAni::CreatePhotoAlbumAni(env, photoAlbum);
    CHECK_COND(env, photoAlbumAni != nullptr, JS_INNER_FAIL);
    ani_object instance = CreateMediaAlbumChangeRequestAni(env, photoAlbumAni);
    CHECK_COND(env, instance != nullptr, JS_INNER_FAIL);

    MediaAlbumChangeRequestAni* changeRequest = Unwrap(env, instance);
    CHECK_COND(env, changeRequest != nullptr, JS_INNER_FAIL);
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::CREATE_ALBUM);
    return instance;
}

ani_status MediaAlbumChangeRequestAni::PlaceBefore([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    [[maybe_unused]] ani_object albumHandle)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }

    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
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
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
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
        PhotoAlbum::IsSmartGroupPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()) ||
        PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only user album, highlight, smart portrait album and group photo can set album name");
    photoAlbum->SetAlbumName(albumName);
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_ALBUM_NAME);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::SetCoverUri(ani_env *env, ani_object object, ani_string coverUri)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
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
        PhotoAlbum::IsSmartGroupPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()) ||
        PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only user album, highlight, smart portrait album and group photo can set cover uri");
    photoAlbum->SetCoverUri(coverUriStr);
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_COVER_URI);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::MergeAlbum(ani_env *env, ani_object object, ani_object albumHandle)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
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
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is nullptr");
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
    CHECK_COND_RET(photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    auto type = photoAlbum->GetPhotoAlbumType();
    auto subtype = photoAlbum->GetPhotoAlbumSubType();
    CHECK_COND_WITH_RET_MESSAGE(env, PhotoAlbum::IsSmartPortraitPhotoAlbum(type, subtype) ||
        PhotoAlbum::IsSmartGroupPhotoAlbum(type, subtype) || PhotoAlbum::IsSmartClassifyAlbum(type, subtype) ||
        PhotoAlbum::IsHighlightAlbum(type, subtype),
        ANI_INVALID_ARGS, "Only portrait, highlight, group photo and classify album can dismiss asset");
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
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
    aniContext->objectInfo = Unwrap(env, object);

    auto changeRequest = aniContext->objectInfo;
    CHECK_COND_RET(changeRequest != nullptr, ANI_INVALID_ARGS, "changeRequest is nullptr");
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()) ||
        PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only user and highlight album can add assets");
    vector<string> assetUriArray;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetUriArrayFromAssets(env, arrayPhotoAsset, assetUriArray) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get assetUriArray");
    if (!CheckDuplicatedAssetArray(assetUriArray, changeRequest->assetsToAdd_)) {
        AniError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT,
            "The previous addAssets operation has contained the same asset");
        return ANI_ERROR;
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
    CHECK_COND_RET(env != nullptr, false, "env is null");
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
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is nullptr");
    aniContext->objectInfo = Unwrap(env, object);
    auto changeRequest = aniContext->objectInfo;
    CHECK_COND_RET(changeRequest != nullptr, ANI_INVALID_ARGS, "changeRequest is nullptr");
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
            return ANI_ERROR;
        }
    }
    changeRequest->RecordMoveAssets(assetUriArray, targetPhotoAlbum);
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::MOVE_ASSETS);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::RemoveAssets(ani_env *env, ani_object object, ani_object arrayPhotoAsset)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
    aniContext->objectInfo = Unwrap(env, object);
    auto changeRequest = aniContext->objectInfo;
    CHECK_COND_RET(changeRequest != nullptr, ANI_INVALID_ARGS, "changeRequest is nullptr");
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(),
        photoAlbum->GetPhotoAlbumSubType()), ANI_INVALID_ARGS, "Only user album can be deleted");
    vector<string> assetUriArray;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetUriArrayFromAssets(env, arrayPhotoAsset, assetUriArray) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get assetUriArray");
    if (!CheckDuplicatedAssetArray(assetUriArray, changeRequest->assetsToRemove_)) {
        AniError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT,
            "The previous RemoveAssets operation has contained the same asset");
        return ANI_ERROR;
    }
    changeRequest->assetsToRemove_.insert(
        changeRequest->assetsToRemove_.end(), assetUriArray.begin(), assetUriArray.end());
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::REMOVE_ASSETS);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::RecoverAssets(ani_env *env, ani_object object, ani_object arrayPhotoAsset)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
    aniContext->objectInfo = Unwrap(env, object);
    auto changeRequest = aniContext->objectInfo;
    CHECK_COND_RET(changeRequest != nullptr, ANI_INVALID_ARGS, "changeRequest is nullptr");
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
        return ANI_ERROR;
    }
    changeRequest->assetsToRecover_.insert(
        changeRequest->assetsToRecover_.end(), assetUriArray.begin(), assetUriArray.end());
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::RECOVER_ASSETS);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::SetDisplayLevel(ani_env *env, ani_object object, ani_int displayLevel)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
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
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
    aniContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(aniContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto photoAlbum = aniContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsSmartPortraitPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only portrait album can set is me");
    aniContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_IS_ME);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::Dismiss(ani_env *env, ani_object object)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto asyncContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(asyncContext != nullptr, ANI_ERROR, "asyncContext is null");
    asyncContext->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(asyncContext->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    auto photoAlbum = asyncContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, ANI_ERROR, "photoAlbum is null");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsSmartGroupPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only group photo can be dismissed");
    asyncContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::DISMISS);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::DeleteAssets(ani_env *env, ani_object object, ani_object arrayPhotoAsset)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
    aniContext->objectInfo = Unwrap(env, object);
    auto changeRequest = aniContext->objectInfo;
    CHECK_COND_RET(changeRequest != nullptr, ANI_INVALID_ARGS, "changeRequest is nullptr");
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
    changeRequest->userId_ = photoAlbum->GetUserId();
    changeRequest->albumChangeOperations_.push_back(AlbumChangeOperation::DELETE_ASSETS);
    return ANI_OK;
}

ani_status MediaAlbumChangeRequestAni::DeleteAlbums(ani_env *env, ani_class clazz, ani_object context,
    ani_object arrayAlbum)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is null");
    CHECK_COND_WITH_RET_MESSAGE(env, MediaAlbumChangeRequestAni::InitUserFileClient(env, context), ANI_INVALID_ARGS,
        "DeleteAlbums InitUserFileClient failed");
    std::vector<PhotoAlbumAni*> array;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetPhotoAlbumAniArray(env, arrayAlbum, array) == ANI_OK, ANI_INVALID_ARGS,
        "Failed to get arrayAlbum");

    vector<string> deleteIds;
    for (const auto& obj : array) {
        CHECK_COND_RET(obj != nullptr && obj->GetPhotoAlbumInstance() != nullptr, ANI_ERROR, "obj is null");
        auto albumType = obj->GetPhotoAlbumInstance()->GetPhotoAlbumType();
        auto albumSubType = obj->GetPhotoAlbumInstance()->GetPhotoAlbumSubType();
        CHECK_COND_WITH_RET_MESSAGE(env, PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubType) ||
            PhotoAlbum::IsHighlightAlbum(albumType, albumSubType), ANI_INVALID_ARGS,
            "Only user and highlight album can be deleted");
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

std::vector<std::pair<std::string, int32_t>> MediaAlbumChangeRequestAni::GetIdOrderPositionPairs() const
{
    return idOrderPositionPairs_;
}

int32_t MediaAlbumChangeRequestAni::GetUserId() const
{
    return userId_;
}


static bool CreateAlbumExecute(MediaAlbumChangeRequestContext& context)
{
    auto changeRequest = context.objectInfo;
    CHECK_COND_RET(changeRequest != nullptr, false, "changeRequest is null");
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");

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
    CHECK_COND_RET(changeRequest != nullptr, false, "changeRequest is null");
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");
    int32_t albumId = photoAlbum->GetAlbumId();
    vector<DataShare::DataShareValuesBucket> valuesBuckets;
    string batchInsertUri;
    if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::HIGHLIGHT ||
        photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS) {
            ANI_INFO_LOG("Add Assets on highlight album");
        for (const auto& asset : changeRequest->GetAddAssetArray()) {
            DataShare::DataShareValuesBucket pair;
            pair.Put(MAP_ALBUM, albumId);
            pair.Put(MAP_ASSET, asset);
            valuesBuckets.push_back(pair);
        }
        batchInsertUri = PAH_INSERT_HIGHLIGHT_ALBUM;
    } else {
        for (const auto& asset : changeRequest->GetAddAssetArray()) {
            DataShare::DataShareValuesBucket pair;
            pair.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
            pair.Put(PhotoColumn::MEDIA_ID, asset);
            valuesBuckets.push_back(pair);
        }
        batchInsertUri = PAH_PHOTO_ALBUM_ADD_ASSET;
    }

    Uri addAssetsUri(batchInsertUri);
    int ret = UserFileClient::BatchInsert(addAssetsUri, valuesBuckets);
    changeRequest->ClearAddAssetArray();
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to add assets into album %{public}d, err: %{public}d", albumId, ret);
        return false;
    }
    if (batchInsertUri == PAH_INSERT_HIGHLIGHT_ALBUM) {
        ANI_INFO_LOG("Add %{public}d asset(s) into highlight album %{public}d", ret, albumId);
        return true;
    }

    ANI_INFO_LOG("Add %{public}d asset(s) into album %{public}d", ret, albumId);
    FetchNewCount(context, photoAlbum);
    return true;
}

static bool RemoveAssetsExecute(MediaAlbumChangeRequestContext& context)
{
    auto changeRequest = context.objectInfo;
    CHECK_COND_RET(changeRequest != nullptr, false, "changeRequest is null");
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");
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
    CHECK_COND_RET(changeRequest != nullptr, false, "changeRequest is null");
    auto photoAlbum = changeRequest->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");
    int32_t albumId = photoAlbum->GetAlbumId();
    auto moveMap = changeRequest->GetMoveMap();
    changeRequest->ClearMoveMap();

    for (auto iter = moveMap.begin(); iter != moveMap.end(); iter++) {
        auto targetPhotoAlbum = iter->first;
        CHECK_COND_RET(targetPhotoAlbum != nullptr, false, "targetPhotoAlbum is nullptr");
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
    CHECK_COND_RET(context.objectInfo != nullptr, false, "objectInfo is nullptr");
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
    CHECK_COND_RET(photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is null");
    int32_t currentCount = photoAlbum->GetCount() - ret;
    photoAlbum->SetCount(currentCount > 0 ? currentCount : 0);
    return true;
}

static bool DeleteAssetsExecute(MediaAlbumChangeRequestContext& context)
{
    CHECK_COND_RET(context.objectInfo != nullptr, false, "objectInfo is nullptr");
    DataShare::DataSharePredicates predicates;
    predicates.In(PhotoColumn::MEDIA_ID, context.objectInfo->GetDeleteAssetArray());
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::MEDIA_DATE_TRASHED, 0);

    Uri deleteAssetsUri(PAH_DELETE_PHOTOS);
    int ret = UserFileClient::Update(deleteAssetsUri, predicates, valuesBucket, context.objectInfo->GetUserId());
    context.objectInfo->ClearDeleteAssetArray();
    if (ret < 0) {
        context.SaveError(ret);
        ANI_ERR_LOG("Failed to delete assets from trash album permanently, err: %{public}d", ret);
        return false;
    }

    ANI_INFO_LOG("Delete %{public}d assets permanently from trash album", ret);
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");
    int32_t currentCount = photoAlbum->GetCount() - ret;
    photoAlbum->SetCount(currentCount > 0 ? currentCount : 0);
    return true;
}

static bool OrderAlbumExecute(MediaAlbumChangeRequestContext& context)
{
    CHECK_COND_RET(context.objectInfo != nullptr, false, "objectInfo is nullptr");
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");
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
    CHECK_COND_RET(context.objectInfo != nullptr, false, "objectInfo is nullptr");
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");
    auto targetAlum = context.objectInfo->GetTargetPhotoAlbumInstance();
    CHECK_COND_RET(targetAlum != nullptr, false, "targetAlum is null");
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
    CHECK_NULL_PTR_RETURN_VOID(photoAlbum, "photoAlbum is null");
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
    CHECK_NULL_PTR_RETURN_VOID(context.objectInfo, "context.objectInfo is null");
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
    CHECK_COND_RET(context.objectInfo != nullptr, false, "objectInfo is nullptr");
    string disMissAssetAssetsUri = PAH_DISMISS_ASSET;
    Uri uri(disMissAssetAssetsUri);

    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");
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

static bool SetOrderPositionExecute(MediaAlbumChangeRequestContext &context)
{
    CHECK_COND_RET(context.objectInfo != nullptr, false, "objectInfo is nullptr");
    DataShare::DataSharePredicates predicates;
    const auto &photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is null");
    const auto &pairs = context.objectInfo->GetIdOrderPositionPairs();
    std::vector<std::string> ids;
    ids.reserve(pairs.size());

    std::stringstream orderString;
    const string mapTable = ANALYSIS_PHOTO_MAP_TABLE;
    orderString << "CASE " << mapTable << "." << MAP_ASSET << " ";
    for (const auto &[assetId, orderPosition] : pairs) {
        orderString << "WHEN " << assetId << " THEN " << orderPosition << " ";
        ids.push_back(assetId);
    }
    orderString << "END";
    predicates.EqualTo(mapTable + "." + MAP_ALBUM, photoAlbum->GetAlbumId())
        ->And()
        ->In(mapTable + "." + MAP_ASSET, ids);

    Uri updateAlbumUri(PAH_UPDATE_ORDER_ANA_ALBUM);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ORDER_POSITION, orderString.str());
    int32_t result = UserFileClient::Update(updateAlbumUri, predicates, valuesBucket);
    if (result < 0) {
        context.SaveError(result);
        ANI_ERR_LOG("Failed to set order position err: %{public}d", result);
        return false;
    }
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
    { AlbumChangeOperation::SET_ORDER_POSITION, SetOrderPositionExecute },
};

static void GetAlbumUpdateCoverUri(const shared_ptr<PhotoAlbum>& photoAlbum, string& uri)
{
    CHECK_NULL_PTR_RETURN_VOID(photoAlbum, "photoAlbum is null");
    if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::PORTRAIT) {
        uri = PAH_PORTRAIT_ANAALBUM_COVER_URI;
    } else if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::GROUP_PHOTO) {
        uri = PAH_GROUP_ANAALBUM_COVER_URI;
    } else if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::HIGHLIGHT ||
        photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS) {
        uri = PAH_HIGHLIGHT_COVER_URI;
    } else {
        uri = PAH_UPDATE_PHOTO_ALBUM;
    }
}

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
            } else if (photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::HIGHLIGHT ||
                photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS) {
                uri = PAH_HIGHLIGHT_ALBUM_NAME;
            } else {
                uri = PAH_SET_PHOTO_ALBUM_NAME;
            }
            property = PhotoAlbumColumns::ALBUM_NAME;
            valuesBucket.Put(property, photoAlbum->GetAlbumName());
            break;
        case AlbumChangeOperation::SET_COVER_URI:
            GetAlbumUpdateCoverUri(photoAlbum, uri);
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
    CHECK_COND_RET(aniContext != nullptr, false, "aniContext is nullptr");
    // In the scenario of creation, the new name will be applied when the album is created.
    if (changeOperation == AlbumChangeOperation::SET_ALBUM_NAME &&
        aniContext->albumChangeOperations.front() == AlbumChangeOperation::CREATE_ALBUM) {
        return true;
    }

    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    CHECK_COND_RET(aniContext->objectInfo != nullptr, false, "aniContext->objectInfo is nullptr");
    auto photoAlbum = aniContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, false, "photoAlbum is nullptr");
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
    CHECK_NULL_PTR_RETURN_VOID(aniContext, "aniContext is null");
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
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    auto aniContext = make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_RET(aniContext != nullptr, ANI_ERROR, "aniContext is nullptr");
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
    CHECK_COND_RET(env != nullptr, false, "env is null");
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

ani_status MediaAlbumChangeRequestAni::SetOrderPosition(ani_env *env, ani_object object, ani_object assets,
    ani_object position)
{
    ANI_DEBUG_LOG("%{public}s is called", __func__);
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    auto context = std::make_unique<MediaAlbumChangeRequestContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, ANI_INVALID_ARGS, "context is nullptr");
    context->objectInfo = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env, context->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is nullptr");
    auto cond = PhotoAlbum::IsAnalysisAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType());
    CHECK_COND_WITH_RET_MESSAGE(env, cond, ANI_INVALID_ARGS, "Only analysis album can set asset order positions");
    // get assets, check duplicated
    std::vector<std::string> assetIdArray;
    auto ret = MediaLibraryAniUtils::ParseAssetIdArray(env, assets, assetIdArray);
    CHECK_COND_WITH_RET_MESSAGE(env, ret == ANI_OK, ANI_INVALID_ARGS, "Failed to parse assets");
    ANI_INFO_LOG("GetOrderPosition assetIdArray size: %{public}zu", assetIdArray.size());
    CHECK_COND_RET(!assetIdArray.empty(), ANI_INVALID_ARGS, "assetIdArray is empty");
    CHECK_COND_WITH_RET_MESSAGE(env, !assetIdArray.empty(), ANI_INVALID_ARGS, "assetIdArray is empty");

    std::set<std::string> idSet(assetIdArray.begin(), assetIdArray.end());
    CHECK_COND_WITH_RET_MESSAGE(env, idSet.size() == assetIdArray.size(), ANI_INVALID_ARGS, "assetIdArray is empty");
    // get order positions, check duplicated
    std::vector<int32_t> orderPositionArray;
    auto order = MediaLibraryAniUtils::GetInt32Array(env, position, orderPositionArray);
    CHECK_COND_WITH_RET_MESSAGE(env, order == ANI_OK, ANI_INVALID_ARGS, "Failed to parse order positions");
    ANI_INFO_LOG("GetOrderPosition orderPositionArray size: %{public}zu", orderPositionArray.size());
    CHECK_COND_WITH_RET_MESSAGE(env, !orderPositionArray.empty(), ANI_INVALID_ARGS, "orderPositionArray is empty");

    std::set<int32_t> positionSet(orderPositionArray.begin(), orderPositionArray.end());
    CHECK_COND_WITH_RET_MESSAGE(env, positionSet.size() == orderPositionArray.size(), ANI_INVALID_ARGS,
        "orderPositionArray has duplicated elements");
    CHECK_COND_WITH_RET_MESSAGE(env, positionSet.size() == idSet.size(), ANI_INVALID_ARGS,
        "The setOrderPosition operation needs same assets and order positions size");

    // store pairs
    auto &pairs = context->objectInfo->idOrderPositionPairs_;
    for (size_t i = 0; i < assetIdArray.size(); i++) {
        pairs.emplace_back(assetIdArray[i], orderPositionArray[i]);
    }
    // add task to queue
    context->objectInfo->albumChangeOperations_.emplace_back(AlbumChangeOperation::SET_ORDER_POSITION);
    return ANI_OK;
}

} // namespace OHOS::Media
