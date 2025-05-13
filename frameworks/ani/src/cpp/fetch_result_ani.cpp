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

#include <iostream>

#include "fetch_result_ani.h"
#include "media_log.h"
#include "ani_class_name.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_tracer.h"

namespace OHOS::Media {
ani_status FetchFileResultAni::UserFileMgrInit(ani_env *env)
{
    return ANI_OK;
}

ani_status FetchFileResultAni::PhotoAccessHelperInit(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    static const char *className = PAH_ANI_CLASS_FETCH_RESULT_HANDLE.c_str();
    ani_class cls;
    auto status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"getAllObjectsSync", nullptr, reinterpret_cast<void *>(GetAllObjects)},
        ani_native_function {"getFirstObjectSync", nullptr, reinterpret_cast<void *>(GetFirstObject)},
        ani_native_function {"getNextObjectSync", nullptr, reinterpret_cast<void *>(GetNextObject)},
        ani_native_function {"getObjectByPositionSync", nullptr, reinterpret_cast<void *>(GetPositionObject)},
        ani_native_function {"getCount", nullptr, reinterpret_cast<void *>(GetCount)},
        ani_native_function {"close", nullptr, reinterpret_cast<void *>(Close)},
    };
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    };

    return ANI_OK;
}

bool FetchFileResultAni::CheckIfPropertyPtrNull()
{
    return propertyPtr == nullptr;
}

FetchResType FetchFileResultAni::GetFetchResType()
{
    return propertyPtr->fetchResType_;
}

std::shared_ptr<FetchResult<FileAsset>> FetchFileResultAni::GetFetchFileResultObject()
{
    return propertyPtr->fetchFileResult_;
}

std::shared_ptr<FetchResult<AlbumAsset>> FetchFileResultAni::GetFetchAlbumResultObject()
{
    return propertyPtr->fetchAlbumResult_;
}

std::shared_ptr<FetchResult<PhotoAlbum>> FetchFileResultAni::GetFetchPhotoAlbumResultObject()
{
    return propertyPtr->fetchPhotoAlbumResult_;
}

std::shared_ptr<FetchResult<SmartAlbumAsset>> FetchFileResultAni::GetFetchSmartAlbumResultObject()
{
    return propertyPtr->fetchSmartAlbumResult_;
}

void FetchFileResultAni::GetFetchResult(unique_ptr<FetchFileResultAni> &obj)
{
    ANI_INFO_LOG("GetFetchResult type: %{public}d", sFetchResType_);
    CHECK_NULL_PTR_RETURN_VOID(obj, "obj is nullptr");
    CHECK_NULL_PTR_RETURN_VOID(obj->propertyPtr, "obj->propertyPtr is nullptr");
    switch (sFetchResType_) {
        case FetchResType::TYPE_FILE: {
            CHECK_NULL_PTR_RETURN_VOID(sFetchFileResult_, "sFetchFileResult_ is nullptr");
            auto fileResult = make_shared<FetchResult<FileAsset>>(move(sFetchFileResult_->GetDataShareResultSet()));
            obj->propertyPtr->fetchFileResult_ = fileResult;
            CHECK_NULL_PTR_RETURN_VOID(obj->propertyPtr->fetchFileResult_, "fetchFileResult_ is nullptr");
            obj->propertyPtr->fetchFileResult_->SetInfo(sFetchFileResult_);
            obj->propertyPtr->fetchFileResult_->SetUserId(sFetchFileResult_->GetUserId());
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            CHECK_NULL_PTR_RETURN_VOID(sFetchAlbumResult_, "sFetchAlbumResult_ is nullptr");
            auto albumResult = make_shared<FetchResult<AlbumAsset>>(move(sFetchAlbumResult_->GetDataShareResultSet()));
            obj->propertyPtr->fetchAlbumResult_ = albumResult;
            CHECK_NULL_PTR_RETURN_VOID(obj->propertyPtr->fetchAlbumResult_, "fetchAlbumResult_ is nullptr");
            obj->propertyPtr->fetchAlbumResult_->SetInfo(sFetchAlbumResult_);
            obj->propertyPtr->fetchAlbumResult_->SetUserId(sFetchAlbumResult_->GetUserId());
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            CHECK_NULL_PTR_RETURN_VOID(sFetchPhotoAlbumResult_, "sFetchPhotoAlbumResult_ is nullptr");
            auto photoAlbumResult =
                make_shared<FetchResult<PhotoAlbum>>(move(sFetchPhotoAlbumResult_->GetDataShareResultSet()));
            obj->propertyPtr->fetchPhotoAlbumResult_ = photoAlbumResult;
            CHECK_NULL_PTR_RETURN_VOID(obj->propertyPtr->fetchPhotoAlbumResult_, "fetchPhotoAlbumResult_ is nullptr");
            obj->propertyPtr->fetchPhotoAlbumResult_->SetInfo(sFetchPhotoAlbumResult_);
            obj->propertyPtr->fetchPhotoAlbumResult_->SetUserId(sFetchPhotoAlbumResult_->GetUserId());
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            CHECK_NULL_PTR_RETURN_VOID(sFetchSmartAlbumResult_, "sFetchSmartAlbumResult_ is nullptr");
            auto smartResult =
                make_shared<FetchResult<SmartAlbumAsset>>(move(sFetchSmartAlbumResult_->GetDataShareResultSet()));
            obj->propertyPtr->fetchSmartAlbumResult_ = smartResult;
            CHECK_NULL_PTR_RETURN_VOID(obj->propertyPtr->fetchSmartAlbumResult_, "fetchSmartAlbumResult_ is nullptr");
            obj->propertyPtr->fetchSmartAlbumResult_->SetInfo(sFetchSmartAlbumResult_);
            break;
        }
        default:
            ANI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

ani_object FetchFileResultAni::FetchFileResultAniConstructor(ani_env *env, ani_class clazz)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    unique_ptr<FetchFileResultAni> obj = make_unique<FetchFileResultAni>();
    CHECK_COND_RET(obj != nullptr, nullptr, "obj is nullptr");
    obj->propertyPtr = make_shared<FetchResultProperty>();
    GetFetchResult(obj);
    CHECK_COND_RET(obj->propertyPtr != nullptr, nullptr, "obj->propertyPtr is nullptr");
    obj->propertyPtr->fetchResType_ = sFetchResType_;

    ani_method ctor {};
    if (ANI_OK != env->Class_FindMethod(clazz, "<ctor>", nullptr, &ctor)) {
        ANI_ERR_LOG("Failed to find method: ctor");
        return nullptr;
    }

    ani_object fetchResult {};
    if (ANI_OK != env->Object_New(clazz, ctor, &fetchResult, reinterpret_cast<ani_long>(obj.release()))) {
        ANI_ERR_LOG("New fetchResult Fail");
        return nullptr;
    }
    return fetchResult;
}

FetchFileResultAni* FetchFileResultAni::Unwrap(ani_env *env, ani_object fetchFileResultHandle)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_long fetchFileResultHandleLong;
    auto status = env->Object_GetFieldByName_Long(fetchFileResultHandle,
        "nativeValue", &fetchFileResultHandleLong);
    if (ANI_OK != status || fetchFileResultHandleLong == 0) {
        ANI_ERR_LOG("GetAllPhotoAssetHandleObjects nullptr");
        return nullptr;
    }
    return reinterpret_cast<FetchFileResultAni *>(fetchFileResultHandleLong);
}

static void GetAllObjectFromFetchResultMore(std::unique_ptr<FetchFileResultAniContext>& aniContest)
{
    CHECK_NULL_PTR_RETURN_VOID(aniContest, "aniContest is nullptr");
    CHECK_NULL_PTR_RETURN_VOID(aniContest->objectInfo, "aniContest->objectInfo is nullptr");
    auto propertyPtr = aniContest->objectInfo->GetPropertyPtrInstance();
    if (propertyPtr == nullptr) {
        ANI_ERR_LOG("propertyPtr is nullptr");
        return;
    }
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_PHOTOALBUM: {
            auto fetchResult = propertyPtr->fetchPhotoAlbumResult_;
            auto photoAlbum = fetchResult->GetFirstObject();
            while (photoAlbum != nullptr) {
                photoAlbum->SetUserId(fetchResult->GetUserId());
                aniContest->filePhotoAlbumArray.emplace_back(move(photoAlbum));
                photoAlbum = fetchResult->GetNextObject();
            }
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            auto fetchResult = propertyPtr->fetchSmartAlbumResult_;
            auto smartAlbum = fetchResult->GetFirstObject();
            while (smartAlbum != nullptr) {
                aniContest->fileSmartAlbumArray.emplace_back(move(smartAlbum));
                smartAlbum = fetchResult->GetNextObject();
            }
            break;
        }
        default:
            ANI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

static void GetAllObjectFromFetchResult(std::unique_ptr<FetchFileResultAniContext>& aniContest)
{
    CHECK_NULL_PTR_RETURN_VOID(aniContest, "aniContest is nullptr");
    CHECK_NULL_PTR_RETURN_VOID(aniContest->objectInfo, "aniContest->objectInfo is nullptr");
    auto propertyPtr = aniContest->objectInfo->GetPropertyPtrInstance();
    if (propertyPtr == nullptr) {
        ANI_ERR_LOG("propertyPtr is nullptr");
        return;
    }

    ANI_DEBUG_LOG("GetAllObject type: %{public}d", propertyPtr->fetchResType_);
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            auto fetchResult = propertyPtr->fetchFileResult_;
            auto file = fetchResult->GetFirstObject();
            while (file != nullptr) {
                file->SetUserId(fetchResult->GetUserId());
                aniContest->fileAssetArray.emplace_back(move(file));
                file = fetchResult->GetNextObject();
            }
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            auto fetchResult = propertyPtr->fetchAlbumResult_;
            auto album = fetchResult->GetFirstObject();
            while (album != nullptr) {
                aniContest->fileAlbumArray.emplace_back(move(album));
                album = fetchResult->GetNextObject();
            }
            break;
        }
        default:
            GetAllObjectFromFetchResultMore(aniContest);
            break;
    }
}

static bool CheckIfFFRAniNotEmpty(FetchFileResultAni* obj)
{
    if (obj == nullptr) {
        ANI_ERR_LOG("FetchFileResultNapi is nullptr");
        return false;
    }
    if (obj->CheckIfPropertyPtrNull()) {
        ANI_ERR_LOG("PropertyPtr in FetchFileResultNapi is nullptr");
        return false;
    }
    return true;
}

static ani_object GetAllObjectComplete(ani_env *env, std::unique_ptr<FetchFileResultAniContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetAllObjectsComplete");
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    CHECK_COND_RET(context->objectPtr != nullptr, nullptr, "context->objectPtr is nullptr");

    ani_object result = nullptr;
    ani_status status;
    FetchResType fetchResType = context->objectPtr->fetchResType_;
    ANI_DEBUG_LOG("fetchResType: %{public}d", fetchResType);
    switch (fetchResType) {
        case FetchResType::TYPE_FILE:
            status = MediaLibraryAniUtils::ToFileAssetAniArray(env, context->fileAssetArray, result);
            break;
        case FetchResType::TYPE_PHOTOALBUM:
            status = MediaLibraryAniUtils::ToPhotoAlbumAniArray(env, context->filePhotoAlbumArray, result);
            break;
        default:
            ANI_ERR_LOG("unsupported FetchResType");
            AniError::ThrowError(env, ERR_INVALID_OUTPUT, "Failed to obtain fileAsset array from DB");
    }
    return result;
}

ani_object FetchFileResultAni::GetAllObjects(ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetAllObjects");
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");

    auto aniContext = make_unique<FetchFileResultAniContext>();
    CHECK_COND_RET(aniContext != nullptr, nullptr, "aniContext is nullptr");
    aniContext->objectInfo = Unwrap(env, fetchFileResultHandle);
    if (CheckIfFFRAniNotEmpty(aniContext->objectInfo)) {
        aniContext->objectPtr = aniContext->objectInfo->propertyPtr;
        CHECK_COND_RET(aniContext->objectPtr, nullptr, "propertyPtr is nullptr");
        GetAllObjectFromFetchResult(aniContext);
        return GetAllObjectComplete(env, aniContext);
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "GetAllObject obj == nullptr");
    }
    return nullptr;
}


ani_status FetchFileResultAni::Close(ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle)
{
    ANI_INFO_LOG("fetch result close");
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    FetchFileResultAni* fetchFileResultAni = Unwrap(env, fetchFileResultHandle);
    if (fetchFileResultAni != nullptr) {
        delete fetchFileResultAni;
        if (ANI_OK != env->Object_SetFieldByName_Long(fetchFileResultHandle, "nativeValue", 0)) {
            ANI_ERR_LOG("Object_SetFieldByName_Long failed");
            return ANI_ERROR;
        }
    }
    return ANI_OK;
}

ani_object FetchFileResultAni::CreateFetchFileResult(ani_env *env, std::unique_ptr<FetchResult<FileAsset>> fileResult)
{
    if (env == nullptr || fileResult == nullptr) {
        ANI_ERR_LOG("env or fetchResult FileAsset is nullptr");
        return nullptr;
    }

    sFetchResType_ = fileResult->GetFetchResType();
    sFetchFileResult_ = move(fileResult);
    ani_object result = nullptr;
    ani_class cls {};
    ANI_INFO_LOG("get FileAsset result type: %{public}d", sFetchFileResult_->GetResultNapiType());
    switch (sFetchFileResult_->GetResultNapiType()) {
        case ResultNapiType::TYPE_USERFILE_MGR: {
            CHECK_COND_RET(MediaLibraryAniUtils::FindClass(env, UFM_ANI_CLASS_FETCH_RESULT_HANDLE, &cls) == ANI_OK,
                nullptr, "Can't find class");
            result = FetchFileResultAniConstructor(env, cls);
            break;
        }
        case ResultNapiType::TYPE_PHOTOACCESS_HELPER: {
            CHECK_COND_RET(MediaLibraryAniUtils::FindClass(env, PAH_ANI_CLASS_FETCH_RESULT_HANDLE, &cls) == ANI_OK,
                nullptr, "Can't find class");
            result = FetchFileResultAniConstructor(env, cls);
            break;
        }
        default:
            result = FetchFileResultAniConstructor(env, cls);
            break;
    }
    sFetchFileResult_ = nullptr;
    return result;
}

ani_object FetchFileResultAni::CreateFetchFileResult(ani_env *env, std::unique_ptr<FetchResult<PhotoAlbum>> fileResult)
{
    if (env == nullptr || fileResult == nullptr) {
        ANI_ERR_LOG("fetchResult PhotoAlbum is nullptr");
        return nullptr;
    }

    sFetchResType_ = fileResult->GetFetchResType();
    sFetchPhotoAlbumResult_ = move(fileResult);
    ani_object result = nullptr;
    ani_class cls {};
    ANI_INFO_LOG("get PhotoAlbum result type: %{public}d", sFetchPhotoAlbumResult_->GetResultNapiType());
    switch (sFetchPhotoAlbumResult_->GetResultNapiType()) {
        case ResultNapiType::TYPE_USERFILE_MGR: {
            CHECK_COND_RET(MediaLibraryAniUtils::FindClass(env, UFM_ANI_CLASS_FETCH_RESULT_HANDLE, &cls) == ANI_OK,
                nullptr, "Can't find class");
            result = FetchFileResultAniConstructor(env, cls);
            break;
        }
        case ResultNapiType::TYPE_PHOTOACCESS_HELPER: {
            CHECK_COND_RET(MediaLibraryAniUtils::FindClass(env, PAH_ANI_CLASS_FETCH_RESULT_HANDLE, &cls) == ANI_OK,
                nullptr, "Can't find class");
            result = FetchFileResultAniConstructor(env, cls);
            break;
        }
        default:
            result = FetchFileResultAniConstructor(env, cls);
            break;
    }
    sFetchPhotoAlbumResult_ = nullptr;
    return result;
}

static void GetFirstAsset(std::unique_ptr<FetchFileResultAniContext>& aniContest)
{
    CHECK_NULL_PTR_RETURN_VOID(aniContest, "aniContest is nullptr");
    CHECK_NULL_PTR_RETURN_VOID(aniContest->objectInfo, "aniContest->objectInfo is nullptr");
    auto propertyPtr = aniContest->objectInfo->GetPropertyPtrInstance();
    if (propertyPtr == nullptr) {
        ANI_ERR_LOG("propertyPtr is nullptr");
        return;
    }

    ANI_INFO_LOG("getFirstAsset type: %{public}d", propertyPtr->fetchResType_);
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            aniContest->fileAsset = propertyPtr->fetchFileResult_->GetFirstObject();
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            aniContest->albumAsset = propertyPtr->fetchAlbumResult_->GetFirstObject();
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            aniContest->photoAlbum = propertyPtr->fetchPhotoAlbumResult_->GetFirstObject();
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            aniContest->smartAlbumAsset = propertyPtr->fetchSmartAlbumResult_->GetFirstObject();
            break;
        }
        default:
            ANI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

static ani_object GetPositionObjectComplete(ani_env *env, std::unique_ptr<FetchFileResultAniContext>& aniContest)
{
    if (aniContest->objectPtr == nullptr) {
        ANI_ERR_LOG("aniContest->objectPtr is nullptr");
        return nullptr;
    }

    ANI_INFO_LOG("fetch result type: %{public}d", aniContest->objectPtr->fetchResType_);
    ani_object etsAsset = nullptr;
    switch (aniContest->objectPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            if (aniContest->fileAsset != nullptr && aniContest->objectPtr->fetchFileResult_ != nullptr) {
                aniContest->fileAsset->SetUserId(aniContest->objectPtr->fetchFileResult_->GetUserId());
            }
            auto fileAssetAni = FileAssetAni::CreateFileAsset(env, aniContest->fileAsset);
            if (fileAssetAni == nullptr) {
                etsAsset = nullptr;
                break;
            }
            FileAssetAniMethod fileAssetAniMethod;
            if (ANI_OK != FileAssetAni::InitFileAssetAniMethod(env,
                fileAssetAni->GetFileAssetInstance()->GetResultNapiType(), fileAssetAniMethod)) {
                ANI_ERR_LOG("InitFileAssetAniMethod failed");
                return nullptr;
            }
            etsAsset = FileAssetAni::Wrap(env, fileAssetAni, fileAssetAniMethod);
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            if (aniContest->photoAlbum != nullptr && aniContest->objectPtr->fetchPhotoAlbumResult_ != nullptr) {
                aniContest->photoAlbum->SetUserId(aniContest->objectPtr->fetchPhotoAlbumResult_->GetUserId());
            }
            etsAsset = PhotoAlbumAni::CreatePhotoAlbumAni(env, aniContest->photoAlbum);
            break;
        }
        default:
            ANI_ERR_LOG("unsupported FetchResType");
            break;
    }

    if (etsAsset == nullptr) {
        ANI_ERR_LOG("Failed to get file asset object");
        AniError::ThrowError(env, JS_INNER_FAIL, "System inner fail");
    }
    return etsAsset;
}

ani_object FetchFileResultAni::GetFirstObject(ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle)
{
    auto aniContext = make_unique<FetchFileResultAniContext>();
    aniContext->objectInfo = Unwrap(env, fetchFileResultHandle);
    if (CheckIfFFRAniNotEmpty(aniContext->objectInfo)) {
        aniContext->objectPtr = aniContext->objectInfo->propertyPtr;
        CHECK_COND_RET(aniContext->objectPtr, nullptr, "propertyPtr is nullptr");
        GetFirstAsset(aniContext);
        return GetPositionObjectComplete(env, aniContext);
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "GetFirstObject obj == nullptr");
    }
    return nullptr;
}

static void GetNextAsset(std::unique_ptr<FetchFileResultAniContext>& aniContest)
{
    std::shared_ptr<FetchResultProperty> propertyPtr = aniContest->objectInfo->GetPropertyPtrInstance();
    if (propertyPtr == nullptr) {
        ANI_ERR_LOG("propertyPtr is nullptr");
        return;
    }

    ANI_INFO_LOG("fetch result type: %{public}d", propertyPtr->fetchResType_);
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            aniContest->fileAsset = propertyPtr->fetchFileResult_->GetNextObject();
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            aniContest->albumAsset = propertyPtr->fetchAlbumResult_->GetNextObject();
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            aniContest->photoAlbum = propertyPtr->fetchPhotoAlbumResult_->GetNextObject();
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            aniContest->smartAlbumAsset = propertyPtr->fetchSmartAlbumResult_->GetNextObject();
            break;
        }
        default:
            ANI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

ani_object FetchFileResultAni::GetNextObject(ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle)
{
    auto aniContext = make_unique<FetchFileResultAniContext>();
    aniContext->objectInfo = Unwrap(env, fetchFileResultHandle);
    if (CheckIfFFRAniNotEmpty(aniContext->objectInfo)) {
        aniContext->objectPtr = aniContext->objectInfo->propertyPtr;
        CHECK_COND_RET(aniContext->objectPtr, nullptr, "propertyPtr is nullptr");
        GetNextAsset(aniContext);
        return GetPositionObjectComplete(env, aniContext);
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "GetNextObject obj == nullptr");
    }
    return nullptr;
}

static void GetObjectAtPosition(std::unique_ptr<FetchFileResultAniContext>& aniContest)
{
    auto propertyPtr = aniContest->objectInfo->GetPropertyPtrInstance();
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            aniContest->fileAsset = propertyPtr->fetchFileResult_->GetObjectAtPosition(aniContest->position);
            break;
        }
        case FetchResType::TYPE_ALBUM: {
            aniContest->albumAsset = propertyPtr->fetchAlbumResult_->GetObjectAtPosition(aniContest->position);
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            aniContest->photoAlbum = propertyPtr->fetchPhotoAlbumResult_->GetObjectAtPosition(aniContest->position);
            break;
        }
        case FetchResType::TYPE_SMARTALBUM: {
            aniContest->smartAlbumAsset =
                propertyPtr->fetchSmartAlbumResult_->GetObjectAtPosition(aniContest->position);
            break;
        }
        default:
            ANI_ERR_LOG("unsupported FetchResType");
            break;
    }
}

ani_object FetchFileResultAni::GetPositionObject(ani_env *env, ani_object fetchFileResultHandle, ani_double index)
{
    auto aniContext = make_unique<FetchFileResultAniContext>();
    aniContext->objectInfo = Unwrap(env, fetchFileResultHandle);
    if (CheckIfFFRAniNotEmpty(aniContext->objectInfo)) {
        aniContext->position = static_cast<int32_t>(index);
        aniContext->objectPtr = aniContext->objectInfo->propertyPtr;
        CHECK_COND_RET(aniContext->objectPtr, nullptr, "propertyPtr is nullptr");
        GetObjectAtPosition(aniContext);
        return GetPositionObjectComplete(env, aniContext);
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "GetPositionObject obj == nullptr");
    }
    return nullptr;
}

ani_double FetchFileResultAni::GetCount([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object fetchFileResultHandle) // number Double
{
    ani_double count = 0.0;
    auto aniContext = make_unique<FetchFileResultAniContext>();
    aniContext->objectInfo = Unwrap(env, fetchFileResultHandle);
    if (CheckIfFFRAniNotEmpty(aniContext->objectInfo)) {
        ANI_INFO_LOG("fetch result type: %{public}d", aniContext->objectInfo->GetFetchResType());
        switch (aniContext->objectInfo->GetFetchResType()) {
            case FetchResType::TYPE_FILE:
                count = aniContext->objectInfo->GetFetchFileResultObject()->GetCount();
                break;
            case FetchResType::TYPE_ALBUM:
                count = aniContext->objectInfo->GetFetchAlbumResultObject()->GetCount();
                break;
            case FetchResType::TYPE_PHOTOALBUM:
                count = aniContext->objectInfo->GetFetchPhotoAlbumResultObject()->GetCount();
                break;
            case FetchResType::TYPE_SMARTALBUM:
                count = aniContext->objectInfo->GetFetchSmartAlbumResultObject()->GetCount();
                break;
            default:
                ANI_ERR_LOG("unsupported FetchResType");
                break;
        }
        if (count < 0) {
            AniError::ThrowError(env, JS_INNER_FAIL, "Failed to get count");
        }
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to get native obj");
    }
    return count;
}
} // namespace OHOS::Media