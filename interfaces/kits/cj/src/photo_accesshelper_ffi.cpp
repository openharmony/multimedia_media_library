/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "photo_accesshelper_ffi.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Media {
extern "C" {

    char* FfiPhotoAssetGetFileDisplayName(int64_t id)
    {
        auto photoAssetImpl = FFIData::GetData<PhotoAssetImpl>(id);
        if (photoAssetImpl == nullptr) {
            LOGE("Invalid object PhotoAssetImpl");
            return nullptr;
        }
        auto fileDisplayName = photoAssetImpl->GetFileDisplayName();
        char* displayName = MallocCString(fileDisplayName);
        return displayName;
    }

    char* FfiPhotoAssetGetFileUri(int64_t id)
    {
        auto photoAssetImpl = FFIData::GetData<PhotoAssetImpl>(id);
        if (photoAssetImpl == nullptr) {
            LOGE("Invalid object PhotoAssetImpl");
            return nullptr;
        }
        auto fileUri = photoAssetImpl->GetFileUri();
        char* uri = MallocCString(fileUri);
        return uri;
    }

    int32_t FfiPhotoAssetGetMediaType(int64_t id)
    {
        auto photoAssetImpl = FFIData::GetData<PhotoAssetImpl>(id);
        if (photoAssetImpl == nullptr) {
            LOGE("Invalid object PhotoAssetImpl");
            return 0;
        }
        int32_t mediaType = static_cast<int32_t>(photoAssetImpl->GetMediaType());
        return mediaType;
    }

    PhotoAssetMember FfiPhotoAssetUserFileMgrGet(int64_t id, char* member, int32_t *errCode)
    {
        PhotoAssetMember assetMember = {
            .memberType = -1,
            .boolValue = false,
            .stringValue = nullptr
        };
        auto photoAssetImpl = FFIData::GetData<PhotoAssetImpl>(id);
        if (photoAssetImpl == nullptr) {
            LOGE("Invalid object PhotoAssetImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return assetMember;
        }
        std::string inputKey(member);
        return photoAssetImpl->UserFileMgrGet(inputKey, *errCode);
    }

    void FfiPhotoAssetUserFileMgrSet(int64_t id, char* member, char* data, int32_t* errCode)
    {
        auto photoAssetImpl = FFIData::GetData<PhotoAssetImpl>(id);
        if (photoAssetImpl == nullptr) {
            LOGE("Invalid object PhotoAssetImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return;
        }
        std::string inputKey(member);
        std::string value(data);
        photoAssetImpl->UserFileMgrSet(inputKey, value, *errCode);
    }

    void FfiPhotoAssetCommitModify(int64_t id, int32_t* errCode)
    {
        auto photoAssetImpl = FFIData::GetData<PhotoAssetImpl>(id);
        if (photoAssetImpl == nullptr) {
            LOGE("Invalid object PhotoAssetImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return;
        }
        photoAssetImpl->CommitModify(*errCode);
    }

    int64_t FfiPhotoAssetGetThumbnail(int64_t id, CSize cSize, int32_t* errCode)
    {
        auto photoAssetImpl = FFIData::GetData<PhotoAssetImpl>(id);
        if (photoAssetImpl == nullptr) {
            LOGE("Invalid object PhotoAssetImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return 0;
        }
        return photoAssetImpl->GetThumbnail(cSize, *errCode);
    }

    int32_t FfiFetchResultGetCount(int64_t id, int32_t* errCode)
    {
        auto fetchResultImpl = FFIData::GetData<FetchResultImpl>(id);
        if (fetchResultImpl == nullptr) {
            LOGE("Invalid object FetchResultImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return 0;
        }
        return fetchResultImpl->GetCount(*errCode);
    }

    bool FfiFetchResultIsAfterLast(int64_t id, int32_t* errCode)
    {
        auto fetchResultImpl = FFIData::GetData<FetchResultImpl>(id);
        if (fetchResultImpl == nullptr) {
            LOGE("Invalid object FetchResultImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return false;
        }
        return fetchResultImpl->IsAfterLast(*errCode);
    }

    void FfiFetchResultClose(int64_t id)
    {
        auto fetchResultImpl = FFIData::GetData<FetchResultImpl>(id);
        if (fetchResultImpl == nullptr) {
            LOGE("Invalid object FetchResultImpl");
            return;
        }
        fetchResultImpl->Close();
    }

    FetchResultObject FfiFetchResultGetFirstObject(int64_t id, int32_t* errCode)
    {
        FetchResultObject fetchResultObject = {
            .id = -1,
            .fetchResType = 0
        };
        auto fetchResultImpl = FFIData::GetData<FetchResultImpl>(id);
        if (fetchResultImpl == nullptr) {
            LOGE("Invalid object FetchResultImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return fetchResultObject;
        }
        return fetchResultImpl->GetFirstObject(*errCode);
    }

    FetchResultObject FfiFetchResultGetNextObject(int64_t id, int32_t* errCode)
    {
        FetchResultObject fetchResultObject = {
            .id = -1,
            .fetchResType = 0
        };
        auto fetchResultImpl = FFIData::GetData<FetchResultImpl>(id);
        if (fetchResultImpl == nullptr) {
            LOGE("Invalid object FetchResultImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return fetchResultObject;
        }
        return fetchResultImpl->GetNextObject(*errCode);
    }

    FetchResultObject FfiFetchResultGetLastObject(int64_t id, int32_t* errCode)
    {
        FetchResultObject fetchResultObject = {
            .id = -1,
            .fetchResType = 0
        };
        auto fetchResultImpl = FFIData::GetData<FetchResultImpl>(id);
        if (fetchResultImpl == nullptr) {
            LOGE("Invalid object FetchResultImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return fetchResultObject;
        }
        return fetchResultImpl->GetLastObject(*errCode);
    }

    FetchResultObject FfiFetchResultGetObjectAtPosition(int64_t id, int32_t position, int32_t* errCode)
    {
        FetchResultObject fetchResultObject = {
            .id = -1,
            .fetchResType = 0
        };
        auto fetchResultImpl = FFIData::GetData<FetchResultImpl>(id);
        if (fetchResultImpl == nullptr) {
            LOGE("Invalid object FetchResultImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return fetchResultObject;
        }
        return fetchResultImpl->GetObjectAtPosition(position, *errCode);
    }

    CArrayFetchResultObject FfiFetchResultGetAllObjects(int64_t id, int32_t* errCode)
    {
        CArrayFetchResultObject cArrayFetchResultObject = {
            .head = nullptr,
            .size = 0
        };
        auto fetchResultImpl = FFIData::GetData<FetchResultImpl>(id);
        if (fetchResultImpl == nullptr) {
            LOGE("Invalid object FetchResultImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return cArrayFetchResultObject;
        }
        return fetchResultImpl->GetAllObjects(*errCode);
    }

    int32_t FfiPhotoAlbumGetPhotoAlbumType(int64_t id)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return 0;
        }
        return photoAlbumImpl->GetPhotoAlbumType();
    }

    int32_t FfiPhotoAlbumGetPhotoAlbumSubType(int64_t id)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return 0;
        }
        return photoAlbumImpl->GetPhotoAlbumSubType();
    }

    char* FfiPhotoAlbumGetAlbumName(int64_t id)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return nullptr;
        }
        auto albumName =  photoAlbumImpl->GetAlbumName();
        char* cAlbumName = MallocCString(albumName);
        return cAlbumName;
    }

    void FfiPhotoAlbumSetAlbumName(int64_t id, char* cAlbumName)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return;
        }
        photoAlbumImpl->SetAlbumName(cAlbumName);
    }

    char* FfiPhotoAlbumGetAlbumUri(int64_t id)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return nullptr;
        }
        auto albumUri = photoAlbumImpl->GetAlbumUri();
        char* cAlbumUri = MallocCString(albumUri);
        return cAlbumUri;
    }

    int32_t FfiPhotoAlbumGetCount(int64_t id)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return 0;
        }
        return photoAlbumImpl->GetCount();
    }

    char* FfiPhotoAlbumGetCoverUri(int64_t id)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return nullptr;
        }
        auto coverUri = photoAlbumImpl->GetCoverUri();
        char* cCoverUri = MallocCString(coverUri);
        return cCoverUri;
    }

    int32_t FfiPhotoAlbumGetImageCount(int64_t id)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return 0;
        }
        return photoAlbumImpl->GetImageCount();
    }

    int32_t FfiPhotoAlbumGetVideoCount(int64_t id)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            return 0;
        }
        return photoAlbumImpl->GetVideoCount();
    }

    int64_t FfiPhotoAlbumGetAssets(int64_t id, COptions options, int32_t* errCode)
    {
        int64_t result = -1;
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return result;
        }
        auto fetchFileResult = photoAlbumImpl->GetAssets(options, *errCode);
        if (fetchFileResult == nullptr) {
            LOGE("GetAssets failed.");
            return result;
        }
        std::unique_ptr<FfiFetchResultProperty> propertyPtr = std::make_unique<FfiFetchResultProperty>();
        propertyPtr->fetchFileResult_ = fetchFileResult;
        propertyPtr->fetchResType_ = FetchResType::TYPE_FILE;
        auto native = FFIData::Create<FetchResultImpl>(std::move(propertyPtr));
        if (native != nullptr) {
            result = native->GetID();
        } else {
            LOGE("Create FetchResultImpl instance failed.");
            *errCode = JS_INNER_FAIL;
        }
        return result;
    }

    void FfiPhotoAlbumCommitModify(int64_t id, int32_t* errCode)
    {
        auto photoAlbumImpl = FFIData::GetData<PhotoAlbumImpl>(id);
        if (photoAlbumImpl == nullptr) {
            LOGE("Invalid object photoAlbumImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return;
        }
        photoAlbumImpl->CommitModify(*errCode);
    }

    int64_t FfiPhotoAccessHelperGetPhotoAccessHelper(int64_t id)
    {
        int64_t result = -1;
        auto ret = FFIData::Create<PhotoAccessHelperImpl>();
        if (!ret) {
            LOGE("creat PhotoAccessHelperImpl instance failed.");
            return result;
        }
        if (!ret->GetPhotoAccessHelper(id)) {
            LOGE("GetPhotoAccessHelper failed.");
            return result;
        }
        result = ret->GetID();
        return result;
    }

    int64_t FfiPhotoAccessHelperGetAssets(int64_t id, COptions options, int32_t* errCode)
    {
        int64_t result = -1;
        auto photoAccessHelperImpl = FFIData::GetData<PhotoAccessHelperImpl>(id);
        if (photoAccessHelperImpl == nullptr) {
            LOGE("Invalid object photoAccessHelperImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return result;
        }
        auto fetchFileResult = photoAccessHelperImpl->GetAssets(options, *errCode);
        if (fetchFileResult == nullptr) {
            LOGE("GetAssets failed.");
            return result;
        }
        std::unique_ptr<FfiFetchResultProperty> propertyPtr = std::make_unique<FfiFetchResultProperty>();
        propertyPtr->fetchFileResult_ = fetchFileResult;
        propertyPtr->fetchResType_ = FetchResType::TYPE_FILE;
        auto native = FFIData::Create<FetchResultImpl>(std::move(propertyPtr));
        if (native != nullptr) {
            result = native->GetID();
        } else {
            LOGE("Create FetchResultImpl instance failed.");
            *errCode = JS_INNER_FAIL;
        }
        return result;
    }

    int64_t FfiPhotoAccessHelperGetBurstAssets(int64_t id, char* cBurstKey, COptions options, int32_t* errCode)
    {
        int64_t result = -1;
        auto photoAccessHelperImpl = FFIData::GetData<PhotoAccessHelperImpl>(id);
        if (photoAccessHelperImpl == nullptr) {
            LOGE("Invalid object photoAccessHelperImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return result;
        }
        auto fetchFileResult = photoAccessHelperImpl->GetBurstAssets(cBurstKey, options, *errCode);
        if (fetchFileResult == nullptr) {
            LOGE("GetAssets failed.");
            return result;
        }
        std::unique_ptr<FfiFetchResultProperty> propertyPtr = std::make_unique<FfiFetchResultProperty>();
        propertyPtr->fetchFileResult_ = fetchFileResult;
        propertyPtr->fetchResType_ = FetchResType::TYPE_FILE;
        auto native = FFIData::Create<FetchResultImpl>(std::move(propertyPtr));
        if (native != nullptr) {
            result = native->GetID();
        } else {
            LOGE("Create FetchResultImpl instance failed.");
            *errCode = JS_INNER_FAIL;
        }
        return result;
    }

    int64_t FfiPhotoAccessHelperGetAlbums(int64_t id, int32_t type, int32_t subtype,
        COptions options, int32_t* errCode)
    {
        int64_t result = -1;
        auto photoAccessHelperImpl = FFIData::GetData<PhotoAccessHelperImpl>(id);
        if (photoAccessHelperImpl == nullptr) {
            LOGE("Invalid object photoAccessHelperImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return result;
        }
        auto fetchPhotoAlbumResult = photoAccessHelperImpl->GetAlbums(type, subtype, options, *errCode);
        if (fetchPhotoAlbumResult == nullptr) {
            LOGE("GetAlbums failed.");
            return result;
        }
        std::unique_ptr<FfiFetchResultProperty> propertyPtr = std::make_unique<FfiFetchResultProperty>();
        propertyPtr->fetchPhotoAlbumResult_ = fetchPhotoAlbumResult;
        propertyPtr->fetchResType_ = FetchResType::TYPE_PHOTOALBUM;
        auto native = FFIData::Create<FetchResultImpl>(std::move(propertyPtr));
        if (native != nullptr) {
            result = native->GetID();
        } else {
            LOGE("Create FetchResultImpl instance failed.");
            *errCode = JS_INNER_FAIL;
        }
        return result;
    }

    void FfiPhotoAccessHelperRegisterChange(int64_t id, char* uri,
        bool forChildUris, int64_t funcId, int32_t *errCode)
    {
        auto photoAccessHelperImpl = FFIData::GetData<PhotoAccessHelperImpl>(id);
        if (photoAccessHelperImpl == nullptr) {
            LOGE("Invalid object photoAccessHelperImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return;
        }
        photoAccessHelperImpl->RegisterChange(uri, forChildUris, funcId, *errCode);
    }

    void FfiPhotoAccessHelperUnRegisterChange(int64_t id, char* uri, int64_t funcId, int32_t *errCode)
    {
        auto photoAccessHelperImpl = FFIData::GetData<PhotoAccessHelperImpl>(id);
        if (photoAccessHelperImpl == nullptr) {
            LOGE("Invalid object photoAccessHelperImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return;
        }
        photoAccessHelperImpl->UnRegisterChange(uri, funcId);
    }

    void FfiPhotoAccessHelperRelease(int64_t id, int32_t *errCode)
    {
        auto photoAccessHelperImpl = FFIData::GetData<PhotoAccessHelperImpl>(id);
        if (photoAccessHelperImpl == nullptr) {
            LOGE("Invalid object photoAccessHelperImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return;
        }
        photoAccessHelperImpl->Release();
    }

    void FfiPhotoAccessHelperShowAssetsCreationDialog(int64_t id, CArrString srcFileUris,
        PhotoCreationConfigs photoCreationConfigs, int64_t funcId, FfiBundleInfo &cBundleInfo, int32_t *errCode)
    {
        auto photoAccessHelperImpl = FFIData::GetData<PhotoAccessHelperImpl>(id);
        if (photoAccessHelperImpl == nullptr) {
            LOGE("Invalid object photoAccessHelperImpl");
            *errCode = OHOS_INVALID_PARAM_CODE;
            return;
        }
        photoAccessHelperImpl->ShowAssetsCreationDialog(srcFileUris,
            photoCreationConfigs, funcId, cBundleInfo, *errCode);
    }

    PhotoSelectResult FfiPhotoAccessHelperStartPhotoPicker(int64_t id,
        PhotoSelectOptions option, int32_t *errCode)
    {
        return PhotoAccessHelperImpl::StartPhotoPicker(id, option, *errCode);
    }

    char* FfiMovingPhotoGetUri(int64_t id, int32_t* errCode)
    {
        auto ffiMovingPhotoImpl = FFIData::GetData<FfiMovingPhotoImpl>(id);
        if (ffiMovingPhotoImpl == nullptr) {
            LOGE("Invalid object movingPhotoImpl");
            *errCode = JS_INNER_FAIL;
            return nullptr;
        }
        auto movingPhotoUri = ffiMovingPhotoImpl->GetUri();
        char* uri = MallocCString(movingPhotoUri);
        return uri;
    }

    void FfiMovingPhotoRequestContentUri(int64_t id,
        char* imageFileUri, char* videoFileUri, int32_t* errCode)
    {
        auto ffiMovingPhotoImpl = FFIData::GetData<FfiMovingPhotoImpl>(id);
        if (ffiMovingPhotoImpl == nullptr) {
            LOGE("Invalid object movingPhotoImpl");
            *errCode = JS_INNER_FAIL;
            return;
        }
        ffiMovingPhotoImpl->RequestContent(imageFileUri, videoFileUri, *errCode);
    }

    void FfiMovingPhotoRequestContentResourceType(int64_t id,
        int32_t resourceType, char* fileUri, int32_t* errCode)
    {
        auto ffiMovingPhotoImpl = FFIData::GetData<FfiMovingPhotoImpl>(id);
        if (ffiMovingPhotoImpl == nullptr) {
            LOGE("Invalid object movingPhotoImpl");
            *errCode = JS_INNER_FAIL;
            return;
        }
        ffiMovingPhotoImpl->RequestContent(resourceType, fileUri, *errCode);
    }

    CArrUI8 FfiMovingPhotoRequestContentArrayBuffer(int64_t id,
        int32_t resourceType, int32_t* errCode)
    {
        CArrUI8 result = { .head = nullptr, .size = 0};
        auto ffiMovingPhotoImpl = FFIData::GetData<FfiMovingPhotoImpl>(id);
        if (ffiMovingPhotoImpl == nullptr) {
            LOGE("Invalid object movingPhotoImpl");
            *errCode = JS_INNER_FAIL;
            return result;
        }
        return ffiMovingPhotoImpl->RequestContent(resourceType, *errCode);
    }

    char* FfiMediaAssetManagerRequestImage(int64_t contextId, int64_t photoAssetId,
        RequestOptions requestOptions, int64_t funcId, int32_t* errCode)
    {
        return MediaAssetManagerImpl::RequestImage(contextId, photoAssetId,
            requestOptions, funcId, *errCode);
    }

    char* FfiMediaAssetManagerRequestImageData(int64_t contextId, int64_t photoAssetId,
        RequestOptions requestOptions, int64_t funcId, int32_t* errCode)
    {
        return MediaAssetManagerImpl::RequestImageData(contextId, photoAssetId,
            requestOptions, funcId, *errCode);
    }

    char* FfiMediaAssetManagerRequestMovingPhoto(int64_t contextId, int64_t photoAssetId,
        RequestOptions requestOptions, int64_t funcId, int32_t* errCode)
    {
        return MediaAssetManagerImpl::RequestMovingPhoto(contextId, photoAssetId,
            requestOptions, funcId, *errCode);
    }

    char* FfiMediaAssetManagerRequestVideoFile(int64_t contextId, int64_t photoAssetId,
        RequestOptions requestOptions, char* fileUri, int64_t funcId, int32_t* errCode)
    {
        return MediaAssetManagerImpl::RequestVideoFile(contextId, photoAssetId,
            requestOptions, fileUri, funcId, *errCode);
    }

    void FfiMediaAssetManagerCancelRequest(int64_t contextId, char* cRequestId, int32_t* errCode)
    {
        MediaAssetManagerImpl::CancelRequest(contextId, cRequestId, *errCode);
    }

    int64_t FfiMediaAssetManagerLoadMovingPhoto(int64_t contextId, char* cImageFileUri,
        char* cVideoFileUri, int32_t* errCode)
    {
        return MediaAssetManagerImpl::LoadMovingPhoto(contextId, cImageFileUri, cVideoFileUri, *errCode);
    }
}
}
}