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
#ifndef PHOTO_ACCESS_HELPER_FFI_H
#define PHOTO_ACCESS_HELPER_FFI_H

#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "fetch_result_impl.h"
#include "media_asset_manager_ffi.h"
#include "media_album_change_request_impl.h"
#include "media_asset_change_request_impl.h"
#include "media_asset_manager_ffi.h"
#include "moving_photo_impl.h"
#include "photo_album_impl.h"
#include "photo_accesshelper_impl.h"
#include "photo_asset_impl.h"

namespace OHOS {
namespace Media {
extern "C" {
// PhotoAccessHelper
FFI_EXPORT int64_t FfiPhotoAccessHelperGetPhotoAccessHelper(int64_t id);
FFI_EXPORT int64_t FfiPhotoAccessHelperGetAssets(int64_t id, COptions options, int32_t* errCode);
FFI_EXPORT int64_t FfiPhotoAccessHelperGetBurstAssets(int64_t id, char* cBurstKey,
    COptions options, int32_t* errCode);
FFI_EXPORT int64_t FfiPhotoAccessHelperGetAlbums(int64_t id, int32_t type, int32_t subtype,
    COptions options, int32_t* errCode);
FFI_EXPORT void FfiPhotoAccessHelperRegisterChange(int64_t id, char* uri,
    bool forChildUris, int64_t funcId, int32_t *errCode);
FFI_EXPORT void FfiPhotoAccessHelperUnRegisterChange(int64_t id, char* uri, int64_t funcId, int32_t *errCode);
FFI_EXPORT void FfiPhotoAccessHelperRelease(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiPhotoAccessHelperShowAssetsCreationDialog(int64_t id, CArrString srcFileUris,
    PhotoCreationConfigs photoCreationConfigs, int64_t funcId, FfiBundleInfo cBundleInfo, int32_t *errCode);
FFI_EXPORT PhotoSelectResult FfiPhotoAccessHelperStartPhotoPicker(int64_t id,
    PhotoSelectOptions option, int32_t *errCode);

// PhotoAsset
FFI_EXPORT char* FfiPhotoAssetGetFileDisplayName(int64_t id);
FFI_EXPORT char* FfiPhotoAssetGetFileUri(int64_t id);
FFI_EXPORT int32_t FfiPhotoAssetGetMediaType(int64_t id);
FFI_EXPORT PhotoAssetMember FfiPhotoAssetUserFileMgrGet(int64_t id, char* member, int32_t* errCode);
FFI_EXPORT void FfiPhotoAssetUserFileMgrSet(int64_t id, char* member, char* data, int32_t* errCode);
FFI_EXPORT void FfiPhotoAssetCommitModify(int64_t id, int32_t* errCode);
FFI_EXPORT int64_t FfiPhotoAssetGetThumbnail(int64_t id, CSize cSize, int32_t* errCode);

// FetchResult
FFI_EXPORT int32_t FfiFetchResultGetCount(int64_t id, int32_t* errCode);
FFI_EXPORT bool FfiFetchResultIsAfterLast(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiFetchResultClose(int64_t id);
FFI_EXPORT FetchResultObject FfiFetchResultGetFirstObject(int64_t id, int32_t* errCode);
FFI_EXPORT FetchResultObject FfiFetchResultGetNextObject(int64_t id, int32_t* errCode);
FFI_EXPORT FetchResultObject FfiFetchResultGetLastObject(int64_t id, int32_t* errCode);
FFI_EXPORT FetchResultObject FfiFetchResultGetObjectAtPosition(int64_t id, int32_t position, int32_t* errCode);
FFI_EXPORT CArrayFetchResultObject FfiFetchResultGetAllObjects(int64_t id, int32_t* errCode);

// Album
FFI_EXPORT int32_t FfiPhotoAlbumGetPhotoAlbumType(int64_t id);
FFI_EXPORT int32_t FfiPhotoAlbumGetPhotoAlbumSubType(int64_t id);
FFI_EXPORT char* FfiPhotoAlbumGetAlbumName(int64_t id);
FFI_EXPORT void FfiPhotoAlbumSetAlbumName(int64_t id, char* cAlbumName);
FFI_EXPORT char* FfiPhotoAlbumGetAlbumUri(int64_t id);
FFI_EXPORT int32_t FfiPhotoAlbumGetCount(int64_t id);
FFI_EXPORT char* FfiPhotoAlbumGetCoverUri(int64_t id);
FFI_EXPORT int32_t FfiPhotoAlbumGetImageCount(int64_t id);
FFI_EXPORT int32_t FfiPhotoAlbumGetVideoCount(int64_t id);
FFI_EXPORT int64_t FfiPhotoAlbumGetAssets(int64_t id, COptions options, int32_t* errCode);
FFI_EXPORT void FfiPhotoAlbumCommitModify(int64_t id, int32_t* errCode);

// MediaAssetManager
FFI_EXPORT char* FfiMediaAssetManagerRequestImage(int64_t contextId, int64_t photoAssetId,
    RequestOptions requestOptions, int64_t funcId, int32_t* errCode);
FFI_EXPORT char* FfiMediaAssetManagerRequestImageData(int64_t contextId, int64_t photoAssetId,
    RequestOptions requestOptions, int64_t funcId, int32_t* errCode);
FFI_EXPORT char* FfiMediaAssetManagerRequestMovingPhoto(int64_t contextId, int64_t photoAssetId,
    RequestOptions requestOptions, int64_t funcId, int32_t* errCode);
FFI_EXPORT char* FfiMediaAssetManagerRequestVideoFile(int64_t contextId, int64_t photoAssetId,
    RequestOptions requestOptions, char* fileUri, int64_t funcId, int32_t* errCode);
FFI_EXPORT void FfiMediaAssetManagerCancelRequest(int64_t contextId, char* cRequestId, int32_t* errCode);
FFI_EXPORT int64_t FfiMediaAssetManagerLoadMovingPhoto(int64_t contextId,
    char* cImageFileUri, char* cVideoFileUri, int32_t* errCode);

// MovingPhoto
FFI_EXPORT char* FfiMovingPhotoGetUri(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiMovingPhotoRequestContentUri(int64_t id,
    char* imageFileUri, char* videoFileUri, int32_t* errCode);
FFI_EXPORT void FfiMovingPhotoRequestContentResourceType(int64_t id,
    int32_t resourceType, char* fileUri, int32_t* errCode);
FFI_EXPORT CArrUI8 FfiMovingPhotoRequestContentArrayBuffer(int64_t id,
    int32_t resourceType, int32_t* errCode);

// MediaAssetChangeRequest
FFI_EXPORT int64_t FfiMediaAssetChangeRequestImplConstructor(int64_t id, int32_t* errCode);
FFI_EXPORT int64_t FfiMediaAssetChangeRequestImplCreateImageAssetRequest(int64_t id, char* fileUri, int32_t* errCode);
FFI_EXPORT int64_t FfiMediaAssetChangeRequestImplCreateVideoAssetRequest(int64_t id, char* fileUri, int32_t* errCode);
FFI_EXPORT RetDataI64 FfiMediaAssetChangeRequestImplCreateAssetRequest(
    int64_t id, int32_t photoType, char* extension, char* title, int32_t subType);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplDeleteAssetsByObject(int64_t id, CArrI64 assets);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplDeleteAssetsByString(int64_t id, CArrString assets);
FFI_EXPORT int64_t FfiMediaAssetChangeRequestImplGetAsset(int64_t id, int32_t* errCode);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplSetTitle(int64_t id, char* title);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplGetWriteCacheHandler(int64_t id, int32_t* errCode);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplAddResourceByString(int64_t id, int32_t resourceType, char* fileUri);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplAddResourceByBuffer(int64_t id, int32_t resourceType, CArrUI8 data);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplSaveCameraPhoto(int64_t id);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplDiscardCameraPhoto(int64_t id);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplSetOrientation(int64_t id, int32_t orientation);
FFI_EXPORT int32_t FfiMediaAssetChangeRequestImplApplyChanges(int64_t id);

// MediaAlbumChangeRequest
FFI_EXPORT int64_t FfiMediaAlbumChangeRequestImplConstructor(int64_t id, int32_t* errCode);
FFI_EXPORT int64_t FfiMediaAlbumChangeRequestImplGetAlbum(int64_t id, int32_t* errCode);
FFI_EXPORT int32_t FfiMediaAlbumChangeRequestImplSetAlbumName(int64_t id, char* albumName);
FFI_EXPORT int32_t FfiMediaAlbumChangeRequestImplAddAssets(int64_t id, CArrI64 assets);
FFI_EXPORT int32_t FfiMediaAlbumChangeRequestImplRemoveAssets(int64_t id, CArrI64 assets);
FFI_EXPORT int32_t FfiMediaAlbumChangeRequestImplApplyChanges(int64_t id);
}
}
}
#endif