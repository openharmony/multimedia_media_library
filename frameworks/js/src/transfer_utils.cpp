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

#include "transfer_utils.h"
#include "file_asset_napi.h"
#include "photo_album_napi.h"
#include "fetch_file_result_napi.h"
#include "moving_photo_napi.h"
#include "medialibrary_napi_log.h"

namespace OHOS {
namespace Media {
napi_value TransferUtils::AttachCreateFileAsset(napi_env env, std::shared_ptr<FileAsset> &iAsset)
{
    if (iAsset == nullptr) {
        NAPI_ERR_LOG("iAsset is null.");
        return nullptr;
    }
    return FileAssetNapi::AttachCreateFileAsset(env, iAsset);
}

shared_ptr<FileAsset> TransferUtils::GetFileAssetInstance(FileAssetNapi* napiFileAsset)
{
    return napiFileAsset->GetFileAssetInstance();
}

napi_value TransferUtils::CreatePhotoAlbumNapi(napi_env env, shared_ptr<PhotoAlbum> &albumData)
{
    if (albumData == nullptr) {
        NAPI_ERR_LOG("albumData is null.");
        return nullptr;
    }
    return PhotoAlbumNapi::CreatePhotoAlbumNapi(env, albumData);
}

std::shared_ptr<PhotoAlbum> TransferUtils::GetPhotoAlbumInstance(PhotoAlbumNapi* napiPhotoAlbum)
{
    return napiPhotoAlbum->GetPhotoAlbumInstance();
}

napi_value TransferUtils::CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<FileAsset>> &fileResult)
{
    if (fileResult == nullptr) {
        NAPI_ERR_LOG("fileResult is null.");
        return nullptr;
    }
    return FetchFileResultNapi::CreateFetchFileResult(env, std::move(fileResult));
}

napi_value TransferUtils::CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<AlbumAsset>> &fileResult)
{
    if (fileResult == nullptr) {
        NAPI_ERR_LOG("fileResult is null.");
        return nullptr;
    }
    return FetchFileResultNapi::CreateFetchFileResult(env, std::move(fileResult));
}

napi_value TransferUtils::CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<PhotoAlbum>> &fileResult)
{
    if (fileResult == nullptr) {
        NAPI_ERR_LOG("fileResult is null.");
        return nullptr;
    }
    return FetchFileResultNapi::CreateFetchFileResult(env, std::move(fileResult));
}

napi_value TransferUtils::CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<SmartAlbumAsset>> &fileResult)
{
    if (fileResult == nullptr) {
        NAPI_ERR_LOG("fileResult is null.");
        return nullptr;
    }
    return FetchFileResultNapi::CreateFetchFileResult(env, std::move(fileResult));
}

napi_value TransferUtils::CreateFetchFileResult(napi_env env,
    std::unique_ptr<FetchResult<PhotoAssetCustomRecord>> &fileResult)
{
    if (fileResult == nullptr) {
        NAPI_ERR_LOG("fileResult is null.");
        return nullptr;
    }
    return FetchFileResultNapi::CreateFetchFileResult(env, std::move(fileResult));
}

napi_value TransferUtils::CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<AlbumOrder>> &fileResult)
{
    if (fileResult == nullptr) {
        NAPI_ERR_LOG("fileResult is null.");
        return nullptr;
    }
    return FetchFileResultNapi::CreateFetchFileResult(env, std::move(fileResult));
}

FetchResType TransferUtils::GetFetchResType(FetchFileResultNapi* fileResult)
{
    return fileResult->GetFetchResType();
}
std::shared_ptr<FetchResult<FileAsset>> TransferUtils::GetFetchFileResultObject(FetchFileResultNapi* fileResult)
{
    if (fileResult == nullptr) {
        NAPI_ERR_LOG("FetchFileResultNapi is null.");
        return nullptr;
    }

    return fileResult->GetFetchFileResultObject();
}

std::shared_ptr<FetchResult<PhotoAlbum>> TransferUtils::GetFetchAlbumResultObject(FetchFileResultNapi* fileResult)
{
    if (fileResult == nullptr) {
        NAPI_ERR_LOG("FetchFileResultNapi is null.");
        return nullptr;
    }

    return fileResult->GetFetchPhotoAlbumResultObject();
}

//MovingPhoto
napi_value TransferUtils::CreateTransferMovingPhotoNapi(napi_env env, std::string uri, int sourceMode,
    TransferMovingPhotoParam movingPhotoParam)
{
    napi_value napiValueOfMedia = nullptr;
    MovingPhotoParam movingPhotoParamNapi;
    movingPhotoParamNapi.requestId = movingPhotoParam.requestId;
    movingPhotoParamNapi.compatibleMode = static_cast<CompatibleMode>(movingPhotoParam.compatibleMode);
    movingPhotoParamNapi.progressHandlerRef = movingPhotoParam.progressHandlerRef;
    movingPhotoParamNapi.threadsafeFunction = movingPhotoParam.threadsafeFunction;
    napiValueOfMedia = MovingPhotoNapi::NewMovingPhotoNapi(env, uri, static_cast<SourceMode>(sourceMode),
        movingPhotoParamNapi);
    return napiValueOfMedia;
}

bool TransferUtils::MovingPhotoGetProperty(MovingPhotoNapi *napiMovingPhoto, std::string &uri, int &sourceMode,
    TransferMovingPhotoParam &movingPhotoParam)
{
    if (napiMovingPhoto == nullptr) {
        NAPI_ERR_LOG("napiMovingPhoto is null.");
        return false;
    }
    uri = napiMovingPhoto->GetUri();
    sourceMode = static_cast<int>(napiMovingPhoto->GetSourceMode());
    movingPhotoParam.requestId = napiMovingPhoto->GetRequestId();
    movingPhotoParam.compatibleMode = static_cast<int>(napiMovingPhoto->GetCompatibleMode());
    movingPhotoParam.progressHandlerRef = napiMovingPhoto->GetProgressHandlerRef();
    movingPhotoParam.threadsafeFunction = napiMovingPhoto->GetThreadsafeFunction();
    if (uri.empty() || movingPhotoParam.requestId.empty()) {
        NAPI_ERR_LOG("input_Uri/RequestId is empty");
        return false;
    }
    return true;
}

extern "C" {
napi_value AttachCreateFileAsset(napi_env env, TransferUtils::TransferSharedPtr transferFileAsset)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    std::shared_ptr<FileAsset> fileAssetPtr = std::shared_ptr<FileAsset>(transferFileAsset.fileAssetPtr);
    if (fileAssetPtr == nullptr) {
        NAPI_ERR_LOG("fileAssetPtr is null.");
        return nullptr;
    }
    return FileAssetNapi::AttachCreateFileAsset(env, fileAssetPtr);
}

TransferUtils::TransferSharedPtr GetFileAssetInstance(FileAssetNapi* napiFileAsset)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    TransferUtils::TransferSharedPtr transferSharedPtr;
    std::shared_ptr<FileAsset> fileAsset = TransferUtils::GetFileAssetInstance(napiFileAsset);
    transferSharedPtr.fileAssetPtr = fileAsset.get();
    return transferSharedPtr;
}

napi_value CreatePhotoAlbumNapi(napi_env env, shared_ptr<PhotoAlbum> &albumData)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::CreatePhotoAlbumNapi(env, albumData);
}

TransferUtils::TransferSharedPtr GetPhotoAlbumInstance(PhotoAlbumNapi* napiPhotoAlbum)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    TransferUtils::TransferSharedPtr transferSharedPtr;
    std::shared_ptr<PhotoAlbum> photoAlbum = TransferUtils::GetPhotoAlbumInstance(napiPhotoAlbum);
    transferSharedPtr.photoAlbumPtr = photoAlbum.get();
    return transferSharedPtr;
}

napi_value CreateFetchFileResultFileAsset(napi_env env, std::unique_ptr<FetchResult<FileAsset>> &fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::CreateFetchFileResult(env, fileResult);
}

napi_value CreateFetchFileResultAlbumAsset(napi_env env, std::unique_ptr<FetchResult<AlbumAsset>> &fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::CreateFetchFileResult(env, fileResult);
}

napi_value CreateFetchFileResultPhotoAlbum(napi_env env, std::unique_ptr<FetchResult<PhotoAlbum>> &fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::CreateFetchFileResult(env, fileResult);
}

napi_value CreateFetchFileResultSmartAlbumAsset(napi_env env, std::unique_ptr<FetchResult<SmartAlbumAsset>> &fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::CreateFetchFileResult(env, fileResult);
}

napi_value CreateFetchFileResultPhotoAssetCustomRecord(napi_env env,
    std::unique_ptr<FetchResult<PhotoAssetCustomRecord>> &fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::CreateFetchFileResult(env, fileResult);
}

napi_value CreateFetchFileResultAlbumOrder(napi_env env, std::unique_ptr<FetchResult<AlbumOrder>> &fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::CreateFetchFileResult(env, fileResult);
}

FetchResType GetFetchResType(FetchFileResultNapi* fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::GetFetchResType(fileResult);
}

TransferUtils::TransferSharedPtr GetFetchFileResultObject(FetchFileResultNapi* fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    TransferUtils::TransferSharedPtr transferSharedPtr;
    std::shared_ptr<FetchResult<FileAsset>> fileAssetPtr = TransferUtils::GetFetchFileResultObject(fileResult);
    transferSharedPtr.fetchFileResultPtr = fileAssetPtr.get();
    return transferSharedPtr;
}

TransferUtils::TransferSharedPtr GetFetchAlbumResultObject(FetchFileResultNapi* fileResult)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    TransferUtils::TransferSharedPtr transferSharedPtr;
    std::shared_ptr<FetchResult<PhotoAlbum>> fileAssetPtr = TransferUtils::GetFetchAlbumResultObject(fileResult);
    transferSharedPtr.fetchPhotoAlbumPtr = fileAssetPtr.get();
    return transferSharedPtr;
}

napi_value CreateTransferMovingPhotoNapi(napi_env env, std::string uri, int sourceMode,
    TransferUtils::TransferMovingPhotoParam movingPhotoParam)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::CreateTransferMovingPhotoNapi(env, uri, sourceMode, movingPhotoParam);
}

bool MovingPhotoGetProperty(MovingPhotoNapi *napiMovingPhoto, std::string &uri, int &sourceMode,
    TransferUtils::TransferMovingPhotoParam &movingPhotoParam)
{
    NAPI_INFO_LOG("%{public}s Called", __func__);
    return TransferUtils::MovingPhotoGetProperty(napiMovingPhoto, uri, sourceMode, movingPhotoParam);
}
}
} // namespace Media
} // namespace OHOS