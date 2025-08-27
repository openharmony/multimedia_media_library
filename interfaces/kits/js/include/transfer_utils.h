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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_TRANSFER_UTILS_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_TRANSFER_UTILS_H

#include <memory>
#include <string>
#include "napi/native_api.h"
#include "file_asset.h"
#include "photo_album.h"
#include "fetch_result.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class FileAssetNapi;
class PhotoAlbumNapi;
class FileAssetNapi;
class FetchFileResultNapi;
class MovingPhotoNapi;

class TransferUtils {
public:
    struct TransferMovingPhotoParam {
        std::string requestId;
        int compatibleMode;
        napi_ref progressHandlerRef;
        napi_threadsafe_function threadsafeFunction;
        TransferMovingPhotoParam() : requestId(""), compatibleMode(0),
            progressHandlerRef(nullptr), threadsafeFunction(nullptr) {};
    };

    typedef struct {
        FileAsset* fileAssetPtr;
        PhotoAlbum* photoAlbumPtr;
        FetchResult<FileAsset>* fetchFileResultPtr;
        FetchResult<PhotoAlbum>* fetchPhotoAlbumPtr;
        FetchResult<AlbumAsset>* fetchAlbumResultPtr;
        FetchResult<SmartAlbumAsset>* fetchSmartAlbumResultPtr;
        FetchResult<PhotoAssetCustomRecord>* fetchPhotoAssetCustomRecordPtr;
        FetchResult<AlbumOrder>* fetchAlbumOrderPtr;
    } TransferSharedPtr;

    EXPORT static napi_value AttachCreateFileAsset(napi_env env, std::shared_ptr<FileAsset> &iAsset);
    EXPORT static std::shared_ptr<FileAsset> GetFileAssetInstance(FileAssetNapi* napiFileAsset);
    EXPORT static napi_value CreatePhotoAlbumNapi(napi_env env, std::unique_ptr<PhotoAlbum> &albumData);
    EXPORT static std::shared_ptr<PhotoAlbum> GetPhotoAlbumInstance(PhotoAlbumNapi* napiPhotoAlbum);
    EXPORT static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<FileAsset>> &fileResult);
    EXPORT static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<AlbumAsset>> &fileResult);
    EXPORT static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<PhotoAlbum>> &fileResult);
    EXPORT static napi_value CreateFetchFileResult(napi_env env,
        std::unique_ptr<FetchResult<SmartAlbumAsset>> &fileResult);
    EXPORT static napi_value CreateFetchFileResult(napi_env env,
        std::unique_ptr<FetchResult<PhotoAssetCustomRecord>> &fileResult);
    EXPORT static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<AlbumOrder>> &fileResult);
    EXPORT static FetchResType GetFetchResType(FetchFileResultNapi* fileResult);
    EXPORT static std::shared_ptr<FetchResult<FileAsset>> GetFetchFileResultObject(FetchFileResultNapi* fileResult);
    EXPORT static std::shared_ptr<FetchResult<PhotoAlbum>> GetFetchAlbumResultObject(FetchFileResultNapi* fileResult);
    EXPORT static napi_value CreateTransferMovingPhotoNapi(napi_env env, std::string uri, int sourceMode,
        TransferMovingPhotoParam movingPhotoParam);
    EXPORT static bool MovingPhotoGetProperty(MovingPhotoNapi *napiMovingPhoto, std::string &uri,
        int &sourceMode, TransferMovingPhotoParam &movingPhotoParam);
};
}
}
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_TRANSFER_UTILS_H
