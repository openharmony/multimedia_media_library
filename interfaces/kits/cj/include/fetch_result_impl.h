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
#ifndef FETCH_RESULT_IMPL_H
#define FETCH_RESULT_IMPL_H


#include <mutex>

#include "album_asset.h"
#include "cj_ffi/cj_common_ffi.h"
#include "fetch_result.h"
#include "photo_accesshelper_utils.h"
#include "photo_album_impl.h"
#include "photo_asset_impl.h"

namespace OHOS {
namespace Media {
class FfiFetchResultProperty {
public:
    std::shared_ptr<FetchResult<FileAsset>> fetchFileResult_ = nullptr;
    std::shared_ptr<FetchResult<AlbumAsset>> fetchAlbumResult_ = nullptr;
    std::shared_ptr<FetchResult<PhotoAlbum>> fetchPhotoAlbumResult_ = nullptr;
    std::shared_ptr<FetchResult<SmartAlbumAsset>> fetchSmartAlbumResult_ = nullptr;
    FetchResType fetchResType_;
};

class FetchResultImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(FetchResultImpl, OHOS::FFI::FFIData)
public:
    explicit FetchResultImpl(std::unique_ptr<FfiFetchResultProperty> propertyPtr_);
    std::shared_ptr<FetchResult<FileAsset>> GetFetchFileResultObject();
    std::shared_ptr<FetchResult<AlbumAsset>> GetFetchAlbumResultObject();
    std::shared_ptr<FetchResult<PhotoAlbum>> GetFetchPhotoAlbumResultObject();
    std::shared_ptr<FetchResult<SmartAlbumAsset>> GetFetchSmartAlbumResultObject();
    int32_t GetCount(int32_t &errCode);
    bool IsAfterLast(int32_t &errCode);
    void Close();
    FetchResultObject GetFirstObject(int32_t &errCode);
    FetchResultObject GetNextObject(int32_t &errCode);
    FetchResultObject GetLastObject(int32_t &errCode);
    FetchResultObject GetObjectAtPosition(int32_t position, int32_t &errCode);
    CArrayFetchResultObject GetAllObjects(int32_t &errCode);

private:
    std::shared_ptr<FfiFetchResultProperty> propertyPtr = nullptr;
    std::unique_ptr<FileAsset> fileAsset;
    std::unique_ptr<AlbumAsset> albumAsset;
    std::unique_ptr<PhotoAlbum> photoAlbum;
    std::unique_ptr<SmartAlbumAsset> smartAlbumAsset;
    std::vector<std::unique_ptr<FileAsset>> fileAssetArray;
    std::vector<std::unique_ptr<AlbumAsset>> fileAlbumArray;
    std::vector<std::unique_ptr<PhotoAlbum>> filePhotoAlbumArray;
    std::vector<std::unique_ptr<SmartAlbumAsset>> fileSmartAlbumArray;
};
}
}
#endif