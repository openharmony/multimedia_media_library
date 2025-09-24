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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_FETCH_RESULT_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_FETCH_RESULT_ANI_H

#include <ani.h>
#include "ani_error.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "photo_album.h"
#include "values_bucket.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "medialibrary_type_const.h"

namespace OHOS {
namespace Media {

class FetchResultProperty {
public:
    std::shared_ptr<FetchResult<FileAsset>> fetchFileResult_ = nullptr;
    std::shared_ptr<FetchResult<AlbumAsset>> fetchAlbumResult_ = nullptr;
    std::shared_ptr<FetchResult<PhotoAlbum>> fetchPhotoAlbumResult_ = nullptr;
    std::shared_ptr<FetchResult<SmartAlbumAsset>> fetchSmartAlbumResult_ = nullptr;
    FetchResType fetchResType_;
};

class FetchFileResultAni {
public:
    FetchFileResultAni() = default;
    ~FetchFileResultAni() = default;
    static ani_status FetchFileResultInit(ani_env *env);
    static FetchFileResultAni* Unwrap(ani_env *env, ani_object fetchFileResultHandle);
    static ani_object Constructor(ani_env *env, [[maybe_unused]] ani_class clazz);

    static ani_object GetAllObjects(ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle);
    static ani_status Close(ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle);
    static ani_object GetFirstObject(ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle);
    static ani_object GetNextObject(ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle);
    static ani_double GetCount([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object fetchFileResultHandle);

    static ani_object CreateFetchFileResult(ani_env *env, std::unique_ptr<FetchResult<FileAsset>> fileResult);
    static ani_object CreateFetchFileResult(ani_env *env, std::unique_ptr<FetchResult<PhotoAlbum>> fileResult);
    std::shared_ptr<FetchResult<FileAsset>> GetFetchFileResultObject();
    std::shared_ptr<FetchResult<AlbumAsset>> GetFetchAlbumResultObject();
    std::shared_ptr<FetchResult<PhotoAlbum>> GetFetchPhotoAlbumResultObject();
    std::shared_ptr<FetchResult<SmartAlbumAsset>> GetFetchSmartAlbumResultObject();

    FetchResType GetFetchResType();
    bool CheckIfPropertyPtrNull();
    inline std::shared_ptr<FetchResultProperty> GetPropertyPtrInstance()
    {
        return propertyPtr;
    }

private:
    EXPORT static void GetFetchResult(unique_ptr<FetchFileResultAni> &obj);
    EXPORT static ani_object FetchFileResultAniConstructor(ani_env *env, [[maybe_unused]] ani_class clazz);

    ani_env *env_;
    std::shared_ptr<FetchResultProperty> propertyPtr;
    static inline thread_local std::unique_ptr<FetchResult<FileAsset>> sFetchFileResult_ = nullptr;
    static inline thread_local std::unique_ptr<FetchResult<AlbumAsset>> sFetchAlbumResult_ = nullptr;
    static inline thread_local std::unique_ptr<FetchResult<PhotoAlbum>> sFetchPhotoAlbumResult_ = nullptr;
    static inline thread_local std::unique_ptr<FetchResult<SmartAlbumAsset>> sFetchSmartAlbumResult_ = nullptr;
    static inline thread_local FetchResType sFetchResType_ = FetchResType::TYPE_FILE;
};

class FetchFileResultAniContext : public AniError {
public:
    FetchFileResultAni* objectInfo;
    std::shared_ptr<FetchResultProperty> objectPtr;
    bool status;
    int32_t position;
    std::unique_ptr<FileAsset> fileAsset;
    std::unique_ptr<AlbumAsset> albumAsset;
    std::unique_ptr<PhotoAlbum> photoAlbum;
    std::unique_ptr<SmartAlbumAsset> smartAlbumAsset;
    std::vector<std::unique_ptr<FileAsset>> fileAssetArray;
    std::vector<std::unique_ptr<AlbumAsset>> fileAlbumArray;
    std::vector<std::unique_ptr<PhotoAlbum>> filePhotoAlbumArray;
    std::vector<std::unique_ptr<SmartAlbumAsset>> fileSmartAlbumArray;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_FETCH_RESULT_ANI_H