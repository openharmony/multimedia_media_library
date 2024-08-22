
/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FETCH_FILE_RESULT_SENDABLE_NAPI_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FETCH_FILE_RESULT_SENDABLE_NAPI_H_

#include <mutex>

#include "fetch_result.h"
#include "album_asset.h"
#include "sendable_file_asset_napi.h"
#include "medialibrary_napi_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
static const std::string FETCH_FILE_RESULT_SENDABLE_CLASS_NAME = "FetchFileResultSendable";
static const std::string PAH_FETCH_FILE_RESULT_SENDABLE_CLASS_NAME = "PhotoAccessHelperFetchFileResultSendable";

class SendableFetchResultProperty {
public:
    std::shared_ptr<FetchResult<FileAsset>> fetchFileResult_ = nullptr;
    std::shared_ptr<FetchResult<AlbumAsset>> fetchAlbumResult_ = nullptr;
    std::shared_ptr<FetchResult<PhotoAlbum>> fetchPhotoAlbumResult_ = nullptr;
    std::shared_ptr<FetchResult<SmartAlbumAsset>> fetchSmartAlbumResult_ = nullptr;
    FetchResType fetchResType_;
};

class SendableFetchFileResultNapi {
public:
    EXPORT SendableFetchFileResultNapi();
    EXPORT ~SendableFetchFileResultNapi();

    EXPORT static napi_value PhotoAccessHelperInit(napi_env env, napi_value exports);

    static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<FileAsset>> fileResult);
    static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<AlbumAsset>> fileResult);
    static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<PhotoAlbum>> fileResult);
    static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<SmartAlbumAsset>> fileResult);
    std::shared_ptr<FetchResult<FileAsset>> GetFetchFileResultObject();
    std::shared_ptr<FetchResult<AlbumAsset>> GetFetchAlbumResultObject();
    std::shared_ptr<FetchResult<PhotoAlbum>> GetFetchPhotoAlbumResultObject();
    std::shared_ptr<FetchResult<SmartAlbumAsset>> GetFetchSmartAlbumResultObject();

    std::shared_ptr<FetchResult<FileAsset>> GetFetchFileResult() const;
    FetchResType GetFetchResType();
    bool CheckIfPropertyPtrNull();
    static void SolveConstructorRef(unique_ptr<FetchResult<FileAsset>> &fileResult, napi_ref &constructorRef);
    static void SolveConstructorRef(unique_ptr<FetchResult<AlbumAsset>> &fileResult, napi_ref &constructorRef);
    static void SolveConstructorRef(unique_ptr<FetchResult<SmartAlbumAsset>> &fileResult, napi_ref &constructorRef);
    static void SolveConstructorRef(unique_ptr<FetchResult<PhotoAlbum>> &fileResult, napi_ref &constructorRef);

private:
    EXPORT static void FetchFileResultNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint);
    EXPORT static void GetFetchResult(unique_ptr<SendableFetchFileResultNapi> &obj);
    EXPORT static napi_value FetchFileResultNapiConstructor(napi_env env, napi_callback_info info);

    EXPORT static napi_value JSGetCount(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSIsAfterLast(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetFirstObject(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetNextObject(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetAllObject(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetLastObject(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetPositionObject(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSClose(napi_env env, napi_callback_info info);

    napi_env env_;
    std::shared_ptr<SendableFetchResultProperty> propertyPtr;
    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref userFileMgrConstructor_;
    static thread_local napi_ref photoAccessHelperConstructor_;
    static inline thread_local std::unique_ptr<FetchResult<FileAsset>> sFetchFileResult_ = nullptr;
    static inline thread_local std::unique_ptr<FetchResult<AlbumAsset>> sFetchAlbumResult_ = nullptr;
    static inline thread_local std::unique_ptr<FetchResult<PhotoAlbum>> sFetchPhotoAlbumResult_ = nullptr;
    static inline thread_local std::unique_ptr<FetchResult<SmartAlbumAsset>> sFetchSmartAlbumResult_ = nullptr;
    static inline thread_local FetchResType sFetchResType_ = FetchResType::TYPE_FILE;
};

class FetchFileResultSendableAsyncContext : public NapiError {
public:
    napi_async_work work;
    napi_ref callbackRef;
    napi_deferred deferred;
    SendableFetchFileResultNapi* objectInfo;
    std::shared_ptr<SendableFetchResultProperty> objectPtr;
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
    void GetFirstAsset();
    void GetObjectAtPosition();
    void GetAllObjectFromFetchResult();
    void GetLastObject();
    void GetNextObject();
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FETCH_FILE_RESULT_SENDABLE_NAPI_H_