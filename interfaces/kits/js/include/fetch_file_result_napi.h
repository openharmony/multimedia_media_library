/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FETCH_FILE_RESULT_NAPI_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FETCH_FILE_RESULT_NAPI_H_

#include "fetch_result.h"
#include "album_asset.h"
#include "file_asset_napi.h"
#include "medialibrary_napi_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
static const std::string FETCH_FILE_RESULT_CLASS_NAME = "FetchFileResult";
static const std::string UFM_FETCH_FILE_RESULT_CLASS_NAME = "UserFileMgrFetchFileResult";
class FetchFileResultNapi {
public:
    FetchFileResultNapi();
    ~FetchFileResultNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value UserFileMgrInit(napi_env env, napi_value exports);

    template<class T>
    static napi_value CreateFetchFileResult(napi_env env, std::unique_ptr<FetchResult<T>> fileResult,
                                            std::shared_ptr<DataShare::DataShareHelper> abilityHelper);

    std::shared_ptr<FetchResult<FileAsset>> GetFetchResultObject();

    std::shared_ptr<DataShare::DataShareHelper> GetMediaDataHelper() const;

    std::shared_ptr<FetchResult<FileAsset>> GetFetchFileResult() const;

    static std::shared_ptr<DataShare::DataShareHelper> sMediaDataHelper;

private:
    static void FetchFileResultNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value FetchFileResultNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value JSGetCount(napi_env env, napi_callback_info info);
    static napi_value JSIsAfterLast(napi_env env, napi_callback_info info);
    static napi_value JSGetFirstObject(napi_env env, napi_callback_info info);
    static napi_value JSGetNextObject(napi_env env, napi_callback_info info);
    static napi_value JSGetLastObject(napi_env env, napi_callback_info info);
    static napi_value JSGetPositionObject(napi_env env, napi_callback_info info);
    static napi_value JSGetAllObject(napi_env env, napi_callback_info info);
    static napi_value JSClose(napi_env env, napi_callback_info info);

    napi_env env_;
    std::shared_ptr<FetchResult<FileAsset>> fetchFileResult_;

    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref userFileMgrConstructor_;
    static inline thread_local std::unique_ptr<FetchResult<FileAsset>> sFetchFileResult_ = nullptr;
    std::shared_ptr<DataShare::DataShareHelper> abilityHelper_;
};

class FetchFileResultAsyncContext : public NapiError {
public:
    napi_async_work work;
    napi_ref callbackRef;
    napi_deferred deferred;
    FetchFileResultNapi* objectInfo;
    bool status;
    int32_t position;
    std::unique_ptr<FileAsset> fileAsset;
    std::vector<std::unique_ptr<FileAsset>> fileAssetArray;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FETCH_FILE_RESULT_NAPI_H_
