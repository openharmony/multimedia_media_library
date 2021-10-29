/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef FETCH_FILE_RESULT_NAPI_H
#define FETCH_FILE_RESULT_NAPI_H

#include "fetch_result.h"
#include "file_asset_napi.h"
#include "medialibrary_napi_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
static const std::string FETCH_FILE_RESULT_CLASS_NAME = "FetchFileResult";
class FetchFileResultNapi {
public:
    FetchFileResultNapi();
    ~FetchFileResultNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateFetchFileResult(napi_env env, Media::FetchResult &fileResult);
    Media::FetchResult *GetFetchResultObject();

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

    napi_env env_;
    napi_ref wrapper_;
    Media::FetchResult *fetchFileResult_ = nullptr;

    static napi_ref sConstructor_;
    static Media::FetchResult *sFetchFileResult_;
};

class FetchFileResultAsyncContext {
public:
    napi_env env;
    napi_async_work work;
    napi_ref callbackRef;
    napi_deferred deferred;
    FetchFileResultNapi* objectInfo;
    bool status;
    int32_t position;
    std::unique_ptr<Media::FileAsset> fileAsset;
    std::vector<std::unique_ptr<Media::FileAsset>> fileAssetArray;
};
} // namespace OHOS
#endif /* FETCH_FILE_RESULT_NAPI_H */