/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_NAPI_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_NAPI_H_

#include <vector>

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "file_asset.h"
#include "media_change_request_napi.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
enum class AssetChangeOperation {
    SET_FAVORITE,
    SET_USER_COMMENT,
};

class MediaAssetChangeRequestNapi : public MediaChangeRequestNapi {
public:
    MediaAssetChangeRequestNapi() = default;
    ~MediaAssetChangeRequestNapi() override = default;

    static napi_value Init(napi_env env, napi_value exports);

    std::shared_ptr<FileAsset> GetFileAssetInstance() const;
    napi_value ApplyChanges(napi_env env, napi_callback_info info) override;

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    static napi_value JSDeleteAssets(napi_env env, napi_callback_info info);
    static napi_value JSSetFavorite(napi_env env, napi_callback_info info);
    static napi_value JSSetUserComment(napi_env env, napi_callback_info info);

    static thread_local napi_ref constructor_;
    std::shared_ptr<FileAsset> fileAsset_ = nullptr;
    std::vector<AssetChangeOperation> assetChangeOperations_;
};

struct MediaAssetChangeRequestAsyncContext : public NapiError {
    size_t argc;
    napi_value argv[NAPI_ARGC_MAX];
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;

    MediaAssetChangeRequestNapi* objectInfo;
    std::vector<AssetChangeOperation> assetChangeOperations;
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSET_CHANGE_REQUEST_NAPI_H_