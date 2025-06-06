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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSETS_CHANGE_REQUEST_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSETS_CHANGE_REQUEST_NAPI_H

#include <vector>

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "file_asset.h"
#include "media_change_request_napi.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
enum class AssetsChangeOperation {
    BATCH_SET_FAVORITE,
    BATCH_SET_HIDDEN,
    BATCH_SET_USER_COMMENT,
    BATCH_SET_RECENT_SHOW,
};

class MediaAssetsChangeRequestNapi : public MediaChangeRequestNapi {
public:
    EXPORT MediaAssetsChangeRequestNapi() = default;
    EXPORT ~MediaAssetsChangeRequestNapi() override = default;

    EXPORT static napi_value Init(napi_env env, napi_value exports);

    std::vector<std::string> GetFileAssetUriArray() const;
    void GetFileAssetIds(std::vector<int32_t> &fileIds) const;
    bool GetFavoriteStatus() const;
    bool GetHiddenStatus() const;
    std::string GetUpdatedUserComment() const;
    bool GetRecentShowStatus() const;
    napi_value ApplyChanges(napi_env env, napi_callback_info info) override;

private:
    EXPORT static napi_value Constructor(napi_env env, napi_callback_info info);
    EXPORT static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    EXPORT static napi_value JSSetFavorite(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetHidden(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetUserComment(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetIsRecentShow(napi_env env, napi_callback_info info);
    bool CheckChangeOperations(napi_env env);

    static thread_local napi_ref constructor_;
    bool isFavorite_;
    bool isHidden_;
    std::string userComment_;
    bool isRecentShow_;
    std::vector<std::shared_ptr<FileAsset>> fileAssets_;
    std::vector<AssetsChangeOperation> assetsChangeOperations_;
};

struct MediaAssetsChangeRequestAsyncContext : public NapiError {
    size_t argc;
    napi_value argv[NAPI_ARGC_MAX];
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;

    MediaAssetsChangeRequestNapi* objectInfo;
    std::vector<AssetsChangeOperation> assetsChangeOperations;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ASSETS_CHANGE_REQUEST_NAPI_H