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

#ifndef ALBUM_NAPI_H
#define ALBUM_NAPI_H

#include <vector>
#include <algorithm>

#include "ability.h"
#include "ability_loader.h"
#include "abs_shared_result_set.h"
#include "album_asset.h"
#include "data_ability_helper.h"
#include "data_ability_predicates.h"
#include "fetch_file_result_napi.h"
#include "fetch_result.h"
#include "medialibrary_napi_utils.h"
#include "media_data_ability_const.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "result_set.h"
#include "uri.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
static const std::string ALBUM_NAPI_CLASS_NAME = "Album";

class AlbumNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateAlbumNapi(napi_env env, AlbumAsset &albumData,
        std::shared_ptr<AppExecFwk::DataAbilityHelper> abilityHelper);
    int32_t GetAlbumId() const;
    std::shared_ptr<AppExecFwk::DataAbilityHelper> GetDataAbilityHelper() const;
    std::string GetAlbumName() const;
    std::string GetAlbumPath() const;

    AlbumNapi();
    ~AlbumNapi();

    static std::shared_ptr<AppExecFwk::DataAbilityHelper> sAbilityHelper;

private:
    static void AlbumNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value AlbumNapiConstructor(napi_env env, napi_callback_info info);
    void SetAlbumNapiProperties(const AlbumAsset &albumData);

    static napi_value JSGetAlbumId(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumName(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumUri(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumDateModified(napi_env env, napi_callback_info info);
    static napi_value JSGetCount(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumRelativePath(napi_env env, napi_callback_info info);
    static napi_value JSGetCoverUri(napi_env env, napi_callback_info info);
    static napi_value JSCommitModify(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumFileAssets(napi_env env, napi_callback_info info);
    static napi_value JSAlbumNameSetter(napi_env env, napi_callback_info info);

    static napi_value JSGetAlbumPath(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumVirtual(napi_env env, napi_callback_info info);
    static napi_value JSSetAlbumPath(napi_env env, napi_callback_info info);

    int32_t albumId_;
    std::string albumName_;
    std::string albumUri_;
    int64_t albumDateModified_;
    int32_t count_;
    std::string albumRelativePath_;
    std::string coverUri_;
    bool albumVirtual_;
    std::string albumPath_ = "";

    std::shared_ptr<AppExecFwk::DataAbilityHelper> abilityHelper_;

    napi_env env_;
    napi_ref wrapper_;

    static napi_ref sConstructor_;
    static AlbumAsset *sAlbumData_;
};

struct AlbumNapiAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    AlbumNapi *objectInfo;
    bool status;
    int32_t changedRows;
    std::string selection;
    std::vector<std::string> selectionArgs;
    std::string order;
    std::unique_ptr<FetchResult> fetchResult;
};
} // namespace Media
} // namespace OHOS
#endif /* ALBUM_NAPI_H */
