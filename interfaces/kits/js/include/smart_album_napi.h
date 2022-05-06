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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_SMART_ALBUM_NAPI_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_SMART_ALBUM_NAPI_H_

#include <algorithm>
#include <vector>

#include "ability.h"
#include "ability_loader.h"
#include "abs_shared_result_set.h"
#include "data_ability_helper.h"
#include "data_ability_predicates.h"
#include "fetch_file_result_napi.h"
#include "fetch_result.h"
#include "smart_album_asset.h"
#include "medialibrary_napi_utils.h"
#include "media_data_ability_const.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "result_set.h"
#include "uri.h"
#include "values_bucket.h"
#include "mediadata_helper.h"
#include "napi_remote_object.h"
#include "mediadata_stub_impl.h"
#include "mediadata_proxy.h"

namespace OHOS {
namespace Media {
static const std::string SMART_ALBUM_NAPI_CLASS_NAME = "SmartAlbum";

class SmartAlbumNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateSmartAlbumNapi(napi_env env, SmartAlbumAsset &albumData,
        std::shared_ptr<AppExecFwk::MediaDataHelper> abilityHelper);
    int32_t GetSmartAlbumId() const;
    std::shared_ptr<AppExecFwk::MediaDataHelper> GetMediaDataHelper() const;
    std::string GetSmartAlbumName() const;
    int32_t GetAlbumPrivateType() const;
    void SetAlbumCapacity(int32_t albumCapacity);
    SmartAlbumNapi();
    ~SmartAlbumNapi();

    static std::shared_ptr<AppExecFwk::MediaDataHelper> sMediaDataHelper;

private:
    static void SmartAlbumNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value SmartAlbumNapiConstructor(napi_env env, napi_callback_info info);
    void SetSmartAlbumNapiProperties(const SmartAlbumAsset &albumData);

    static napi_value JSGetSmartAlbumId(napi_env env, napi_callback_info info);
    static napi_value JSGetSmartAlbumName(napi_env env, napi_callback_info info);
    static napi_value JSGetSmartAlbumUri(napi_env env, napi_callback_info info);
    static napi_value JSGetSmartAlbumTag(napi_env env, napi_callback_info info);
    static napi_value JSGetSmartAlbumCapacity(napi_env env, napi_callback_info info);
    static napi_value JSGetSmartAlbumCategoryId(napi_env env, napi_callback_info info);
    static napi_value JSGetSmartAlbumCategoryName(napi_env env, napi_callback_info info);
    static napi_value JSGetSmartAlbumCoverUri(napi_env env, napi_callback_info info);

    static napi_value JSSmartAlbumNameSetter(napi_env env, napi_callback_info info);
    static napi_value JSCommitModify(napi_env env, napi_callback_info info);
    static napi_value JSAddAsset(napi_env env, napi_callback_info info);
    static napi_value JSRemoveAsset(napi_env env, napi_callback_info info);
    static napi_value JSGetSmartAlbumFileAssets(napi_env env, napi_callback_info info);
    int32_t albumId_;
    std::string albumName_;
    std::string albumUri_;
    std::string albumTag_;
    int32_t albumPrivateType_;
    int32_t albumCapacity_;
    int32_t albumCategoryId_;
    std::string albumCategoryName_;
    std::string albumCoverUri_;

    std::shared_ptr<AppExecFwk::MediaDataHelper> abilityHelper_;
    static thread_local SmartAlbumAsset *sAlbumData_;
    napi_env env_;
    napi_ref wrapper_;

    static thread_local napi_ref sConstructor_;
};

struct SmartAlbumNapiAsyncContext {
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    SmartAlbumNapi *objectInfo;
    bool status;
    int32_t changedRows;
    std::string selection;
    OHOS::NativeRdb::ValuesBucket valuesBucket;
    std::vector<std::string> selectionArgs;
    std::string order;
    std::unique_ptr<FetchResult> fetchResult;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_SMART_ALBUM_NAPI_H_
