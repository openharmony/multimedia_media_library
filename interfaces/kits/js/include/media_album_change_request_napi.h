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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ALBUM_CHANGE_REQUEST_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ALBUM_CHANGE_REQUEST_NAPI_H

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "media_change_request_napi.h"
#include "photo_album.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
enum class AlbumChangeOperation {
    SET_ALBUM_NAME,
    SET_COVER_URI,
    ORDER_ALBUM,
    SET_DISPLAY_LEVEL,
    MERGE_ALBUM,
    DISMISS_ASSET,
    SET_IS_ME,
};

class MediaAlbumChangeRequestNapi : public MediaChangeRequestNapi {
public:
    MediaAlbumChangeRequestNapi() = default;
    ~MediaAlbumChangeRequestNapi() override = default;
    static napi_value Init(napi_env env, napi_value exports);

    std::shared_ptr<PhotoAlbum> GetPhotoAlbumInstance() const;
    std::shared_ptr<PhotoAlbum> GetReferencePhotoAlbumInstance() const;
    napi_value ApplyChanges(napi_env env, napi_callback_info info) override;
    std::shared_ptr<PhotoAlbum> GetTargetPhotoAlbumInstance() const;
    std::vector<std::string> GetDismissAssets() const;
    void ClearDismissAssetArray();

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    static napi_value JSSetAlbumName(napi_env env, napi_callback_info info);
    static napi_value JSSetCoverUri(napi_env env, napi_callback_info info);
    static napi_value JSPlaceBefore(napi_env env, napi_callback_info info);
    static napi_value JSSetDisplayLevel(napi_env env, napi_callback_info info);
    static napi_value JSMergeAlbum(napi_env env, napi_callback_info info);
    static napi_value JSDismissAsset(napi_env env, napi_callback_info info);
    static napi_value JSSetIsMe(napi_env env, napi_callback_info info);
    bool CheckPortraitMergeAlbum();
    static bool CheckDismissAssetVaild(std::vector<std::string> &dismissAssets,
        std::vector<std::string> &newAssetArray);

    static thread_local napi_ref constructor_;
    std::shared_ptr<PhotoAlbum> photoAlbum_ = nullptr;
    std::shared_ptr<PhotoAlbum> referencePhotoAlbum_ = nullptr;
    std::vector<AlbumChangeOperation> albumChangeOperations_;
    std::shared_ptr<PhotoAlbum> targetAlbum_ = nullptr;
    std::vector<std::string> dismissAssets_;
};
struct MediaAlbumChangeRequestAsyncContext : public NapiError {
    size_t argc;
    napi_value argv[NAPI_ARGC_MAX];
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;

    MediaAlbumChangeRequestNapi* objectInfo;
    std::vector<AlbumChangeOperation> albumChangeOperations;
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_ALBUM_CHANGE_REQUEST_NAPI_H