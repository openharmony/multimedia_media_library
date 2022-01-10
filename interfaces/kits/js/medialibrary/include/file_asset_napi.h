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

#ifndef FILE_ASSET_NAPI_H
#define FILE_ASSET_NAPI_H

#include "ability.h"
#include "ability_loader.h"
#include "file_asset.h"
#include "data_ability_helper.h"
#include "medialibrary_napi_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
static const std::string FILE_ASSET_NAPI_CLASS_NAME = "FileAsset";

class FileAssetNapi {
public:
    FileAssetNapi();
    ~FileAssetNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateFileAsset(napi_env env, FileAsset &iAsset);

    std::string GetFileDisplayName() const;
    std::string GetRelativePath() const;
    std::string GetTitle() const;
    std::string GetFileUri() const;
    int32_t GetFileId() const;
    static std::shared_ptr<AppExecFwk::DataAbilityHelper> GetDataAbilityHelper(napi_env env);
    static std::shared_ptr<AppExecFwk::DataAbilityHelper> sAbilityHelper_;
private:
    static void FileAssetNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value FileAssetNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value JSGetFileId(napi_env env, napi_callback_info info);
    static napi_value JSGetFileUri(napi_env env, napi_callback_info info);
    static napi_value JSGetFileDisplayName(napi_env env, napi_callback_info info);
    static napi_value JSGetFilePath(napi_env env, napi_callback_info info);
    static napi_value JSGetMimeType(napi_env env, napi_callback_info info);
    static napi_value JSGetMediaType(napi_env env, napi_callback_info info);
    static napi_value JSGetTitle(napi_env env, napi_callback_info info);
    static napi_value JSGetArtist(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbum(napi_env env, napi_callback_info info);
    static napi_value JSGetSize(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumId(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumName(napi_env env, napi_callback_info info);
    static napi_value JSGetDateAdded(napi_env env, napi_callback_info info);
    static napi_value JSGetDateModified(napi_env env, napi_callback_info info);
    static napi_value JSGetOrientation(napi_env env, napi_callback_info info);
    static napi_value JSGetWidth(napi_env env, napi_callback_info info);
    static napi_value JSGetHeight(napi_env env, napi_callback_info info);
    static napi_value JSGetDuration(napi_env env, napi_callback_info info);
    static napi_value JSGetRelativePath(napi_env env, napi_callback_info info);

    static napi_value JSSetFileDisplayName(napi_env env, napi_callback_info info);
    static napi_value JSSetRelativePath(napi_env env, napi_callback_info info);
    static napi_value JSSetTitle(napi_env env, napi_callback_info info);

    static napi_value JSParent(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbumUri(napi_env env, napi_callback_info info);
    static napi_value JSGetDateTaken(napi_env env, napi_callback_info info);
    static napi_value JSIsDirectory(napi_env env, napi_callback_info info);
    static napi_value JSCommitModify(napi_env env, napi_callback_info info);
    static napi_value JSOpen(napi_env env, napi_callback_info info);
    static napi_value JSClose(napi_env env, napi_callback_info info);
    static napi_value JSGetThumbnail(napi_env env, napi_callback_info info);
    static napi_value JSFavorite(napi_env env, napi_callback_info info);
    static napi_value JSIsFavorite(napi_env env, napi_callback_info info);
    static napi_value JSTrash(napi_env env, napi_callback_info info);
    static napi_value JSIsTrash(napi_env env, napi_callback_info info);
    void UpdateFileAssetInfo();

    int32_t fileId_;
    std::string fileUri_;
    Media::MediaType mediaType_;
    std::string displayName_;
    std::string relativePath_;
    std::string filePath_;
    std::string parent_;

    int64_t size_;
    int64_t dateAdded_;
    int64_t dateModified_;
    int64_t dateTaken_;
    std::string mimeType_;

    // audio
    std::string title_;
    std::string artist_;
    std::string album_;

    // video, image
    int32_t duration_;
    int32_t orientation_;
    int32_t width_;
    int32_t height_;

    // album
    int32_t albumId_;
    std::string albumUri_;
    std::string albumName_;

    napi_env env_;
    napi_ref wrapper_;

    static napi_ref sConstructor_;
    static FileAsset *sFileAsset_;
};
struct FileAssetAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    bool status;
    FileAssetNapi *objectInfo;
    OHOS::NativeRdb::ValuesBucket valuesBucket;
};
} // namespace Media
} // namespace OHOS
#endif /* FILE_ASSET_NAPI_H */
