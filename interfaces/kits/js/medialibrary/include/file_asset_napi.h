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

#include "file_asset.h"
#include "medialibrary_napi_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
static const std::string FILE_ASSET_NAPI_CLASS_NAME = "FileAsset";

class FileAssetNapi {
public:
    FileAssetNapi();
    ~FileAssetNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateFileAsset(napi_env env, FileAsset &iAsset);

    std::string GetFilePath() const;
    MediaType GetFileMediaType() const;
    std::string GetFileDisplayName() const;

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

    static napi_value JSSetFilePath(napi_env env, napi_callback_info info);
    static napi_value JSSetMediaType(napi_env env, napi_callback_info info);
    static napi_value JSSetFileDisplayName(napi_env env, napi_callback_info info);

    void UpdateFileAssetInfo();

    int32_t fileId_;
    std::string fileUri_;
    std::string displayName_;
    std::string filePath_;
    std::string mimeType_;
    MediaType mediaType_;
    int64_t size_;
    int64_t dateAdded_;
    int64_t dateModified_;
    std::string relativePath_;

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
    std::string albumName_;

    napi_env env_;
    napi_ref wrapper_;

    static napi_ref sConstructor_;
    static FileAsset *sFileAsset_;
};
} // namespace Media
} // namespace OHOS
#endif /* FILE_ASSET_NAPI_H */
