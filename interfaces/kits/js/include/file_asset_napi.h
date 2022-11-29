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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FILE_ASSET_NAPI_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FILE_ASSET_NAPI_H_

#include <mutex>

#include "file_asset.h"
#include "medialibrary_type_const.h"
#include "media_thumbnail_helper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_error.h"
#include "pixel_map_napi.h"
#include "values_bucket.h"
#include "napi_remote_object.h"
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "datashare_helper.h"

namespace OHOS {
namespace Media {
static const std::string FILE_ASSET_NAPI_CLASS_NAME = "FileAsset";
static const std::string USERFILEMGR_FILEASSET_NAPI_CLASS_NAME = "UserFileMgrFileAsset";

class FileAssetNapi {
public:
    FileAssetNapi();
    ~FileAssetNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value UserFileMgrInit(napi_env env, napi_value exports);
    static napi_value CreateFileAsset(napi_env env, std::unique_ptr<FileAsset> &iAsset);
    static napi_value UserFileMgrCreateAsset(napi_env env, FileAsset &iAsset);

    std::string GetFileDisplayName() const;
    std::string GetRelativePath() const;
    std::string GetFilePath() const;
    std::string GetTitle() const;
    std::string GetFileUri() const;
    int32_t GetFileId() const;
    int32_t GetOrientation() const;
    MediaType GetMediaType() const;
    std::string GetNetworkId() const;
    std::string GetTypeMask() const;
    void SetTypeMask(const std::string &typeMask);
    bool IsFavorite() const;
    void SetFavorite(bool isFavorite);
    bool IsTrash() const;
    void SetTrash(bool isTrash);
    static std::unique_ptr<PixelMap> NativeGetThumbnail(const std::string &uri,
        const std::shared_ptr<AbilityRuntime::Context> &context);
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
    static napi_value JSGetDateTrashed(napi_env env, napi_callback_info info);
    static napi_value JSSetFileDisplayName(napi_env env, napi_callback_info info);
    static napi_value JSSetRelativePath(napi_env env, napi_callback_info info);
    static napi_value JSSetTitle(napi_env env, napi_callback_info info);
    static napi_value JSSetOrientation(napi_env env, napi_callback_info info);

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
    static napi_value JSGetCount(napi_env env, napi_callback_info info);
    void UpdateFileAssetInfo();
    static napi_value UserFileMgrSet(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrGet(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrOpen(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrClose(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrCommitModify(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrFavorite(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrTrash(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrIsDirectory(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrGetThumbnail(napi_env env, napi_callback_info info);
    bool HandleParamSet(const std::string &inputKey, const std::string &value);
    napi_env env_;

    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref userFileMgrConstructor_;
    static thread_local FileAsset *sFileAsset_;
    std::shared_ptr<FileAsset> fileAssetPtr = nullptr;
    std::unordered_map<std::string, std::variant<int32_t, int64_t, std::string>> member_;
};
struct FileAssetAsyncContext : public NapiError {
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    bool status;
    FileAssetNapi *objectInfo;
    std::shared_ptr<FileAsset> objectPtr = nullptr;
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    int32_t thumbWidth;
    int32_t thumbHeight;
    bool isDirectory;
    int32_t changedRows;
    int32_t fd;
    bool isFavorite = false;
    bool isTrash = false;
    std::string networkId;
    std::shared_ptr<PixelMap> pixelmap;

    size_t argc;
    napi_value argv[NAPI_ARGC_MAX];
    std::string typeMask;
    ResultNapiType resultNapiType;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_FILE_ASSET_NAPI_H_
