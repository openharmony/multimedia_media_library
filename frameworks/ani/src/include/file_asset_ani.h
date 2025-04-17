/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_FILE_ASSET_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_FILE_ASSET_ANI_H

#include <ani.h>
#include <memory>
#include "ani_error.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "file_asset.h"
#include "pixel_map.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {

constexpr int64_t SECONDS_LEVEL_LIMIT = 1e10;
static const std::string MEDIA_FILEMODE = "mode";

struct FileAssetContext : public AniError {
    std::shared_ptr<FileAsset> objectPtr;
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    Size size;
    int32_t changedRows;
    int32_t fd;
    int32_t analysisType = AnalysisType::ANALYSIS_INVALID;
    bool isFavorite = false;
    bool isHidden = false;
    std::string analysisData;
    std::shared_ptr<PixelMap> pixelmap;

    ResultNapiType resultNapiType;
    std::string userComment;
};

struct FileAssetAniMethod {
    ani_class cls;
    ani_method ctor;
    ani_method setUri;
    ani_method setPhotoType;
    ani_method setDisplayName;
};

struct FileAssetAttributes {
    std::string uri;
    MediaType photoType;
    std::string displayName;
};

class FileAssetAni {
public:
    FileAssetAni(std::shared_ptr<FileAsset> fileAsset);
    FileAssetAni();
    ~FileAssetAni();
    std::shared_ptr<FileAsset> GetFileAssetInstance() const;
    static FileAssetAni* CreatePhotoAsset(ani_env *env, std::shared_ptr<FileAsset> &fileAsset);
    static FileAssetAni* CreateFileAsset(ani_env *env, std::unique_ptr<FileAsset> &fileAsset);

    static ani_status FileAssetAniInit(ani_env *env);
    static ani_object Constructor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz);
    static void Destructor([[maybe_unused]] ani_env env, void *nativeObject, void *finalize_hint);
    static ani_object Wrap(ani_env *env, FileAssetAni *fileAssetAni, const FileAssetAniMethod &fileAssetAniMethod);
    static FileAssetAni* Unwrap(ani_env *env, ani_object object);
    static ani_status InitFileAssetAniMethod(ani_env *env, ResultNapiType classType,
        FileAssetAniMethod &fileAssetAniMethod);
    static ani_status BindAniAttributes(ani_env *env, ani_object object, const FileAssetAniMethod &fileAssetAniMethod,
        const FileAssetAttributes &attrs);

    static void Set(ani_env *env, ani_object object, ani_string member, ani_string value);
    static ani_object Get(ani_env *env, ani_object object, ani_string member);
    static void CommitModify(ani_env *env, ani_object object);
    static ani_double Open(ani_env *env, ani_object object, ani_string mode);
    static void Close(ani_env *env, ani_object object, ani_double fd);
    static ani_object GetThumbnail(ani_env *env, ani_object object, ani_object size);
    static void SetUserComment([[maybe_unused]] ani_env *env, ani_object object, ani_string userComment);
    static ani_string GetAnalysisData([[maybe_unused]] ani_env *env, ani_object object, ani_enum_item analysisType);
    static void SetHidden([[maybe_unused]] ani_env *env, ani_object object, ani_boolean hiddenState);
    static void SetFavorite([[maybe_unused]] ani_env *env, ani_object object, ani_boolean favoriteState);

private:
    static thread_local std::shared_ptr<FileAsset> sFileAsset_;
    std::shared_ptr<FileAsset> fileAssetPtr = nullptr;
};

} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_FILE_ASSET_ANI_H