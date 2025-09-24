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
#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSETS_CHANGE_REQUEST_HANDLEIMPL_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSETS_CHANGE_REQUEST_HANDLEIMPL_H

#include <memory>
#include <vector>

#include <ani.h>
#include "datashare_result_set.h"
#include "file_asset.h"
#include "ipc_skeleton.h"
#include "media_column.h"
#include "medialibrary_db_const.h"
#include "tokenid_kit.h"
#include "userfilemgr_uri.h"
#include "medialibrary_ani_utils.h"
#include "media_change_request_ani.h"

namespace OHOS {
namespace Media {

enum class AssetsChangeOperation {
    BATCH_SET_FAVORITE,
    BATCH_SET_HIDDEN,
    BATCH_SET_USER_COMMENT,
};

class MediaAssetsChangeRequestAni : public MediaChangeRequestAni {
public:
    static ani_status MediaAssetsChangeRequestAniInit(ani_env *env);
    MediaAssetsChangeRequestAni(std::vector<std::shared_ptr<FileAsset>> fileAssets);
    ~MediaAssetsChangeRequestAni();
    static void RecordChangeOperation(AssetsChangeOperation changeOperation);
    static void SetFavorite([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_boolean isFavorite);
    static void SetHidden([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_boolean isHidden);
    static ani_object create([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz);
    static MediaAssetsChangeRequestAni* unwrapp(ani_env *env, ani_object object);
    static std::vector<std::shared_ptr<FileAsset>> fileAssets_;
    static std::vector<AssetsChangeOperation> assetsChangeOperations_;
    static std::vector<std::string> GetFileAssetUriArray();
    static bool GetFavoriteStatus();
    static bool GetHiddenStatus();
    static bool SetAssetsPropertyExecute(const AssetsChangeOperation& changeOperation);
    virtual ani_status ApplyChanges(ani_env *env, ani_object aniObject) override;

private:
    static bool isFavorite_;
    static bool isHidden_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSETS_CHANGE_REQUEST_HANDLEIMPL_H