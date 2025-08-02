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

#include <string>
#include <vector>

#include "ani_error.h"
#include "file_asset.h"
#include "media_change_request_ani.h"

namespace OHOS {
namespace Media {

enum class AssetsChangeOperation {
    BATCH_SET_FAVORITE,
    BATCH_SET_HIDDEN,
    BATCH_SET_USER_COMMENT,
    BATCH_SET_RECENT_SHOW,
};

class MediaAssetsChangeRequestAni : public MediaChangeRequestAni {
public:
    static ani_status Init(ani_env *env);
    explicit MediaAssetsChangeRequestAni(std::vector<std::shared_ptr<FileAsset>> fileAssets);
    ~MediaAssetsChangeRequestAni();

    static void SetFavorite([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_boolean isFavorite);
    static void SetHidden([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_boolean isHidden);
    static ani_object SetUserComment([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
        ani_string comment);
    static ani_object SetIsRecentShow([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
        ani_boolean isRecentShowAni);
    static ani_status Constructor(ani_env *env, ani_object object, ani_object arrayPhotoAssets);
    static MediaAssetsChangeRequestAni* Unwrap(ani_env *env, ani_object object);
    std::vector<std::string> GetFileAssetUriArray();
    bool GetFavoriteStatus() const;
    bool GetHiddenStatus() const;
    std::string GetUserComment() const;
    bool GetRecentShowStatus() const;
    ani_status ApplyChanges(ani_env *env) override;
    void GetFileAssetIds(std::vector<int32_t> &fileIds) const;
private:
    bool isFavorite_;
    bool isHidden_;
    std::string userComment_;
    bool isRecentShow_;
    std::vector<std::shared_ptr<FileAsset>> fileAssets_;
    std::vector<AssetsChangeOperation> assetsChangeOperations_;
};

struct MediaAssetsChangeRequestAniContext : public AniError {
    MediaAssetsChangeRequestAni* objectInfo;
    std::vector<AssetsChangeOperation> assetsChangeOperations;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_ANI_SRC_INCLUDE_MEDIA_ASSETS_CHANGE_REQUEST_HANDLEIMPL_H