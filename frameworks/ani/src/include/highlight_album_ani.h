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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_HIGHLIGHT_ALBUM_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_HIGHLIGHT_ALBUM_ANI_H

#include <memory>
#include <string>
#include <vector>
#include "ani_error.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "photo_album.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

struct HighlightAlbumInfo {
    std::string uriStr;
    std::vector<std::string> fetchColumn;
};
class HighlightAlbumAni {
public:
    EXPORT HighlightAlbumAni();
    EXPORT ~HighlightAlbumAni();

    EXPORT static ani_status Init(ani_env *env);
    EXPORT static ani_status AnalysisAlbumInit(ani_env *env);
    std::shared_ptr<PhotoAlbum> GetPhotoAlbumInstance() const;

private:
    EXPORT static ani_object GetOrderPosition(ani_env *env, ani_object aniObject, ani_object photoAssets);
    EXPORT static ani_long Constructor(ani_env *env, [[maybe_unused]] ani_object object, ani_object aniAlbum);
    EXPORT static void Destructor(ani_env *env, ani_object object);
    static HighlightAlbumAni* Unwrap(ani_env *env, ani_object object);

    EXPORT static ani_string GetHighlightAlbumInfo(ani_env *env, ani_object object, ani_enum_item type);
    EXPORT static ani_object GetHighlightResource(ani_env *env, ani_object object, ani_string resourceUri);
    EXPORT static ani_status SetHighlightUserActionData(ani_env *env, ani_object object, ani_enum_item type,
         ani_int actionDataAni);
    EXPORT static ani_status SetSubTitle(ani_env *env, ani_object object, ani_object subTitle);
    EXPORT static ani_double DeleteHighlightAlbums(ani_env *env, ani_object object, ani_object context,
        ani_object albums);

    ani_env *highlightEnv_;
    std::shared_ptr<PhotoAlbum> highlightAlbumPtr = nullptr;
};

struct HighlightAlbumAniContext : public AniError {
    int32_t changedRows;
    int32_t newCount;
    std::vector<std::string> fetchColumn;
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    std::vector<DataShare::DataShareValuesBucket> valuesBuckets;
    std::string networkId;
    std::string uri;
    std::unique_ptr<FetchResult<FileAsset>> fetchResult;
    ResultNapiType resultNapiType;
    std::string highlightAlbumInfo;
    std::vector<std::string> assetIdArray;
    std::vector<int32_t> orderPositionArray;
    int32_t albumId;
    PhotoAlbumSubType subType;

    int32_t highlightAlbumInfoType = HighlightAlbumInfoType::INVALID_INFO;
    int32_t highlightUserActionType = HighlightUserActionType::INVALID_USER_ACTION;

    int32_t actionData = 0;
    std::string resourceUri;
    std::string subtitle;
    ani_arraybuffer aniArrayBuffer;
    HighlightAlbumAni *objectInfo;
};

} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_HIGHLIGHT_ALBUM_ANI_H