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

#ifndef __MEDIA_ANI_NATIVE_IMPL_H__
#define __MEDIA_ANI_NATIVE_IMPL_H__

#include <array>
#include <string>
#include <memory>
#include <vector>
#include <functional>

#include "fetch_result.h"
#include "file_asset.h"
#include "datashare_predicates.h"
#include "medialibrary_ani_utils.h"
#include "photo_access_helper_ani.h"

namespace OHOS {
namespace Media {
class MediaAniNativeImpl {
private:
    static bool HandleSpecialPredicate(std::shared_ptr<MediaLibraryAsyncContext> context,
        std::shared_ptr<DataShare::DataShareAbsPredicates> predicate, const FetchOptionType &fetchOptType);
    static bool GetLocationPredicate(std::shared_ptr<MediaLibraryAsyncContext> context,
        std::shared_ptr<DataShare::DataShareAbsPredicates> predicate);
    static bool AddDefaultAssetColumns(std::vector<std::string> &fetchColumn,
        std::function<bool(const std::string &columnName)> isValidColumn,
        const PhotoAlbumSubType subType = PhotoAlbumSubType::USER_GENERIC);
    static bool PhotoAccessGetAssetsExecuteSync(std::shared_ptr<MediaLibraryAsyncContext> context,
        std::vector<std::unique_ptr<FileAsset>>& fileAssetArray);
    static bool PhotoAccessGetAssetsExecute(std::shared_ptr<MediaLibraryAsyncContext> context);
    static std::shared_ptr<MediaLibraryAsyncContext> GetAssetsContext(std::vector<std::string> fetchColumns,
        std::shared_ptr<DataShare::DataShareAbsPredicates> predicate);

public:
    static std::vector<std::unique_ptr<FileAsset>> GetAssetsSync(std::vector<std::string> fetchColumns,
        std::shared_ptr<DataShare::DataShareAbsPredicates> predicate);
    static std::unique_ptr<FetchResult<FileAsset>> GetAssets(std::vector<std::string> fetchColumns,
        std::shared_ptr<DataShare::DataShareAbsPredicates> predicate);
};
} // namespace Media
} // namespace OHOS

#endif // __MEDIA_ANI_NATIVE_IMPL_H__