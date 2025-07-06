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

#include "medialibrary_album_helper.h"

#include "media_log.h"
#include "media_column.h"
#include "photo_album_column.h"
#include "shooting_mode_column.h"

using namespace std;

namespace OHOS {
namespace Media {

bool MediaLibraryAlbumHelper::GetAnalysisAlbumPredicates(const int32_t albumId, const PhotoAlbumSubType subType,
    const string albumName, NativeRdb::RdbPredicates& predicates, const bool hiddenState)
{
    switch (subType) {
        case PhotoAlbumSubType::PORTRAIT: {
            PhotoAlbumColumns::GetPortraitAlbumPredicates(albumId, predicates);
            return true;
        }
        case PhotoAlbumSubType::SHOOTING_MODE: {
            ShootingModeAlbumType type {};
            if (!ShootingModeAlbum::AlbumNameToShootingModeAlbumType(albumName, type)) {
                MEDIA_ERR_LOG("Invalid shooting mode album name: %{public}s", albumName.c_str());
                predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(0));
                return false;
            }
            ShootingModeAlbum::GetShootingModeAlbumPredicates(albumId, type, predicates, hiddenState);
            return true;
        }
        default: {
            PhotoAlbumColumns::GetAnalysisPhotoMapPredicates(albumId, predicates, hiddenState);
            return true;
        }
    }
}

} // namespace Media
} // namespace OHOS