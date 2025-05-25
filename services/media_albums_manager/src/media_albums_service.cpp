/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaAlbumsService"

#include "media_albums_service.h"

#include <string>

#include "medialibrary_album_operations.h"
#include "media_albums_rdb_operations.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "photo_album_column.h"
#include "media_file_utils.h"

using namespace std;

namespace OHOS::Media {

MediaAlbumsService &MediaAlbumsService::GetInstance()
{
    static MediaAlbumsService service;
    return service;
}

int32_t MediaAlbumsService::DeleteHighlightAlbums(const vector<string>& albumIds)
{
    // Only Highlight albums can be deleted by this way
    MEDIA_INFO_LOG("Delete highlight albums");
    int32_t changedRows = this->rdbOperation_.DeleteHighlightAlbums(albumIds);
    CHECK_AND_RETURN_RET_LOG(changedRows >= 0, E_HAS_DB_ERROR,
        "Delete highlight album failed, changedRows is %{private}d", changedRows);
    
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_RET_LOG(watch != nullptr, E_ERR, "Can not get MediaLibraryNotify Instance");

    if (changedRows > 0) {
        for (size_t i = 0; i < albumIds.size(); ++i) {
            watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX,
                albumIds[i]), NotifyType::NOTIFY_REMOVE);
        }
    }
    return changedRows;
}

int32_t MediaAlbumsService::DeletePhotoAlbums(const std::vector<std::string> &albumIds)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
    rdbPredicate.In(PhotoAlbumColumns::ALBUM_ID, albumIds);
    return MediaLibraryAlbumOperations::DeletePhotoAlbum(rdbPredicate);
}

int32_t MediaAlbumsService::CreatePhotoAlbum(const std::string& albumName)
{
    NativeRdb::ValuesBucket value;
    value.PutString(PhotoAlbumColumns::ALBUM_NAME, albumName);
    MediaLibraryCommand cmd(OperationObject::PHOTO_ALBUM, OperationType::CREATE, value);
    return MediaLibraryAlbumOperations::HandlePhotoAlbumOperations(cmd);
}
} // namespace OHOS::Media