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

#ifndef OHOS_MEDIA_PHOTO_ALBUM_COPY_META_DATA_OPERATION_H
#define OHOS_MEDIA_PHOTO_ALBUM_COPY_META_DATA_OPERATION_H

#include <string>
#include <vector>
#include <unordered_map>

#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "photo_album_column.h"

namespace OHOS::Media {
class PhotoAlbumCopyMetaDataOperation {
private:
    struct AlbumInfo {
        int64_t albumId;
        int32_t albumType;
        std::string albumName;
        std::string bundleName;
        std::string lPath;
    };

private:
    std::shared_ptr<MediaLibraryRdbStore> mediaRdbStore_;

public:
    PhotoAlbumCopyMetaDataOperation &SetRdbStore(const std::shared_ptr<MediaLibraryRdbStore> &upgradeStore);
    int64_t CopyAlbumMetaData(NativeRdb::ValuesBucket &values);

private:
    void ReadAlbumValue(AlbumInfo &albumInfo, NativeRdb::ValuesBucket &values);
    void FindAlbumInfo(AlbumInfo &albumInfo);
    void UpdateMetaData(const AlbumInfo &albumInfo, NativeRdb::ValuesBucket &values);
    int64_t GetOrCreateAlbum(const std::string &lPath, NativeRdb::ValuesBucket &values);
    int64_t GetLatestAlbumIdBylPath(const std::string &lPath, int32_t &dirty);
    int32_t QueryAlbumPluginInfo(std::string &lPath, std::string &bundle_name, std::string &album_name);

private:
    const std::string SQL_PHOTO_ALBUM_SELECT_MAX_ALBUM_ID_BY_LPATH = "\
        SELECT album_id, \
        dirty \
        FROM PhotoAlbum \
        WHERE LOWER(COALESCE(lpath, '')) = LOWER(?) \
        ORDER BY album_id DESC \
        LIMIT 1;";
    const std::string SQL_ALBUM_PLUGIN_SELECT_BY_NAME = "\
        SELECT lPath, \
        album_name, \
        bundle_name \
        FROM album_plugin \
        WHERE (album_name = ? or album_name_en = ?) \
        AND priority = '1';";
    const std::string SQL_ALBUM_PLUGIN_SELECT_BY_BUNDLE_AND_NAME = "\
        SELECT lPath, \
        album_name, \
        bundle_name \
        FROM album_plugin \
        WHERE (album_name = ? or album_name_en = ?) \
        AND bundle_name = ? \
        AND priority = '1';";
};
} // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_ALBUM_COPY_META_DATA_OPERATION_H