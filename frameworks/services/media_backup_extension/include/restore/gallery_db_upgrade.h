/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_MEDIA_DATATRANSFER_GALLERY_DB_UPGRADE_H
#define OHOS_MEDIA_DATATRANSFER_GALLERY_DB_UPGRADE_H

#include "rdb_store.h"
#include "db_upgrade_utils.h"

namespace OHOS::Media {
namespace DataTransfer {
class GalleryDbUpgrade {
public:
    int32_t OnUpgrade(std::shared_ptr<NativeRdb::RdbStore> galleryRdbPtr);

private:
    int32_t OnUpgrade(NativeRdb::RdbStore &store);
    int32_t AddPhotoQualityOfGalleryMedia(NativeRdb::RdbStore &store);
    int32_t AddResolutionOfGalleryMedia(NativeRdb::RdbStore &store);
    int32_t AddRelativeBucketIdOfGalleryAlbum(NativeRdb::RdbStore &store);
    int32_t GarbageAlbumUpgrade(NativeRdb::RdbStore &store);
    int32_t GarbageAlbumCheckOrAddRelativeBucketId(NativeRdb::RdbStore &store);
    int32_t GarbageAlbumCheckOrAddType(NativeRdb::RdbStore &store);
    int32_t AddIndexOfGalleryAlbum(NativeRdb::RdbStore &store);
    int32_t AddIndexOfAlbumPlugin(NativeRdb::RdbStore &store);

private:
    // Note: The column photo_quality's default value is 0.
    // But we should set it to 1 for the existing data.
    const std::string SQL_GALLERY_MEDIA_TABLE_ADD_PHOTO_QUALITY = "\
        ALTER TABLE gallery_media ADD COLUMN photo_quality INTEGER DEFAULT 1;";
    const std::string SQL_GALLERY_MEDIA_TABLE_ADD_RESOLUTION = "\
        ALTER TABLE gallery_media ADD COLUMN resolution TEXT;";
    const std::string SQL_GALLERY_ALBUM_TABLE_ADD_RELATIVE_BUCKET_ID = "\
        ALTER TABLE gallery_album ADD COLUMN relativeBucketId TEXT;";
    const std::string SQL_GARBAGE_ALBUM_TABLE_ADD_RELATIVE_BUCKET_ID = "\
        ALTER TABLE garbage_album ADD COLUMN relative_bucket_id TEXT;";
    const std::string SQL_GARBAGE_ALBUM_TABLE_ADD_TYPE = "\
        ALTER TABLE garbage_album ADD COLUMN type INTEGER DEFAULT 0;";
    const std::string SQL_GALLERY_ALBUM_INDEX_RELATIVE_BUCKET_ID = "\
        CREATE INDEX IF NOT EXISTS gallery_album_index_relativeBucketId ON gallery_album \
        ( \
            relativeBucketId \
        );";
    const std::string SQL_ALBUM_PLUGIN_INDEX_ALBUM_NAME = "\
        CREATE INDEX IF NOT EXISTS album_plugin_index_album_name ON album_plugin \
        ( \
            album_name \
        );";

private:
    DbUpgradeUtils dbUpgradeUtils_;
};
}  // namespace DataTransfer
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_DATATRANSFER_GALLERY_DB_UPGRADE_H