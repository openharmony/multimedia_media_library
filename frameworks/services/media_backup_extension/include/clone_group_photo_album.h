/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_CLONE_GROUP_PHOTO_ALBUM_H
#define OHOS_CLONE_GROUP_PHOTO_ALBUM_H


#include "media_column.h"
#include "base_restore.h"
#include "backup_const.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sys/stat.h>

namespace OHOS {
namespace Media {

class CloneGroupPhotoAlbum {
public:
    CloneGroupPhotoAlbum(std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb,
    std::shared_ptr<NativeRdb::RdbStore> galleryRdb);
    ~CloneGroupPhotoAlbum() = default;
    void UpdateGroupPhoto();

private:
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::shared_ptr<NativeRdb::RdbStore> galleryRdb_;

    bool GetFileIdsByGroupTag(GroupAlbumInfo& info);
    std::vector<GroupAlbumInfo> GetGroupPhotoAlbumInfo();
    void QueryGroupPhotoAlbum(std::vector<GroupAlbumInfo> &groupPhotoAlbumInfos,
        std::map<int32_t, std::vector<int32_t>> &groupPhotoMap);
    void InsertAnalysisPhotoMap(const std::map<int32_t, std::vector<int32_t>> &groupPhotoMap);
    bool QueryTagIdFromMergeTag(GroupAlbumInfo& info);
    bool ExecuteBatchSql(const std::string& sql, const std::string& updateSql);
    int32_t BatchInsertWithRetry(const std::string &tableName,
        std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum);
};
}
}
#endif // OHOS_CLONE_GROUP_PHOTO_ALBUM_H
