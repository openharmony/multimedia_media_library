/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_SMARTALBUM_MAP_OPERATIONS_H
#define OHOS_MEDIALIBRARY_SMARTALBUM_MAP_OPERATIONS_H

#include <string>
#include <variant>
#include <grp.h>
#include <securec.h>
#include <unistd.h>
#include <unordered_map>

#include "dir_asset.h"
#include "file_asset.h"
#include "medialibrary_db_const.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_command.h"
#include "native_album_asset.h"
#include "rdb_store.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
enum TrashType {
    NOT_TRASHED = 0,
    TRASHED_ASSET,
    TRASHED_DIR,
    TRASHED_DIR_CHILD
};
constexpr int32_t DEFAULT_ALBUMID = -1;
constexpr int32_t DEFAULT_ASSETID = -1;
class MediaLibrarySmartAlbumMapOperations {
public:
    static int32_t HandleSmartAlbumMapOperation(MediaLibraryCommand &cmd);
    static int32_t HandleAddAssetOperation(const int32_t albumId,
        const int32_t childFileAssetId, const int32_t childAlbumId, MediaLibraryCommand &cmd);
    static int32_t HandleRemoveAssetOperation(const int32_t albumId,
        const int32_t childFileAssetId, MediaLibraryCommand &cmd);
    static int32_t HandleAgingOperation();
    static void SetInterrupt(bool interrupt);
    static bool GetInterrupt();

private:
    static std::string MakeSuffixPathName(std::string &assetPath);
    static int32_t DeleteFileAssetsInfoUtil(std::unique_ptr<FileAsset> &fileAsset);
    static int32_t DeleteDirAssetsInfoUtil(std::unique_ptr<FileAsset> &fileAsset);
    static int32_t UpdateFavoriteAssetsInfoUtil(const int32_t fileAssetId, const bool isFavorites);
    static int32_t InsertTrashAssetsInfoUtil(const int32_t fileAssetId, MediaLibraryCommand &cmd);
    static int32_t TrashFileAssetsInfoUtil(const int32_t assetId, MediaLibraryCommand &cmd);
    static int32_t TrashDirAssetsInfoUtil(const int32_t assetId, MediaLibraryCommand &cmd);
    static int32_t TrashChildAssetsInfoUtil(const int32_t parentId, const int64_t &trashDate);
    static int32_t UpdateAssetTrashInfoInDb(const int32_t assetId, const int64_t trashDate, std::string &recyclePath,
        const std::string &oldPath);
    static int32_t UpdateChildTrashInfoInDb(const int32_t assetId, const int64_t trashDate);
    static int32_t UpdateDirTrashInfoInDb(const int32_t assetId, const int64_t trashDate, std::string &recyclePath,
        const std::string &oldPath);
    static int32_t RemoveTrashAssetsInfoUtil(const int32_t fileAssetId);
    static int32_t RecycleFileAssetsInfoUtil(const std::shared_ptr<FileAsset> &fileAsset);
    static int32_t RecycleDirAssetsInfoUtil(const std::shared_ptr<FileAsset> &fileAsset);
    static int32_t RecycleFile(const std::shared_ptr<FileAsset> &fileAsset, const std::string &recyclePath,
        std::string &outSameNamePath);
    static int32_t UpdateParentDirRecycleInfoInDb(const int32_t assetId, const int32_t parentId,
        const std::string &parentName);
    static int32_t UpdateSameNameInfoInDb(const int32_t assetId, const std::string &displayName,
        const std::string &path);
    static int32_t UpdateRecycleInfoInDb(const int32_t assetId, const int64_t recycleDate,
        const std::string &recyclePath, const std::string &realPath);
    static int32_t RecycleDir(const std::shared_ptr<FileAsset> &fileAsset, const std::string &recyclePath,
        std::string &outSameNamePath);
    static int32_t RecycleChildAssetsInfoUtil(const int32_t parentId, const int64_t recycleDate);
    static int32_t RecycleChildSameNameInfoUtil(const int32_t parentId, const std::string &relativePath);
    static int32_t UpdateChildPathInfoInDb(const int32_t assetId, const std::string &path,
        const std::string &relativePath, const int32_t isTrash);
    static int32_t UpdateChildRecycleInfoInDb(const int32_t assetId, const int64_t recycleDate);
    static int32_t GetAlbumAsset(const std::string &id, NativeAlbumAsset &albumAsset);
    static int32_t GetAssetRecycle(const int32_t assetId, std::string &outOldPath, std::string &outTrashDirPath,
        const std::unordered_map <std::string, DirAsset> &dirQuerySetMap);
    static bool GetRecyclePath(const int32_t assetId, std::string &outRecyclePath);
    static int32_t MakeRecycleDisplayName(const int32_t assetId,
        const std::string &trashDirPath, std::string &outDisplayName);
    static std::shared_ptr<NativeRdb::ResultSet> QueryAgeingTrashFiles();
    static int32_t UpdateTrashInfoInDb(const int32_t assetId, const int64_t trashDate, std::string &recyclePath,
        const std::string &oldPath, const uint32_t trashType);
    static std::atomic<bool> isInterrupt_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_SMARTALBUM_MAP_OPERATIONS_H
