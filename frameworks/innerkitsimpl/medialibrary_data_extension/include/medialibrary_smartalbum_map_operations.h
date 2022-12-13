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
#include "medialibrary_smartalbum_map_db.h"
#include "medialibrary_data_manager_utils.h"
#include "native_album_asset.h"
#include "rdb_store.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
struct SmartAlbumMapQueryData {
    NativeRdb::ValuesBucket values;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore;
    MediaLibrarySmartAlbumMapDb smartAlbumMapDbOprn;
    std::unordered_map<std::string, DirAsset> dirQuerySetMap;
};

class MediaLibrarySmartAlbumMapOperations {
public:
    int32_t HandleSmartAlbumMapOperations(const std::string &uri,
                                          const NativeRdb::ValuesBucket &values,
                                          const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                          const std::unordered_map<std::string, DirAsset> &dirQuerySetMap);
    int32_t HandleAddAssetOperations(const int32_t &albumId,
                                     const int32_t &childFileAssetId,
                                     SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t HandleRemoveAssetOperations(const int32_t &albumId,
                                        const int32_t &childFileAssetId,
                                        SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t HandleAgeingOperations(SmartAlbumMapQueryData &smartAlbumMapQueryData);
private:
    int32_t InsertAlbumAssetsInfoUtil(SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t InsertTrashAssetsInfoUtil(const int32_t &fileAssetId,
                                      SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t RemoveTrashAssetsInfoUtil(const int32_t &fileAssetId,
                                      SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t RemoveAlbumAssetsInfoUtil(const int32_t &albumId,
                                      SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t TrashFileAssetsInfoUtil(const int32_t &assetId,
                                    SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t TrashDirAssetsInfoUtil(const int32_t &assetId,
                                   SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t TrashChildAssetsInfoUtil(const int32_t &assetId,
                                     const int64_t &trashDate,
                                     SmartAlbumMapQueryData &smartAlbumMapQueryData);

    int32_t RecycleFileAssetsInfoUtil(const std::shared_ptr<FileAsset> &fileAsset,
                                      SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t RecycleDirAssetsInfoUtil(const std::shared_ptr<FileAsset> &fileAsset,
                                     SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t RecycleFile(const std::shared_ptr<FileAsset> &fileAsset,
                        const std::string &recyclePath,
                        std::string &outSameNamePath,
                        SmartAlbumMapQueryData &smartAlbumMapQueryData);
    std::string MakeSuffixPathName(std::string &assetPath);
    int32_t RecycleChildAssetsInfoUtil(const int32_t &assetId,
                                       const int64_t &newPath,
                                       SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t RecycleChildSameNameInfoUtil(const int32_t &parentId,
                                         const std::string &relativePath,
                                         SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t DeleteFileAssetsInfoUtil(const std::unique_ptr<FileAsset> &fileAsset,
                                     SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t DeleteDirAssetsInfoUtil(const std::unique_ptr<FileAsset> &fileAsset,
                                    SmartAlbumMapQueryData &smartAlbumMapQueryData);
    int32_t DeleteDir(const std::string &recyclePath);
    int32_t DeleteFile(const std::unique_ptr<FileAsset> &fileAsset,
                       const std::string &recyclePath);
    int32_t UpdateFavoriteAssetsInfoUtil(const int32_t &fileAssetId,
                                         const bool &isFavorites,
                                         SmartAlbumMapQueryData &smartAlbumMapQueryData);

    NativeAlbumAsset GetAlbumAsset(const std::string &id, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    int32_t GetAssetRecycle(const int32_t &assetId, std::string &outOldPath, std::string &outTrashDirPath,
                            const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                            const std::unordered_map<std::string, DirAsset> &dirQuerySetMap);
    bool IsRecycleAssetExist(const int32_t &assetId, std::string &outRecyclePath,
                             const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    int32_t MakeRecycleDisplayName(const int32_t &assetId, std::string &outDisplayName, const std::string &trashDirPath,
                                   const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    std::shared_ptr<AbsSharedResultSet> QueryAgeingTrashFiles(const std::shared_ptr<RdbStore> &rdbStore);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_SMARTALBUM_MAP_OPERATIONS_H
