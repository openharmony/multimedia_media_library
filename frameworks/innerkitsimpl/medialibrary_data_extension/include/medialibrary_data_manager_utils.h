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

#ifndef MEDIALIBRARY_DATA_ABILITY_UTILS
#define MEDIALIBRARY_DATA_ABILITY_UTILS

#include <string>
#include <sys/stat.h>
#include <unordered_map>

#include "dir_asset.h"
#include "media_data_ability_const.h"
#include "media_lib_service_const.h"
#include "rdb_store.h"
#include "medialibrary_album_operations.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "datashare_abs_result_set.h"
#include "result_set_bridge.h"

namespace OHOS {
namespace Media {
using namespace OHOS::DataShare;
class MediaLibraryDataManagerUtils {
public:
    MediaLibraryDataManagerUtils();
    ~MediaLibraryDataManagerUtils();

    static std::string GetFileName(const std::string &path);
    static std::string GetParentPath(const std::string &path);
    static int32_t GetParentIdFromDb(const std::string &path, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static bool IsNumber(const std::string &str);
    static int64_t GetAlbumDateModified(const std::string &albumPath);
    static std::string GetOperationType(const std::string &uri);
    static std::string GetIdFromUri(const std::string &uri);
    static std::string GetMediaTypeUri(MediaType mediaType);
    static bool isFileExistInDb(const std::string &relativePath,
                                const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static std::string GetPathFromDb(const std::string &id, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static std::string GetRecyclePathFromDb(const std::string &id,
                                            const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static shared_ptr<FileAsset> GetFileAssetFromDb(const std::string &id,
                                                    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static bool checkFilePending(const std::shared_ptr<FileAsset> fileAsset);
    static bool checkOpenMode(const std::string &mode);
    static int32_t setFilePending(string &id, bool isPending, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static NativeAlbumAsset CreateDirectorys(const std::string relativePath,
                                             const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                             vector<int32_t> &outIds);
    static int32_t DeleteDirectorys(vector<int32_t> &outIds,
                                    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static NativeAlbumAsset GetAlbumAsset(const std::string &id, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static std::string GetFileTitle(const std::string& displayName);
    static bool isAlbumExistInDb(const std::string &path,
                                 const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                 int32_t &outRow);
    static NativeAlbumAsset GetLastAlbumExistInDb(const std::string &path,
                                      const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static int64_t UTCTimeSeconds();
    static bool CheckDisplayName(std::string displayName);
    static std::shared_ptr<AbsSharedResultSet> QueryFiles(const std::string &strQueryCondition,
        const std::shared_ptr<RdbStore> &rdbStore);
    static std::shared_ptr<AbsSharedResultSet> QueryFavFiles(const std::shared_ptr<RdbStore> &rdbStore);
    static std::shared_ptr<AbsSharedResultSet> QueryTrashFiles(const std::shared_ptr<RdbStore> &rdbStore);
    static string GetParentDisplayNameFromDb(const int &id, const shared_ptr<RdbStore> &rdbStore);
    static std::string GetNetworkIdFromUri(const std::string &uri);
    static std::string GetDistributedAlbumSql(const std::string &strQueryCondition, const std::string &tableName);
    static int32_t GetAssetRecycle(const int32_t &assetId,
                                   std::string &outOldPath,
                                   std::string &outTrashDirPath,
                                   const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                   const std::unordered_map <std::string, DirAsset> &dirQuerySetMap);
    static int32_t MakeRecycleDisplayName(const int32_t &assetId,
                                          std::string &outDisplayName,
                                          const std::string &trashDirPath,
                                          const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    static bool IsColumnValueExist(const std::string &value,
                                   const std::string &column,
                                   const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    static int32_t MakeHashDispalyName(const std::string &input, std::string &outRes);

    static bool isRecycleAssetExist(const int32_t &assetId,
        std::string &outRecyclePath,
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static std::shared_ptr<AbsSharedResultSet> QueryAgeingTrashFiles(const std::shared_ptr<RdbStore> &rdbStore);
    static std::string GetDisPlayNameFromPath(std::string &path);
    static bool isAssetExistInDb(const int &id,
                                 const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_DATA_ABILITY_UTILS