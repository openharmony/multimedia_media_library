/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_OPERATIONS_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_OPERATIONS_H_

#include <string>
#include <variant>
#include <grp.h>
#include <securec.h>
#include <unistd.h>
#include <unordered_map>

#include "dir_asset.h"
#include "datashare_values_bucket.h"
#include "medialibrary_db_const.h"
#include "medialibrary_dir_db.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "values_bucket.h"


namespace OHOS {
namespace Media {
class MediaLibraryDirOperations {
public:
    const std::string DIR_PARENT_WHERECLAUSE = MEDIA_DATA_DB_PARENT_ID + " = ?";
    const std::string DIR_DIRECTORY_WHERECLAUSE = CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY + " = ?";
    const std::string DIR_DIRECTORY_TYPE_WHERECLAUSE = CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY_TYPE + " = ?";
    const std::string DIR_FILE_WHERECLAUSE = MEDIA_DATA_DB_ID + " = ?";
    const std::string DIR_RELATIVEPATH_WHERECLAUSE = MEDIA_DATA_DB_RELATIVE_PATH +
        " LIKE ? OR " + MEDIA_DATA_DB_FILE_PATH + " = ? AND " + MEDIA_DATA_DB_IS_TRASH + " = 0";

    int32_t HandleDirOperations(const std::string &oprn,
                                const NativeRdb::ValuesBucket &values,
                                const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                const std::unordered_map
                                <std::string, DirAsset> &dirQuerySetMap = {});

    int32_t HandleDeleteDir(const NativeRdb::ValuesBucket &values,
                            const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    int32_t HandleCheckDirExtension(const NativeRdb::ValuesBucket &values,
                                    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                    const std::unordered_map
                                    <std::string, DirAsset> &dirQuerySetMap);

    int32_t HandleFMSDeleteDir(const NativeRdb::ValuesBucket &values,
                               const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    int32_t HandleFMSTrashDir(const NativeRdb::ValuesBucket &values,
                              const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                              const std::unordered_map
                              <std::string, DirAsset> &dirQuerySetMap);

private:
    int32_t DeleteDirInfoUtil(const int &parent,
                              const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                              const MediaLibraryDirDb &dirDbOprn);

    int32_t DeleteFMSDirInfoUtil(const std::string &relativePath,
                                 const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                 const MediaLibraryDirDb &dirDbOprn);

    int32_t CheckDirInfoUtil(const NativeRdb::ValuesBucket &values,
                             const std::shared_ptr<RdbStore> &rdbStore,
                             const std::unordered_map
                             <std::string, DirAsset> &dirQuerySetMap);

    int32_t GetRootDirAndExtension(std::string &displayName, std::string &relativePath,
                                   int mediaType, NativeRdb::ValuesBucket &outValues);

    int32_t CheckFileExtension(const int mediaType, string extension, const string &dstMediaType);

    DirAsset GetDirQuerySet(const NativeRdb::ValuesBucket &values,
        const std::shared_ptr<RdbStore> &rdbStore,
        const std::unordered_map<std::string, DirAsset> &dirQuerySetMap);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_OPERATIONS_H_
