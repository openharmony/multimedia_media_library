/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_FILE_OPERATIONS
#define MEDIALIBRARY_FILE_OPERATIONS

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include "abs_shared_result_set.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "file_asset.h"
#include "media_column.h"
#include "medialibrary_command.h"
#include "value_object.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
class MediaLibraryAssetOperations {
public:
    static int32_t HandleInsertOperation(MediaLibraryCommand &cmd);
    static int32_t CreateOperation(MediaLibraryCommand &cmd);
    static int32_t DeleteOperation(MediaLibraryCommand &cmd);
    static std::shared_ptr<NativeRdb::ResultSet> QueryOperation(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns);
    static int32_t UpdateOperation(MediaLibraryCommand &cmd);
    static int32_t OpenOperation(MediaLibraryCommand &cmd, const std::string &mode);
    static int32_t CloseOperation(MediaLibraryCommand &cmd);

protected:
    static std::shared_ptr<FileAsset> GetFileAssetFromDb(const std::string &byKey,
        const std::string &byValue, OperationObject oprnObject, const std::string &networkId = "");

    static int32_t InsertAssetInDb(MediaLibraryCommand &cmd, const FileAsset &fileAsset);
    static int32_t CheckDisplayNameWithType(const std::string &displayName, int32_t mediaType);
    static void GetAssetRootDir(int32_t mediaType, std::string &rootDirPath);
    static int32_t SetAssetPathInCreate(FileAsset &fileAsset);
    static int32_t DeleteAssetInDb(MediaLibraryCommand &cmd);
    static void InvalidateThumbnail(const std::string &fileId);

    static int32_t BeginTransaction();
    static int32_t TransactionCommit();
    static int32_t TransactionRollback();
private:
    static int32_t CreateAssetUniqueId(int32_t type);
    static int32_t CreateAssetBucket(int32_t fileId, int32_t &bucketNum);
    static int32_t CreateAssetRealName(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &name);
    static int32_t CreateAssetPathById(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &filePath);
    
    static constexpr int ASSET_IN_BUCKET_NUM_MAX = 1000;
    static constexpr int ASSET_DIR_START_NUM = 16;
    static constexpr int ASSET_MAX_COMPLEMENT_ID = 999;
};

} // namespace Media
} // namespace OHOS

#endif // MEDIALIBRARY_FILE_OPERATIONS