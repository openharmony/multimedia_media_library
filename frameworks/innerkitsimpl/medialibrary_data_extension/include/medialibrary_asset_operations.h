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

#include "abs_predicates.h"
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
static constexpr int UNCREATE_FILE_TIMEPENDING = -1;

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
    static int32_t DeleteToolOperation(MediaLibraryCommand &cmd);

protected:
    static std::shared_ptr<FileAsset> GetFileAssetFromDb(const std::string &column, const std::string &value,
        OperationObject oprnObject, const std::vector<std::string> &columns = {}, const std::string &networkId = "");
    static std::shared_ptr<FileAsset> GetFileAssetFromDb(NativeRdb::AbsPredicates &predicates,
        OperationObject oprnObject, const std::vector<std::string> &columns = {}, const std::string &networkId = "");

    static int32_t InsertAssetInDb(MediaLibraryCommand &cmd, const FileAsset &fileAsset);
    static int32_t CheckWithType(bool isContains, const std::string &displayName,
         const std::string &extention, int32_t mediaType);
    static int32_t CheckDisplayNameWithType(const std::string &displayName, int32_t mediaType);
    static int32_t CheckExtWithType(const std::string &extention, int32_t mediaType);
    static int32_t CheckRelativePathWithType(const std::string &relativePath, int32_t mediaType);
    static void GetAssetRootDir(int32_t mediaType, std::string &rootDirPath);
    static int32_t SetAssetPathInCreate(FileAsset &fileAsset);
    static int32_t SetAssetPath(FileAsset &fileAsset, const std::string &extention);
    static int32_t DeleteAssetInDb(MediaLibraryCommand &cmd);

    static bool IsContainsValue(NativeRdb::ValuesBucket &values, const std::string &key);
    static int32_t ModifyAssetInDb(MediaLibraryCommand &cmd);
    static int32_t UpdateFileName(MediaLibraryCommand &cmd, const std::shared_ptr<FileAsset> &fileAsset,
        bool &isNameChanged);
    static int32_t UpdateRelativePath(MediaLibraryCommand &cmd, const std::shared_ptr<FileAsset> &fileAsset,
        bool &isNameChanged);
    static void UpdateVirtualPath(MediaLibraryCommand &cmd, const std::shared_ptr<FileAsset> &fileAsset);
    static int32_t UpdateFileInDb(MediaLibraryCommand &cmd);
    static int32_t OpenAsset(const std::shared_ptr<FileAsset> &fileAsset, const std::string &mode,
        MediaLibraryApi api);
    static int32_t CloseAsset(const std::shared_ptr<FileAsset> &fileAsset, bool isCreateThumbSync = false);
    static void InvalidateThumbnail(const std::string &fileId, int32_t mediaType);
    static int32_t SendTrashNotify(MediaLibraryCommand &cmd, int32_t rowId);
    static void SendFavoriteNotify(MediaLibraryCommand &cmd, int32_t rowId);
    static int32_t SendHideNotify(MediaLibraryCommand &cmd, int32_t rowId);

    static bool GetInt32FromValuesBucket(const NativeRdb::ValuesBucket &values, const std::string &column,
        int32_t &value);
    static bool GetStringFromValuesBucket(const NativeRdb::ValuesBucket &values, const std::string &column,
        std::string &value);

private:
    static int32_t CreateAssetUniqueId(int32_t type);
    static int32_t CreateAssetBucket(int32_t fileId, int32_t &bucketNum);
    static int32_t CreateAssetRealName(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &name);
    static int32_t CreateAssetPathById(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &filePath);
    static void ScanFile(const std::string &path, bool isCreateThumbSync = false);
    
    static constexpr int ASSET_IN_BUCKET_NUM_MAX = 1000;
    static constexpr int ASSET_DIR_START_NUM = 16;
    static constexpr int ASSET_MAX_COMPLEMENT_ID = 999;
};

using VerifyFunction = bool (*) (NativeRdb::ValueObject&, MediaLibraryCommand&);
class AssetInputParamVerification {
public:
    static bool CheckParamForUpdate(MediaLibraryCommand &cmd);
    
private:
    static bool Forbidden(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsInt32(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsInt64(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsBool(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsString(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsDouble(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsBelowApi9(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsStringNotNull(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsUniqueValue(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);

    static const std::unordered_map<std::string, std::vector<VerifyFunction>> UPDATE_VERIFY_PARAM_MAP;
};
} // namespace Media
} // namespace OHOS

#endif // MEDIALIBRARY_FILE_OPERATIONS
