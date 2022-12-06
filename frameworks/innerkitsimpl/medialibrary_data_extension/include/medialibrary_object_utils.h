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

#ifndef OHOS_MEDIALIBRARY_OBJECT_UTILS_H
#define OHOS_MEDIALIBRARY_OBJECT_UTILS_H

#include <string>
#include <vector>

#include "datashare_abs_result_set.h"
#include "datashare_values_bucket.h"
#include "file_asset.h"
#include "medialibrary_command.h"
#include "medialibrary_db_const.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_unistore_manager.h"
#include "native_album_asset.h"
#include "rdb_utils.h"
#include "result_set_bridge.h"
#include "uri.h"
#include "value_object.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
class MediaLibraryObjectUtils {
public:
    static int32_t CreateFileObj(MediaLibraryCommand &cmd);
    static int32_t CreateDirWithPath(const std::string &path);
    static int32_t CreateDirObj(MediaLibraryCommand &cmd, int64_t &rowId);
    static int32_t DeleteFileObj(MediaLibraryCommand &cmd, const std::string &filePath);
    static int32_t DeleteDirObj(MediaLibraryCommand &cmd, const std::string &dirPath);
    static int32_t RenameFileObj(MediaLibraryCommand &cmd, const std::string &srcFilePath,
        const std::string &dstFilePath);
    static int32_t RenameDirObj(MediaLibraryCommand &cmd, const std::string &srcDirPath,
        const std::string &dstDirPath);
    static int32_t OpenFile(MediaLibraryCommand &cmd, const std::string &mode);
    static int32_t CloseFile(MediaLibraryCommand &cmd);

    static int32_t GetIdByPathFromDb(const std::string &path);
    static std::string GetPathByIdFromDb(const std::string &id);
    static std::string GetRecyclePathByIdFromDb(const std::string &id);
    static int32_t GetParentIdByIdFromDb(const std::string &fileId);
    static std::shared_ptr<FileAsset> GetFileAssetFromDb(const std::string &uriStr);
    static void GetDefaultRelativePath(const int32_t mediaType, string &relativePath);

    static int32_t InsertInDb(MediaLibraryCommand &cmd);
    static int32_t ModifyInfoByIdInDb(MediaLibraryCommand &cmd, const std::string &fileId = "");
    static int32_t DeleteInfoByIdInDb(MediaLibraryCommand &cmd, const std::string &fileId = "");
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryWithCondition(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns, const std::string &conditionColumn = "");

    static bool IsColumnValueExist(const std::string &value, const std::string &column);
    static bool IsAssetExistInDb(const int32_t id);
    static bool IsFileExistInDb(const std::string &path);
    static void UpdateDateModified(const std::string &dirPath);

private:
    static int32_t ModifyInfoByPathInDb(MediaLibraryCommand &cmd, const std::string &path);
    static int32_t DeleteInfoByPathInDb(MediaLibraryCommand &cmd, const std::string &path);
    static std::string GetStringColumnByIdFromDb(const std::string &id, const std::string &column);
    static NativeAlbumAsset GetDirAsset(const std::string &relativePath);
    static int32_t InsertFileInDb(MediaLibraryCommand &cmd, const FileAsset &fileAsset,
        const NativeAlbumAsset &dirAsset);
    static int32_t DeleteInvalidRowInDb(const std::string &path);
    static NativeAlbumAsset GetLastDirExistInDb(const std::string &dirPath);
    static int32_t DeleteRows(const std::vector<int64_t> &rowIds);
    static int32_t InsertDirToDbRecursively(const std::string &dirPath, int64_t &rowId);
    static bool ProcessNoMediaFile(const std::string &dstFileName, const std::string &dstAlbumPath);
    static bool ProcessHiddenFile(const std::string &dstFileName, const std::string &srcPath);
    static int32_t ProcessHiddenDir(const std::string &dstDirName, const std::string &srcDirPath);
    static int32_t UpdateFileInfoInDb(MediaLibraryCommand &cmd, const std::string &dstPath,
        const int &bucketId, const std::string &bucketName);
    static void ScanFile(std::string &srcPath);
    static int32_t DeleteEmptyDirsRecursively(int32_t dirId);
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_OBJECT_UTILS_H
