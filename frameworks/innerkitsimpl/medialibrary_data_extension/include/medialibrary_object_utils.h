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

#include "data_ability_predicates.h"
#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "hilog/log.h"
#include "imedia_scanner_client.h"
#include "media_data_ability_const.h"
#include "medialibrary_command.h"
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
    MediaLibraryObjectUtils()
    {
        uniStore_ = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    };
    ~MediaLibraryObjectUtils() = default;

    int32_t CreateFileObj(MediaLibraryCommand &cmd);
    int32_t CreateDirWithPath(const std::string &path);
    int32_t CreateDirObj(MediaLibraryCommand &cmd, int64_t &rowId);
    int32_t DeleteFileObj(MediaLibraryCommand &cmd, const std::string &filePath);
    int32_t DeleteDirObj(MediaLibraryCommand &cmd, const std::string &dirPath);
    int32_t RenameFileObj(MediaLibraryCommand &cmd, const std::string &srcFilePath, const std::string &dstFilePath);
    int32_t RenameDirObj(MediaLibraryCommand &cmd, const std::string &srcDirPath, const std::string &dstDirPath);
    int32_t OpenFile(MediaLibraryCommand &cmd, const std::string &mode);
    int32_t CloseFile(MediaLibraryCommand &cmd);

    int32_t GetIdByPathFromDb(const std::string &path);
    std::string GetPathByIdFromDb(const std::string &id);
    int32_t GetParentIdWithId(const std::string &fileId);
    int32_t ModifyInfoInDbWithPath(MediaLibraryCommand &cmd, const std::string &path);
    int32_t ModifyInfoInDbWithId(MediaLibraryCommand &cmd, const std::string &fileId = "");
    int32_t DeleteInfoInDbWithPath(MediaLibraryCommand &cmd, const std::string &path);
    int32_t DeleteInfoInDbWithId(MediaLibraryCommand &cmd, const std::string &fileId = "");
    std::shared_ptr<AbsSharedResultSet> QueryFiles(MediaLibraryCommand &cmd);

private:
    NativeAlbumAsset GetDirAsset(const std::string &relativePath);
    std::shared_ptr<FileAsset> GetFileAssetFromDb(const std::string &uriStr);
    int32_t DeleteInvalidRowInDb(const std::string &path);
    NativeAlbumAsset GetLastDirExistInDb(const std::string &dirPath);
    int32_t DeleteRows(const std::vector<int64_t> &rowIds);
    int32_t InsertDirToDbRecursively(const std::string &dirPath, int64_t &rowId);
    int32_t SetFilePending(std::string &uriStr, bool isPending);
    bool ProcessNoMediaFile(const std::string &dstFileName, const std::string &dstAlbumPath);
    bool ProcessHiddenFile(const std::string &dstFileName, const std::string &srcPath);
    int32_t ProcessHiddenDir(const std::string &dstDirName, const std::string &srcDirPath);
    int32_t UpdateFileInfoInDb(MediaLibraryCommand &cmd, const std::string &dstPath, const int &bucketId,
                               const std::string &bucketName);
    void UpdateDateModifiedForAlbum(const std::string &dirPath);
    void ScanFile(const std::string &srcPath);

    std::shared_ptr<MediaLibraryUnistore> uniStore_{nullptr};
};

} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_OBJECT_UTILS_H