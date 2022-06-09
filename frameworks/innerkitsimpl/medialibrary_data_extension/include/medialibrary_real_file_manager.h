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

#ifndef OHOS_MEDIALIBRARY_REAL_FILE_MANAGER_H
#define OHOS_MEDIALIBRARY_REAL_FILE_MANAGER_H

#include "medialibrary_file_manager.h"
#include "native_album_asset.h"

namespace OHOS {
namespace Media {

class MediaLibraryRealFileManager : public MediaLibraryFileManager {
public:
    MediaLibraryRealFileManager() = default;
    ~MediaLibraryRealFileManager() = default;

    int32_t CreateFile(MediaLibraryCommand &cmd) override;
    int32_t BatchCreateFile(MediaLibraryCommand &cmd) override;
    int32_t DeleteFile(MediaLibraryCommand &cmd) override;
    // int32_t RenameFile(MediaLibraryCommandParse &command) override;
    int32_t CloseFile(MediaLibraryCommand &cmd) override;
    int32_t ModifyFile(MediaLibraryCommand &cmd) override;

private:
    void ScanFile(const std::string &srcPath);
    NativeRdb::ValuesBucket UpdateBasicAssetDetails(int32_t mediaType, const std::string &fileName,
                                                    const std::string &relPath, const std::string &path);
    int32_t CreateDirectorys(const std::string &path);
    NativeAlbumAsset GetAlbumAsset(const std::string &relativePath);
    void UpdateDateModifiedForAlbum(const std::string &albumPath);
    int32_t CreateFileAsset(MediaLibraryCommand &cmd);
    int32_t CreateAlbum(MediaLibraryCommand &cmd, bool checkDup);
    int32_t DeleteFileAsset(MediaLibraryCommand &cmd, const std::string &srcPath);
    int32_t DeleteAlbum(MediaLibraryCommand &cmd, const std::string &albumPath);
    int32_t ModifyFileAsset(MediaLibraryCommand &cmd, const std::string &srcPath);
    int32_t ModifyAlbum(MediaLibraryCommand &cmd, const std::string &srcPath);
    bool IsNoMediaFile(const std::string &dstFileName, const std::string &dstAlbumPath);
    bool IsHiddenFile(const std::string &dstFileName, const std::string &srcPath);
    int32_t UpdateFileInfoInDb(MediaLibraryCommand &cmd, const std::string &dstPath, const int &bucketId,
                               const std::string &bucketName);
    int32_t InsertAlbumToDb(const std::string &albumPath);
    NativeAlbumAsset GetLastAlbumExistInDb(const std::string &albumPath);
    int32_t DeleteRows(const std::vector<int64_t> &rowIds);
};

} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_REAL_FILE_MANAGER_H