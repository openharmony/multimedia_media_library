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

#ifndef MEDIALIBRARY_PHOTO_OPERATIONS_H
#define MEDIALIBRARY_PHOTO_OPERATIONS_H

#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

#include "abs_shared_result_set.h"
#include "file_asset.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaLibraryPhotoOperations : public MediaLibraryAssetOperations {
public:
    EXPORT static int32_t Create(MediaLibraryCommand &cmd);
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> Query(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns);
    EXPORT static int32_t Update(MediaLibraryCommand &cmd);
    EXPORT static int32_t Delete(MediaLibraryCommand &cmd);
    EXPORT static int32_t Open(MediaLibraryCommand &cmd, const std::string &mode);
    EXPORT static int32_t Close(MediaLibraryCommand &cmd);
    EXPORT static int32_t SubmitCache(MediaLibraryCommand &cmd);
    EXPORT static int32_t CommitEditInsert(MediaLibraryCommand &cmd);
    EXPORT static int32_t RevertToOrigin(MediaLibraryCommand &cmd);
    EXPORT static void DeleteRevertMessage(const std::string &path);
    EXPORT static void StoreThumbnailSize(const std::string& photoId, const std::string& photoPath);
    EXPORT static void RemoveThumbnailSizeRecord(const std::string& photoId);

private:
    static int32_t CreateV9(MediaLibraryCommand &cmd);
    static int32_t CreateV10(MediaLibraryCommand &cmd);
    static int32_t DeletePhoto(const std::shared_ptr<FileAsset> &fileAsset, MediaLibraryApi api);
    static int32_t UpdateV9(MediaLibraryCommand &cmd);
    static int32_t UpdateV10(MediaLibraryCommand &cmd);
    static int32_t TrashPhotos(MediaLibraryCommand &cmd);
    static void SolvePhotoAlbumInCreate(MediaLibraryCommand &cmd, FileAsset &fileAsset);
    static int32_t OpenCache(MediaLibraryCommand &cmd, const std::string &mode, bool &isCacheOperation);
    static int32_t DeleteCache(MediaLibraryCommand &cmd);
    static int32_t OpenEditOperation(MediaLibraryCommand &cmd, bool &isSkip);
    static int32_t RequestEditData(MediaLibraryCommand &cmd);
    static int32_t RequestEditSource(MediaLibraryCommand &cmd);
    static int32_t CommitEditOpen(MediaLibraryCommand &cmd);
    static int32_t CommitEditOpenExecute(const std::shared_ptr<FileAsset> &fileAsset);
    static int32_t CommitEditInsertExecute(const std::shared_ptr<FileAsset> &fileAsset,
        const std::string &editData);
    static int32_t DoRevertEdit(const std::shared_ptr<FileAsset> &fileAsset);
    static int32_t ParseMediaAssetEditData(MediaLibraryCommand &cmd, std::string &editData);
    static int32_t SaveSourceAndEditData(const std::shared_ptr<FileAsset> &fileAsset, const std::string &editData);
    static int32_t SubmitEditCacheExecute(MediaLibraryCommand &cmd,
        const std::shared_ptr<FileAsset> &fileAsset, const std::string &cachePath);
    static int32_t SubmitCacheExecute(MediaLibraryCommand &cmd,
        const std::shared_ptr<FileAsset> &fileAsset, const std::string &cachePath);
    static bool CheckCacheCmd(MediaLibraryCommand &cmd, int32_t subtype, const std::string &displayName);
    static int32_t MoveCacheFile(MediaLibraryCommand &cmd, int32_t subtype,
        const std::string &cachePath, const std::string &destPath);
    static int32_t UpdateFileAsset(MediaLibraryCommand &cmd);
    static int32_t BatchSetUserComment(MediaLibraryCommand &cmd);
};

class PhotoEditingRecord {
public:
    EXPORT explicit PhotoEditingRecord();
    EXPORT static std::shared_ptr<PhotoEditingRecord> GetInstance();

    EXPORT bool StartCommitEdit(int32_t fileId);
    EXPORT void EndCommitEdit(int32_t fileId);
    EXPORT bool StartRevert(int32_t fileId);
    EXPORT void EndRevert(int32_t fileId);
    EXPORT bool IsInRevertOperation(int32_t fileId);
    EXPORT bool IsInEditOperation(int32_t fileId);

private:
    static std::mutex mutex_;
    static std::shared_ptr<PhotoEditingRecord> instance_;
    std::shared_mutex addMutex_;
    std::set<int32_t> editingPhotoSet_;
    std::set<int32_t> revertingPhotoSet_;
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_PHOTO_OPERATIONS_H