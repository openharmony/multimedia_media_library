/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_OTHERS_CLONE_RESTORE_H
#define OHOS_MEDIA_OTHERS_CLONE_RESTORE_H

#include <sys/stat.h>

#include "base_restore.h"
#include "photos_restore.h"

namespace OHOS {
namespace Media {

struct CloneDbInfo {
    std::string displayName;
    std::string data;
    double dateModified {0.0};
    double dateTaken {0.0};
};

class OthersCloneRestore : public BaseRestore {
public:
    OthersCloneRestore(int32_t sceneCode, const std::string &mediaAppName, const std::string &bundleInfo = "");
    virtual ~OthersCloneRestore() = default;

    int32_t Init(const std::string &backupRetorePath, const std::string &upgradePath, bool isUpgrade);
    NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType);

private:
    void RestorePhoto(void);
    void RestoreAudio(void);
    void HandleRestData(void);
    bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
        std::string dbName = "");
    bool ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info);
    void AnalyzeSource();

    void InsertPhoto(std::vector<FileInfo> &fileInfos);
    void RestoreAlbum(std::vector<FileInfo> &fileInfos);
    void UpdateAlbumInfo(FileInfo &info);
    bool NeedBatchQueryPhotoForPortrait(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap);
    void SetFileInfosInCurrentDir(const std::string &file, struct stat &statInfo);
    std::string Base32Decode(const std::string &input);
    std::vector<std::string> GetSubString(const std::string &originalString, char delimiter);
    void RecoverHiddenOrRecycleFile(std::string &currentPath, FileInfo &tmpInfo);
    int32_t GetAllfilesInCurrentDir(const std::string &path);
    void UpDateFileModifiedTime(FileInfo &fileInfo);
    void GetCloneDbInfos(const std::string &dbName, std::vector<CloneDbInfo> &mediaDbInfo);
    bool HasSameFileForDualClone(FileInfo &fileInfo);
    void HandleSelectBatch(std::shared_ptr<NativeRdb::RdbStore> mediaRdb, int32_t offset, int32_t sceneCode,
        std::vector<CloneDbInfo> &mediaDbInfo);
    void CloneInfoPushBack(std::vector<CloneDbInfo> &pushInfos, std::vector<CloneDbInfo> &popInfos);
    void HandleInsertBatch(int32_t offset);
    PhotoAlbumDao::PhotoAlbumRowData FindAlbumInfo(FileInfo &fileInfo);

private:
    std::mutex cloneMutex_;
    std::string clonePhoneName_;
    std::string mediaAppName_;
    std::vector<FileInfo> photoInfos_;
    std::vector<FileInfo> audioInfos_;
    std::vector<CloneDbInfo> photoDbInfo_;
    std::vector<CloneDbInfo> audioDbInfo_;
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb_;
    PhotoAlbumDao photoAlbumDao_;
    PhotoAlbumRestore photoAlbumRestore_;
    PhotosRestore photosRestore_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_OTHERS_CLONE_RESTORE_H
