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

#ifndef OHOS_MEDIA_UPGRADE_RESTORE_H
#define OHOS_MEDIA_UPGRADE_RESTORE_H

#include "base_restore.h"

namespace OHOS {
namespace Media {
class UpgradeRestore : public BaseRestore {
public:
    UpgradeRestore(const std::string &galleryAppName, const std::string &mediaAppName, int32_t sceneCode);
    UpgradeRestore(const std::string &galleryAppName, const std::string &mediaAppName, int32_t sceneCode,
        const std::string &dualDirName);
    virtual ~UpgradeRestore() = default;
    int32_t Init(const std::string &backupRestorePath, const std::string &upgradePath, bool isUpgrade) override;
    int32_t QueryTotalNumber(void) override;
    std::vector<FileInfo> QueryFileInfos(int32_t offset) override;
    NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType) const override;
    std::vector<FileInfo> QueryFileInfosFromExternal(int32_t offset, int32_t maxId, bool isCamera);
    std::vector<FileInfo> QueryAudioFileInfosFromExternal(int32_t offset);
    std::vector<FileInfo> QueryAudioFileInfosFromAudio(int32_t offset);
    int32_t QueryNotSyncTotalNumber(int32_t offset, bool isCamera);
    void InitGarbageAlbum();
    void HandleClone();

private:
    void RestorePhoto(void) override;
    void RestoreAudio(void) override;
    void HandleRestData(void) override;
    bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) override;
    bool ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) override;
    bool ParseResultSetFromExternal(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
        int mediaType = DUAL_MEDIA_TYPE::IMAGE_TYPE);
    bool ParseResultSetFromAudioDb(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info);
    bool ParseResultSetFromGallery(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info);
    void RestoreFromGallery();
    void RestoreFromExternal(bool isCamera);
    void RestoreAudioFromExternal();
    void RestoreAudioFromFile();
    bool IsValidDir(const std::string &path);
    void RestoreBatch(int32_t offset);
    void RestoreAudioBatch(int32_t offset);
    void RestoreExternalBatch(int32_t offset, int32_t maxId, bool isCamera, int32_t type);
    bool ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix, std::string &newPath,
        std::string &relativePath) override;
    void AnalyzeSource() override;
    void AnalyzeGallerySource();
    void AnalyzeExternalSource();
    void HandleCloneBatch(int32_t offset, int32_t maxId);
    void UpdateCloneWithRetry(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, int32_t &number);

private:
    std::shared_ptr<NativeRdb::RdbStore> galleryRdb_;
    std::shared_ptr<NativeRdb::RdbStore> externalRdb_;
    std::shared_ptr<NativeRdb::RdbStore> audioRdb_;
    std::string galleryDbPath_;
    std::string filePath_;
    std::string externalDbPath_;
    std::string appDataPath_;
    std::string galleryAppName_;
    std::string mediaAppName_;
    std::string audioAppName_;
    std::set<std::string> cacheSet_;
    std::unordered_map<std::string, std::string> nickMap_;
    bool sceneCode_;
    std::string audioDbPath_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_UPGRADE_RESTORE_H
