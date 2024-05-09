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

#ifndef OHOS_MEDIA_CLONE_RESTORE_H
#define OHOS_MEDIA_CLONE_RESTORE_H

#include "base_restore.h"

namespace OHOS {
namespace Media {
class CloneRestore : public BaseRestore {
public:
    CloneRestore() = default;
    virtual ~CloneRestore() = default;
    // upgradePath is useless now
    void StartRestore(const std::string &backupRestorePath, const std::string &upgradePath) override;
    int32_t Init(const std::string &backupRestoreDir, const std::string &upgradeFilePath, bool isUpgrade) override;
    NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType) const override;

private:
    void RestorePhoto(void) override;
    void HandleRestData(void) override;
    int32_t QueryTotalNumber(void) override;
    std::vector<FileInfo> QueryFileInfos(int32_t offset) override;
    bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &fileInfo) override;
    bool ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) override;
    void AnalyzeSource() override;
    void RestoreAlbum(void);
    void RestoreAudio(void) override;
    void InsertPhoto(std::vector<FileInfo> &fileInfos);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(int32_t sceneCode, std::vector<FileInfo> &fileInfos,
        int32_t sourceType);
    int32_t MoveAsset(FileInfo &fileInfo);
    bool IsFilePathExist(const std::string &filePath) const;
    int32_t QueryTotalNumber(const std::string &tableName);
    std::vector<AlbumInfo> QueryAlbumInfos(const std::string &tableName, int32_t offset);
    bool ParseAlbumResultSet(const std::string &tableName, const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        AlbumInfo &albumInfo);
    bool PrepareCommonColumnInfoMap(const std::string &tableName,
        const std::unordered_map<std::string, std::string> &srcColumnInfoMap,
        const std::unordered_map<std::string, std::string> &dstColumnInfoMap);
    bool HasSameColumn(const std::unordered_map<std::string, std::string> &columnInfoMap, const std::string &columnName,
        const std::string &columnType);
    void GetValFromResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        std::unordered_map<std::string, std::variant<int32_t, int64_t, double, std::string>> &valMap,
        const std::string &columnName, const std::string &columnType);
    void PrepareCommonColumnVal(NativeRdb::ValuesBucket &values, const std::string &columnName,
        const std::variant<int32_t, int64_t, double, std::string> &columnVal,
        const std::unordered_map<std::string, std::string> &commonColumnInfoMap) const;
    void GetQueryWhereClause(const std::string &tableName,
        const std::unordered_map<std::string, std::string> &columnInfoMap);
    void QueryTableAlbumSetMap(FileInfo &fileInfo);
    void BatchQueryPhoto(std::vector<FileInfo> &fileInfos);
    void BatchNotifyPhoto(const std::vector<FileInfo> &fileInfos);
    void InsertAlbum(std::vector<AlbumInfo> &albumInfos, const std::string &tableName);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(std::vector<AlbumInfo> &albumInfos,
        const std::string &tableName);
    bool HasSameAlbum(const AlbumInfo &albumInfo, const std::string &tableName) const;
    void BatchQueryAlbum(std::vector<AlbumInfo> &albumInfos, const std::string &tableName);
    void BatchInsertMap(std::vector<FileInfo> &fileInfos, int64_t &totalRowNum);
    NativeRdb::ValuesBucket GetInsertValue(const MapInfo &mapInfo) const;
    NativeRdb::ValuesBucket GetInsertValue(const AlbumInfo &albumInfo, const std::string &tableName) const;
    void CheckTableColumnStatus(const std::vector<std::vector<std::string>> &cloneTableList);
    bool HasColumns(const std::unordered_map<std::string, std::string> &columnInfoMap,
        const std::unordered_set<std::string> &columnSet);
    bool HasColumn(const std::unordered_map<std::string, std::string> &columnInfoMap, const std::string &columnName);
    void GetAlbumExtraQueryWhereClause(const std::string &tableName);
    bool IsReadyForRestore(const std::string &tableName);
    void UpdateAlbumToNotifySet(const std::string &tableName, const std::unordered_set<int32_t> &albumSet);
    void NotifyAlbum();
    void PrepareEditTimeVal(NativeRdb::ValuesBucket &values, int64_t editTime, const FileInfo &fileInfo,
        const std::unordered_map<std::string, std::string> &commonColumnInfoMap) const;
    void RestoreGallery();
    bool PrepareCloudPath(const std::string &tableName, FileInfo &fileInfo);
    void RestoreMusic();
    std::vector<FileInfo> QueryFileInfos(const std::string &tableName, int32_t offset);
    bool ParseResultSet(const std::string &tableName, const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        FileInfo &fileInfo);
    void InsertAudio(std::vector<FileInfo> &fileInfos);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(const std::string &tableName, int32_t sceneCode,
        std::vector<FileInfo> &fileInfos, int32_t sourceType, const std::unordered_set<int32_t> &excludedFileIdSet);
    NativeRdb::ValuesBucket GetInsertValue(const std::string &tableName, const FileInfo &fileInfo,
        const std::string &newPath, int32_t sourceType) const;

private:
    std::atomic<uint64_t> migrateDatabaseAlbumNumber_{0};
    std::atomic<uint64_t> migrateDatabaseMapNumber_{0};
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb_;
    std::string filePath_;
    std::string dbPath_;
    std::unordered_map<std::string, bool> tableColumnStatusMap_;
    std::unordered_map<std::string, std::string> tableQueryWhereClauseMap_;
    std::unordered_map<std::string, std::unordered_map<int32_t, int32_t>> tableAlbumIdMap_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> tableCommonColumnInfoMap_;
    std::unordered_set<std::string> albumToNotifySet_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_CLONE_RESTORE_H
