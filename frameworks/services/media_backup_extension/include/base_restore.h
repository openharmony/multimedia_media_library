/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_BASE_RESTORE_H
#define OHOS_MEDIA_BASE_RESTORE_H

#include <atomic>
#include <mutex>
#include <unordered_map>

#include "backup_const.h"
#include "medialibrary_rdb_transaction.h"
#include "nlohmann/json.hpp"
#include "rdb_helper.h"
#include "result_set.h"

namespace OHOS {
namespace Media {
class BaseRestore {
public:
    BaseRestore() = default;
    virtual ~BaseRestore() = default;
    virtual void StartRestore(const std::string &backupRetorePath, const std::string &upgradePath);
    virtual int32_t Init(const std::string &backupRetorePath, const std::string &upgradePath, bool isUpgrade) = 0;
    virtual int32_t QueryTotalNumber(void) = 0;
    virtual std::vector<FileInfo> QueryFileInfos(int32_t offset) = 0;
    virtual NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType) const = 0;
    virtual NativeRdb::ValuesBucket GetAudioInsertValue(const FileInfo &fileInfo, const std::string &newPath) const;
    virtual std::string GetBackupInfo();
    void StartRestoreEx(const std::string &backupRetorePath, const std::string &upgradePath,
        std::string &restoreExInfo);
    std::string GetRestoreExInfo();
    void ReportPortraitStat(int32_t sceneCode);

protected:
    int32_t Init(void);
    
    virtual void RestorePhoto(void) = 0;
    virtual void RestoreAudio(void) = 0;
    virtual void HandleRestData(void) = 0;

    virtual bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
        std::string dbName = "") = 0;
    virtual bool ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) = 0;
    virtual void AnalyzeSource() = 0;
    virtual bool ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix, std::string &newPath,
        std::string &relativePath);
    virtual bool NeedBatchQueryPhotoForPortrait(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap);
    virtual void InsertFaceAnalysisData(const std::vector<FileInfo> &fileInfos, const NeedQueryMap &needQueryMap,
        int64_t &faceRowNum, int64_t &mapRowNum, int64_t &photoNum);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(int32_t sceneCode, std::vector<FileInfo> &fileInfos,
        int32_t sourceType);
    std::vector<NativeRdb::ValuesBucket> GetAudioInsertValues(int32_t sceneCode, std::vector<FileInfo> &fileInfos);
    int32_t MoveFile(const std::string &srcFile, const std::string &dstFile) const;
    std::shared_ptr<NativeRdb::ResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &selectionArgs = std::vector<std::string>()) const;
    void InsertPhoto(int32_t sceneCode, std::vector<FileInfo> &fileInfos, int32_t sourceType);
    void InsertAudio(int32_t sceneCode, std::vector<FileInfo> &fileInfos);
    void SetValueFromMetaData(FileInfo &info, NativeRdb::ValuesBucket &value);
    void SetAudioValueFromMetaData(FileInfo &info, NativeRdb::ValuesBucket &value);
    int32_t BatchInsertWithRetry(const std::string &tableName, std::vector<NativeRdb::ValuesBucket> &value,
        int64_t &rowNum);
    int32_t MoveDirectory(const std::string &srcDir, const std::string &dstDir) const;
    bool IsSameFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
        FileInfo &fileInfo);
    bool HasSameFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
        FileInfo &fileInfo);
    bool HasSameFileForDualClone(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
        FileInfo &fileInfo);
    void InsertPhotoMap(std::vector<FileInfo> &fileInfos, int64_t &mapRowNum);
    void BatchQueryPhoto(std::vector<FileInfo> &fileInfos, bool isFull, const NeedQueryMap &needQueryMap);
    void BatchInsertMap(const std::vector<FileInfo> &fileInfos, int64_t &totalRowNum);
    nlohmann::json GetErrorInfoJson();
    nlohmann::json GetCountInfoJson(const std::vector<std::string> &countInfoTypes);
    SubCountInfo GetSubCountInfo(const std::string &type);
    std::unordered_map<std::string, int32_t> GetFailedFiles(const std::string &type);
    nlohmann::json GetSubCountInfoJson(const std::string &type, const SubCountInfo &subCountInfo);
    void SetErrorCode(int32_t errorCode);
    void UpdateFailedFileByFileType(int32_t fileType, const std::string &filePath, int32_t errorCode);
    void UpdateFailedFiles(int32_t fileType, const std::string &filePath, int32_t errorCode);
    void UpdateFailedFiles(const std::vector<FileInfo> &fileInfos, int32_t errorCode);
    void UpdateDuplicateNumber(int32_t fileType);
    void GetMaxFileId(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    void DeleteMoveFailedData(std::vector<std::string> &moveFailedData);
    void MoveMigrateFile(std::vector<FileInfo> &fileInfos, int32_t &fileMoveCount, int32_t &videoFileMoveCount,
        int32_t sceneCode);
    void SetParameterForClone();
    void StopParameterForClone(int32_t sceneCode);
    std::string GetSameFileQuerySql(const FileInfo &fileInfo);
    void InsertPhotoRelated(std::vector<FileInfo> &fileInfos, int32_t sourceType);
    bool NeedBatchQueryPhoto(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap);
    bool NeedBatchQueryPhotoForPhotoMap(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap);
    bool NeedQuery(const FileInfo &fileInfo, const NeedQueryMap &needQueryMap);
    bool NeedQueryByPhotoRelatedType(const FileInfo &fileInfo, PhotoRelatedType photoRelatedType,
        const std::unordered_set<std::string> &needQuerySet);
    void UpdateFaceAnalysisStatus();
    int32_t GetUniqueId(int32_t fileType);

protected:
    std::atomic<uint64_t> migrateDatabaseNumber_;
    std::atomic<uint64_t> migrateFileNumber_;
    std::atomic<uint64_t> migrateVideoFileNumber_;
    std::atomic<uint64_t> migrateAudioDatabaseNumber_;
    std::atomic<uint64_t> migrateAudioFileNumber_;
    std::atomic<uint64_t> migratePhotoDuplicateNumber_{0};
    std::atomic<uint64_t> migrateVideoDuplicateNumber_{0};
    std::atomic<uint64_t> migrateAudioDuplicateNumber_{0};
    std::atomic<uint64_t> migratePortraitPhotoNumber_{0};
    std::atomic<uint64_t> migratePortraitFaceNumber_{0};
    std::atomic<uint64_t> migratePortraitTotalTimeCost_{0};
    std::atomic<uint32_t> imageNumber_;
    std::atomic<uint32_t> videoNumber_;
    std::atomic<uint64_t> migrateDatabaseMapNumber_{0};
    std::atomic<uint32_t> audioNumber_;
    std::string dualDirName_ = "";
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::string backupRestoreDir_;
    std::mutex imageMutex_;
    std::mutex videoMutex_;
    std::mutex audioMutex_;
    std::mutex failedFilesMutex_;
    int32_t errorCode_{RestoreError::SUCCESS};
    std::string errorInfo_;
    std::unordered_map<std::string, std::unordered_map<std::string, int32_t>> failedFilesMap_;
    int fileMinSize_ = 0;
    int maxFileId_ = 0;
    int maxCount_ = 0;
    int32_t sceneCode_ = -1;
    std::unordered_map<std::string, std::string> tagIdMap_;
    std::unordered_map<std::string, std::string> groupTagMap_;
    std::unordered_map<std::string, int32_t> portraitAlbumIdMap_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_BASE_RESTORE_H
