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
#include "media_file_utils.h"
#include "nlohmann/json.hpp"
#include "photos_dao.h"
#include "rdb_helper.h"
#include "result_set.h"
#include "tab_old_photos_restore.h"
#include "geo_knowledge_restore.h"
#include "highlight_restore.h"

namespace OHOS {
namespace Media {
class BaseRestore {
public:
    BaseRestore() = default;
    virtual ~BaseRestore() = default;
    virtual void StartRestore(const std::string &backupRetorePath, const std::string &upgradePath);
    virtual int32_t Init(const std::string &backupRetorePath, const std::string &upgradePath, bool isUpgrade) = 0;
    virtual NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType) = 0;
    virtual std::string GetBackupInfo();
    void StartRestoreEx(const std::string &backupRetorePath, const std::string &upgradePath,
        std::string &restoreExInfo);
    std::string GetRestoreExInfo();
    void ReportPortraitStat(int32_t sceneCode);
    std::string GetProgressInfo();
    virtual void StartBackup();
    std::string restoreInfo_;

protected:
    int32_t Init(void);
    static std::mutex fileInfoMutext_;

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
    void NotifyAlbum();
    virtual std::string CheckInvalidFile(const FileInfo &fileInfo, int32_t errCode);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(int32_t sceneCode, std::vector<FileInfo> &fileInfos,
        int32_t sourceType);
    std::vector<NativeRdb::ValuesBucket> GetCloudInsertValues(int32_t sceneCode, std::vector<FileInfo> &fileInfos,
        int32_t sourceType);
    int32_t CopyFile(const std::string &srcFile, const std::string &dstFile) const;
    void GetAccountValid();
    void GetSourceDeviceInfo();
    int32_t MoveFile(const std::string &srcFile, const std::string &dstFile) const;
    std::shared_ptr<NativeRdb::ResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &selectionArgs = std::vector<std::string>()) const;
    int InsertPhoto(int32_t sceneCode, std::vector<FileInfo> &fileInfos, int32_t sourceType);
    int InsertCloudPhoto(int32_t sceneCode, std::vector<FileInfo> &fileInfos, int32_t sourceType);
    void InsertAudio(int32_t sceneCode, std::vector<FileInfo> &fileInfos);
    void SetValueFromMetaData(FileInfo &info, NativeRdb::ValuesBucket &value);
    int32_t BatchInsertWithRetry(const std::string &tableName, std::vector<NativeRdb::ValuesBucket> &value,
        int64_t &rowNum);
    int32_t MoveDirectory(const std::string &srcDir, const std::string &dstDir, bool deleteOriginalFile = true) const;
    bool IsSameAudioFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
        FileInfo &fileInfo);
    bool HasSameAudioFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
        FileInfo &fileInfo);
    virtual bool HasSameFileForDualClone(FileInfo &fileInfo)
    {
        return false;
    }
    void InsertPhotoMap(std::vector<FileInfo> &fileInfos, int64_t &mapRowNum);
    void BatchQueryPhoto(std::vector<FileInfo> &fileInfos, bool isFull, const NeedQueryMap &needQueryMap);
    void BatchInsertMap(const std::vector<FileInfo> &fileInfos, int64_t &totalRowNum);
    nlohmann::json GetErrorInfoJson();
    nlohmann::json GetCountInfoJson(const std::vector<std::string> &countInfoTypes);
    SubCountInfo GetSubCountInfo(const std::string &type);
    std::unordered_map<std::string, FailedFileInfo> GetFailedFiles(const std::string &type);
    nlohmann::json GetSubCountInfoJson(const std::string &type, const SubCountInfo &subCountInfo, size_t &limit);
    void SetErrorCode(int32_t errorCode);
    void UpdateFailedFileByFileType(int32_t fileType, const FileInfo &fileInfo, int32_t errorCode);
    void UpdateFailedFiles(int32_t fileType, const FileInfo &fileInfo, int32_t errorCode);
    void UpdateFailedFiles(const std::vector<FileInfo> &fileInfos, int32_t errorCode);
    void UpdateDuplicateNumber(int32_t fileType);
    void DeleteMoveFailedData(std::vector<std::string> &moveFailedData);
    void MoveMigrateFile(std::vector<FileInfo> &fileInfos, int32_t &fileMoveCount, int32_t &videoFileMoveCount,
        int32_t sceneCode);
    bool RestoreLcdAndThumbFromCloud(const FileInfo &fileInfo, int32_t type, int32_t sceneCode);
    bool RestoreLcdAndThumbFromKvdb(const FileInfo &fileInfo, int32_t type, int32_t sceneCode);
    int32_t BatchCreateDentryFile(std::vector<FileInfo> &fileInfos, std::vector<std::string> &failCloudIds,
        std::string fileType);
    int32_t SetVisiblePhoto(std::vector<FileInfo> &fileInfos);
    void HandleFailData(std::vector<FileInfo> &fileInfos, std::vector<std::string> &failCloudIds,
        std::string fileType);
    void MoveMigrateCloudFile(std::vector<FileInfo> &fileInfos, int32_t &fileMoveCount, int32_t &videoFileMoveCount,
        int32_t sceneCode);
    void SetParameterForClone();
    void StopParameterForClone(int32_t sceneCode);
    void InsertPhotoRelated(std::vector<FileInfo> &fileInfos, int32_t sourceType);
    void UpdateLcdVisibleColumn(const FileInfo &fileInfo);
    bool NeedBatchQueryPhoto(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap);
    bool NeedBatchQueryPhotoForPhotoMap(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap);
    bool NeedQuery(const FileInfo &fileInfo, const NeedQueryMap &needQueryMap);
    bool NeedQueryByPhotoRelatedType(const FileInfo &fileInfo, PhotoRelatedType photoRelatedType,
        const std::unordered_set<std::string> &needQuerySet);
    int32_t GetUniqueId(int32_t fileType);
    int32_t IsFileValid(FileInfo &fileInfo, const int32_t sceneCode);
    void CreateDir(std::string &dir);
    void RecursiveCreateDir(std::string &relativePath, std::string &suffix);
    SubProcessInfo GetSubProcessInfo(const std::string &type);
    void UpdateProcessedNumber(const std::atomic<int32_t> &processStatus, std::atomic<uint64_t> &processedNumber,
        const std::atomic<uint64_t> &totalNumber);
    nlohmann::json GetSubProcessInfoJson(const std::string &type, const SubProcessInfo &subProcessInfo);
    void UpdateDatabase();
    void GetUpdateTotalCount();
    void GetUpdateAllAlbumsCount();
    void GetUpdateUniqueNumberCount();
    void RestoreThumbnail();
    std::string GetRestoreTotalInfo();
    virtual int32_t GetNoNeedMigrateCount();
    bool ExtraCheckForCloneSameFile(FileInfo &fileInfo, PhotosDao::PhotosRowData &rowData);
    void UpdatePhotosByFileInfoMap(std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb,
        std::vector<FileInfo>& fileInfos);
    int32_t RemoveDentryFileWithConflict(const FileInfo &fileInfo);

protected:
    std::atomic<uint64_t> migrateDatabaseNumber_{0};
    std::atomic<uint64_t> migrateFileNumber_{0};
    std::atomic<uint64_t> migrateVideoFileNumber_{0};
    std::atomic<uint64_t> migrateAudioDatabaseNumber_{0};
    std::atomic<uint64_t> migrateAudioFileNumber_{0};
    std::atomic<uint64_t> totalNumber_{0};
    std::atomic<uint64_t> audioTotalNumber_{0};
    std::atomic<uint64_t> updateTotalNumber_{0};
    std::atomic<uint64_t> thumbnailTotalNumber_{0};
    std::atomic<uint64_t> otherTotalNumber_{0};
    std::atomic<uint64_t> ongoingTotalNumber_{0};
    std::atomic<uint64_t> updateProcessedNumber_{0};
    std::atomic<uint64_t> thumbnailProcessedNumber_{0};
    std::atomic<uint64_t> otherProcessedNumber_{0};
    std::atomic<uint64_t> migratePhotoDuplicateNumber_{0};
    std::atomic<uint64_t> migrateVideoDuplicateNumber_{0};
    std::atomic<uint64_t> migrateAudioDuplicateNumber_{0};
    std::atomic<uint64_t> migratePortraitPhotoNumber_{0};
    std::atomic<uint64_t> migratePortraitFaceNumber_{0};
    std::atomic<uint64_t> migratePortraitAlbumNumber_{0};
    std::atomic<uint64_t> migratePortraitTotalTimeCost_{0};
    std::atomic<uint32_t> imageNumber_{0};
    std::atomic<uint32_t> videoNumber_{0};
    std::atomic<uint64_t> migrateDatabaseMapNumber_{0};
    std::atomic<uint32_t> audioNumber_{0};
    std::atomic<uint64_t> lcdMigrateFileNumber_{0};
    std::atomic<uint64_t> thumbMigrateFileNumber_{0};
    std::atomic<uint64_t> rotateLcdMigrateFileNumber_{0};
    std::atomic<uint64_t> rotateThmMigrateFileNumber_{0};
    std::atomic<int32_t> updateProcessStatus_{ProcessStatus::STOP};
    std::atomic<int32_t> otherProcessStatus_{ProcessStatus::STOP};
    std::string dualDirName_ = "";
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::string backupRestoreDir_;
    std::string upgradeRestoreDir_;
    std::string albumOdid_;
    std::string dualDeviceSoftName_;
    std::mutex imageMutex_;
    std::mutex videoMutex_;
    std::mutex audioMutex_;
    std::mutex failedFilesMutex_;
    int32_t errorCode_{RestoreError::SUCCESS};
    std::string errorInfo_;
    std::unordered_map<std::string, std::unordered_map<std::string, FailedFileInfo>> failedFilesMap_;
    int fileMinSize_ = 0;
    int32_t sceneCode_ = DEFAULT_RESTORE_ID;
    std::unordered_map<std::string, std::string> tagIdMap_;
    std::unordered_map<std::string, int32_t> portraitAlbumIdMap_;
    bool hasLowQualityImage_ = false;
    std::string taskId_ = std::to_string(MediaFileUtils::UTCTimeSeconds());
    TabOldPhotosRestore tabOldPhotosRestore_;
    bool needReportFailed_ = false;
    bool isAccountValid_ = false;
    GeoKnowledgeRestore geoKnowledgeRestore_;
    HighlightRestore highlightRestore_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_BASE_RESTORE_H
