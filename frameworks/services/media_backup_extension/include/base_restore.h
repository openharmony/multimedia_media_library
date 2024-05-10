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

#ifndef OHOS_MEDIA_BASE_RESTORE_H
#define OHOS_MEDIA_BASE_RESTORE_H

#include <atomic>
#include <unordered_map>

#include "backup_const.h"
#include "medialibrary_rdb_transaction.h"
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
        int32_t sourceType) const;
    virtual NativeRdb::ValuesBucket GetAudioInsertValue(const FileInfo &fileInfo, const std::string &newPath) const;

protected:
    int32_t Init(void);
    
    virtual void RestorePhoto(void) = 0;
    virtual void RestoreAudio(void) = 0;
    virtual void HandleRestData(void) = 0;

    virtual bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) = 0;
    virtual bool ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) = 0;
    virtual void AnalyzeSource() = 0;
    virtual bool ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix, std::string &newPath,
        std::string &relativePath);
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

protected:
    std::atomic<uint64_t> migrateDatabaseNumber_;
    std::atomic<uint64_t> migrateFileNumber_;
    std::atomic<uint64_t> migrateAudioDatabaseNumber_;
    std::atomic<uint64_t> migrateAudioFileNumber_;
    std::atomic<uint32_t> imageNumber_;
    std::atomic<uint32_t> videoNumber_;
    std::atomic<uint32_t> audioNumber_;
    std::string dualDirName_ = "";
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_BASE_RESTORE_H
