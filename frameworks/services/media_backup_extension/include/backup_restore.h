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

#ifndef OHOS_MEDIA_BACKUP_RESTORE_H_
#define OHOS_MEDIA_BACKUP_RESTORE_H_

#include "backup_defines.h"
#include "rdb_helper.h"
#include "result_set.h"

namespace OHOS {
namespace Media {
class BackupRestore {
public:
    static BackupRestore &GetInstance(void);
    void StartRestore(std::vector<FileInfo> &fileInfos);
    void MoveFiles(const std::string &originPath) const;

private:
    BackupRestore() = default;
    virtual ~BackupRestore() = default;
    int32_t InitRdb(void);
    int32_t GetFileId(int32_t mediaType) const;
    int32_t ExecuteSql(const std::string &sql) const;
    std::shared_ptr<NativeRdb::ResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &selectionArgs = std::vector<std::string>()) const;
    void SetUniqueNumber(std::vector<int32_t> &value) const;
    int32_t CreateAssetBucket(int32_t fileId, int32_t &bucketNum) const;
    int32_t CreateAssetRealName(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &name) const;
    int32_t CreateAssetPathById(int32_t fileId, FileInfo &fileInfo, std::string &cloudPath,
        std::string &localPath) const;
    int32_t InsertSql(FileInfo &fileInfo, std::string &newPath) const;
    int32_t UpdaterAlbum(const std::string &notifyUri, const std::string &albumSubtype) const;
    int32_t QueryMaxId(void) const;
    void NotifyPhotoAdd(const std::string &path, const FileInfo &fileInfo) const;

private:
    std::shared_ptr<NativeRdb::RdbStore> rdb_;
};

class RdbCallback : public NativeRdb::RdbOpenCallback {
public:
    virtual int32_t OnCreate(NativeRdb::RdbStore &r) override
    {
        return 0;
    }

    virtual int32_t OnUpgrade(NativeRdb::RdbStore &r, int32_t oldVersion,
        int32_t newVersion) override
    {
        return 0;
    }
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_BACKUP_RESTORE_H_
