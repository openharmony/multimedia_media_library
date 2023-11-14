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

#include "backup_const.h"
#include "rdb_helper.h"
#include "result_set.h"

namespace OHOS {
namespace Media {
class BaseRestore {
public:
    BaseRestore() = default;
    virtual ~BaseRestore() = default;
    void StartRestore(const std::string &orignPath, const std::string &updatePath);
    virtual int32_t Init(const std::string &orignPath, const std::string &updatePath, bool isUpdate) = 0;
    virtual int32_t QueryTotalNumber(void) = 0;
    virtual std::vector<FileInfo> QueryFileInfos(int32_t offset) = 0;
    virtual NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType) const;

protected:
    int32_t Init(void);
    
    virtual void RestorePhoto(void) = 0;
    virtual void HandleRestData(void) = 0;

    virtual bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) = 0;
    static std::string CloudSyncTriggerFunc(const std::vector<std::string> &args);
    static std::string IsCallerSelfFunc(const std::vector<std::string> &args);
    int32_t MoveFile(const std::string &srcFile, const std::string &dstFile) const;
    std::shared_ptr<NativeRdb::ResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &selectionArgs = std::vector<std::string>()) const;
    void InsertPhoto(int32_t sceneCode, const std::vector<FileInfo> &fileInfos, int32_t sourceType) const;
    bool ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix,
        std::string &newPath, std::string &relativePath);
    bool IsSameFile(const FileInfo &fileInfo) const;

private:
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
};

class RdbCallback : public NativeRdb::RdbOpenCallback {
public:
    virtual int32_t OnCreate(NativeRdb::RdbStore &rdb) override
    {
        return 0;
    }

    virtual int32_t OnUpgrade(NativeRdb::RdbStore &rdb, int32_t oldVersion,
        int32_t newVersion) override
    {
        return 0;
    }
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_BASE_RESTORE_H
