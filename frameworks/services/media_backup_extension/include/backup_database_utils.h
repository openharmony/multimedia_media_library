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

#ifndef BACKUP_DATABASE_UTILS_H
#define BACKUP_DATABASE_UTILS_H

#include <string>

#include "rdb_helper.h"
#include "result_set.h"

namespace OHOS {
namespace Media {
class BackupDatabaseUtils {
public:
    static int32_t InitDb(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &dbName,
        const std::string &dbPath, const std::string &bundleName, bool isMediaLibary);
    static int32_t QueryInt(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &sql,
        const std::string &column);
    static int32_t Update(std::shared_ptr<NativeRdb::RdbStore> &rdbStore, int32_t &changeRows,
        NativeRdb::ValuesBucket &valuesBucket, std::unique_ptr<NativeRdb::AbsRdbPredicates> &predicates);
    static int32_t InitGarbageAlbum(std::shared_ptr<NativeRdb::RdbStore> rdbStore, std::set<std::string> &cacheSet,
        std::unordered_map<std::string, std::string> &nickMap);
    static int32_t QueryGalleryAllCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryImageCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryVideoCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryHiddenCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryTrashedCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryCloneCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGallerySDCardCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryScreenVideoCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryGalleryCloudCount(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    static int32_t QueryExternalImageCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb);
    static int32_t QueryExternalVideoCount(std::shared_ptr<NativeRdb::RdbStore> externalRdb);
    static std::shared_ptr<NativeRdb::ResultSet> GetQueryResultSet(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::string &querySql);
    static std::unordered_map<std::string, std::string> GetColumnInfoMap(
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName);

private:
    static std::string CloudSyncTriggerFunc(const std::vector<std::string> &args);
    static std::string IsCallerSelfFunc(const std::vector<std::string> &args);
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

#endif  // BACKUP_DATABASE_UTILS_H