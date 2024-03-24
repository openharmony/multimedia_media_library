/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_RDBSTORE_H
#define OHOS_MEDIALIBRARY_RDBSTORE_H

#include <memory>

#include "medialibrary_async_worker.h"
#include "medialibrary_sync_operation.h"
#include "medialibrary_unistore.h"
#include "timer.h"
#include "value_object.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
#ifdef DISTRIBUTED
class MediaLibraryRdbStoreObserver;
#endif

class MediaLibraryDataCallBack;

class MediaLibraryRdbStore final : public MediaLibraryUnistore {
public:
    EXPORT explicit MediaLibraryRdbStore(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context);
    EXPORT virtual ~MediaLibraryRdbStore();

    EXPORT virtual int32_t Init() override;
    EXPORT virtual void Stop() override;

    EXPORT virtual int32_t Insert(MediaLibraryCommand &cmd, int64_t &rowId) override;
    EXPORT virtual int32_t Delete(MediaLibraryCommand &cmd, int32_t &deletedRows) override;
    EXPORT virtual int32_t Update(MediaLibraryCommand &cmd, int32_t &changedRows) override;
    EXPORT std::shared_ptr<NativeRdb::ResultSet> Query(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns) override;

    EXPORT int32_t ExecuteSql(const std::string &sql) override;
    EXPORT std::shared_ptr<NativeRdb::ResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &selectionArgs = std::vector<std::string>()) override;

    EXPORT std::shared_ptr<NativeRdb::RdbStore> GetRaw() const;

    EXPORT static void BuildValuesSql(const NativeRdb::ValuesBucket &values,
        std::vector<NativeRdb::ValueObject> &bindArgs, std::string &sql);
    EXPORT static void BuildQuerySql(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, std::vector<NativeRdb::ValueObject> &bindArgs, std::string &sql);
    EXPORT static int32_t ExecuteForLastInsertedRowId(const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &bindArgs);
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> Query(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns);
    EXPORT static int32_t Delete(const NativeRdb::AbsRdbPredicates &predicates);
    EXPORT static int32_t Update(NativeRdb::ValuesBucket &values, const NativeRdb::AbsRdbPredicates &predicates);
    static void ReplacePredicatesUriToId(NativeRdb::AbsRdbPredicates &predicates);
    static std::shared_ptr<NativeRdb::ResultSet> GetIndexOfUri(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, const std::string &id);
    static int32_t GetInt(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::string &column);
    static std::string GetString(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::string &column);
    static void ResetAnalysisTables();
    static void ResetSearchTables();
    EXPORT static int32_t UpdateLastVisitTime(MediaLibraryCommand &cmd, int32_t &changedRows);
    EXPORT static bool HasColumnInTable(RdbStore &store, const std::string &columnName, const std::string &tableName);

private:
    EXPORT static const std::string CloudSyncTriggerFunc(const std::vector<std::string> &args);
    EXPORT static const std::string IsCallerSelfFunc(const std::vector<std::string> &args);
    static std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
#ifdef DISTRIBUTED
    std::shared_ptr<MediaLibraryRdbStoreObserver> rdbStoreObs_;
#endif
    std::string bundleName_ {BUNDLE_NAME};
    NativeRdb::RdbStoreConfig config_ {""};
};

class MediaLibraryDataCallBack : public NativeRdb::RdbOpenCallback {
public:
    struct DirValuesBucket {
        int32_t directoryType;
        std::string dirValues;
        std::string typeValues;
        std::string extensionValues;
    };

    struct SmartAlbumValuesBucket {
        int32_t albumId;
        std::string albumName;
        int32_t albumType;
    };

    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;

private:
    int32_t PrepareDir(NativeRdb::RdbStore &store);
    int32_t PrepareSmartAlbum(NativeRdb::RdbStore &store);

    int32_t InsertDirValues(const DirValuesBucket &dirValuesBucket, NativeRdb::RdbStore &store);
    int32_t InsertSmartAlbumValues(const SmartAlbumValuesBucket &smartAlbum, NativeRdb::RdbStore &store);
};

class DeleteFilesTask : public AsyncTaskData {
public:
    DeleteFilesTask(const std::vector<std::string> &ids, const std::vector<std::string> &paths,
        const std::vector<std::string> &notifyUris, const std::vector<std::string> &dateAddeds,
        const std::string &table, int32_t deleteRows, std::string bundleName) : ids_(ids), paths_(paths),
        notifyUris_(notifyUris), dateAddeds_(dateAddeds), table_(table), deleteRows_(deleteRows),
        bundleName_(bundleName) {}
    virtual ~DeleteFilesTask() override = default;

    std::vector<std::string> ids_;
    std::vector<std::string> paths_;
    std::vector<std::string> notifyUris_;
    std::vector<std::string> dateAddeds_;
    std::string table_;
    int32_t deleteRows_;
    std::string bundleName_;
};

#ifdef DISTRIBUTED
class MediaLibraryRdbStoreObserver : public NativeRdb::RdbStore::RdbStoreObserver {
public:
    explicit MediaLibraryRdbStoreObserver(const std::string &bundleName);
    virtual ~MediaLibraryRdbStoreObserver();
    void OnChange(const std::vector<std::string> &devices) override;

private:
    void NotifyDeviceChange();
    static constexpr int NOTIFY_TIME_INTERVAL = 10000;
    std::unique_ptr<OHOS::Utils::Timer> timer_;
    uint32_t timerId_ {0};
    std::string bundleName_;
    bool isNotifyDeviceChange_;
};
#endif
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_RDBSTORE_OPERATIONS_H
