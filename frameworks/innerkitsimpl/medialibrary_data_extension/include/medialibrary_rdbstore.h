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
#include <mutex>

#include "medialibrary_async_worker.h"
#include "medialibrary_unistore.h"
#include "timer.h"
#include "value_object.h"
#include "medialibrary_rdb_transaction.h"

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
    EXPORT int32_t Init(const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback);
    EXPORT virtual void Stop() override;
    EXPORT static bool CheckRdbStore();
    EXPORT virtual int32_t Insert(MediaLibraryCommand &cmd, int64_t &rowId) override;
    EXPORT virtual int32_t BatchInsert(MediaLibraryCommand &cmd, int64_t& outInsertNum,
        const std::vector<NativeRdb::ValuesBucket>& values) override;
    EXPORT virtual int32_t Delete(MediaLibraryCommand &cmd, int32_t &deletedRows) override;
    EXPORT virtual int32_t Update(MediaLibraryCommand &cmd, int32_t &changedRows) override;
    EXPORT std::shared_ptr<NativeRdb::ResultSet> Query(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns) override;
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> Query(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns);

    EXPORT int32_t ExecuteSql(const std::string &sql) override;
    EXPORT std::shared_ptr<NativeRdb::ResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &selectionArgs = std::vector<std::string>()) override;

    EXPORT static int32_t BatchInsert(int64_t &outRowId, const std::string &table,
        const std::vector<NativeRdb::ValuesBucket> &values);
    EXPORT static void BuildValuesSql(const NativeRdb::ValuesBucket &values,
        std::vector<NativeRdb::ValueObject> &bindArgs, std::string &sql);
    EXPORT static void BuildQuerySql(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, std::vector<NativeRdb::ValueObject> &bindArgs, std::string &sql);
    EXPORT static int32_t ExecuteForLastInsertedRowId(const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &bindArgs);
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> QueryWithFilter(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns);
    EXPORT static int32_t Delete(const NativeRdb::AbsRdbPredicates &predicates);
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> StepQueryWithoutCheck(
        const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> &columns);
    EXPORT static int32_t UpdateWithDateTime(NativeRdb::ValuesBucket &values,
        const NativeRdb::AbsRdbPredicates &predicates);
    static void ReplacePredicatesUriToId(NativeRdb::AbsRdbPredicates &predicates);
    static std::shared_ptr<NativeRdb::ResultSet> GetIndexOfUri(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, const std::string &id);
    static std::shared_ptr<NativeRdb::ResultSet> GetIndexOfUriForPhotos(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, const std::string &id);
    static int32_t GetInt(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::string &column);
    static std::string GetString(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::string &column);
    EXPORT static bool ResetAnalysisTables();
    EXPORT static bool ResetSearchTables();
    EXPORT static int32_t UpdateLastVisitTime(const std::string &id);
    EXPORT static bool HasColumnInTable(NativeRdb::RdbStore &store, const std::string &columnName,
        const std::string &tableName);
    static void AddColumnIfNotExists(NativeRdb::RdbStore &store, const std::string &columnName,
        const std::string &columnType, const std::string &tableName);
    EXPORT static int32_t QueryPragma(const std::string &key, int64_t &value);
    EXPORT static void SetOldVersion(int32_t oldVersion);
    EXPORT static int32_t GetOldVersion();
    EXPORT static void CreateBurstIndex(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void UpdateBurstDirty(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void UpdateReadyOnThumbnailUpgrade(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void UpdateDateTakenToMillionSecond(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void UpdateDateTakenIndex(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void UpdateDateTakenAndDetalTime(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void ClearAudios(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void UpdateIndexForCover(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void UpdateLcdStatusNotUploaded(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void AddReadyCountIndex(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void RevertFixDateAddedIndex(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void AddAlbumIndex(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void AddCloudEnhancementAlbumIndex(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void AddPhotoDateAddedIndex(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static void UpdateLatitudeAndLongitudeDefaultNull(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static int32_t ReconstructMediaLibraryStorageFormat(const std::shared_ptr<MediaLibraryRdbStore> store);
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> QueryEditDataExists(
        const NativeRdb::AbsRdbPredicates &predicates);
    EXPORT int Update(int &changedRows, const std::string &table, const NativeRdb::ValuesBucket &row,
        const std::string &whereClause, const std::vector<std::string> &args);
    EXPORT std::string ObtainDistributedTableName(const std::string &device, const std::string &table, int &errCode);
    EXPORT int Backup(const std::string &databasePath, const std::vector<uint8_t> &encryptKey = {});
    EXPORT int Sync(const DistributedRdb::SyncOption &option, const NativeRdb::AbsRdbPredicates &predicate,
        const DistributedRdb::AsyncBrief &async);
    EXPORT std::shared_ptr<NativeRdb::ResultSet> QueryByStep(const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &args = {});
    EXPORT std::shared_ptr<NativeRdb::ResultSet> QueryByStep(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns = {});
    EXPORT int Update(int &changedRows, const NativeRdb::ValuesBucket &row,
        const NativeRdb::AbsRdbPredicates &predicates);
    EXPORT int Insert(int64_t &outRowId, const std::string &table, const NativeRdb::ValuesBucket &row);
    EXPORT int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &args);
    EXPORT int Delete(int &deletedRows, const NativeRdb::AbsRdbPredicates &predicates);
    EXPORT std::shared_ptr<NativeRdb::AbsSharedResultSet> QuerySql(const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &args);
    EXPORT int InterruptBackup();
    EXPORT bool IsSlaveDiffFromMaster() const;
    EXPORT int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey = {});
    static int32_t DoDeleteFromPredicates(const NativeRdb::AbsRdbPredicates &predicates, int32_t &deletedRows);
    int32_t DataCallBackOnCreate();
    EXPORT int32_t ExecuteSql(std::string &sql, const std::vector<NativeRdb::ValueObject> &args)
    {
        return MediaLibraryRdbStore::GetRaw()->ExecuteSql(sql, args);
    }
    static void WalCheckPoint();
    EXPORT int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &args = {});
    static void UpdateMediaTypeAndThumbnailReadyIdx(const std::shared_ptr<MediaLibraryRdbStore> rdbStore);

private:
    EXPORT static std::shared_ptr<NativeRdb::RdbStore> GetRaw();
    EXPORT static const std::string CloudSyncTriggerFunc(const std::vector<std::string> &args);
    EXPORT static const std::string IsCallerSelfFunc(const std::vector<std::string> &args);
    EXPORT static const std::string RegexReplaceFunc(const std::vector<std::string> &args);
    friend class TransactionOperations;
    static std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    EXPORT static const std::string BeginGenerateHighlightThumbnail(const std::vector<std::string>& args);
    EXPORT static const std::string PhotoAlbumNotifyFunc(const std::vector<std::string>& args);
    static std::mutex reconstructLock_;
    static std::mutex walCheckPointMutex_;
#ifdef DISTRIBUTED
    std::shared_ptr<MediaLibraryRdbStoreObserver> rdbStoreObs_;
#endif
    std::string bundleName_ {BUNDLE_NAME};
    NativeRdb::RdbStoreConfig config_ {""};
};

class CompensateAlbumIdData : public AsyncTaskData {
public:
    CompensateAlbumIdData(const std::shared_ptr<MediaLibraryRdbStore> store, std::mutex &lock)
        : upgradeStore_(store), lock_(lock){};
    virtual ~CompensateAlbumIdData() override = default;
    std::shared_ptr<MediaLibraryRdbStore> upgradeStore_;
    std::mutex &lock_;
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
        const std::vector<std::string> &notifyUris, const std::vector<std::string> &dateTakens,
        const std::vector<int32_t> &subTypes, const std::string &table, int32_t deleteRows, std::string bundleName)
        : ids_(ids), paths_(paths), notifyUris_(notifyUris), dateTakens_(dateTakens), subTypes_(subTypes),
        table_(table), deleteRows_(deleteRows), bundleName_(bundleName) {}
    virtual ~DeleteFilesTask() override = default;

    std::vector<std::string> ids_;
    std::vector<std::string> paths_;
    std::vector<std::string> notifyUris_;
    std::vector<std::string> dateTakens_;
    std::vector<int32_t> subTypes_;
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
