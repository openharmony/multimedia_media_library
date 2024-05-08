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
#define MLOG_TAG "RdbStore"

#include "medialibrary_rdbstore.h"

#include <mutex>

#include "cloud_sync_helper.h"
#include "ipc_skeleton.h"
#include "location_column.h"
#include "media_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_remote_thumbnail_column.h"
#include "media_smart_album_column.h"
#ifdef DISTRIBUTED
#include "medialibrary_device.h"
#endif
#include "medialibrary_business_record_column.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_tracer.h"
#include "media_scanner.h"
#include "media_scanner_manager.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "post_event_utils.h"
#include "rdb_sql_utils.h"
#include "result_set_utils.h"
#include "source_album.h"
#include "vision_column.h"
#include "form_map.h"
#include "search_column.h"
#include "story_db_sqls.h"
#include "dfx_const.h"
#include "dfx_timer.h"

using namespace std;
using namespace OHOS::NativeRdb;
namespace OHOS::Media {
shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::rdbStore_;
struct UniqueMemberValuesBucket {
    std::string assetMediaType;
    int32_t startNumber;
};


struct ShootingModeValueBucket {
    int32_t albumType;
    int32_t albumSubType;
    std::string albumName;
};

const std::string MediaLibraryRdbStore::CloudSyncTriggerFunc(const std::vector<std::string> &args)
{
    CloudSyncHelper::GetInstance()->StartSync();
    return "";
}

const std::string MediaLibraryRdbStore::IsCallerSelfFunc(const std::vector<std::string> &args)
{
    return "true";
}

MediaLibraryRdbStore::MediaLibraryRdbStore(const shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return;
    }
    string databaseDir = context->GetDatabaseDir();
    string name = MEDIA_DATA_ABILITY_DB_NAME;
    int32_t errCode = 0;
    string realPath = RdbSqlUtils::GetDefaultDatabasePath(databaseDir, name, errCode);
    config_.SetName(move(name));
    config_.SetPath(move(realPath));
    config_.SetBundleName(context->GetBundleName());
    config_.SetArea(context->GetArea());
    config_.SetSecurityLevel(SecurityLevel::S3);
    config_.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config_.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);
}

int32_t MediaLibraryRdbStore::Init()
{
    MEDIA_INFO_LOG("Init rdb store");
    if (rdbStore_ != nullptr) {
        return E_OK;
    }

    int32_t errCode = 0;
    MediaLibraryDataCallBack rdbDataCallBack;
    rdbStore_ = RdbHelper::GetRdbStore(config_, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("GetRdbStore is failed ");
        return E_ERR;
    }
    MEDIA_INFO_LOG("SUCCESS");
    return E_OK;
}

MediaLibraryRdbStore::~MediaLibraryRdbStore() = default;

void MediaLibraryRdbStore::Stop()
{
    if (rdbStore_ == nullptr) {
        return;
    }

    rdbStore_ = nullptr;
}

bool g_upgradeErr = false;
void UpdateFail(const string &errFile, const int &errLine)
{
    g_upgradeErr = true;
    VariantMap map = {{KEY_ERR_FILE, errFile}, {KEY_ERR_LINE, errLine}};
    PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_UPGRADE_ERR, map);
}

static int32_t ExecSqls(const vector<string> &sqls, RdbStore &store)
{
    int32_t err = NativeRdb::E_OK;
    for (const auto &sql : sqls) {
        err = store.ExecuteSql(sql);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Failed to exec: %{private}s", sql.c_str());
            /* try update as much as possible */
            UpdateFail(__FILE__, __LINE__);
            continue;
        }
    }
    return NativeRdb::E_OK;
}

#ifdef DISTRIBUTED
void GetAllNetworkId(vector<string> &networkIds)
{
    vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
    MediaLibraryDevice::GetInstance()->GetAllNetworkId(deviceList);
    for (auto& deviceInfo : deviceList) {
        networkIds.push_back(deviceInfo.networkId);
    }
}
#endif

int32_t MediaLibraryRdbStore::Insert(MediaLibraryCommand &cmd, int64_t &rowId)
{
    DfxTimer dfxTimer(DfxType::RDB_INSERT, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::Insert");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->Insert(rowId, cmd.GetTableName(), cmd.GetValueBucket());
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Insert failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }

    MEDIA_DEBUG_LOG("rdbStore_->Insert end, rowId = %d, ret = %{public}d", (int)rowId, ret);
    return ret;
}

static int32_t DoDeleteFromPredicates(NativeRdb::RdbStore &rdb, const AbsRdbPredicates &predicates,
    int32_t &deletedRows)
{
    DfxTimer dfxTimer(DfxType::RDB_DELETE, INVALID_DFX, RDB_TIME_OUT, false);
    int32_t ret = NativeRdb::E_ERROR;
    string tableName = predicates.GetTableName();
    ValuesBucket valuesBucket;
    if (tableName == MEDIALIBRARY_TABLE || tableName == PhotoColumn::PHOTOS_TABLE) {
        valuesBucket.PutInt(MEDIA_DATA_DB_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        valuesBucket.PutInt(MEDIA_DATA_DB_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_UPLOAD));
        valuesBucket.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        ret = rdb.Update(deletedRows, tableName, valuesBucket, predicates.GetWhereClause(),
            predicates.GetWhereArgs());
    } else if (tableName == PhotoAlbumColumns::TABLE) {
        valuesBucket.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        ret = rdb.Update(deletedRows, tableName, valuesBucket, predicates.GetWhereClause(),
            predicates.GetWhereArgs());
    } else if (tableName == PhotoMap::TABLE) {
        valuesBucket.PutInt(PhotoMap::DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        ret = rdb.Update(deletedRows, tableName, valuesBucket, predicates.GetWhereClause(),
            predicates.GetWhereArgs());
    } else {
        ret = rdb.Delete(deletedRows, tableName, predicates.GetWhereClause(), predicates.GetWhereArgs());
    }
    return ret;
}

int32_t MediaLibraryRdbStore::Delete(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->DeleteByCmd");
    /* local delete */
    int32_t ret = DoDeleteFromPredicates(*rdbStore_, *(cmd.GetAbsRdbPredicates()), deletedRows);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Delete failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    CloudSyncHelper::GetInstance()->StartSync();
    return ret;
}

int32_t MediaLibraryRdbStore::Update(MediaLibraryCommand &cmd, int32_t &changedRows)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return E_HAS_DB_ERROR;
    }

    if (cmd.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        cmd.GetValueBucket().PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED,
            MediaFileUtils::UTCTimeMilliSeconds());
        cmd.GetValueBucket().PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME,
            MediaFileUtils::UTCTimeMilliSeconds());
    }

    DfxTimer dfxTimer(DfxType::RDB_UPDATE_BY_CMD, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->UpdateByCmd");
    int32_t ret = rdbStore_->Update(changedRows, cmd.GetTableName(), cmd.GetValueBucket(),
        cmd.GetAbsRdbPredicates()->GetWhereClause(), cmd.GetAbsRdbPredicates()->GetWhereArgs());
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Update failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::GetIndexOfUri(const AbsRdbPredicates &predicates,
    const vector<string> &columns, const string &id)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("GetIndexOfUri");
    string sql;
    sql.append("SELECT ").append(PHOTO_INDEX).append(" From (");
    sql.append(RdbSqlUtils::BuildQueryString(predicates, columns));
    sql.append(") where "+ MediaColumn::MEDIA_ID + " = ").append(id);
    MEDIA_DEBUG_LOG("sql = %{private}s", sql.c_str());
    const vector<string> &args = predicates.GetWhereArgs();
    for (const auto &arg : args) {
        MEDIA_DEBUG_LOG("arg = %{private}s", arg.c_str());
    }
    return rdbStore_->QuerySql(sql, args);
}

int32_t MediaLibraryRdbStore::UpdateLastVisitTime(MediaLibraryCommand &cmd, int32_t &changedRows)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryTracer tracer;
    tracer.Start("UpdateLastVisitTime");
    cmd.GetValueBucket().PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, MediaFileUtils::UTCTimeMilliSeconds());
    int32_t ret = rdbStore_->Update(changedRows, cmd.GetTableName(), cmd.GetValueBucket(),
        cmd.GetAbsRdbPredicates()->GetWhereClause(), cmd.GetAbsRdbPredicates()->GetWhereArgs());
    if (ret != NativeRdb::E_OK || changedRows <= 0) {
        MEDIA_ERR_LOG("rdbStore_->UpdateLastVisitTime failed, changedRows = %{public}d, ret = %{public}d",
            changedRows, ret);
    }
    return changedRows;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::Query(MediaLibraryCommand &cmd,
    const vector<string> &columns)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }

    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->QueryByCmd");
#ifdef MEDIALIBRARY_COMPATIBILITY
    auto predicates = cmd.GetAbsRdbPredicates();
    MEDIA_DEBUG_LOG("tablename = %{private}s", predicates->GetTableName().c_str());
    for (const auto &col : columns) {
        MEDIA_DEBUG_LOG("col = %{private}s", col.c_str());
    }
    MEDIA_DEBUG_LOG("whereClause = %{private}s", predicates->GetWhereClause().c_str());
    const vector<string> &args = predicates->GetWhereArgs();
    for (const auto &arg : args) {
        MEDIA_DEBUG_LOG("whereArgs = %{private}s", arg.c_str());
    }
    MEDIA_DEBUG_LOG("limit = %{public}d", predicates->GetLimit());
#endif

    /*
     * adapter pattern:
     * Reuse predicates-based query so that no need to modify both func
     * if later logic changes take place
     */
    auto resultSet = Query(*cmd.GetAbsRdbPredicates(), columns);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
    }
    return resultSet;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::Query(const AbsRdbPredicates &predicates,
    const vector<string> &columns)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }

    /* add filter */
    MediaLibraryRdbUtils::AddQueryFilter(const_cast<AbsRdbPredicates &>(predicates));
    DfxTimer dfxTimer(RDB_QUERY, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->QueryByPredicates");
    auto resultSet = rdbStore_->Query(predicates, columns);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
    }
    return resultSet;
}

int32_t MediaLibraryRdbStore::ExecuteSql(const string &sql)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    DfxTimer dfxTimer(RDB_EXECUTE_SQL, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->ExecuteSql");
    int32_t ret = rdbStore_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->ExecuteSql failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}

void MediaLibraryRdbStore::BuildValuesSql(const NativeRdb::ValuesBucket &values, vector<ValueObject> &bindArgs,
    string &sql)
{
    map<string, ValueObject> valuesMap;
    values.GetAll(valuesMap);
    sql.append("(");
    for (auto iter = valuesMap.begin(); iter != valuesMap.end(); iter++) {
        sql.append(((iter == valuesMap.begin()) ? "" : ", "));
        sql.append(iter->first);               // columnName
        bindArgs.push_back(iter->second); // columnValue
    }

    sql.append(") select ");
    for (size_t i = 0; i < valuesMap.size(); i++) {
        sql.append(((i == 0) ? "?" : ", ?"));
    }
    sql.append(" ");
}

void MediaLibraryRdbStore::BuildQuerySql(const AbsRdbPredicates &predicates, const vector<string> &columns,
    vector<ValueObject> &bindArgs, string &sql)
{
    sql.append(RdbSqlUtils::BuildQueryString(predicates, columns));
    const vector<string> &args = predicates.GetWhereArgs();
    for (const auto &arg : args) {
        bindArgs.emplace_back(arg);
    }
}

/**
 * Returns last insert row id. If insert succeed but no new rows inserted, then return -1.
 * Return E_HAS_DB_ERROR on error cases.
 */
int32_t MediaLibraryRdbStore::ExecuteForLastInsertedRowId(const string &sql, const vector<ValueObject> &bindArgs)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int64_t lastInsertRowId = 0;
    int32_t err = rdbStore_->ExecuteForLastInsertedRowId(lastInsertRowId, sql, bindArgs);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute insert, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return lastInsertRowId;
}

int32_t MediaLibraryRdbStore::Delete(const AbsRdbPredicates &predicates)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    int err = E_ERR;
    int32_t deletedRows = 0;
    err = DoDeleteFromPredicates(*rdbStore_, predicates, deletedRows);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute delete, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    CloudSyncHelper::GetInstance()->StartSync();
    return deletedRows;
}

/**
 * Return changed rows on success, or negative values on error cases.
 */
int32_t MediaLibraryRdbStore::Update(ValuesBucket &values,
    const AbsRdbPredicates &predicates)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    if (predicates.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        values.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, MediaFileUtils::UTCTimeMilliSeconds());
    }

    DfxTimer dfxTimer(DfxType::RDB_UPDATE, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::Update by predicates");
    int32_t changedRows = -1;
    int err = rdbStore_->Update(changedRows, values, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute update, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }

    return changedRows;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::QuerySql(const string &sql, const vector<string> &selectionArgs)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }

    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->QuerySql");
    auto resultSet = rdbStore_->QuerySql(sql, selectionArgs);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
    }

    return resultSet;
}

shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::GetRaw() const
{
    return rdbStore_;
}

void MediaLibraryRdbStore::ReplacePredicatesUriToId(AbsRdbPredicates &predicates)
{
    const vector<string> &whereUriArgs = predicates.GetWhereArgs();
    vector<string> whereIdArgs;
    whereIdArgs.reserve(whereUriArgs.size());
    for (const auto &arg : whereUriArgs) {
        if (!MediaFileUtils::StartsWith(arg, PhotoColumn::PHOTO_URI_PREFIX)) {
            whereIdArgs.push_back(arg);
            continue;
        }
        whereIdArgs.push_back(MediaFileUri::GetPhotoId(arg));
    }

    predicates.SetWhereArgs(whereIdArgs);
}

int32_t MediaLibraryRdbStore::GetInt(const shared_ptr<ResultSet> &resultSet, const string &column)
{
    return get<int32_t>(ResultSetUtils::GetValFromColumn(column, resultSet, TYPE_INT32));
}

string MediaLibraryRdbStore::GetString(const shared_ptr<ResultSet> &resultSet, const string &column)
{
    return get<string>(ResultSetUtils::GetValFromColumn(column, resultSet, TYPE_STRING));
}

inline void BuildInsertSystemAlbumSql(const ValuesBucket &values, const AbsRdbPredicates &predicates,
    string &sql, vector<ValueObject> &bindArgs)
{
    // Build insert sql
    sql.append("INSERT").append(" OR ROLLBACK ").append(" INTO ").append(PhotoAlbumColumns::TABLE).append(" ");
    MediaLibraryRdbStore::BuildValuesSql(values, bindArgs, sql);
    sql.append(" WHERE NOT EXISTS (");
    MediaLibraryRdbStore::BuildQuerySql(predicates, { PhotoAlbumColumns::ALBUM_ID }, bindArgs, sql);
    sql.append(");");
}

int32_t PrepareSystemAlbums(RdbStore &store)
{
    ValuesBucket values;
    int32_t err = E_FAIL;
    store.BeginTransaction();
    for (int32_t i = PhotoAlbumSubType::SYSTEM_START; i <= PhotoAlbumSubType::SYSTEM_END; i++) {
        values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumType::SYSTEM);
        values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, i);
        values.PutInt(PhotoAlbumColumns::ALBUM_ORDER, i - PhotoAlbumSubType::SYSTEM_START);

        AbsRdbPredicates predicates(PhotoAlbumColumns::TABLE);
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SYSTEM));
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(i));

        string sql;
        vector<ValueObject> bindArgs;
        BuildInsertSystemAlbumSql(values, predicates, sql, bindArgs);
        err = store.ExecuteSql(sql, bindArgs);
        if (err != E_OK) {
            store.RollBack();
            return err;
        }
        values.Clear();
    }
    store.Commit();
    return E_OK;
}

int32_t MediaLibraryDataCallBack::PrepareDir(RdbStore &store)
{
    DirValuesBucket cameraDir = {
        CAMERA_DIRECTORY_TYPE_VALUES, CAMERA_DIR_VALUES, CAMERA_TYPE_VALUES, CAMERA_EXTENSION_VALUES
    };
    DirValuesBucket videoDir = {
        VIDEO_DIRECTORY_TYPE_VALUES, VIDEO_DIR_VALUES, VIDEO_TYPE_VALUES, VIDEO_EXTENSION_VALUES
    };
    DirValuesBucket pictureDir = {
        PIC_DIRECTORY_TYPE_VALUES, PIC_DIR_VALUES, PIC_TYPE_VALUES, PIC_EXTENSION_VALUES
    };
    DirValuesBucket audioDir = {
        AUDIO_DIRECTORY_TYPE_VALUES, AUDIO_DIR_VALUES, AUDIO_TYPE_VALUES, AUDIO_EXTENSION_VALUES
    };
    DirValuesBucket documentDir = {
        DOC_DIRECTORY_TYPE_VALUES, DOCS_PATH, DOC_TYPE_VALUES, DOC_EXTENSION_VALUES
    };
    DirValuesBucket downloadDir = {
        DOWNLOAD_DIRECTORY_TYPE_VALUES, DOCS_PATH, DOWNLOAD_TYPE_VALUES, DOWNLOAD_EXTENSION_VALUES
    };

    vector<DirValuesBucket> dirValuesBuckets = {
        cameraDir, videoDir, pictureDir, audioDir, documentDir, downloadDir
    };

    for (const auto& dirValuesBucket : dirValuesBuckets) {
        if (InsertDirValues(dirValuesBucket, store) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("PrepareDir failed");
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::InsertDirValues(const DirValuesBucket &dirValuesBucket, RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(DIRECTORY_DB_DIRECTORY_TYPE, dirValuesBucket.directoryType);
    valuesBucket.PutString(DIRECTORY_DB_DIRECTORY, dirValuesBucket.dirValues);
    valuesBucket.PutString(DIRECTORY_DB_MEDIA_TYPE, dirValuesBucket.typeValues);
    valuesBucket.PutString(DIRECTORY_DB_EXTENSION, dirValuesBucket.extensionValues);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket);
    MEDIA_DEBUG_LOG("insert dir outRowId: %{public}ld insertResult: %{public}d", (long)outRowId, insertResult);
    return insertResult;
}

int32_t MediaLibraryDataCallBack::PrepareSmartAlbum(RdbStore &store)
{
    SmartAlbumValuesBucket trashAlbum = {
        TRASH_ALBUM_ID_VALUES, TRASH_ALBUM_NAME_VALUES, TRASH_ALBUM_TYPE_VALUES
    };

    SmartAlbumValuesBucket favAlbum = {
        FAVOURITE_ALBUM_ID_VALUES, FAVOURTIE_ALBUM_NAME_VALUES, FAVOURITE_ALBUM_TYPE_VALUES
    };

    vector<SmartAlbumValuesBucket> smartAlbumValuesBuckets = {
        trashAlbum, favAlbum
    };

    for (const auto& smartAlbum : smartAlbumValuesBuckets) {
        if (InsertSmartAlbumValues(smartAlbum, store) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Prepare smartAlbum failed");
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

static int32_t InsertShootingModeAlbumValues(
    const ShootingModeValueBucket &shootingModeAlbum, RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(SMARTALBUM_DB_ALBUM_TYPE, shootingModeAlbum.albumType);
    valuesBucket.PutInt(COMPAT_ALBUM_SUBTYPE, shootingModeAlbum.albumSubType);
    valuesBucket.PutString(MEDIA_DATA_DB_ALBUM_NAME, shootingModeAlbum.albumName);
    valuesBucket.PutInt(MEDIA_DATA_DB_IS_LOCAL, 1); // local album is 1.
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, ANALYSIS_ALBUM_TABLE, valuesBucket);
    return insertResult;
}

static int32_t PrepareShootingModeAlbum(RdbStore &store)
{
    ShootingModeValueBucket portraitAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, PORTRAIT_ALBUM
    };
    ShootingModeValueBucket wideApertureAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, WIDE_APERTURE_ALBUM
    };
    ShootingModeValueBucket nightShotAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, NIGHT_SHOT_ALBUM
    };
    ShootingModeValueBucket movingPictureAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, MOVING_PICTURE_ALBUM
    };
    ShootingModeValueBucket proPhotoAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, PRO_PHOTO_ALBUM
    };
    ShootingModeValueBucket slowMotionAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, SLOW_MOTION_ALBUM
    };
    ShootingModeValueBucket lightPaintingAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, LIGHT_PAINTING_ALBUM
    };
    ShootingModeValueBucket highPixelAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, HIGH_PIXEL_ALBUM
    };
    ShootingModeValueBucket superMicroAlbum = {
        SHOOTING_MODE_TYPE, SHOOTING_MODE_SUB_TYPE, SUPER_MACRO_ALBUM
    };

    vector<ShootingModeValueBucket> shootingModeValuesBucket = {
        portraitAlbum, wideApertureAlbum, nightShotAlbum, movingPictureAlbum,
        proPhotoAlbum, lightPaintingAlbum, highPixelAlbum, superMicroAlbum, slowMotionAlbum
    };
    for (const auto& shootingModeAlbum : shootingModeValuesBucket) {
        if (InsertShootingModeAlbumValues(shootingModeAlbum, store) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Prepare shootingMode album failed");
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::InsertSmartAlbumValues(const SmartAlbumValuesBucket &smartAlbum, RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(SMARTALBUM_DB_ID, smartAlbum.albumId);
    valuesBucket.PutString(SMARTALBUM_DB_NAME, smartAlbum.albumName);
    valuesBucket.PutInt(SMARTALBUM_DB_ALBUM_TYPE, smartAlbum.albumType);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, SMARTALBUM_TABLE, valuesBucket);
    return insertResult;
}

static int32_t InsertUniqueMemberTableValues(const UniqueMemberValuesBucket &uniqueMemberValues,
    RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutString(ASSET_MEDIA_TYPE, uniqueMemberValues.assetMediaType);
    valuesBucket.PutInt(UNIQUE_NUMBER, uniqueMemberValues.startNumber);
    int64_t outRowId = -1;
    int32_t insertResult = store.Insert(outRowId, ASSET_UNIQUE_NUMBER_TABLE, valuesBucket);
    return insertResult;
}

static int32_t PrepareUniqueMemberTable(RdbStore &store)
{
    string queryRowSql = "SELECT COUNT(*) as count FROM " + ASSET_UNIQUE_NUMBER_TABLE;
    auto resultSet = store.QuerySql(queryRowSql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get AssetUniqueNumberTable count");
        UpdateFail(__FILE__, __LINE__);
        return NativeRdb::E_ERROR;
    }
    if (GetInt32Val("count", resultSet) != 0) {
        MEDIA_DEBUG_LOG("AssetUniqueNumberTable is already inited");
        return E_OK;
    }

    UniqueMemberValuesBucket imageBucket = { IMAGE_ASSET_TYPE, 0 };
    UniqueMemberValuesBucket videoBucket = { VIDEO_ASSET_TYPE, 0 };
    UniqueMemberValuesBucket audioBucket = { AUDIO_ASSET_TYPE, 0 };

    vector<UniqueMemberValuesBucket> uniqueNumberValueBuckets = {
        imageBucket, videoBucket, audioBucket
    };

    for (const auto& uniqueNumberValueBucket : uniqueNumberValueBuckets) {
        if (InsertUniqueMemberTableValues(uniqueNumberValueBucket, store) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Prepare smartAlbum failed");
            UpdateFail(__FILE__, __LINE__);
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

static const string &TriggerDeleteAlbumClearMap()
{
    static const string TRIGGER_CLEAR_MAP = BaseColumn::CreateTrigger() + "photo_album_clear_map" +
    " AFTER DELETE ON " + PhotoAlbumColumns::TABLE +
    " BEGIN " +
        "DELETE FROM " + PhotoMap::TABLE +
        " WHERE " + PhotoMap::ALBUM_ID + "=" + "OLD." + PhotoAlbumColumns::ALBUM_ID + ";" +
    " END;";
    return TRIGGER_CLEAR_MAP;
}

static const string &TriggerAddAssets()
{
    static const string TRIGGER_ADD_ASSETS = BaseColumn::CreateTrigger() + "photo_album_insert_asset" +
    " AFTER INSERT ON " + PhotoMap::TABLE +
    " BEGIN " +
        "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
            PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " + 1 " +
        "WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + "NEW." + PhotoMap::ALBUM_ID + ";" +
    " END;";
    return TRIGGER_ADD_ASSETS;
}

static const string &TriggerRemoveAssets()
{
    static const string TRIGGER_REMOVE_ASSETS = BaseColumn::CreateTrigger() + "photo_album_delete_asset" +
    " AFTER DELETE ON " + PhotoMap::TABLE +
    " BEGIN " +
        "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
            PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " - 1 " +
        "WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + "OLD." + PhotoMap::ALBUM_ID + ";" +
    " END;";
    return TRIGGER_REMOVE_ASSETS;
}

static const string &TriggerDeletePhotoClearMap()
{
    static const string TRIGGER_DELETE_ASSETS = BaseColumn::CreateTrigger() + "delete_photo_clear_map" +
    " AFTER DELETE ON " + PhotoColumn::PHOTOS_TABLE +
    " BEGIN " +
        "DELETE FROM " + PhotoMap::TABLE +
        " WHERE " + PhotoMap::ASSET_ID + "=" + "OLD." + MediaColumn::MEDIA_ID + ";" +
        "DELETE FROM " + ANALYSIS_PHOTO_MAP_TABLE +
        " WHERE " + PhotoMap::ASSET_ID + "=" + "OLD." + MediaColumn::MEDIA_ID + ";" +
    " END;";
    return TRIGGER_DELETE_ASSETS;
}

static const string &QueryAlbumJoinMap()
{
    static const string QUERY_ALBUM_JOIN_MAP = " SELECT " + PhotoAlbumColumns::ALBUM_ID +
        " FROM " + PhotoAlbumColumns::TABLE + " INNER JOIN " + PhotoMap::TABLE + " ON " +
            PhotoAlbumColumns::ALBUM_ID + " = " + PhotoMap::ALBUM_ID + " AND " +
            PhotoMap::ASSET_ID + " = " + "NEW." + MediaColumn::MEDIA_ID;
    return QUERY_ALBUM_JOIN_MAP;
}

static const string &SetHiddenUpdateCount()
{
    // Photos.hidden 1 -> 0
    static const string SET_HIDDEN_UPDATE_COUNT = " UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " + 1" +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" +
            QueryAlbumJoinMap() + " WHERE " +
                "NEW." + MediaColumn::MEDIA_HIDDEN + " = 0" + " AND " +
                "(OLD." + MediaColumn::MEDIA_HIDDEN + " - NEW." + MediaColumn::MEDIA_HIDDEN + " > 0)" +
        ");";
    return SET_HIDDEN_UPDATE_COUNT;
}

static const string &SetTrashUpdateCount()
{
    // Photos.date_trashed timestamp -> 0
    static const string SET_TRASH_UPDATE_COUNT = " UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " + 1" +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" +
            QueryAlbumJoinMap() + " WHERE " +
                "SIGN(NEW." + MediaColumn::MEDIA_DATE_TRASHED + ") = 0" + " AND " +
                "NEW." + MediaColumn::MEDIA_HIDDEN + " = 0" + " AND " +
                "(" +
                    "SIGN(OLD." + MediaColumn::MEDIA_DATE_TRASHED + ") - " +
                    "SIGN(NEW." + MediaColumn::MEDIA_DATE_TRASHED + ") > 0" +
                ")" +
        ");";
    return SET_TRASH_UPDATE_COUNT;
}

static const string &UnSetHiddenUpdateCount()
{
    // Photos.hidden 0 -> 1
    static const string UNSET_HIDDEN_UPDATE_COUNT = " UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " - 1" +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" +
            QueryAlbumJoinMap() + " WHERE " +
                "NEW." + MediaColumn::MEDIA_HIDDEN + " = 1" + " AND " +
                "(NEW." + MediaColumn::MEDIA_HIDDEN + " - OLD." + MediaColumn::MEDIA_HIDDEN + " > 0)" +
        ");";
    return UNSET_HIDDEN_UPDATE_COUNT;
}

static const string &UnSetTrashUpdateCount()
{
    // Photos.date_trashed 0 -> timestamp
    static const string UNSET_TRASH_UPDATE_COUNT = " UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_COUNT + " = " + PhotoAlbumColumns::ALBUM_COUNT + " - 1" +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" +
            QueryAlbumJoinMap() + " WHERE " +
                "SIGN(NEW." + MediaColumn::MEDIA_DATE_TRASHED + ") = 1" + " AND " +
                "NEW." + MediaColumn::MEDIA_HIDDEN + " = 0" + " AND " +
                "(" +
                    "SIGN(NEW." + MediaColumn::MEDIA_DATE_TRASHED + ") - "
                    "SIGN(OLD." + MediaColumn::MEDIA_DATE_TRASHED + ") > 0" +
                ")" +
        ");";
    return UNSET_TRASH_UPDATE_COUNT;
}

static const string &TriggerUpdateUserAlbumCount()
{
    static const string TRIGGER_UPDATE_USER_ALBUM_COUNT = BaseColumn::CreateTrigger() + "update_user_album_count" +
        " AFTER UPDATE ON " + PhotoColumn::PHOTOS_TABLE +
        " BEGIN " +
            SetHiddenUpdateCount() +
            SetTrashUpdateCount() +
            UnSetHiddenUpdateCount() +
            UnSetTrashUpdateCount() +
        " END;";
    return TRIGGER_UPDATE_USER_ALBUM_COUNT;
}

static const vector<string> onCreateSqlStrs = {
    CREATE_MEDIA_TABLE,
    PhotoColumn::CREATE_PHOTO_TABLE,
    PhotoColumn::CREATE_CLOUD_ID_INDEX,
    PhotoColumn::INDEX_SCTHP_ADDTIME,
    PhotoColumn::INDEX_CAMERA_SHOT_KEY,
    PhotoColumn::CREATE_YEAR_INDEX,
    PhotoColumn::CREATE_MONTH_INDEX,
    PhotoColumn::CREATE_DAY_INDEX,
    PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
    PhotoColumn::CREATE_SCHPT_DAY_INDEX,
    PhotoColumn::CREATE_HIDDEN_TIME_INDEX,
    PhotoColumn::CREATE_SCHPT_HIDDEN_TIME_INDEX,
    PhotoColumn::CREATE_PHOTO_FAVORITE_INDEX,
    PhotoColumn::CREATE_PHOTOS_DELETE_TRIGGER,
    PhotoColumn::CREATE_PHOTOS_FDIRTY_TRIGGER,
    PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER,
    PhotoColumn::CREATE_PHOTOS_INSERT_CLOUD_SYNC,
    PhotoColumn::CREATE_PHOTOS_UPDATE_CLOUD_SYNC,
    AudioColumn::CREATE_AUDIO_TABLE,
    CREATE_SMARTALBUM_TABLE,
    CREATE_SMARTALBUMMAP_TABLE,
    CREATE_DEVICE_TABLE,
    CREATE_CATEGORY_SMARTALBUMMAP_TABLE,
    CREATE_ASSET_UNIQUE_NUMBER_TABLE,
    CREATE_ALBUM_REFRESH_TABLE,
    CREATE_IMAGE_VIEW,
    CREATE_VIDEO_VIEW,
    CREATE_AUDIO_VIEW,
    CREATE_ALBUM_VIEW,
    CREATE_SMARTALBUMASSETS_VIEW,
    CREATE_ASSETMAP_VIEW,
    CREATE_MEDIATYPE_DIRECTORY_TABLE,
    CREATE_BUNDLE_PREMISSION_TABLE,
    CREATE_MEDIALIBRARY_ERROR_TABLE,
    CREATE_REMOTE_THUMBNAIL_TABLE,
    CREATE_FILES_DELETE_TRIGGER,
    CREATE_FILES_MDIRTY_TRIGGER,
    CREATE_FILES_FDIRTY_TRIGGER,
    CREATE_INSERT_CLOUD_SYNC_TRIGGER,
    PhotoAlbumColumns::CREATE_TABLE,
    PhotoAlbumColumns::INDEX_ALBUM_TYPES,
    PhotoAlbumColumns::CREATE_ALBUM_INSERT_TRIGGER,
    PhotoAlbumColumns::CREATE_ALBUM_MDIRTY_TRIGGER,
    PhotoAlbumColumns::CREATE_ALBUM_DELETE_TRIGGER,
    PhotoAlbumColumns::ALBUM_DELETE_ORDER_TRIGGER,
    PhotoAlbumColumns::ALBUM_INSERT_ORDER_TRIGGER,
    PhotoMap::CREATE_TABLE,
    PhotoMap::CREATE_NEW_TRIGGER,
    PhotoMap::CREATE_DELETE_TRIGGER,
    TriggerDeleteAlbumClearMap(),
    TriggerDeletePhotoClearMap(),
    CREATE_TAB_ANALYSIS_OCR,
    CREATE_TAB_ANALYSIS_LABEL,
    CREATE_TAB_ANALYSIS_VIDEO_LABEL,
    CREATE_TAB_ANALYSIS_AESTHETICS,
    CREATE_TAB_ANALYSIS_SALIENCY_DETECT,
    CREATE_TAB_ANALYSIS_OBJECT,
    CREATE_TAB_ANALYSIS_RECOMMENDATION,
    CREATE_TAB_ANALYSIS_SEGMENTATION,
    CREATE_TAB_ANALYSIS_COMPOSITION,
    CREATE_TAB_ANALYSIS_HEAD,
    CREATE_TAB_ANALYSIS_POSE,
    CREATE_TAB_IMAGE_FACE,
    CREATE_TAB_FACE_TAG,
    CREATE_TAB_ANALYSIS_TOTAL_FOR_ONCREATE,
    CREATE_VISION_UPDATE_TRIGGER,
    CREATE_VISION_DELETE_TRIGGER,
    CREATE_VISION_INSERT_TRIGGER_FOR_ONCREATE,
    CREATE_IMAGE_FACE_INDEX,
    CREATE_OBJECT_INDEX,
    CREATE_RECOMMENDATION_INDEX,
    CREATE_COMPOSITION_INDEX,
    CREATE_HEAD_INDEX,
    CREATE_POSE_INDEX,
    CREATE_GEO_KNOWLEDGE_TABLE,
    CREATE_GEO_DICTIONARY_TABLE,
    CREATE_ANALYSIS_ALBUM_FOR_ONCREATE,
    CREATE_ANALYSIS_ALBUM_MAP,
    CREATE_HIGHLIGHT_ALBUM_TABLE,
    CREATE_HIGHLIGHT_COVER_INFO_TABLE,
    CREATE_HIGHLIGHT_PLAY_INFO_TABLE,
    CREATE_USER_PHOTOGRAPHY_INFO_TABLE,
    INSERT_PHOTO_INSERT_SOURCE_ALBUM,
    INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
    CREATE_SOURCE_ALBUM_INDEX,
    FormMap::CREATE_FORM_MAP_TABLE,
    CREATE_DICTIONARY_INDEX,
    CREATE_KNOWLEDGE_INDEX,
    CREATE_CITY_NAME_INDEX,
    CREATE_LOCATION_KEY_INDEX,

    // search
    CREATE_SEARCH_TOTAL_TABLE,
    CREATE_SEARCH_INSERT_TRIGGER,
    CREATE_SEARCH_UPDATE_TRIGGER,
    CREATE_SEARCH_UPDATE_STATUS_TRIGGER,
    CREATE_SEARCH_DELETE_TRIGGER,
    CREATE_ALBUM_MAP_INSERT_SEARCH_TRIGGER,
    CREATE_ALBUM_MAP_DELETE_SEARCH_TRIGGER,
    CREATE_ALBUM_UPDATE_SEARCH_TRIGGER,
    CREATE_ANALYSIS_UPDATE_SEARCH_TRIGGER,
    CREATE_ANALYSIS_ALBUM_UPDATE_SEARCH_TRIGGER,
    MedialibraryBusinessRecordColumn::CREATE_TABLE,
    MedialibraryBusinessRecordColumn::CREATE_BUSINESS_KEY_INDEX,
    PhotoExtColumn::CREATE_PHOTO_EXT_TABLE,
};

static int32_t ExecuteSql(RdbStore &store)
{
    for (const string& sqlStr : onCreateSqlStrs) {
        if (store.ExecuteSql(sqlStr) != NativeRdb::E_OK) {
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::OnCreate(RdbStore &store)
{
    if (ExecuteSql(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareSystemAlbums(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareDir(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareSmartAlbum(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareUniqueMemberTable(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareShootingModeAlbum(store)!= NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    return NativeRdb::E_OK;
}

void VersionAddCloud(RdbStore &store)
{
    const std::string alterCloudId = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_CLOUD_ID +" TEXT";
    int32_t result = store.ExecuteSql(alterCloudId);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb cloud_id error %{private}d", result);
    }
    const std::string alterDirty = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_DIRTY +" INT DEFAULT 0";
    result = store.ExecuteSql(alterDirty);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb dirty error %{private}d", result);
    }
    const std::string alterSyncStatus = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_SYNC_STATUS +" INT DEFAULT 0";
    result = store.ExecuteSql(alterSyncStatus);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb syncStatus error %{private}d", result);
    }
    const std::string alterPosition = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_POSITION +" INT DEFAULT 1";
    result = store.ExecuteSql(alterPosition);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb position error %{private}d", result);
    }
}

static void AddPortraitInAnalysisAlbum(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        ADD_TAG_ID_COLUMN_FOR_ALBUM,
        ADD_USER_OPERATION_COLUMN_FOR_ALBUM,
        ADD_GROUP_TAG_COLUMN_FOR_ALBUM,
        ADD_USER_DISPLAY_LEVEL_COLUMN_FOR_ALBUM,
        ADD_IS_ME_COLUMN_FOR_ALBUM,
        ADD_IS_REMOVED_COLUMN_FOR_ALBUM,
        ADD_RENAME_OPERATION_COLUMN_FOR_ALBUM,
        CREATE_ANALYSIS_ALBUM_UPDATE_SEARCH_TRIGGER
    };
    MEDIA_INFO_LOG("start add aesthetic composition tables");
    ExecSqls(executeSqlStrs, store);
}

void AddMetaModifiedColumn(RdbStore &store)
{
    const std::string alterMetaModified =
        "ALTER TABLE " + MEDIALIBRARY_TABLE + " ADD COLUMN " +
        MEDIA_DATA_DB_META_DATE_MODIFIED + " BIGINT DEFAULT 0";
    int32_t result = store.ExecuteSql(alterMetaModified);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb meta_date_modified error %{private}d", result);
    }
    const std::string alterSyncStatus = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_SYNC_STATUS + " INT DEFAULT 0";
    result = store.ExecuteSql(alterSyncStatus);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb syncStatus error %{private}d", result);
    }
}

void AddTableType(RdbStore &store)
{
    const std::string alterTableName =
        "ALTER TABLE " + BUNDLE_PERMISSION_TABLE + " ADD COLUMN " +
        PERMISSION_TABLE_TYPE + " INT";
    int32_t result = store.ExecuteSql(alterTableName);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb table_name error %{private}d", result);
    }
}

void API10TableCreate(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        PhotoColumn::INDEX_SCTHP_ADDTIME,
        PhotoColumn::INDEX_CAMERA_SHOT_KEY,
        PhotoColumn::CREATE_PHOTOS_DELETE_TRIGGER,
        PhotoColumn::CREATE_PHOTOS_FDIRTY_TRIGGER,
        PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER,
        PhotoColumn::CREATE_PHOTOS_INSERT_CLOUD_SYNC,
        AudioColumn::CREATE_AUDIO_TABLE,
        CREATE_ASSET_UNIQUE_NUMBER_TABLE,
        CREATE_FILES_DELETE_TRIGGER,
        CREATE_FILES_MDIRTY_TRIGGER,
        CREATE_FILES_FDIRTY_TRIGGER,
        CREATE_INSERT_CLOUD_SYNC_TRIGGER,
        PhotoAlbumColumns::CREATE_TABLE,
        PhotoAlbumColumns::INDEX_ALBUM_TYPES,
        PhotoMap::CREATE_TABLE,
        FormMap::CREATE_FORM_MAP_TABLE,
        TriggerDeleteAlbumClearMap(),
        TriggerAddAssets(),
        TriggerRemoveAssets(),
        TriggerDeletePhotoClearMap(),
        TriggerUpdateUserAlbumCount(),
    };

    for (size_t i = 0; i < executeSqlStrs.size(); i++) {
        if (store.ExecuteSql(executeSqlStrs[i]) != NativeRdb::E_OK) {
            UpdateFail(__FILE__, __LINE__);
            MEDIA_ERR_LOG("upgrade fail idx:%{public}zu", i);
        }
    }
}

void ModifySyncStatus(RdbStore &store)
{
    const std::string dropSyncStatus = "ALTER TABLE " + MEDIALIBRARY_TABLE + " DROP column syncing";
    auto result = store.ExecuteSql(dropSyncStatus);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb syncing error %{private}d", result);
    }

    const std::string addSyncStatus = "ALTER TABLE " + MEDIALIBRARY_TABLE + " ADD COLUMN " +
        MEDIA_DATA_DB_SYNC_STATUS +" INT DEFAULT 0";
    result = store.ExecuteSql(addSyncStatus);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb syncStatus error %{private}d", result);
    }
}

void ModifyDeleteTrigger(RdbStore &store)
{
    /* drop old delete trigger */
    const std::string dropDeleteTrigger = "DROP TRIGGER IF EXISTS photos_delete_trigger";
    if (store.ExecuteSql(dropDeleteTrigger) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("upgrade fail: drop old delete trigger");
    }

    /* create new delete trigger */
    if (store.ExecuteSql(PhotoColumn::CREATE_PHOTOS_DELETE_TRIGGER) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("upgrade fail: create new delete trigger");
    }
}

void AddCloudVersion(RdbStore &store)
{
    const std::string addSyncStatus = "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
        PhotoColumn::PHOTO_CLOUD_VERSION +" BIGINT DEFAULT 0";
    auto result = store.ExecuteSql(addSyncStatus);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb cloudVersion error %{private}d", result);
    }
}

static string UpdateCloudPathSql(const string &table, const string &column)
{
    static const string LOCAL_PATH = "/storage/media/local/";
    static const string CLOUD_PATH = "/storage/cloud/";
    /*
     * replace only once:
     * UPDATE photos
     * SET data = ([replace](substring(data, 1, len(local_path)), local_path, cloud_path) ||
     * substring(data, len(local_path) + 1));
     */
    return "UPDATE " + table + " SET " + column + " = (REPLACE(SUBSTRING(" +
        column + ", 1, " + to_string(LOCAL_PATH.length()) + "), '" +
        LOCAL_PATH + "', '" + CLOUD_PATH + "') || SUBSTRING(" + column + ", " +
        to_string(LOCAL_PATH.length() + 1) + "))" +
        " WHERE " + column + " LIKE '" + LOCAL_PATH + "%';";
}

static void UpdateMdirtyTriggerForSdirty(RdbStore &store)
{
    const string dropMdirtyCreateTrigger = "DROP TRIGGER IF EXISTS photos_mdirty_trigger";
    int32_t ret = store.ExecuteSql(dropMdirtyCreateTrigger);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("drop photos_mdirty_trigger fail, ret = %{public}d", ret);
        UpdateFail(__FILE__, __LINE__);
    }

    ret = store.ExecuteSql(PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("add photos_mdirty_trigger fail, ret = %{public}d", ret);
        UpdateFail(__FILE__, __LINE__);
    }
}

static int32_t UpdateCloudPath(RdbStore &store)
{
    const vector<string> updateCloudPath = {
        UpdateCloudPathSql(MEDIALIBRARY_TABLE, MEDIA_DATA_DB_FILE_PATH),
        UpdateCloudPathSql(MEDIALIBRARY_TABLE, MEDIA_DATA_DB_RECYCLE_PATH),
        UpdateCloudPathSql(MEDIALIBRARY_ERROR_TABLE, MEDIA_DATA_ERROR),
        UpdateCloudPathSql(PhotoColumn::PHOTOS_TABLE, MediaColumn::MEDIA_FILE_PATH),
    };
    auto result = ExecSqls(updateCloudPath, store);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
    }
    return result;
}

void UpdateAPI10Table(RdbStore &store)
{
    store.ExecuteSql("DROP INDEX IF EXISTS idx_sthp_dateadded");
    store.ExecuteSql("DROP INDEX IF EXISTS photo_album_types");

    store.ExecuteSql("DROP TRIGGER IF EXISTS photos_delete_trigger");
    store.ExecuteSql("DROP TRIGGER IF EXISTS photos_fdirty_trigger");
    store.ExecuteSql("DROP TRIGGER IF EXISTS photos_mdirty_trigger");
    store.ExecuteSql("DROP TRIGGER IF EXISTS photo_insert_cloud_sync_trigger");

    store.ExecuteSql("DROP TRIGGER IF EXISTS delete_trigger");
    store.ExecuteSql("DROP TRIGGER IF EXISTS mdirty_trigger");
    store.ExecuteSql("DROP TRIGGER IF EXISTS fdirty_trigger");
    store.ExecuteSql("DROP TRIGGER IF EXISTS insert_cloud_sync_trigger");

    store.ExecuteSql("DROP TRIGGER IF EXISTS photo_album_clear_map");
    store.ExecuteSql("DROP TRIGGER IF EXISTS photo_album_insert_asset");
    store.ExecuteSql("DROP TRIGGER IF EXISTS photo_album_delete_asset");
    store.ExecuteSql("DROP TRIGGER IF EXISTS delete_photo_clear_map");
    store.ExecuteSql("DROP TRIGGER IF EXISTS update_user_album_count");

    store.ExecuteSql("DROP TABLE IF EXISTS Photos");
    store.ExecuteSql("DROP TABLE IF EXISTS Audios");
    store.ExecuteSql("DROP TABLE IF EXISTS UniqueNumber");
    store.ExecuteSql("DROP TABLE IF EXISTS PhotoAlbum");
    store.ExecuteSql("DROP TABLE IF EXISTS PhotoMap");
    store.ExecuteSql("DROP TABLE IF EXISTS FormMap");

    API10TableCreate(store);
    if (PrepareSystemAlbums(store) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
    }

    if (PrepareUniqueMemberTable(store) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
    }

    // set scan error
    MediaScannerManager::GetInstance()->ErrorRecord();
}

static void AddLocationTables(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        CREATE_GEO_DICTIONARY_TABLE,
        CREATE_GEO_KNOWLEDGE_TABLE,
    };
    MEDIA_INFO_LOG("start init location db");
    ExecSqls(executeSqlStrs, store);
}

static void UpdateLocationTables(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS tab_geo_dictionary",
        "DROP TABLE IF EXISTS tab_geo_knowledge",
        CREATE_GEO_DICTIONARY_TABLE,
        CREATE_GEO_KNOWLEDGE_TABLE,
    };
    MEDIA_INFO_LOG("fix location db");
    ExecSqls(executeSqlStrs, store);
}

static void AddAnalysisTables(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS tab_analysis_label",
        CREATE_TAB_ANALYSIS_OCR,
        CREATE_TAB_ANALYSIS_LABEL,
        CREATE_TAB_ANALYSIS_AESTHETICS,
        CREATE_TAB_ANALYSIS_TOTAL,
        CREATE_VISION_UPDATE_TRIGGER,
        CREATE_VISION_DELETE_TRIGGER,
        CREATE_VISION_INSERT_TRIGGER,
        INIT_TAB_ANALYSIS_TOTAL,
    };
    MEDIA_INFO_LOG("start init vision db");
    ExecSqls(executeSqlStrs, store);
}

static void AddFaceTables(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        CREATE_TAB_IMAGE_FACE,
        CREATE_TAB_FACE_TAG,
        DROP_INSERT_VISION_TRIGGER,
        CREATE_INSERT_VISION_TRIGGER_FOR_ADD_FACE,
        ADD_FACE_STATUS_COLUMN,
        UPDATE_TOTAL_VALUE,
        UPDATE_NOT_SUPPORT_VALUE,
        CREATE_IMAGE_FACE_INDEX
    };
    MEDIA_INFO_LOG("start add face tables");
    ExecSqls(executeSqlStrs, store);
}

static void AddSaliencyTables(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        CREATE_TAB_ANALYSIS_SALIENCY_DETECT,
        DROP_INSERT_VISION_TRIGGER,
        CREATE_VISION_INSERT_TRIGGER_FOR_ADD_SALIENCY,
        ADD_SALIENCY_STATUS_COLUMN,
        UPDATE_SALIENCY_TOTAL_VALUE,
        UPDATE_SALIENCY_NOT_SUPPORT_VALUE
    };
    MEDIA_INFO_LOG("start add saliency tables");
    ExecSqls(executeSqlStrs, store);
}

static void AddVideoLabelTable(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        CREATE_TAB_ANALYSIS_VIDEO_LABEL,
        DROP_INSERT_VISION_TRIGGER,
        CREATE_VISION_INSERT_TRIGGER_FOR_ADD_VIDEO_LABEL
    };
    MEDIA_INFO_LOG("start add video label tables");
    ExecSqls(executeSqlStrs, store);
}

static void UpdateVideoLabelTable(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS tab_analysis_video_label",
        CREATE_TAB_ANALYSIS_VIDEO_LABEL,
    };
    MEDIA_INFO_LOG("start update video label tables");
    ExecSqls(executeSqlStrs, store);
}

static void AddSourceAlbumTrigger(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        DROP_INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        DROP_INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_DELETE_PHOTO_UPDATE_SOURCE_ALBUM,
        INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DELETE_PHOTO_UPDATE_SOURCE_ALBUM,
    };
    MEDIA_INFO_LOG("start add source album trigger");
    ExecSqls(executeSqlStrs, store);
}

static void RemoveSourceAlbumToAnalysis(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        DROP_INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        DROP_INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_DELETE_PHOTO_UPDATE_SOURCE_ALBUM,
        CLEAR_SOURCE_ALBUM_PHOTO_MAP,
        CLEAR_SYSTEM_SOURCE_ALBUM,
        INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DELETE_PHOTO_UPDATE_SOURCE_ALBUM,
    };
    MEDIA_INFO_LOG("start add source album trigger");
    ExecSqls(executeSqlStrs, store);
}

static void MoveSourceAlbumToPhotoAlbumAndAddColumns(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        DROP_INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        DROP_INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_DELETE_PHOTO_UPDATE_SOURCE_ALBUM,
        ADD_SOURCE_ALBUM_BUNDLE_NAME,
        INSERT_SOURCE_ALBUMS_FROM_PHOTOS,
        INSERT_SOURCE_ALBUM_MAP_FROM_PHOTOS,
        CLEAR_SOURCE_ALBUM_ANALYSIS_PHOTO_MAP,
        CLEAR_ANALYSIS_SOURCE_ALBUM,
        INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DELETE_PHOTO_UPDATE_SOURCE_ALBUM,
    };
    MEDIA_INFO_LOG("start move source album to photo album & add columns");
    ExecSqls(executeSqlStrs, store);
}

static void ModifySourceAlbumTriggers(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        DROP_INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        DROP_INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_UPDATE_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_DELETE_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_SOURCE_ALBUM_INDEX,
        ADD_SOURCE_ALBUM_LOCAL_LANGUAGE,
        CREATE_SOURCE_ALBUM_INDEX,
        INSERT_SOURCE_ALBUMS_FROM_PHOTOS_FULL,
        INSERT_SOURCE_ALBUM_MAP_FROM_PHOTOS_FULL,
        INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
    };
    MEDIA_INFO_LOG("start modify source album triggers");
    ExecSqls(executeSqlStrs, store);
    std::unordered_map<int32_t, int32_t> updateResult;
    MediaLibraryRdbUtils::UpdateSourceAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), updateResult);
    MEDIA_INFO_LOG("end modify source album triggers");
}

static void AddAnalysisAlbum(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "ALTER TABLE tab_analysis_ocr ADD COLUMN width INT;",
        "ALTER TABLE tab_analysis_ocr ADD COLUMN height INT;",
        CREATE_ANALYSIS_ALBUM,
        CREATE_ANALYSIS_ALBUM_MAP,
    };
    MEDIA_INFO_LOG("start init vision album");
    ExecSqls(executeSqlStrs, store);
}

static void AddAestheticCompositionTables(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        CREATE_TAB_ANALYSIS_OBJECT,
        CREATE_TAB_ANALYSIS_RECOMMENDATION,
        CREATE_TAB_ANALYSIS_SEGMENTATION,
        CREATE_TAB_ANALYSIS_COMPOSITION,
        DROP_INSERT_VISION_TRIGGER,
        CREATE_VISION_INSERT_TRIGGER_FOR_ADD_AC,
        AC_ADD_OBJECT_COLUMN_FOR_TOTAL,
        AC_UPDATE_OBJECT_TOTAL_VALUE,
        AC_UPDATE_OBJECT_TOTAL_NOT_SUPPORT_VALUE,
        AC_ADD_RECOMMENDATION_COLUMN_FOR_TOTAL,
        AC_UPDATE_RECOMMENDATION_TOTAL_VALUE,
        AC_UPDATE_RECOMMENDATION_TOTAL_NOT_SUPPORT_VALUE,
        AC_ADD_SEGMENTATION_COLUMN_FOR_TOTAL,
        AC_UPDATE_SEGMENTATION_TOTAL_VALUE,
        AC_UPDATE_SEGMENTATION_TOTAL_NOT_SUPPORT_VALUE,
        AC_ADD_COMPOSITION_COLUMN_FOR_TOTAL,
        AC_UPDATE_COMPOSITION_TOTAL_VALUE,
        AC_UPDATE_COMPOSITION_TOTAL_NOT_SUPPORT_VALUE,
        CREATE_OBJECT_INDEX,
        CREATE_RECOMMENDATION_INDEX,
        CREATE_COMPOSITION_INDEX,
    };
    MEDIA_INFO_LOG("start add aesthetic composition tables");
    ExecSqls(executeSqlStrs, store);
}

static void UpdateSpecForAddScreenshot(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        DROP_INSERT_VISION_TRIGGER,
        CREATE_VISION_INSERT_TRIGGER_FOR_UPDATE_SPEC,
    };
    MEDIA_INFO_LOG("update media analysis service specifications for add screenshot");
    ExecSqls(executeSqlStrs, store);
}

static void AddHeadAndPoseTables(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        CREATE_TAB_ANALYSIS_HEAD,
        CREATE_TAB_ANALYSIS_POSE,
        DROP_INSERT_VISION_TRIGGER,
        CREATE_VISION_INSERT_TRIGGER_FOR_ADD_HEAD_AND_POSE,
        ADD_HEAD_STATUS_COLUMN,
        UPDATE_HEAD_TOTAL_VALUE,
        UPDATE_HEAD_NOT_SUPPORT_VALUE,
        ADD_POSE_STATUS_COLUMN,
        UPDATE_POSE_TOTAL_VALUE,
        UPDATE_POSE_NOT_SUPPORT_VALUE,
        CREATE_HEAD_INDEX,
        CREATE_POSE_INDEX,
    };
    MEDIA_INFO_LOG("start add head and pose tables");
    ExecSqls(executeSqlStrs, store);
}

static void AddSegmentationColumns(RdbStore &store)
{
    const string addNameOnSegmentation = "ALTER TABLE " + VISION_SEGMENTATION_TABLE + " ADD COLUMN " +
        SEGMENTATION_NAME + " INT";
    const string addProbOnSegmentation = "ALTER TABLE " + VISION_SEGMENTATION_TABLE + " ADD COLUMN " +
        PROB + " REAL";

    const vector<string> addSegmentationColumns = { addNameOnSegmentation, addProbOnSegmentation };
    ExecSqls(addSegmentationColumns, store);
}

static void AddSearchTable(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS " + SEARCH_TOTAL_TABLE,
        "DROP TRIGGER IF EXISTS " + INSERT_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + UPDATE_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + UPDATE_SEARCH_STATUS_TRIGGER,
        "DROP TRIGGER IF EXISTS " + DELETE_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + ALBUM_MAP_INSERT_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + ALBUM_MAP_DELETE_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + ALBUM_UPDATE_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + ANALYSIS_UPDATE_SEARCH_TRIGGER,
        CREATE_SEARCH_TOTAL_TABLE,
        CREATE_SEARCH_INSERT_TRIGGER,
        CREATE_SEARCH_UPDATE_TRIGGER,
        CREATE_SEARCH_UPDATE_STATUS_TRIGGER,
        CREATE_SEARCH_DELETE_TRIGGER,
        CREATE_ALBUM_MAP_INSERT_SEARCH_TRIGGER,
        CREATE_ALBUM_MAP_DELETE_SEARCH_TRIGGER,
        CREATE_ALBUM_UPDATE_SEARCH_TRIGGER,
        CREATE_ANALYSIS_UPDATE_SEARCH_TRIGGER,
    };
    MEDIA_INFO_LOG("start init search db");
    ExecSqls(executeSqlStrs, store);
}

void MediaLibraryRdbStore::ResetSearchTables()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return;
    }
    static const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS " + SEARCH_TOTAL_TABLE,
        "DROP TRIGGER IF EXISTS " + INSERT_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + UPDATE_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + UPDATE_SEARCH_STATUS_TRIGGER,
        "DROP TRIGGER IF EXISTS " + DELETE_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + ALBUM_MAP_INSERT_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + ALBUM_MAP_DELETE_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + ALBUM_UPDATE_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS " + ANALYSIS_UPDATE_SEARCH_TRIGGER,
    };
    MEDIA_INFO_LOG("start update search db");
    ExecSqls(executeSqlStrs, *rdbStore_);
    AddSearchTable(*rdbStore_);
}

void MediaLibraryRdbStore::ResetAnalysisTables()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return;
    }
    static const vector<string> executeSqlStrs = {
        "DROP TRIGGER IF EXISTS delete_vision_trigger",
        "DROP TRIGGER IF EXISTS insert_vision_trigger",
        "DROP TRIGGER IF EXISTS update_vision_trigger",
        "DROP TABLE IF EXISTS tab_analysis_ocr",
        "DROP TABLE IF EXISTS tab_analysis_label",
        "DROP TABLE IF EXISTS tab_analysis_saliency_detect",
        "DROP TABLE IF EXISTS tab_analysis_aesthetics_score",
        "DROP TABLE IF EXISTS tab_analysis_object",
        "DROP TABLE IF EXISTS tab_analysis_recommendation",
        "DROP TABLE IF EXISTS tab_analysis_segmentation",
        "DROP TABLE IF EXISTS tab_analysis_composition",
        "DROP TABLE IF EXISTS tab_analysis_total",
        "DROP TABLE IF EXISTS tab_analysis_image_face",
        "DROP TABLE IF EXISTS tab_analysis_face_tag",
        "DROP TABLE IF EXISTS tab_analysis_head",
        "DROP TABLE IF EXISTS tab_analysis_pose",
    };
    MEDIA_INFO_LOG("start update analysis table");
    ExecSqls(executeSqlStrs, *rdbStore_);
    AddAnalysisTables(*rdbStore_);
    AddFaceTables(*rdbStore_);
    AddAestheticCompositionTables(*rdbStore_);
    AddSaliencyTables(*rdbStore_);
    UpdateSpecForAddScreenshot(*rdbStore_);
    AddHeadAndPoseTables(*rdbStore_);
    AddSegmentationColumns(*rdbStore_);
}

static void AddPackageNameColumnOnTables(RdbStore &store)
{
    static const string ADD_PACKAGE_NAME_ON_PHOTOS = "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
        " ADD COLUMN " + PhotoColumn::MEDIA_PACKAGE_NAME + " TEXT";
    static const string ADD_PACKAGE_NAME_ON_AUDIOS = "ALTER TABLE " + AudioColumn::AUDIOS_TABLE +
        " ADD COLUMN " + AudioColumn::MEDIA_PACKAGE_NAME + " TEXT";
    static const string ADD_PACKAGE_NAME_ON_FILES = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_PACKAGE_NAME + " TEXT";

    int32_t result = store.ExecuteSql(ADD_PACKAGE_NAME_ON_PHOTOS);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to update PHOTOS");
    }
    result = store.ExecuteSql(ADD_PACKAGE_NAME_ON_AUDIOS);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to update AUDIOS");
    }
    result = store.ExecuteSql(ADD_PACKAGE_NAME_ON_FILES);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to update FILES");
    }
}

void UpdateCloudAlbum(RdbStore &store)
{
    /* album - add columns */
    const std::string addAlbumDirty = "ALTER TABLE " + PhotoAlbumColumns::TABLE +
        " ADD COLUMN " + PhotoAlbumColumns::ALBUM_DIRTY + " INT DEFAULT " +
        to_string(static_cast<int32_t>(DirtyTypes::TYPE_NEW)) + ";";
    int32_t ret = store.ExecuteSql(addAlbumDirty);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: add ablum dirty", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    const std::string addAlbumCloudId = "ALTER TABLE " + PhotoAlbumColumns::TABLE +
        " ADD COLUMN " + PhotoAlbumColumns::ALBUM_CLOUD_ID + " TEXT;";
    ret = store.ExecuteSql(addAlbumCloudId);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: add ablum cloud id", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    /* album - add triggers */
    ret = store.ExecuteSql(PhotoAlbumColumns::CREATE_ALBUM_INSERT_TRIGGER);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: create album insert trigger", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    ret = store.ExecuteSql(PhotoAlbumColumns::CREATE_ALBUM_MDIRTY_TRIGGER);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: create album modify trigger", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    ret = store.ExecuteSql(PhotoAlbumColumns::CREATE_ALBUM_DELETE_TRIGGER);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: create album delete trigger", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    /* album map - add columns */
    const std::string addAlbumMapColumns = "ALTER TABLE " + PhotoMap::TABLE +
        " ADD COLUMN " + PhotoMap::DIRTY +" INT DEFAULT " +
        to_string(static_cast<int32_t>(DirtyTypes::TYPE_NEW)) + ";";
    ret = store.ExecuteSql(addAlbumMapColumns);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: add ablum columns", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    /* album map - add triggers */
    ret = store.ExecuteSql(PhotoMap::CREATE_NEW_TRIGGER);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: create album map insert trigger", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    ret = store.ExecuteSql(PhotoMap::CREATE_DELETE_TRIGGER);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: create album map delete trigger", ret);
        UpdateFail(__FILE__, __LINE__);
    }
}

static void AddCameraShotKey(RdbStore &store)
{
    static const string ADD_CAMERA_SHOT_KEY_ON_PHOTOS = "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
        " ADD COLUMN " + PhotoColumn::CAMERA_SHOT_KEY + " TEXT";
    int32_t result = store.ExecuteSql(ADD_CAMERA_SHOT_KEY_ON_PHOTOS);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to update PHOTOS");
    }
    result = store.ExecuteSql(PhotoColumn::INDEX_CAMERA_SHOT_KEY);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to create CAMERA_SHOT_KEY index");
    }
}

void RemoveAlbumCountTrigger(RdbStore &store)
{
    const vector<string> removeAlbumCountTriggers = {
        BaseColumn::DropTrigger() + "update_user_album_count",
        BaseColumn::DropTrigger() + "photo_album_insert_asset",
        BaseColumn::DropTrigger() + "photo_album_delete_asset",
    };
    ExecSqls(removeAlbumCountTriggers, store);
}

void AddExifAndUserComment(RdbStore &store)
{
    const string addUserCommentOnPhotos = "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
        " ADD COLUMN " + PhotoColumn::PHOTO_USER_COMMENT + " TEXT";

    const string addAllExifOnPhotos = "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
        " ADD COLUMN " + PhotoColumn::PHOTO_ALL_EXIF + " TEXT";

    const vector<string> addExifColumns = { addUserCommentOnPhotos, addAllExifOnPhotos };
    ExecSqls(addExifColumns, store);
}

void AddUpdateCloudSyncTrigger(RdbStore &store)
{
    const vector<string> addUpdateCloudSyncTrigger = { PhotoColumn::CREATE_PHOTOS_UPDATE_CLOUD_SYNC };
    ExecSqls(addUpdateCloudSyncTrigger, store);
}

void UpdateYearMonthDayData(RdbStore &store)
{
    MEDIA_DEBUG_LOG("UpdateYearMonthDayData start");
    const vector<string> updateSql = {
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Audios_ON_DELETE",
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Audios_ON_INSERT",
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Audios_ON_UPDATE",
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Files_ON_DELETE",
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Files_ON_INSERT",
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Files_ON_UPDATE",
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Photos_ON_DELETE",
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Photos_ON_INSERT",
        "DROP TRIGGER IF EXISTS naturalbase_rdb_Photos_ON_UPDATE",
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_DATE_YEAR_INDEX,
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_DATE_MONTH_INDEX,
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_DATE_DAY_INDEX,
        "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
            PhotoColumn::PHOTO_DATE_YEAR + " = strftime('%Y', datetime(date_added, 'unixepoch', 'localtime')), " +
            PhotoColumn::PHOTO_DATE_MONTH + " = strftime('%Y%m', datetime(date_added, 'unixepoch', 'localtime')), " +
            PhotoColumn::PHOTO_DATE_DAY + " = strftime('%Y%m%d', datetime(date_added, 'unixepoch', 'localtime'))",
        PhotoColumn::CREATE_YEAR_INDEX,
        PhotoColumn::CREATE_MONTH_INDEX,
        PhotoColumn::CREATE_DAY_INDEX,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
    };
    ExecSqls(updateSql, store);
    MEDIA_DEBUG_LOG("UpdateYearMonthDayData end");
}

void FixIndexOrder(RdbStore &store)
{
    const vector<string> updateSql = {
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_DATE_YEAR_INDEX,
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_DATE_MONTH_INDEX,
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_DATE_DAY_INDEX,
        "DROP INDEX IF EXISTS idx_media_type",
        "DROP INDEX IF EXISTS idx_sthp_dateadded",
        PhotoColumn::CREATE_YEAR_INDEX,
        PhotoColumn::CREATE_MONTH_INDEX,
        PhotoColumn::CREATE_DAY_INDEX,
        PhotoColumn::INDEX_SCTHP_ADDTIME,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_SCHPT_DAY_INDEX,
    };
    ExecSqls(updateSql, store);
}

void AddYearMonthDayColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_DATE_YEAR + " TEXT",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_DATE_MONTH + " TEXT",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_DATE_DAY + " TEXT",
    };
    ExecSqls(sqls, store);
}

void AddCleanFlagAndThumbStatus(RdbStore &store)
{
    const vector<string> addSyncStatus = {
        "DROP INDEX IF EXISTS idx_shpt_date_added",
        "DROP INDEX IF EXISTS idx_shpt_media_type",
        "DROP INDEX IF EXISTS idx_shpt_date_day",
        BaseColumn::AlterTableAddIntColumn(PhotoColumn::PHOTOS_TABLE, PhotoColumn::PHOTO_CLEAN_FLAG),
        BaseColumn::AlterTableAddIntColumn(PhotoColumn::PHOTOS_TABLE, PhotoColumn::PHOTO_THUMB_STATUS),
        PhotoColumn::INDEX_SCTHP_ADDTIME,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_SCHPT_DAY_INDEX,
    };
    int32_t result = ExecSqls(addSyncStatus, store);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb need clean and thumb status error %{private}d", result);
    }
}

void AddCloudIndex(RdbStore &store)
{
    const vector<string> sqls = {
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_CLOUD_ID_INDEX,
        PhotoColumn::CREATE_CLOUD_ID_INDEX,
    };
    ExecSqls(sqls, store);
}

static void AddPhotoEditTimeColumn(RdbStore &store)
{
    const string addEditTimeOnPhotos = "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
        " ADD COLUMN " + PhotoColumn::PHOTO_EDIT_TIME + " BIGINT DEFAULT 0";
    const vector<string> addEditTime = { addEditTimeOnPhotos };
    ExecSqls(addEditTime, store);
}

void AddShootingModeColumn(RdbStore &store)
{
    const std::string addShootringMode =
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
        PhotoColumn::PHOTO_SHOOTING_MODE + " TEXT";
    const vector<string> addShootingModeColumn = { addShootringMode };
    int32_t result = ExecSqls(addShootingModeColumn, store);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb shooting_mode error %{private}d", result);
    }
}

void AddShootingModeTagColumn(RdbStore &store)
{
    const std::string addShootringModeTag =
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
        PhotoColumn::PHOTO_SHOOTING_MODE_TAG + " TEXT";
    const std::string dropExpiredClearMapTrigger =
        "DROP TRIGGER IF EXISTS delete_photo_clear_map";
    const vector<string> addShootingModeTagColumn = {addShootringModeTag,
        dropExpiredClearMapTrigger, TriggerDeletePhotoClearMap()};
    int32_t result = ExecSqls(addShootingModeTagColumn, store);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb shooting_mode error %{private}d", result);
    }
}

static void AddHiddenViewColumn(RdbStore &store)
{
    vector<string> upgradeSqls = {
        BaseColumn::AlterTableAddIntColumn(PhotoAlbumColumns::TABLE, PhotoAlbumColumns::CONTAINS_HIDDEN),
        BaseColumn::AlterTableAddIntColumn(PhotoAlbumColumns::TABLE, PhotoAlbumColumns::HIDDEN_COUNT),
        BaseColumn::AlterTableAddTextColumn(PhotoAlbumColumns::TABLE, PhotoAlbumColumns::HIDDEN_COVER),
    };
    ExecSqls(upgradeSqls, store);
}

static void ModifyMdirtyTriggers(RdbStore &store)
{
    /* drop old mdirty trigger */
    const vector<string> dropMdirtyTriggers = {
        "DROP TRIGGER IF EXISTS photos_mdirty_trigger",
        "DROP TRIGGER IF EXISTS mdirty_trigger",
    };
    if (ExecSqls(dropMdirtyTriggers, store) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("upgrade fail: drop old mdirty trigger");
    }

    /* create new mdirty trigger */
    if (store.ExecuteSql(PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("upgrade fail: create new photos mdirty trigger");
    }

    if (store.ExecuteSql(CREATE_FILES_MDIRTY_TRIGGER) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("upgrade fail: create new mdirty trigger");
    }
}

static void AddLastVisitTimeColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + AudioColumn::AUDIOS_TABLE + " DROP time_visit ",
        "ALTER TABLE " + REMOTE_THUMBNAIL_TABLE + " DROP time_visit ",
        "ALTER TABLE " + MEDIALIBRARY_TABLE + " DROP time_visit ",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " DROP time_visit ",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
        PhotoColumn::PHOTO_LAST_VISIT_TIME + " BIGINT DEFAULT 0",
    };
    int32_t result = ExecSqls(sqls, store);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb last_visit_time error %{private}d", result);
    }
}

void AddHiddenTimeColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
            " ADD COLUMN " + PhotoColumn::PHOTO_HIDDEN_TIME + " BIGINT DEFAULT 0",
        PhotoColumn::CREATE_HIDDEN_TIME_INDEX,
    };
    ExecSqls(sqls, store);
}

void AddAlbumOrderColumn(RdbStore &store)
{
    const std::string addAlbumOrderColumn =
        "ALTER TABLE " + PhotoAlbumColumns::TABLE + " ADD COLUMN " +
        PhotoAlbumColumns::ALBUM_ORDER + " INT";
    const std::string initOriginOrder =
        "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
        PhotoAlbumColumns::ALBUM_ORDER + " = rowid";
    const std::string albumDeleteTrigger =
        " CREATE TRIGGER IF NOT EXISTS update_order_trigger AFTER DELETE ON " + PhotoAlbumColumns::TABLE +
        " FOR EACH ROW " +
        " BEGIN " +
        " UPDATE " + PhotoAlbumColumns::TABLE + " SET album_order = album_order - 1" +
        " WHERE album_order > old.album_order; " +
        " END";
    const std::string albumInsertTrigger =
        " CREATE TRIGGER IF NOT EXISTS insert_order_trigger AFTER INSERT ON " + PhotoAlbumColumns::TABLE +
        " BEGIN " +
        " UPDATE " + PhotoAlbumColumns::TABLE + " SET album_order = (" +
        " SELECT COALESCE(MAX(album_order), 0) + 1 FROM " + PhotoAlbumColumns::TABLE +
        ") WHERE rowid = new.rowid;" +
        " END";

    const vector<string> addAlbumOrder = { addAlbumOrderColumn, initOriginOrder,
        albumDeleteTrigger, albumInsertTrigger};
    int32_t result = ExecSqls(addAlbumOrder, store);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Upgrade rdb album order error %{private}d", result);
    }
}

static void AddFormMap(RdbStore &store)
{
    int32_t result = store.ExecuteSql(FormMap::CREATE_FORM_MAP_TABLE);
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to update PHOTOS");
    }
}

static void FixDocsPath(RdbStore &store)
{
    vector<string> sqls = {
        "UPDATE Files SET "
            " data = REPLACE(data, '/storage/cloud/files/Documents', '/storage/cloud/files/Docs/Documents'),"
            " data = REPLACE(data, '/storage/cloud/files/Download', '/storage/cloud/files/Docs/Download'),"
            " relative_path = REPLACE(relative_path, 'Documents/', 'Docs/Documents/'),"
            " relative_path = REPLACE(relative_path, 'Download/', 'Docs/Download/')"
        " WHERE data LIKE '/storage/cloud/files/Documents%' OR "
            " data LIKE '/storage/cloud/files/Download%' OR"
            " relative_path LIKE 'Documents/%' OR"
            " relative_path LIKE 'Download/%';",
        "UPDATE MediaTypeDirectory SET directory = 'Docs/' WHERE directory_type = 4 OR directory_type = 5",
    };

    ExecSqls(sqls, store);
}

static void AddImageVideoCount(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoAlbumColumns::TABLE +
                " ADD COLUMN " + PhotoAlbumColumns::ALBUM_IMAGE_COUNT + " INT DEFAULT 0",
        "ALTER TABLE " + PhotoAlbumColumns::TABLE +
                " ADD COLUMN " + PhotoAlbumColumns::ALBUM_VIDEO_COUNT + " INT DEFAULT 0",
    };
}

static void AddSCHPTHiddenTimeIndex(RdbStore &store)
{
    const vector<string> sqls = {
        PhotoColumn::CREATE_SCHPT_HIDDEN_TIME_INDEX,
    };
    ExecSqls(sqls, store);
}

static void UpdateClassifyDirtyData(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        DROP_TABLE_ANALYSISALBUM,
        DROP_TABLE_ANALYSISPHOTOMAP,
        ALTER_WIDTH_COLUMN,
        ALTER_HEIGHT_COLUMN,
        CREATE_ANALYSIS_ALBUM,
        CREATE_ANALYSIS_ALBUM_MAP,
        CREATE_TAB_IMAGE_FACE,
        CREATE_TAB_FACE_TAG,
        DROP_INSERT_VISION_TRIGGER,
        CREATE_INSERT_VISION_TRIGGER_FOR_ADD_FACE,
        ADD_FACE_STATUS_COLUMN,
        UPDATE_TOTAL_VALUE,
        UPDATE_NOT_SUPPORT_VALUE,
        CREATE_IMAGE_FACE_INDEX
    };
    MEDIA_INFO_LOG("start clear dirty data");
    ExecSqls(executeSqlStrs, store);
}

static void UpdateGeoTables(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE tab_geo_dictionary RENAME TO " +  GEO_DICTIONARY_TABLE,
        "ALTER TABLE tab_geo_knowledge RENAME TO " +  GEO_KNOWLEDGE_TABLE,
        CREATE_DICTIONARY_INDEX,
        CREATE_KNOWLEDGE_INDEX,
        CREATE_CITY_NAME_INDEX,
        CREATE_LOCATION_KEY_INDEX,
    };
    ExecSqls(sqls, store);
}

static void UpdatePhotosMdirtyTrigger(RdbStore& store)
{
    string dropSql = "DROP TRIGGER IF EXISTS photos_mdirty_trigger";
    if (store.ExecuteSql(dropSql) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to drop old photos_mdirty_trigger: %{private}s", dropSql.c_str());
        UpdateFail(__FILE__, __LINE__);
    }

    if (store.ExecuteSql(PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to upgrade new photos_mdirty_trigger, %{private}s",
            PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER.c_str());
    }
}

static void UpdateAlbumRefreshTable(RdbStore &store)
{
    const vector<string> sqls = {
        CREATE_ALBUM_REFRESH_TABLE,
    };
    ExecSqls(sqls, store);
}

static void UpdateFavoriteIndex(RdbStore &store)
{
    MEDIA_INFO_LOG("Upgrade rdb UpdateFavoriteIndex");
    const vector<string> sqls = {
        PhotoColumn::CREATE_PHOTO_FAVORITE_INDEX,
        PhotoColumn::DROP_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
    };
    ExecSqls(sqls, store);
}

static void AddMissingUpdates(RdbStore &store)
{
    MEDIA_INFO_LOG("start add missing updates");
    vector<string> sqls;
    bool hasShootingModeTag = MediaLibraryRdbStore::HasColumnInTable(store, PhotoColumn::PHOTO_SHOOTING_MODE_TAG,
        PhotoColumn::PHOTOS_TABLE);
    if (!hasShootingModeTag) {
        MEDIA_INFO_LOG("start add shooting mode tag");
        const vector<string> sqls = {
            "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_SHOOTING_MODE_TAG +
                " TEXT",
        };
        ExecSqls(sqls, store);
    }
    bool hasBundleName = MediaLibraryRdbStore::HasColumnInTable(store, PhotoAlbumColumns::ALBUM_BUNDLE_NAME,
        PhotoAlbumColumns::TABLE);
    bool hasLocalLanguage = MediaLibraryRdbStore::HasColumnInTable(store, PhotoAlbumColumns::ALBUM_LOCAL_LANGUAGE,
        PhotoAlbumColumns::TABLE);
    if (!hasBundleName) {
        MoveSourceAlbumToPhotoAlbumAndAddColumns(store);
        ModifySourceAlbumTriggers(store);
    } else if (!hasLocalLanguage) {
        ModifySourceAlbumTriggers(store);
    } else {
        MEDIA_INFO_LOG("both columns exist, no need to start source album related updates");
    }
    MEDIA_INFO_LOG("start add cloud index");
    AddCloudIndex(store);
    MEDIA_INFO_LOG("start update photos mdirty trigger");
    UpdatePhotosMdirtyTrigger(store);
    MEDIA_INFO_LOG("end add missing updates");
}

void AddMultiStagesCaptureColumns(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_ID + " TEXT",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_QUALITY + " INT",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_FIRST_VISIT_TIME +
            " BIGINT DEFAULT 0",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_DEFERRED_PROC_TYPE +
            " INT DEFAULT 0",
    };
    ExecSqls(sqls, store);
}

void UpdateMillisecondDate(RdbStore &store)
{
    MEDIA_DEBUG_LOG("UpdateMillisecondDate start");
    const vector<string> updateSql = {
        "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
        MediaColumn::MEDIA_DATE_ADDED + " = " + MediaColumn::MEDIA_DATE_ADDED + "*1000," +
        MediaColumn::MEDIA_DATE_MODIFIED + " = " + MediaColumn::MEDIA_DATE_MODIFIED + "*1000," +
        MediaColumn::MEDIA_DATE_TRASHED + " = " + MediaColumn::MEDIA_DATE_TRASHED + "*1000;",
        "UPDATE " + AudioColumn::AUDIOS_TABLE + " SET " +
        MediaColumn::MEDIA_DATE_ADDED + " = " + MediaColumn::MEDIA_DATE_ADDED + "*1000," +
        MediaColumn::MEDIA_DATE_MODIFIED + " = " + MediaColumn::MEDIA_DATE_MODIFIED + "*1000," +
        MediaColumn::MEDIA_DATE_TRASHED + " = " + MediaColumn::MEDIA_DATE_TRASHED + "*1000;",
        "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
        MediaColumn::MEDIA_DATE_MODIFIED + " = " +  MediaColumn::MEDIA_DATE_MODIFIED + "*1000;",
        "UPDATE " + MEDIALIBRARY_TABLE + " SET " +
        MediaColumn::MEDIA_DATE_ADDED + " = " + MediaColumn::MEDIA_DATE_ADDED + "*1000," +
        MediaColumn::MEDIA_DATE_MODIFIED + " = " + MediaColumn::MEDIA_DATE_MODIFIED + "*1000;",
    };
    ExecSqls(updateSql, store);
    MEDIA_DEBUG_LOG("UpdateMillisecondDate end");
}

void AddHasAstcColumns(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_HAS_ASTC + " INT DEFAULT 0 ",
    };
    ExecSqls(sqls, store);
}

void AddAddressDescriptionColumns(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + CITY_NAME + " TEXT",
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + ADDRESS_DESCRIPTION + " TEXT",
    };
    ExecSqls(sqls, store);
}

void AddIsLocalAlbum(RdbStore &store)
{
    const vector<string> sqls = {
        ADD_IS_LOCAL_COLUMN_FOR_ALBUM,
        ADD_PHOTO_ALBUM_IS_LOCAL,
    };
    MEDIA_INFO_LOG("start add islocal column");
    ExecSqls(sqls, store);
}

void AddStoryTables(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        CREATE_HIGHLIGHT_ALBUM_TABLE,
        CREATE_HIGHLIGHT_COVER_INFO_TABLE,
        CREATE_HIGHLIGHT_PLAY_INFO_TABLE,
        CREATE_USER_PHOTOGRAPHY_INFO_TABLE,
        "ALTER TABLE " + VISION_LABEL_TABLE + " ADD COLUMN " + SALIENCY_SUB_PROB + " TEXT",
    };
    MEDIA_INFO_LOG("start init story db");
    ExecSqls(executeSqlStrs, store);
}

void UpdateHighlightTables(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS tab_story_album",
        "DROP TABLE IF EXISTS tab_story_cover_info",
        "DROP TABLE IF EXISTS tab_story_play_info",
        CREATE_HIGHLIGHT_ALBUM_TABLE,
        CREATE_HIGHLIGHT_COVER_INFO_TABLE,
        CREATE_HIGHLIGHT_PLAY_INFO_TABLE,
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + LOCATION_TYPE + " TEXT",
    };
    MEDIA_INFO_LOG("update highlight db");
    ExecSqls(executeSqlStrs, store);
}

void UpdateHighlightCoverTables(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS tab_highlight_cover_info",
        CREATE_HIGHLIGHT_COVER_INFO_TABLE,
    };
    MEDIA_INFO_LOG("update highlight cover db");
    ExecSqls(executeSqlStrs, store);
}

void AddBussinessRecordAlbum(RdbStore &store)
{
    string updateDirtyForShootingMode = "UPDATE Photos SET dirty = 2 WHERE cloud_id is not null AND " +
        PhotoColumn::PHOTO_SHOOTING_MODE + " is not null AND " +
        PhotoColumn::PHOTO_SHOOTING_MODE + " != ''";
    const vector<string> sqls = {
        MedialibraryBusinessRecordColumn::CREATE_TABLE,
        MedialibraryBusinessRecordColumn::CREATE_BUSINESS_KEY_INDEX,
        updateDirtyForShootingMode,
    };

    MEDIA_INFO_LOG("start add bussiness record album");
    ExecSqls(sqls, store);
    UpdatePhotosMdirtyTrigger(store);
}

void AddIsCoverSatisfiedColumn(RdbStore &store)
{
    const vector<string> sqls = {
        ADD_IS_COVER_SATISFIED_FOR_ALBUM,
    };
    ExecSqls(sqls, store);
}

void AddOwnerAppId(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + MediaColumn::MEDIA_OWNER_APPID + " TEXT",
        "ALTER TABLE " + AudioColumn::AUDIOS_TABLE + " ADD COLUMN " + MediaColumn::MEDIA_OWNER_APPID + " TEXT"
    };
    MEDIA_INFO_LOG("start add owner_appid column");
    ExecSqls(sqls, store);
}

static void UpgradeOtherTable(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_PACKAGE_NAME) {
        AddPackageNameColumnOnTables(store);
    }

    if (oldVersion < VERSION_ADD_CLOUD_ALBUM) {
        UpdateCloudAlbum(store);
    }

    if (oldVersion < VERSION_ADD_CAMERA_SHOT_KEY) {
        AddCameraShotKey(store);
    }

    if (oldVersion < VERSION_REMOVE_ALBUM_COUNT_TRIGGER) {
        RemoveAlbumCountTrigger(store);
    }

    if (oldVersion < VERSION_ADD_ALL_EXIF) {
        AddExifAndUserComment(store);
    }

    if (oldVersion < VERSION_ADD_UPDATE_CLOUD_SYNC_TRIGGER) {
        AddUpdateCloudSyncTrigger(store);
    }

    if (oldVersion < VERSION_ADD_YEAR_MONTH_DAY) {
        AddYearMonthDayColumn(store);
    }

    if (oldVersion < VERSION_UPDATE_YEAR_MONTH_DAY) {
        UpdateYearMonthDayData(store);
    }

    if (oldVersion < VERSION_ADD_PHOTO_EDIT_TIME) {
        AddPhotoEditTimeColumn(store);
    }

    if (oldVersion < VERSION_ADD_SHOOTING_MODE) {
        AddShootingModeColumn(store);
    }

    if (oldVersion < VERSION_FIX_INDEX_ORDER) {
        FixIndexOrder(store);
    }

    if (oldVersion < VERSION_FIX_DOCS_PATH) {
        FixDocsPath(store);
    }
    if (oldVersion < VERSION_ADD_SHOOTING_MODE_TAG) {
        AddShootingModeTagColumn(store);
        PrepareShootingModeAlbum(store);
    }

    if (oldVersion < VERSION_ADD_PORTRAIT_IN_ALBUM) {
        AddPortraitInAnalysisAlbum(store);
    }

    if (oldVersion < VERSION_UPDATE_GEO_TABLE) {
        UpdateGeoTables(store);
    }

    if (oldVersion < VERSION_ADD_MULTISTAGES_CAPTURE) {
        AddMultiStagesCaptureColumns(store);
    }
}

static void UpgradeGalleryFeatureTable(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_HIDDEN_VIEW_COLUMNS) {
        AddHiddenViewColumn(store);
    }

    if (oldVersion < VERSION_ADD_LAST_VISIT_TIME) {
        ModifyMdirtyTriggers(store);
        AddLastVisitTimeColumn(store);
    }

    if (oldVersion < VERSION_ADD_HIDDEN_TIME) {
        AddHiddenTimeColumn(store);
    }

    if (oldVersion < VERSION_ADD_LOCATION_TABLE) {
        AddLocationTables(store);
    }

    if (oldVersion < VERSION_ADD_ALBUM_ORDER) {
        AddAlbumOrderColumn(store);
    }

    if (oldVersion < VERSION_ADD_FORM_MAP) {
        AddFormMap(store);
    }

    if (oldVersion < VERSION_UPDATE_LOCATION_TABLE) {
        UpdateLocationTables(store);
    }

    if (oldVersion < VERSION_ADD_IMAGE_VIDEO_COUNT) {
        AddImageVideoCount(store);
    }

    if (oldVersion < VERSION_ADD_SCHPT_HIDDEN_TIME_INDEX) {
        AddSCHPTHiddenTimeIndex(store);
    }

    if (oldVersion < VERSION_UPDATE_PHOTOS_MDIRTY_TRIGGER) {
        UpdatePhotosMdirtyTrigger(store);
    }

    if (oldVersion < VERSION_ALBUM_REFRESH) {
        UpdateAlbumRefreshTable(store);
    }

    if (oldVersion < VERSION_ADD_FAVORITE_INDEX) {
        UpdateFavoriteIndex(store);
    }

    if (oldVersion < VERSION_ADD_OWNER_APPID) {
        AddOwnerAppId(store);
    }
}

static void UpgradeVisionTable(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_VISION_TABLE) {
        AddAnalysisTables(store);
    }

    if (oldVersion < VERSION_ADD_FACE_TABLE) {
        AddFaceTables(store);
    }

    if (oldVersion < VERSION_ADD_SOURCE_ALBUM_TRIGGER) {
        AddSourceAlbumTrigger(store);
    }

    if (oldVersion < VERSION_ADD_VISION_ALBUM) {
        AddAnalysisAlbum(store);
    }

    if (oldVersion < VERSION_ADD_AESTHETIC_COMPOSITION_TABLE) {
        AddAestheticCompositionTables(store);
    }

    if (oldVersion < VERSION_ADD_SEARCH_TABLE) {
        AddSearchTable(store);
    }

    if (oldVersion < VERSION_ADD_SALIENCY_TABLE) {
        AddSaliencyTables(store);
    }

    if (oldVersion < VERSION_UPDATE_SOURCE_ALBUM_TRIGGER) {
        AddSourceAlbumTrigger(store);
    }

    if (oldVersion < VERSION_CLEAR_LABEL_DATA) {
        UpdateClassifyDirtyData(store);
    }

    if (oldVersion < VERSION_REOMOVE_SOURCE_ALBUM_TO_ANALYSIS) {
        RemoveSourceAlbumToAnalysis(store);
    }

    if (oldVersion < VERSION_UPDATE_DATE_TO_MILLISECOND) {
        UpdateMillisecondDate(store);
    }

    if (oldVersion < VERSION_ADD_HAS_ASTC) {
        AddHasAstcColumns(store);
    }

    if (oldVersion < VERSION_ADD_ADDRESS_DESCRIPTION) {
        AddAddressDescriptionColumns(store);
    }

    if (oldVersion < VERSION_UPDATE_SPEC_FOR_ADD_SCREENSHOT) {
        UpdateSpecForAddScreenshot(store);
    }

    if (oldVersion < VERSION_MOVE_SOURCE_ALBUM_TO_PHOTO_ALBUM_AND_ADD_COLUMNS) {
        MoveSourceAlbumToPhotoAlbumAndAddColumns(store);
    }

    if (oldVersion < VERSION_MODIFY_SOURCE_ALBUM_TRIGGERS) {
        ModifySourceAlbumTriggers(store);
    }
}

static void UpgradeExtendedVisionTable(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_HEAD_AND_POSE_TABLE) {
        AddHeadAndPoseTables(store);
    }

    if (oldVersion < VERSION_ADD_IS_COVER_SATISFIED_COLUMN) {
        AddIsCoverSatisfiedColumn(store);
    }

    if (oldVersion < VERSION_ADD_VIDEO_LABEL_TABEL) {
        AddVideoLabelTable(store);
    }

    if (oldVersion < VERSION_ADD_SEGMENTATION_COLUMNS) {
        AddSegmentationColumns(store);
    }
}

static void UpgradeAlbumTable(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_IS_LOCAL_ALBUM) {
        AddIsLocalAlbum(store);
    }
}

static void UpgradeHistory(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_MISSING_UPDATES) {
        AddMissingUpdates(store);
    }

    if (oldVersion < VERSION_UPDATE_MDIRTY_TRIGGER_FOR_SDIRTY) {
        UpdateMdirtyTriggerForSdirty(store);
    }

    if (oldVersion < VERSION_SHOOTING_MODE_CLOUD) {
        AddBussinessRecordAlbum(store);
    }
}

static void UpdatePhotosSearchUpdateTrigger(RdbStore& store)
{
    static const vector<string> executeSqlStrs = {
        "DROP TRIGGER IF EXISTS update_search_status_trigger",
        CREATE_SEARCH_UPDATE_STATUS_TRIGGER,
    };
    MEDIA_INFO_LOG("Start update photos search trigger");
    ExecSqls(executeSqlStrs, store);
}

static void CreatePhotosExtTable(RdbStore& store)
{
    static const vector<string> executeSqlStrs = {
        PhotoExtColumn::CREATE_PHOTO_EXT_TABLE
    };
    MEDIA_INFO_LOG("Start create photo ext table in update");
    ExecSqls(executeSqlStrs, store);
}

static void UpgradeExtension(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_STOYR_TABLE) {
        AddStoryTables(store);
    }

    if (oldVersion < VERSION_UPDATE_HIGHLIGHT_TABLE) {
        UpdateHighlightTables(store);
    }

    if (oldVersion < VERSION_UPDATE_SEARCH_INDEX) {
        UpdatePhotosSearchUpdateTrigger(store);
    }

    if (oldVersion < VERSION_UPDATE_HIGHLIGHT_COVER_TABLE) {
        UpdateHighlightCoverTables(store);
    }

    if (oldVersion < VERSION_CREATE_PHOTOS_EXT_TABLE) {
        CreatePhotosExtTable(store);
    }

    if (oldVersion < VERSION_UPDATE_VIDEO_LABEL_TABEL) {
        UpdateVideoLabelTable(store);
    }
}

static void CheckDateAdded(RdbStore &store)
{
    vector<string> sqls = {
        " UPDATE Photos "
        " SET date_added = "
            " CASE "
                " WHEN date_added = 0 AND date_taken = 0 AND date_modified = 0 THEN strftime('%s', 'now') "
                " WHEN date_added = 0 AND date_taken = 0 THEN date_modified "
                " WHEN date_added = 0 AND date_taken <> 0 THEN date_taken "
                " ELSE date_added "
            " END "
        " WHERE date_added = 0 OR strftime('%Y%m%d', date_added, 'unixepoch', 'localtime') <> date_day;",
        " UPDATE Photos "
        " SET "
            " date_year = strftime('%Y', date_added, 'unixepoch', 'localtime'), "
            " date_month = strftime('%Y%m', date_added, 'unixepoch', 'localtime'), "
            " date_day = strftime('%Y%m%d', date_added, 'unixepoch', 'localtime'), "
            " dirty = 2 "
        " WHERE date_added = 0 OR strftime('%Y%m%d', date_added, 'unixepoch', 'localtime') <> date_day;",
    };
    ExecSqls(sqls, store);
}

static void AlwaysCheck(RdbStore &store)
{
    CheckDateAdded(store);
}

int32_t MediaLibraryDataCallBack::OnUpgrade(RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
    MEDIA_DEBUG_LOG("OnUpgrade old:%d, new:%d", oldVersion, newVersion);
    g_upgradeErr = false;
    if (oldVersion < VERSION_ADD_CLOUD) {
        VersionAddCloud(store);
    }

    if (oldVersion < VERSION_ADD_META_MODIFED) {
        AddMetaModifiedColumn(store);
    }

    if (oldVersion < VERSION_MODIFY_SYNC_STATUS) {
        ModifySyncStatus(store);
    }

    if (oldVersion < VERSION_ADD_API10_TABLE) {
        API10TableCreate(store);
    }

    if (oldVersion < VERSION_MODIFY_DELETE_TRIGGER) {
        ModifyDeleteTrigger(store);
    }

    if (oldVersion < VERSION_ADD_CLOUD_VERSION) {
        AddCloudVersion(store);
    }

    if (oldVersion < VERSION_UPDATE_CLOUD_PATH) {
        UpdateCloudPath(store);
    }

    if (oldVersion < VERSION_UPDATE_API10_TABLE) {
        UpdateAPI10Table(store);
    }

    if (oldVersion < VERSION_ADD_TABLE_TYPE) {
        AddTableType(store);
    }

    if (oldVersion < VERSION_ADD_PHOTO_CLEAN_FLAG_AND_THUMB_STATUS) {
        AddCleanFlagAndThumbStatus(store);
    }

    if (oldVersion < VERSION_ADD_CLOUD_ID_INDEX) {
        AddCloudIndex(store);
    }

    UpgradeOtherTable(store, oldVersion);
    UpgradeGalleryFeatureTable(store, oldVersion);
    UpgradeVisionTable(store, oldVersion);
    UpgradeExtendedVisionTable(store, oldVersion);
    UpgradeAlbumTable(store, oldVersion);
    UpgradeHistory(store, oldVersion);

    AlwaysCheck(store);
    UpgradeExtension(store, oldVersion);
    if (!g_upgradeErr) {
        VariantMap map = {{KEY_PRE_VERSION, oldVersion}, {KEY_AFTER_VERSION, newVersion}};
        PostEventUtils::GetInstance().PostStatProcess(StatType::DB_UPGRADE_STAT, map);
    }
    return NativeRdb::E_OK;
}

bool MediaLibraryRdbStore::HasColumnInTable(RdbStore &store, const string &columnName, const string &tableName)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM pragma_table_info('" + tableName + "') WHERE name = '" +
        columnName + "'";
    auto resultSet = store.QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Get column count failed");
        return false;
    }
    int32_t count = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    MEDIA_DEBUG_LOG("%{private}s in %{private}s: %{public}d", columnName.c_str(), tableName.c_str(), count);
    return count > 0;
}

#ifdef DISTRIBUTED
MediaLibraryRdbStoreObserver::MediaLibraryRdbStoreObserver(const string &bundleName)
{
    bundleName_ = bundleName;
    isNotifyDeviceChange_ = false;

    if (timer_ == nullptr) {
        timer_ = make_unique<OHOS::Utils::Timer>(bundleName_);
        timerId_ = timer_->Register(bind(&MediaLibraryRdbStoreObserver::NotifyDeviceChange, this),
            NOTIFY_TIME_INTERVAL);
        timer_->Setup();
    }
}

MediaLibraryRdbStoreObserver::~MediaLibraryRdbStoreObserver()
{
    if (timer_ != nullptr) {
        timer_->Shutdown();
        timer_->Unregister(timerId_);
        timer_ = nullptr;
    }
}

void MediaLibraryRdbStoreObserver::OnChange(const vector<string> &devices)
{
    MEDIA_INFO_LOG("MediaLibraryRdbStoreObserver OnChange call");
    if (devices.empty() || bundleName_.empty()) {
        return;
    }
    MediaLibraryDevice::GetInstance()->NotifyRemoteFileChange();
}

void MediaLibraryRdbStoreObserver::NotifyDeviceChange()
{
    if (isNotifyDeviceChange_) {
        MediaLibraryDevice::GetInstance()->NotifyDeviceChange();
        isNotifyDeviceChange_ = false;
    }
}
#endif
} // namespace OHOS::Media
