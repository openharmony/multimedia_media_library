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

#include "album_plugin_table_event_handler.h"
#include "cloud_sync_helper.h"
#include "dfx_manager.h"
#include "dfx_timer.h"
#include "dfx_const.h"
#include "dfx_reporter.h"
#include "ipc_skeleton.h"
#include "location_column.h"
#include "media_column.h"
#include "media_app_uri_permission_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_remote_thumbnail_column.h"
#include "media_smart_album_column.h"
#ifdef DISTRIBUTED
#include "medialibrary_device.h"
#endif
#include "medialibrary_album_fusion_utils.h"
#include "medialibrary_album_compatibility_fusion_sql.h"
#include "medialibrary_album_refresh.h"
#include "medialibrary_business_record_column.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_restore.h"
#include "medialibrary_tracer.h"
#include "media_container_types.h"
#include "media_scanner.h"
#include "media_scanner_manager.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "parameters.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "post_event_utils.h"
#include "rdb_sql_utils.h"
#include "result_set_utils.h"
#include "source_album.h"
#include "vision_column.h"
#include "form_map.h"
#include "search_column.h"
#include "shooting_mode_column.h"
#include "story_db_sqls.h"
#include "dfx_const.h"
#include "dfx_timer.h"
#include "vision_multi_crop_column.h"
#include "preferences.h"
#include "preferences_helper.h"

using namespace std;
using namespace OHOS::NativeRdb;
namespace OHOS::Media {
const std::string DIR_ALL_AUDIO_CONTAINER_TYPE = "." + AUDIO_CONTAINER_TYPE_AAC + "?" +
                                                 "." + AUDIO_CONTAINER_TYPE_MP3 + "?" +
                                                 "." + AUDIO_CONTAINER_TYPE_FLAC + "?" +
                                                 "." + AUDIO_CONTAINER_TYPE_WAV + "?" +
                                                 "." + AUDIO_CONTAINER_TYPE_OGG + "?" +
                                                 "." + AUDIO_CONTAINER_TYPE_M4A + "?";

const std::string DIR_ALL_VIDEO_CONTAINER_TYPE = "." + VIDEO_CONTAINER_TYPE_MP4 + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_3GP + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_MPG + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_MOV + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_WEBM + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_MKV + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_H264 + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_MPEG + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_TS + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_M4V + "?" +
                                                 "." + VIDEO_CONTAINER_TYPE_3G2 + "?";

const std::string DIR_ALL_IMAGE_CONTAINER_TYPE = "." + IMAGE_CONTAINER_TYPE_BMP + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_BM + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_GIF + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_JPG + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_JPEG + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_JPE + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_PNG + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_WEBP + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_RAW + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_SVG + "?" +
                                                 "." + IMAGE_CONTAINER_TYPE_HEIF + "?";

const std::string CAMERA_EXTENSION_VALUES = DIR_ALL_IMAGE_CONTAINER_TYPE + DIR_ALL_VIDEO_CONTAINER_TYPE;

const std::string VIDEO_EXTENSION_VALUES = DIR_ALL_VIDEO_CONTAINER_TYPE;

const std::string PIC_EXTENSION_VALUES = DIR_ALL_IMAGE_CONTAINER_TYPE;

const std::string AUDIO_EXTENSION_VALUES = DIR_ALL_AUDIO_CONTAINER_TYPE;

const std::string RDB_CONFIG = "/data/storage/el2/base/preferences/rdb_config.xml";

const std::string RDB_OLD_VERSION = "rdb_old_version";

shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::rdbStore_;
int32_t oldVersion_ = -1;
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
    config_.SetHaMode(HAMode::MANUAL_TRIGGER);
    config_.SetAllowRebuild(true);
    config_.SetName(move(name));
    config_.SetPath(move(realPath));
    config_.SetBundleName(context->GetBundleName());
    config_.SetArea(context->GetArea());
    config_.SetSecurityLevel(SecurityLevel::S3);
    config_.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config_.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);
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

void MediaLibraryRdbStore::CreateBurstIndex(RdbStore &store)
{
    const vector<string> sqls = {
        PhotoColumn::DROP_SCHPT_DAY_INDEX,
        PhotoColumn::CREATE_SCHPT_DAY_INDEX,
        PhotoColumn::DROP_SCHPT_HIDDEN_TIME_INDEX,
        PhotoColumn::CREATE_SCHPT_HIDDEN_TIME_INDEX,
        PhotoColumn::DROP_PHOTO_FAVORITE_INDEX,
        PhotoColumn::CREATE_PHOTO_FAVORITE_INDEX,
        PhotoColumn::DROP_INDEX_SCTHP_ADDTIME,
        PhotoColumn::INDEX_SCTHP_ADDTIME,
        PhotoColumn::DROP_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_PHOTO_BURSTKEY_INDEX
    };
    MEDIA_INFO_LOG("start create idx_burstkey");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end create idx_burstkey");
}

void MediaLibraryRdbStore::UpdateBurstDirty(RdbStore &store)
{
    const vector<string> sqls = {
        "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_DIRTY + " = " +
        to_string(static_cast<int32_t>(DirtyTypes::TYPE_NEW)) + " WHERE " + PhotoColumn::PHOTO_SUBTYPE + " = " +
        to_string(static_cast<int32_t>(PhotoSubType::BURST)) + " AND " + PhotoColumn::PHOTO_DIRTY + " = -1 ",
    };
    MEDIA_INFO_LOG("start UpdateBurstDirty");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end UpdateBurstDirty");
}

void MediaLibraryRdbStore::UpdateReadyOnThumbnailUpgrade(RdbStore &store)
{
    const vector<string> sqls = {
        PhotoColumn::UPDATE_READY_ON_THUMBNAIL_UPGRADE,
    };
    MEDIA_INFO_LOG("start update ready for thumbnail upgrade");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("finish update ready for thumbnail upgrade");
}

void MediaLibraryRdbStore::UpdateDateTakenToMillionSecond(RdbStore &store)
{
    MEDIA_INFO_LOG("UpdateDateTakenToMillionSecond start");
    const vector<string> updateSql = {
        "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
            MediaColumn::MEDIA_DATE_TAKEN + " = " + MediaColumn::MEDIA_DATE_TAKEN +  "*1000 WHERE " +
            MediaColumn::MEDIA_DATE_TAKEN + " < 1e10",
    };
    ExecSqls(updateSql, store);
    MEDIA_INFO_LOG("UpdateDateTakenToMillionSecond end");
}

void MediaLibraryRdbStore::UpdateDateTakenIndex(RdbStore &store)
{
    const vector<string> sqls = {
        PhotoColumn::DROP_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::DROP_PHOTO_FAVORITE_INDEX,
        PhotoColumn::DROP_INDEX_SCTHP_ADDTIME,
        PhotoColumn::DROP_INDEX_SCHPT_READY,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_PHOTO_FAVORITE_INDEX,
        PhotoColumn::INDEX_SCTHP_ADDTIME,
        PhotoColumn::INDEX_SCHPT_READY,
    };
    MEDIA_INFO_LOG("update index for datetaken change start");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("update index for datetaken change end");
}

void MediaLibraryRdbStore::ClearAudios(RdbStore &store)
{
    const vector<string> sqls = {
        "DELETE From Audios",
    };
    MEDIA_INFO_LOG("clear audios start");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("clear audios end");
}

int32_t MediaLibraryRdbStore::Init()
{
    MEDIA_INFO_LOG("Init rdb store: [version: %{public}d]", MEDIA_RDB_VERSION);
    if (rdbStore_ != nullptr) {
        return E_OK;
    }

    int32_t errCode = 0;
    MediaLibraryDataCallBack rdbDataCallBack;
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::Init GetRdbStore");
    rdbStore_ = RdbHelper::GetRdbStore(config_, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    tracer.Finish();
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("GetRdbStore is failed ");
        return errCode;
    }
    MEDIA_INFO_LOG("MediaLibraryRdbStore::Init(), SUCCESS");
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
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }

    MEDIA_DEBUG_LOG("rdbStore_->Insert end, rowId = %d, ret = %{public}d", (int)rowId, ret);
    return ret;
}

int32_t MediaLibraryRdbStore::BatchInsert(int64_t &outRowId, const std::string &table,
    const std::vector<NativeRdb::ValuesBucket> &values)
{
    DfxTimer dfxTimer(DfxType::RDB_INSERT, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::BatchInsert");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->BatchInsert(outRowId, table, values);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->BatchInsert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }

    MEDIA_DEBUG_LOG("rdbStore_->BatchInsert end, rowId = %d, ret = %{public}d", (int)outRowId, ret);
    return ret;
}

int32_t MediaLibraryRdbStore::BatchInsert(MediaLibraryCommand &cmd, int64_t& outInsertNum,
    const std::vector<ValuesBucket>& values)
{
    DfxTimer dfxTimer(DfxType::RDB_BATCHINSERT, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::BatchInsert");
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int32_t ret = rdbStore_->BatchInsert(outInsertNum, cmd.GetTableName(), values);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->BatchInsert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    tracer.Finish();
    MEDIA_DEBUG_LOG("rdbStore_->BatchInsert end, rowId = %d, ret = %{public}d", (int)outInsertNum, ret);
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
        MEDIA_INFO_LOG("delete photos permanently, ret: %{public}d", ret);
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
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
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
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
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
    auto resultSet = rdbStore_->QuerySql(sql, args);
    MediaLibraryRestore::GetInstance().CheckResultSet(resultSet);
    return resultSet;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::GetIndexOfUriForPhotos(const AbsRdbPredicates &predicates,
    const vector<string> &columns, const string &id)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("GetIndexOfUriForPhotos");
    string sql;
    sql.append(RdbSqlUtils::BuildQueryString(predicates, columns));
    MEDIA_DEBUG_LOG("sql = %{private}s", sql.c_str());
    const vector<string> &args = predicates.GetWhereArgs();
    for (const auto &arg : args) {
        MEDIA_DEBUG_LOG("arg = %{private}s", arg.c_str());
    }
    auto resultSet = rdbStore_->QuerySql(sql, args);
    MediaLibraryRestore::GetInstance().CheckResultSet(resultSet);
    return resultSet;
}

int32_t MediaLibraryRdbStore::UpdateLastVisitTime(const string &id)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        return E_HAS_DB_ERROR;
    }
    MediaLibraryTracer tracer;
    tracer.Start("UpdateLastVisitTime");
    ValuesBucket values;
    int32_t changedRows = 0;
    values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, MediaFileUtils::UTCTimeMilliSeconds());
    string whereClause = MediaColumn::MEDIA_ID + " = ?";
    vector<string> whereArgs = {id};
    int32_t ret = rdbStore_->Update(changedRows, PhotoColumn::PHOTOS_TABLE, values, whereClause, whereArgs);
    if (ret != NativeRdb::E_OK || changedRows <= 0) {
        MEDIA_ERR_LOG("rdbStore_->UpdateLastVisitTime failed, changedRows = %{public}d, ret = %{public}d",
            changedRows, ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
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
    MEDIA_DEBUG_LOG("Predicates Statement is %{public}s", predicates.GetStatement().c_str());
    auto resultSet = rdbStore_->QueryByStep(predicates, columns);
    MediaLibraryRestore::GetInstance().CheckResultSet(resultSet);
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
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}

int32_t MediaLibraryRdbStore::QueryPragma(const string &key, int64_t &value)
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    std::shared_ptr<ResultSet> resultSet = rdbStore_->QuerySql("PRAGMA " + key);
    MediaLibraryRestore::GetInstance().CheckResultSet(resultSet);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->QuerySql failed");
        return E_HAS_DB_ERROR;
    }
    resultSet->GetLong(0, value);
    resultSet->Close();
    return E_OK;
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
        MediaLibraryRestore::GetInstance().CheckRestore(err);
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
        MediaLibraryRestore::GetInstance().CheckRestore(err);
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
        MediaLibraryRestore::GetInstance().CheckRestore(err);
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
    MediaLibraryRestore::GetInstance().CheckResultSet(resultSet);
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

int32_t PrepareAlbumPlugin(RdbStore &store)
{
    AlbumPluginTableEventHandler albumPluginTableEventHander;
    return albumPluginTableEventHander.OnCreate(store);
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
        int32_t insertResult = InsertDirValues(dirValuesBucket, store);
        if (insertResult != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("insert failed, insertResult: %{public}d", insertResult);
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

static const string &TriggerDeletePhotoClearAppUriPermission()
{
    static const string TRIGGER_PHOTO_DELETE_APP_URI_PERMISSION = BaseColumn::CreateTrigger() +
    "delete_photo_clear_App_uri_permission" + " AFTER DELETE ON " + PhotoColumn::PHOTOS_TABLE +
    " BEGIN " +
        "DELETE FROM " + AppUriPermissionColumn::APP_URI_PERMISSION_TABLE +
        " WHERE " + AppUriPermissionColumn::FILE_ID + "=" + "OLD." + MediaColumn::MEDIA_ID +
        " AND " + AppUriPermissionColumn::URI_TYPE + "=" + std::to_string(AppUriPermissionColumn::URI_PHOTO) + ";" +
    " END;";
    return TRIGGER_PHOTO_DELETE_APP_URI_PERMISSION;
}

static const string &TriggerDeleteAudioClearAppUriPermission()
{
    static const string TRIGGER_AUDIO_DELETE_APP_URI_PERMISSION = BaseColumn::CreateTrigger() +
    "delete_audio_clear_App_uri_permission" + " AFTER DELETE ON " + AudioColumn::AUDIOS_TABLE +
    " BEGIN " +
        "DELETE FROM " + AppUriPermissionColumn::APP_URI_PERMISSION_TABLE +
        " WHERE " + AppUriPermissionColumn::FILE_ID + "=" + "OLD." + MediaColumn::MEDIA_ID +
        " AND " + AppUriPermissionColumn::URI_TYPE + "=" + std::to_string(AppUriPermissionColumn::URI_AUDIO) + ";" +
    " END;";
    return TRIGGER_AUDIO_DELETE_APP_URI_PERMISSION;
}

static const vector<string> onCreateSqlStrs = {
    CREATE_MEDIA_TABLE,
    PhotoColumn::CREATE_PHOTO_TABLE,
    PhotoColumn::CREATE_CLOUD_ID_INDEX,
    PhotoColumn::INDEX_SCTHP_ADDTIME,
    PhotoColumn::INDEX_CAMERA_SHOT_KEY,
    PhotoColumn::INDEX_SCHPT_READY,
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
    CREATE_TAB_VIDEO_FACE,
    CREATE_TAB_FACE_TAG,
    CREATE_TAB_ANALYSIS_TOTAL_FOR_ONCREATE,
    CREATE_VISION_UPDATE_TRIGGER,
    CREATE_VISION_DELETE_TRIGGER,
    CREATE_VISION_INSERT_TRIGGER_FOR_ONCREATE,
    CREATE_IMAGE_FACE_INDEX,
    CREATE_VIDEO_FACE_INDEX,
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
    CREATE_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER,
    CREATE_INSERT_SOURCE_UPDATE_ALBUM_ID_TRIGGER,
    INSERT_PHOTO_UPDATE_ALBUM_BUNDLENAME,
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
    PhotoColumn::CREATE_PHOTO_DISPLAYNAME_INDEX,
    AppUriPermissionColumn::CREATE_APP_URI_PERMISSION_TABLE,
    AppUriPermissionColumn::CREATE_URI_URITYPE_APPID_INDEX,
    TriggerDeletePhotoClearAppUriPermission(),
    TriggerDeleteAudioClearAppUriPermission(),
    PhotoColumn::CREATE_PHOTO_BURSTKEY_INDEX,
    PhotoColumn::UPDATA_PHOTOS_DATA_UNIQUE,
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
    MEDIA_INFO_LOG("Rdb OnCreate");
    if (ExecuteSql(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareSystemAlbums(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

    if (PrepareAlbumPlugin(store) != NativeRdb::E_OK) {
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

    MediaLibraryRdbStore::SetOldVersion(MEDIA_RDB_VERSION);
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
        DROP_UPDATE_VISION_TRIGGER,
        CREATE_VISION_INSERT_TRIGGER_FOR_ADD_VIDEO_LABEL,
        CREATE_VISION_UPDATE_TRIGGER_FOR_ADD_VIDEO_LABEL,
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
    MediaLibraryRdbUtils::UpdateSourceAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
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

static void AddFaceOcclusionAndPoseTypeColumn(RdbStore &store)
{
    MEDIA_INFO_LOG("start add face occlusion and pose type column");
    MediaLibraryRdbStore::AddColumnIfNotExists(store, FACE_OCCLUSION, "INT", VISION_IMAGE_FACE_TABLE);
    MediaLibraryRdbStore::AddColumnIfNotExists(store, POSE_TYPE, "INT", VISION_POSE_TABLE);
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

static void UpdateInsertPhotoUpdateAlbumTrigger(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        INSERT_PHOTO_UPDATE_ALBUM_BUNDLENAME,
    };
    MEDIA_INFO_LOG("start update insert photo update album");
    ExecSqls(executeSqlStrs, store);
}

bool MediaLibraryRdbStore::ResetSearchTables()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return false;
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
    return true;
}

bool MediaLibraryRdbStore::ResetAnalysisTables()
{
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return false;
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
    AddFaceOcclusionAndPoseTypeColumn(*rdbStore_);
    AddVideoLabelTable(*rdbStore_);
    return true;
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

void UpdateAnalysisTables(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        "ALTER TABLE " + VISION_OCR_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_LABEL_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_VIDEO_LABEL_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_AESTHETICS_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_SALIENCY_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_OBJECT_TABLE + " ADD COLUMN " + SCALE_X + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_OBJECT_TABLE + " ADD COLUMN " + SCALE_Y + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_OBJECT_TABLE + " ADD COLUMN " + SCALE_WIDTH + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_OBJECT_TABLE + " ADD COLUMN " + SCALE_HEIGHT + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_OBJECT_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_RECOMMENDATION_TABLE + " ADD COLUMN " + SCALE_X + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_RECOMMENDATION_TABLE + " ADD COLUMN " + SCALE_Y + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_RECOMMENDATION_TABLE + " ADD COLUMN " + SCALE_WIDTH + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_RECOMMENDATION_TABLE + " ADD COLUMN " + SCALE_HEIGHT + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_RECOMMENDATION_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_SEGMENTATION_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_COMPOSITION_TABLE + " ADD COLUMN " + SCALE_X + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_COMPOSITION_TABLE + " ADD COLUMN " + SCALE_Y + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_COMPOSITION_TABLE + " ADD COLUMN " + SCALE_WIDTH + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_COMPOSITION_TABLE + " ADD COLUMN " + SCALE_HEIGHT + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_COMPOSITION_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_HEAD_TABLE + " ADD COLUMN " + SCALE_X + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_HEAD_TABLE + " ADD COLUMN " + SCALE_Y + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_HEAD_TABLE + " ADD COLUMN " + SCALE_WIDTH + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_HEAD_TABLE + " ADD COLUMN " + SCALE_HEIGHT + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_HEAD_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_POSE_TABLE + " ADD COLUMN " + SCALE_X + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_POSE_TABLE + " ADD COLUMN " + SCALE_Y + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_POSE_TABLE + " ADD COLUMN " + SCALE_WIDTH + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_POSE_TABLE + " ADD COLUMN " + SCALE_HEIGHT + " REAL DEFAULT 0 ",
        "ALTER TABLE " + VISION_POSE_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_IMAGE_FACE_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
        "ALTER TABLE " + VISION_FACE_TAG_TABLE + " ADD COLUMN " + ANALYSIS_VERSION + " TEXT ",
    };
    MEDIA_INFO_LOG("update analysis tables of db");
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

void UpdateHighlightTablePrimaryKey(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS tab_highlight_album",
        "DROP TABLE IF EXISTS tab_highlight_cover_info",
        CREATE_HIGHLIGHT_ALBUM_TABLE,
        CREATE_HIGHLIGHT_COVER_INFO_TABLE,
    };
    MEDIA_INFO_LOG("update primary key of highlight db");
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

void UpdateThumbnailReadyColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " RENAME COLUMN " + PhotoColumn::PHOTO_HAS_ASTC
            + " TO " + PhotoColumn::PHOTO_THUMBNAIL_READY,
    };
    MEDIA_INFO_LOG("update has_astc to thumbnail_ready begin");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("update has_astc to thumbnail_ready finished");
}

void AddOwnerAppIdToFiles(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + MEDIALIBRARY_TABLE + " ADD COLUMN " + MediaColumn::MEDIA_OWNER_APPID + " TEXT"
    };
    MEDIA_INFO_LOG("start add owner_appid column to files table");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("add owner_appid column to files table finished");
}

void AddDynamicRangeType(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE + " INT DEFAULT 0"
    };
    MEDIA_INFO_LOG("start add dynamic_range_type column");
    ExecSqls(sqls, store);
}

void AddLcdAndThumbSizeColumns(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_LCD_SIZE + " TEXT",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_THUMB_SIZE + " TEXT",
    };
    ExecSqls(sqls, store);
}

void UpdatePhotoAlbumTigger(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "DROP TRIGGER IF EXISTS album_modify_trigger",
        PhotoAlbumColumns::CREATE_ALBUM_MDIRTY_TRIGGER,
    };
    MEDIA_INFO_LOG("Start update album modify trigger");
    ExecSqls(executeSqlStrs, store);
}

static void AddMovingPhotoEffectMode(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::MOVING_PHOTO_EFFECT_MODE + " INT DEFAULT 0"
    };
    MEDIA_INFO_LOG("start add moving_photo_effect_mode column");
    ExecSqls(sqls, store);
}

void AddBurstCoverLevelAndBurstKey(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_BURST_COVER_LEVEL +
            " INT DEFAULT 1",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_BURST_KEY + " TEXT",
    };
    MEDIA_INFO_LOG("start add burst_cover_level and burst_key column");
    ExecSqls(sqls, store);
}

static void AddCloudEnhancementColumns(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_CE_AVAILABLE + " INT DEFAULT 0",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_CE_STATUS_CODE + " INT ",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_STRONG_ASSOCIATION + " INT DEFAULT 0",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_ASSOCIATE_FILE_ID + " INT DEFAULT 0",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK + " INT DEFAULT 0",
    };
    MEDIA_INFO_LOG("start add cloud enhancement columns");
    ExecSqls(sqls, store);
}

static void UpdateVisionTriggerForVideoLabel(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        DROP_UPDATE_VISION_TRIGGER,
        CREATE_VISION_UPDATE_TRIGGER_FOR_ADD_VIDEO_LABEL,
    };
    MEDIA_INFO_LOG("start update vision trigger for video label");
    ExecSqls(executeSqlStrs, store);
}

static void UpdateIndexForAlbumQuery(RdbStore &store)
{
    const vector<string> sqls = {
        PhotoColumn::DROP_INDEX_SCTHP_ADDTIME,
        PhotoColumn::INDEX_SCTHP_ADDTIME,
        PhotoColumn::DROP_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
    };
    MEDIA_INFO_LOG("start updating photo index");
    ExecSqls(sqls, store);
}

static void UpdateVideoLabelTableForSubLabelType(RdbStore &store)
{
    const vector<string> sqls = {
        "DROP TABLE IF EXISTS " + VISION_VIDEO_LABEL_TABLE,
        CREATE_TAB_ANALYSIS_VIDEO_LABEL,
        UPDATE_VIDEO_LABEL_TOTAL_VALUE,
        UPDATE_SEARCH_INDEX_FOR_VIDEO,
    };
    MEDIA_INFO_LOG("start update video label table for sub_label_type");
    ExecSqls(sqls, store);
}

static void UpdateDataAddedIndexWithFileId(RdbStore &store)
{
    const vector<string> sqls = {
        PhotoColumn::DROP_INDEX_SCTHP_ADDTIME,
        PhotoColumn::INDEX_SCTHP_ADDTIME,
    };
    MEDIA_INFO_LOG("start update index of date added with file desc");
    ExecSqls(sqls, store);
}

static void UpdateMultiCropInfo(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "ALTER TABLE " + VISION_RECOMMENDATION_TABLE + " ADD COLUMN " + MOVEMENT_CROP + " TEXT",
        "ALTER TABLE " + VISION_RECOMMENDATION_TABLE + " ADD COLUMN " + MOVEMENT_VERSION + " TEXT",
    };
    MEDIA_INFO_LOG("start update multi crop triggers");
    ExecSqls(executeSqlStrs, store);
}

static void UpdateSearchIndexTrigger(RdbStore &store)
{
    const vector<string> sqls = {
        "DROP TRIGGER IF EXISTS update_search_status_trigger",
        CREATE_SEARCH_UPDATE_STATUS_TRIGGER,
        "DROP TRIGGER IF EXISTS album_map_insert_search_trigger",
        CREATE_ALBUM_MAP_INSERT_SEARCH_TRIGGER,
        "DROP TRIGGER IF EXISTS album_map_delete_search_trigger",
        CREATE_ALBUM_MAP_DELETE_SEARCH_TRIGGER,
    };
    MEDIA_INFO_LOG("start update search index");
    ExecSqls(sqls, store);
}

static void AddOriginalSubtype(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_ORIGINAL_SUBTYPE + " INT"
    };
    MEDIA_INFO_LOG("start add original_subtype column");
    ExecSqls(sqls, store);
}

static void ReportFailInfoAsync(AsyncTaskData *data)
{
    MEDIA_INFO_LOG("Start ReportFailInfoAsync");
    const int32_t sleepTimeMs = 1000;
    this_thread::sleep_for(chrono::milliseconds(sleepTimeMs));
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("MediaDataAbility insert functionality rebStore is null.");
        return;
    }
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        MEDIA_ERR_LOG("MediaDataAbility insert functionality rdbStorePtr is null.");
        return;
    }

    string querySql = "SELECT data FROM Photos GROUP BY data HAVING COUNT(*) > 1";
    auto result = rdbStorePtr->QuerySql(querySql);
    int32_t count = 0;
    if (result == nullptr) {
        MEDIA_ERR_LOG("result is null");
        return;
    }
    if (result->GetRowCount(count) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetRowCount fail");
    }
    result->Close();
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    DfxReporter::ReportStartResult(DfxType::ADD_DATA_UNIQUE_INDEX_FAIL, count, startTime);
    bool ret = system::SetParameter("persist.multimedia.medialibrary.data_unique", "1");
    if (!ret) {
        MEDIA_ERR_LOG("Failed to set parameter, ret:%{public}d", ret);
    }
    MEDIA_INFO_LOG("HasDirtyData count:%{public}d", count);
}

static void ReportFailInfo()
{
    MEDIA_INFO_LOG("Start ReportFailInfo");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Failed to get async worker instance!");
        return;
    }
    shared_ptr<MediaLibraryAsyncTask> reportTask =
        make_shared<MediaLibraryAsyncTask>(ReportFailInfoAsync, nullptr);
    if (reportTask != nullptr) {
        asyncWorker->AddTask(reportTask, false);
    } else {
        MEDIA_ERR_LOG("Failed to create async task for reportTask!");
    }
}

static void UpdateDataUniqueIndex(RdbStore &store)
{
    MEDIA_INFO_LOG("Start UpdateDataUniqueIndex");
    string sql = PhotoColumn::UPDATA_PHOTOS_DATA_UNIQUE;
    auto err = store.ExecuteSql(sql);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to exec: %{public}s", sql.c_str());
        ReportFailInfo();
    }
    MEDIA_INFO_LOG("End UpdateDataUniqueIndex");
}

static void ResetCloudCursorAfterInitFinish()
{
    static uint32_t baseUserRange = 200000; // uid base offset
    uid_t uid = getuid() / baseUserRange;
    const string paramKey = "multimedia.medialibrary.startup." + to_string(uid);
    string value = "true";
    int32_t maxTryTimes = 10;
    int32_t checkTimes = 0;
    while (checkTimes < maxTryTimes) {
        std::string initStatus = system::GetParameter(paramKey.c_str(), "false");
        if (!initStatus.empty() && initStatus == "true") {
            MEDIA_INFO_LOG("Strat reset cloud cursor");
            FileManagement::CloudSync::CloudSyncManager::GetInstance().ResetCursor();
            MEDIA_INFO_LOG("End reset cloud cursor");
            break;
        }
        checkTimes++;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

static void ReconstructMediaLibraryStorageFormatExecutor(AsyncTaskData *data)
{
    if (data == nullptr) {
        return;
    }
    MediaLibraryAlbumFusionUtils::SetParameterToStopSync();
    CompensateAlbumIdData* compensateData = static_cast<CompensateAlbumIdData*>(data);
    MEDIA_INFO_LOG("ALBUM_FUSE: Processing old data start");
    MEDIA_INFO_LOG("ALBUM_FUSE: Compensating album id for old asset start");
    int64_t beginTime = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t cleanDataBeginTime = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t matchedDataHandleResult = MediaLibraryAlbumFusionUtils::HandleMatchedDataFusion(
        compensateData->upgradeStore_);
    if (matchedDataHandleResult != E_OK) {
        MEDIA_ERR_LOG("Fatal err, handle matched relationship fail by %{public}d", matchedDataHandleResult);
        // This should not happen, and if it does, should avoid cleaning up more data.
        return;
    }
    int32_t notMatchedDataHandleResult = MediaLibraryAlbumFusionUtils::HandleNotMatchedDataFusion(
        compensateData->upgradeStore_);
    if (notMatchedDataHandleResult != E_OK) {
        MEDIA_ERR_LOG("Fatal err, handle not matched relationship fail by %{public}d", notMatchedDataHandleResult);
        // This should not happen, and if it does, avoid cleaning up more data.
        return;
    }
    MEDIA_INFO_LOG("ALBUM_FUSE: End compensate album id for old asset cost %{public}ld",
        (long)(MediaFileUtils::UTCTimeMilliSeconds() - cleanDataBeginTime));
    MEDIA_INFO_LOG("ALBUM_FUSE: Start rebuild album and update relationship");
    int64_t albumCleanBeginTime = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t rebuildResult = MediaLibraryAlbumFusionUtils::RebuildAlbumAndFillCloudValue(compensateData->upgradeStore_);
    MEDIA_INFO_LOG("ALBUM_FUSE: End rebuild album and update relationship cost %{public}ld",
        (long)(MediaFileUtils::UTCTimeMilliSeconds() - albumCleanBeginTime));
    // Restore cloud sync
    MediaLibraryAlbumFusionUtils::SetParameterToStartSync();
    ResetCloudCursorAfterInitFinish();
    MediaLibraryRdbUtils::SetNeedRefreshAlbum(true);
    RefreshAlbums(true);
    MEDIA_INFO_LOG("ALBUM_FUSE: Processing old data start end, cost %{public}ld",
        (long)(MediaFileUtils::UTCTimeMilliSeconds() - beginTime));
}

static void AddOwnerAlbumIdAndRefractorTrigger(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_OWNER_ALBUM_ID + " INT DEFAULT 0",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_ORIGINAL_ASSET_CLOUD_ID + " TEXT",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_SOURCE_PATH + " TEXT",
        "DROP TABLE IF EXISTS album_plugin ",
        DROP_PHOTO_ALBUM_CLEAR_MAP_SQL,
        DROP_INSERT_PHOTO_INSERT_SOURCE_ALBUM_SQL,
        DROP_INSERT_PHOTO_UPDATE_SOURCE_ALBUM_SQL,
        DROP_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER,
        DROP_INSERT_SOURCE_PHOTO_UPDATE_ALBUM_ID_TRIGGER,
        "DROP TRIGGER IF EXISTS photos_mdirty_trigger",
        PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER,
        CREATE_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER,
        CREATE_INSERT_SOURCE_UPDATE_ALBUM_ID_TRIGGER,

    };
    MEDIA_INFO_LOG("Add owner_album_id column for Photos");
    ExecSqls(sqls, store);
}

static void AddMergeInfoColumnForAlbum(RdbStore &store)
{
    const vector<string> addMergeInfoSql = {
        "ALTER TABLE " + PhotoAlbumColumns::TABLE + " ADD COLUMN " +
        PhotoAlbumColumns::ALBUM_DATE_ADDED + " BIGINT DEFAULT 0",
        "ALTER TABLE " + PhotoAlbumColumns::TABLE + " ADD COLUMN " +
        PhotoAlbumColumns::ALBUM_PRIORITY + " INT",
        "ALTER TABLE " + PhotoAlbumColumns::TABLE + " ADD COLUMN " +
        PhotoAlbumColumns::ALBUM_LPATH + " TEXT",
        DROP_INDEX_SOURCE_ALBUM_INDEX,
        CREATE_SOURCE_ALBUM_INDEX,
        CREATE_DEFALUT_ALBUM_FOR_NO_RELATIONSHIP_ASSET,
    };
    MEDIA_INFO_LOG("Add merge info for PhotoAlbum");
    ExecSqls(addMergeInfoSql, store);
    const std::string queryHiddenAlbumId =
        "SELECT album_id FROM PhotoAlbum WHERE album_name = '.hiddenAlbum'";
    auto resultSet = store.QuerySql(queryHiddenAlbumId);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        int32_t err = store.ExecuteSql(CREATE_HIDDEN_ALBUM_FOR_DUAL_ASSET);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Failed to exec: %{private}s", CREATE_HIDDEN_ALBUM_FOR_DUAL_ASSET.c_str());
        }
    }
}

static int32_t ReconstructMediaLibraryStorageFormat(RdbStore &store)
{
    MEDIA_INFO_LOG("ALBUM_FUSE: Start reconstruct medialibrary storage format task!");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker ==  nullptr) {
        MEDIA_ERR_LOG("Failed to get aysnc worker instance!");
        return E_FAIL;
    }
    auto *taskData = new (std::nothrow) CompensateAlbumIdData(&store);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to alloc async data for compensate album id");
        return E_NO_MEMORY;
    }
    auto asyncTask = std::make_shared<MediaLibraryAsyncTask>(ReconstructMediaLibraryStorageFormatExecutor, taskData);
    asyncWorker->AddTask(asyncTask, false);
    return E_OK;
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
    // !! Do not add upgrade code here !!
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

    if (oldVersion < VERSION_ADD_DYNAMIC_RANGE_TYPE) {
        AddDynamicRangeType(store);
    }
    // !! Do not add upgrade code here !!
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
    // !! Do not add upgrade code here !!
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
    // !! Do not add upgrade code here !!
}

static void UpgradeAlbumTable(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_IS_LOCAL_ALBUM) {
        AddIsLocalAlbum(store);
    }
    // !! Do not add upgrade code here !!
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
    // !! Do not add upgrade code here !!
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

static void AddIsTemp(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_IS_TEMP + " INT DEFAULT 0"
    };
    MEDIA_INFO_LOG("Start add is_temp on Photos in upgrade");
    ExecSqls(executeSqlStrs, store);
}

static void AddIsTempToTrigger(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_SCHPT_DAY_INDEX,
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_SCHPT_MEDIA_TYPE_INDEX,
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_SCHPT_HIDDEN_TIME_INDEX,
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_FAVORITE_INDEX,
        "DROP INDEX IF EXISTS " + PhotoColumn::PHOTO_SCHPT_ADDED_INDEX,
        PhotoColumn::CREATE_SCHPT_DAY_INDEX,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_SCHPT_HIDDEN_TIME_INDEX,
        PhotoColumn::CREATE_PHOTO_FAVORITE_INDEX,
        PhotoColumn::INDEX_SCTHP_ADDTIME,
    };
    MEDIA_INFO_LOG("Add is_temp to trigger in upgrade");
    ExecSqls(executeSqlStrs, store);
}

static void AddFrontCameraType(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_FRONT_CAMERA + " TEXT"
    };
    MEDIA_INFO_LOG("Start add front column");
    ExecSqls(sqls, store);
}

static void AddDisplayNameIndex(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        PhotoColumn::CREATE_PHOTO_DISPLAYNAME_INDEX,
    };
    MEDIA_INFO_LOG("Add displayname index");
    ExecSqls(executeSqlStrs, store);
}

static void AddPortraitCoverSelectionColumn(RdbStore &store)
{
    MEDIA_INFO_LOG("Start add portrait cover selection column");

    const vector<string> sqls = {
        "ALTER TABLE " + VISION_IMAGE_FACE_TABLE + " ADD COLUMN " + BEAUTY_BOUNDER_X + " REAL",
        "ALTER TABLE " + VISION_IMAGE_FACE_TABLE + " ADD COLUMN " + BEAUTY_BOUNDER_Y + " REAL",
        "ALTER TABLE " + VISION_IMAGE_FACE_TABLE + " ADD COLUMN " + BEAUTY_BOUNDER_WIDTH + " REAL",
        "ALTER TABLE " + VISION_IMAGE_FACE_TABLE + " ADD COLUMN " + BEAUTY_BOUNDER_HEIGHT + " REAL",
        "ALTER TABLE " + VISION_IMAGE_FACE_TABLE + " ADD COLUMN " + FACE_AESTHETICS_SCORE + " REAL",
    };
    ExecSqls(sqls, store);
}

static void UpdatePortraitCoverSelectionColumns(RdbStore &store)
{
    MEDIA_INFO_LOG("Start update portrait cover selection columns");
 
    const vector<string> sqls = {
        "ALTER TABLE " + VISION_IMAGE_FACE_TABLE + " ADD COLUMN " + BEAUTY_BOUNDER_VERSION + " TEXT default '' ",
        "ALTER TABLE " + VISION_IMAGE_FACE_TABLE + " ADD COLUMN " + IS_EXCLUDED + " INT default 0 ",
    };
    ExecSqls(sqls, store);
}

static void AddAppUriPermissionInfo(RdbStore &store)
{
    const std::string SYNC_DATA_FROM_PHOTOS_SQL =
        "insert into "+ AppUriPermissionColumn::APP_URI_PERMISSION_TABLE + "(" +
        AppUriPermissionColumn::APP_ID + ", " + AppUriPermissionColumn::FILE_ID + ", " +
        AppUriPermissionColumn::URI_TYPE + ", " + AppUriPermissionColumn::PERMISSION_TYPE + ", " +
        AppUriPermissionColumn::DATE_MODIFIED + ") " +
        "select " +
        MediaColumn::MEDIA_OWNER_APPID + ", " + MediaColumn::MEDIA_ID + ", " +
        std::to_string(AppUriPermissionColumn::URI_PHOTO) + ", " +
        std::to_string(AppUriPermissionColumn::PERMISSION_PERSIST_READ_WRITE) + ", " +
        MediaColumn::MEDIA_DATE_ADDED +
        " from " + PhotoColumn::PHOTOS_TABLE +
        " where " + MediaColumn::MEDIA_OWNER_APPID + " is not null";

    const std::string SYNC_DATA_FROM_AUDIOS_SQL =
        "insert into "+ AppUriPermissionColumn::APP_URI_PERMISSION_TABLE + "(" +
        AppUriPermissionColumn::APP_ID + ", " + AppUriPermissionColumn::FILE_ID + ", " +
        AppUriPermissionColumn::URI_TYPE + ", " + AppUriPermissionColumn::PERMISSION_TYPE + ", " +
        AppUriPermissionColumn::DATE_MODIFIED + ") " +
        "select " +
        MediaColumn::MEDIA_OWNER_APPID + ", " + MediaColumn::MEDIA_ID + ", " +
        std::to_string(AppUriPermissionColumn::URI_AUDIO) + ", " +
        std::to_string(AppUriPermissionColumn::PERMISSION_PERSIST_READ_WRITE) + ", " +
        MediaColumn::MEDIA_DATE_ADDED +
        " from " + AudioColumn::AUDIOS_TABLE +
        " where " + MediaColumn::MEDIA_OWNER_APPID + " is not null";
    const vector<string> sqls = {
        AppUriPermissionColumn::CREATE_APP_URI_PERMISSION_TABLE,
        AppUriPermissionColumn::CREATE_URI_URITYPE_APPID_INDEX,
        SYNC_DATA_FROM_PHOTOS_SQL,
        SYNC_DATA_FROM_AUDIOS_SQL,
        TriggerDeletePhotoClearAppUriPermission(),
        TriggerDeleteAudioClearAppUriPermission(),
    };
    MEDIA_INFO_LOG("add uriPermission table info when upgrade phone");
    ExecSqls(sqls, store);
}

static void AddCoverPosition(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_COVER_POSITION +
            " BIGINT DEFAULT 0",
    };
    MEDIA_INFO_LOG("start add cover_position column");
    ExecSqls(sqls, store);
}

static void AddSchptReadyIndex(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        PhotoColumn::INDEX_SCHPT_READY,
    };
    MEDIA_INFO_LOG("Add schpt ready index");
    ExecSqls(executeSqlStrs, store);
}

static void UpdateSourceAlbumAndAlbumBundlenameTriggers(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        DROP_INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        DROP_INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        DROP_INSERT_PHOTO_UPDATE_ALBUM_BUNDLENAME,
        INSERT_PHOTO_INSERT_SOURCE_ALBUM,
        INSERT_PHOTO_UPDATE_SOURCE_ALBUM,
        INSERT_PHOTO_UPDATE_ALBUM_BUNDLENAME,
    };
    MEDIA_INFO_LOG("start update source album and album bundlename triggers");
    ExecSqls(executeSqlStrs, store);
}

static void AddDetailTimeToPhotos(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_DETAIL_TIME + " TEXT"
    };
    MEDIA_INFO_LOG("Add detail_time column start");
    ExecSqls(sqls, store);
}

static void AddVideoFaceTable(RdbStore &store)
{
    const vector<string> sqls = {
        CREATE_TAB_VIDEO_FACE,
        CREATE_VIDEO_FACE_INDEX,
        "ALTER TABLE " + VISION_TOTAL_TABLE + " ADD COLUMN " + GEO + " INT"
    };
    MEDIA_INFO_LOG("Add video face table start");
    ExecSqls(sqls, store);
}

static void UpgradeExtensionPart2(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_UPDATE_PHOTO_INDEX_FOR_ALBUM_COUNT_COVER) {
        UpdateIndexForAlbumQuery(store);
    }

    if (oldVersion < VERSION_UPDATE_VIDEO_LABEL_TABLE_FOR_SUB_LABEL_TYPE) {
        UpdateVideoLabelTableForSubLabelType(store);
    }

    // VERSION_UPGRADE_THUMBNAIL = 101 move to UpgradeRdbStoreAsync(), avoid to cost for long time.

    if (oldVersion < VISION_UPDATE_DATA_ADDED_INDEX) {
        UpdateDataAddedIndexWithFileId(store);
    }

    if (oldVersion < VISION_UPDATE_SEARCH_INDEX_TRIGGER) {
        UpdateSearchIndexTrigger(store);
    }

    if (oldVersion < VISION_UPDATE_MULTI_CROP_INFO) {
        UpdateMultiCropInfo(store);
    }

    if (oldVersion < VISION_ADD_ORIGINAL_SUBTYPE) {
        AddOriginalSubtype(store);
    }

    // VERSION_UPDATE_BURST_DIRTY = 106 move to UpgradeRdbStoreAsync(), avoid to cost for long time.

    if (oldVersion < VERSION_UDAPTE_DATA_UNIQUE) {
        UpdateDataUniqueIndex(store);
    }

    if (oldVersion < VERSION_ADD_DETAIL_TIME) {
        AddDetailTimeToPhotos(store);
    }

    if (oldVersion < VERSION_ADD_VIDEO_FACE_TABLE) {
        AddVideoFaceTable(store);
    }

    if (oldVersion < VERSION_ADD_OWNER_ALBUM_ID) {
        AddOwnerAlbumIdAndRefractorTrigger(store);
        AlbumPluginTableEventHandler albumPluginTableEventHandler;
        albumPluginTableEventHandler.OnUpgrade(store, oldVersion, oldVersion);
        AddMergeInfoColumnForAlbum(store);
        ReconstructMediaLibraryStorageFormat(store);
    }

    if (oldVersion < VERSION_CLOUD_ENAHCNEMENT) {
        AddCloudEnhancementColumns(store);
    }

    if (oldVersion < VERSION_UPDATE_MDIRTY_TRIGGER_FOR_UPLOADING_MOVING_PHOTO) {
        UpdatePhotosMdirtyTrigger(store);
    }
}

static void UpgradeExtensionPart1(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_OWNER_APPID_TO_FILES_TABLE) {
        AddOwnerAppIdToFiles(store);
    }

    if (oldVersion < VERSION_ADD_IS_TEMP_TO_TRIGGER) {
        AddIsTempToTrigger(store);
    }

    if (oldVersion < VERSION_UPDATE_ANALYSIS_TABLES) {
        UpdateAnalysisTables(store);
    }

    if (oldVersion < VERSION_UPDATE_PHOTO_THUMBNAIL_READY) {
        UpdateThumbnailReadyColumn(store);
    }

    if (oldVersion < VERSION_ADD_FRONT_CAMERA_TYPE) {
        AddFrontCameraType(store);
    }

    if (oldVersion < PHOTOS_CREATE_DISPLAYNAME_INDEX) {
        AddDisplayNameIndex(store);
    }

    if (oldVersion < VERSION_PORTRAIT_COVER_SELECTION_ADD_COLUMNS) {
        AddPortraitCoverSelectionColumn(store);
    }

    if (oldVersion < VERSION_ADD_BURST_COVER_LEVEL_AND_BURST_KEY) {
        AddBurstCoverLevelAndBurstKey(store);
    }

    if (oldVersion < VERSION_ADD_COVER_POSITION) {
        AddCoverPosition(store);
    }

    if (oldVersion < VERSION_ADD_SCHPT_READY_INEDX) {
        AddSchptReadyIndex(store);
    }

    if (oldVersion < VERSION_UPDATE_PORTRAIT_COVER_SELECTION_COLUMNS) {
        UpdatePortraitCoverSelectionColumns(store);
    }
    
    if (oldVersion < VERSION_ADD_APP_URI_PERMISSION_INFO) {
        AddAppUriPermissionInfo(store);
    }

    if (oldVersion < VERSION_UPDATE_SOURCE_ALBUM_AND_ALBUM_BUNDLENAME_TRIGGERS) {
        UpdateSourceAlbumAndAlbumBundlenameTriggers(store);
    }

    // VERSION_CREATE_BURSTKEY_INDEX = 98 move to UpgradeRdbStoreAsync(), avoid to cost for long time.

    UpgradeExtensionPart2(store, oldVersion);
    // !! Do not add upgrade code here !!
}

static void CreatePhotosExtTable(RdbStore &store)
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

    if (oldVersion < VERSION_ADD_FACE_OCCLUSION_AND_POSE_TYPE_COLUMN) {
        AddFaceOcclusionAndPoseTypeColumn(store);
    }

    if (oldVersion < VERSION_UPDATE_PHOTO_ALBUM_BUNDLENAME) {
        UpdateInsertPhotoUpdateAlbumTrigger(store);
    }

    if (oldVersion < VERSION_UPDATE_PHOTO_ALBUM_TIGGER) {
        UpdatePhotoAlbumTigger(store);
    }

    if (oldVersion < VERSION_ADD_THUMB_LCD_SIZE_COLUMN) {
        AddLcdAndThumbSizeColumns(store);
    }

    if (oldVersion < VERSION_UPDATE_HIGHLIGHT_TABLE_PRIMARY_KEY) {
        UpdateHighlightTablePrimaryKey(store);
    }

    if (oldVersion < VERSION_ADD_MOVING_PHOTO_EFFECT_MODE) {
        AddMovingPhotoEffectMode(store);
    }

    if (oldVersion < VERSION_UPDATE_VISION_TRIGGER_FOR_VIDEO_LABEL) {
        UpdateVisionTriggerForVideoLabel(store);
    }

    if (oldVersion < VERSION_ADD_IS_TEMP) {
        AddIsTemp(store);
    }

    UpgradeExtensionPart1(store, oldVersion);
    // !! Do not add upgrade code here !!
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
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryDataCallBack::OnUpgrade");
    if (MediaLibraryRdbStore::GetOldVersion() == -1) {
        MediaLibraryRdbStore::SetOldVersion(oldVersion);
    }
    MEDIA_INFO_LOG("OnUpgrade old:%{public}d, new:%{public}d", oldVersion, newVersion);
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
    UpgradeExtension(store, oldVersion);

    AlwaysCheck(store);
    if (!g_upgradeErr) {
        VariantMap map = {{KEY_PRE_VERSION, oldVersion}, {KEY_AFTER_VERSION, newVersion}};
        PostEventUtils::GetInstance().PostStatProcess(StatType::DB_UPGRADE_STAT, map);
    }
    return NativeRdb::E_OK;
}

void MediaLibraryRdbStore::SetOldVersion(int32_t oldVersion)
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(RDB_CONFIG, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    prefs->PutInt(RDB_OLD_VERSION, oldVersion);
    prefs->FlushSync();
}

int32_t MediaLibraryRdbStore::GetOldVersion()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(RDB_CONFIG, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return oldVersion_;
    }
    return prefs->GetInt(RDB_OLD_VERSION, oldVersion_);
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

void MediaLibraryRdbStore::AddColumnIfNotExists(
    RdbStore &store, const string &columnName, const string &columnType, const string &tableName)
{
    if (!HasColumnInTable(store, columnName, tableName)) {
        string sql = "ALTER TABLE " + tableName + " ADD COLUMN " + columnName + " " + columnType;
        store.ExecuteSql(sql);
    }
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
