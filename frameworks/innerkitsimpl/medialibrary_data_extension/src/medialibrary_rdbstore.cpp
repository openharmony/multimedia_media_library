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
#include <regex>

#include "album_plugin_table_event_handler.h"
#include "cloud_sync_helper.h"
#include "custom_records_column.h"
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
#include "medialibrary_album_fusion_utils.h"
#include "medialibrary_album_compatibility_fusion_sql.h"
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
#ifdef META_RECOVERY_SUPPORT
#include "medialibrary_meta_recovery.h"
#endif
#include "medialibrary_notify.h"
#include "medialibrary_operation_record.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "moving_photo_processor.h"
#include "parameters.h"
#include "parameter.h"
#include "photo_album_column.h"
#include "photo_file_utils.h"
#include "photo_map_column.h"
#include "post_event_utils.h"
#include "rdb_sql_utils.h"
#include "result_set_utils.h"
#include "source_album.h"
#include "tab_old_photos_table_event_handler.h"
#include "tab_facard_photos_table_event_handler.h"
#include "vision_column.h"
#include "vision_ocr_column.h"
#include "form_map.h"
#include "search_column.h"
#include "shooting_mode_column.h"
#include "story_cover_info_column.h"
#include "story_db_sqls.h"
#include "story_play_info_column.h"
#include "dfx_const.h"
#include "dfx_timer.h"
#include "vision_multi_crop_column.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "thumbnail_service.h"
#include "medialibrary_rdb_transaction.h"
#include "table_event_handler.h"

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

constexpr ssize_t RDB_WAL_LIMIT_SIZE = 1024 * 1024 * 1024; /* default wal file maximum size : 1GB */
constexpr ssize_t RDB_CHECK_WAL_SIZE = 50 * 1024 * 1024;   /* check wal file size : 50MB */
std::mutex MediaLibraryRdbStore::walCheckPointMutex_;

shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::rdbStore_;

std::mutex MediaLibraryRdbStore::reconstructLock_;

int32_t oldVersion_ = -1;

const int TRASH_ALBUM_TYPE_VALUES = 2;
const std::string TRASH_ALBUM_NAME_VALUES = "TrashAlbum";
struct UniqueMemberValuesBucket {
    std::string assetMediaType;
    int32_t startNumber;
};


struct ShootingModeValueBucket {
    int32_t albumType;
    int32_t albumSubType;
    std::string albumName;
};

static int32_t ExecSqlWithRetry(std::function<int32_t()> execSql)
{
    int32_t currentTime = 0;
    int32_t busyRetryTime = 0;
    int32_t err = NativeRdb::E_OK;
    bool isSkipCloudSync = false;
    while (busyRetryTime < MAX_BUSY_TRY_TIMES && currentTime <= MAX_TRY_TIMES) {
        err = execSql();
        if (err == NativeRdb::E_OK) {
            break;
        } else if (err == NativeRdb::E_SQLITE_LOCKED) {
            std::this_thread::sleep_for(std::chrono::milliseconds(TRANSACTION_WAIT_INTERVAL));
            currentTime++;
            MEDIA_ERR_LOG("execSql busy, err: %{public}d, currentTime: %{public}d", err, currentTime);
        } else if (err == NativeRdb::E_SQLITE_BUSY || err == NativeRdb::E_DATABASE_BUSY) {
            busyRetryTime++;
            MEDIA_ERR_LOG("execSql busy, err:%{public}d, busyRetryTime:%{public}d", err, busyRetryTime);
            if (err == NativeRdb::E_SQLITE_BUSY && !isSkipCloudSync) {
                MEDIA_INFO_LOG("Stop cloud sync");
                FileManagement::CloudSync::CloudSyncManager::GetInstance()
                    .StopSync("com.ohos.medialibrary.medialibrarydata");
                isSkipCloudSync = true;
            }
        } else {
            MEDIA_ERR_LOG("execSql failed, err: %{public}d, currentTime: %{public}d", err, currentTime);
            break;
        }
    }
    if (isSkipCloudSync) {
        MEDIA_INFO_LOG("recover cloud sync after execsql busy");
        CloudSyncHelper::GetInstance()->StartSync();
    }
    return err;
}

const std::string MediaLibraryRdbStore::CloudSyncTriggerFunc(const std::vector<std::string> &args)
{
    CloudSyncHelper::GetInstance()->StartSync();
    return "";
}

const std::string MediaLibraryRdbStore::BeginGenerateHighlightThumbnail(const std::vector<std::string> &args)
{
    if (args.size() < STAMP_PARAM || args[STAMP_PARAM_ZERO].empty() || args[STAMP_PARAM_ONE].empty() ||
        args[STAMP_PARAM_TWO].empty() || args[STAMP_PARAM_THREE].empty()) {
            MEDIA_ERR_LOG("Invalid input: args must contain at least 4 non-empty strings");
            return "";
    }
    std::string id = args[STAMP_PARAM_ZERO].c_str();
    std::string tracks = args[STAMP_PARAM_ONE].c_str();
    std::string trigger = args[STAMP_PARAM_TWO].c_str();
    std::string genType = args[STAMP_PARAM_THREE].c_str();
    MEDIA_INFO_LOG("id = %{public}s, tracks = %{public}s, trigger = %{public}s", id.c_str(),
        tracks.c_str(), trigger.c_str());
    ThumbnailService::GetInstance()->TriggerHighlightThumbnail(id, tracks, trigger, genType);
    return "";
}

const std::string MediaLibraryRdbStore::IsCallerSelfFunc(const std::vector<std::string> &args)
{
    return "true";
}

constexpr int REGEXP_REPLACE_PARAM_NUM = 3;
const std::string MediaLibraryRdbStore::RegexReplaceFunc(const std::vector<std::string> &args)
{
    if (args.size() < REGEXP_REPLACE_PARAM_NUM) {
        MEDIA_ERR_LOG("Invalid arg count %{public}zu: args must contain at least 3 strings", args.size());
        return "";
    }
    const std::string &input = args[0];
    const std::string &pattern = args[1];
    const std::string &replacement = args[2];

    std::regex re(pattern);
    return std::regex_replace(input, re, replacement);
}

const std::string MediaLibraryRdbStore::PhotoAlbumNotifyFunc(const std::vector<std::string> &args)
{
    if (args.size() < 1) {
        MEDIA_ERR_LOG("Invalid input: args must contain at least 1 strings");
        return "";
    }

    std::string albumId = args[0].c_str();
    if (!all_of(albumId.begin(), albumId.end(), ::isdigit)) {
        MEDIA_ERR_LOG("Invalid albunId PhotoAlbumNotifyFunc Abortion");
        return "";
    }

    MEDIA_DEBUG_LOG("albumId = %{public}s", albumId.c_str());
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_RET_LOG(watch != nullptr, "", "Failed to get MediaLibraryNotify");
    watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX, albumId),
        NotifyType::NOTIFY_ADD);
    return "";
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
    config_.SetScalarFunction("REGEXP_REPLACE", REGEXP_REPLACE_PARAM_NUM, RegexReplaceFunc);
    config_.SetScalarFunction("begin_generate_highlight_thumbnail", STAMP_PARAM, BeginGenerateHighlightThumbnail);
    config_.SetWalLimitSize(RDB_WAL_LIMIT_SIZE);
    config_.SetScalarFunction("photo_album_notify_func", 1, PhotoAlbumNotifyFunc);
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
        err = ExecSqlWithRetry([&]() { return store.ExecuteSql(sql); });
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Failed to exec: %{private}s", sql.c_str());
            /* try update as much as possible */
            UpdateFail(__FILE__, __LINE__);
            continue;
        }
    }
    return NativeRdb::E_OK;
}

void MediaLibraryRdbStore::CreateBurstIndex(const shared_ptr<MediaLibraryRdbStore> store)
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
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end create idx_burstkey");
}

void MediaLibraryRdbStore::UpdateBurstDirty(const shared_ptr<MediaLibraryRdbStore> store)
{
    const vector<string> sqls = {
        "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_DIRTY + " = " +
        to_string(static_cast<int32_t>(DirtyTypes::TYPE_NEW)) + " WHERE " + PhotoColumn::PHOTO_SUBTYPE + " = " +
        to_string(static_cast<int32_t>(PhotoSubType::BURST)) + " AND " + PhotoColumn::PHOTO_DIRTY + " = -1 ",
    };
    MEDIA_INFO_LOG("start UpdateBurstDirty");
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end UpdateBurstDirty");
}

void MediaLibraryRdbStore::UpdateReadyOnThumbnailUpgrade(const shared_ptr<MediaLibraryRdbStore> store)
{
    const vector<string> sqls = {
        PhotoColumn::UPDATE_READY_ON_THUMBNAIL_UPGRADE,
    };
    MEDIA_INFO_LOG("start update ready for thumbnail upgrade");
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("finish update ready for thumbnail upgrade");
}

void MediaLibraryRdbStore::UpdateDateTakenToMillionSecond(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("UpdateDateTakenToMillionSecond start");
    const vector<string> updateSql = {
        "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " +
            MediaColumn::MEDIA_DATE_TAKEN + " = " + MediaColumn::MEDIA_DATE_TAKEN +  "*1000 WHERE " +
            MediaColumn::MEDIA_DATE_TAKEN + " < 1e10",
    };
    ExecSqls(updateSql, *store->GetRaw().get());
    MEDIA_INFO_LOG("UpdateDateTakenToMillionSecond end");
}

void MediaLibraryRdbStore::UpdateDateTakenIndex(const shared_ptr<MediaLibraryRdbStore> store)
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
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("update index for datetaken change end");
}

void MediaLibraryRdbStore::UpdateDateTakenAndDetalTime(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("UpdateDateTakenAndDetalTime start");
    string updateDateTakenSql = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + MediaColumn::MEDIA_DATE_TAKEN +
            " = " + PhotoColumn::MEDIA_DATE_MODIFIED + "," + PhotoColumn::PHOTO_DETAIL_TIME +
            " = strftime('%Y:%m:%d %H:%M:%S', " + MediaColumn::MEDIA_DATE_MODIFIED +
            "/1000, 'unixepoch', 'localtime')" + " WHERE " + MediaColumn::MEDIA_DATE_TAKEN + " = 0";
    string updateDetalTimeSql = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_DETAIL_TIME +
            " = strftime('%Y:%m:%d %H:%M:%S', " + MediaColumn::MEDIA_DATE_TAKEN + "/1000, 'unixepoch', 'localtime')" +
            " WHERE " + PhotoColumn::PHOTO_DETAIL_TIME + " IS NULL";
    const vector<string> updateSql = {
        updateDateTakenSql,
        updateDetalTimeSql,
    };
    ExecSqls(updateSql, *store->GetRaw().get());
    MEDIA_INFO_LOG("UpdateDateTakenAndDetalTime end");
}

void MediaLibraryRdbStore::ClearAudios(const shared_ptr<MediaLibraryRdbStore> store)
{
    const vector<string> sqls = {
        "DELETE From Audios",
    };
    MEDIA_INFO_LOG("clear audios start");
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("clear audios end");
}

void MediaLibraryRdbStore::UpdateIndexForCover(const shared_ptr<MediaLibraryRdbStore> store)
{
    const vector<string> sqls = {
        PhotoColumn::DROP_SCHPT_MEDIA_TYPE_INDEX,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
    };
    MEDIA_INFO_LOG("update index for photo album cover start");
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("update index for photo album cover end");
}

void MediaLibraryRdbStore::UpdateLcdStatusNotUploaded(const std::shared_ptr<MediaLibraryRdbStore> store)
{
    const vector<string> sqls = {
        PhotoColumn::UPDATE_LCD_STATUS_NOT_UPLOADED,
    };
    MEDIA_INFO_LOG("start update lcd status for photos have not been uploaded");
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("finish update lcd status for photos have not been uploaded");

    MEDIA_INFO_LOG("start CheckLcdSizeAndUpdateStatus");
    ThumbnailService::GetInstance()->CheckLcdSizeAndUpdateStatus();
    MEDIA_INFO_LOG("finish CheckLcdSizeAndUpdateStatus");
}

void MediaLibraryRdbStore::AddReadyCountIndex(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start add ready count index");
    const vector<string> sqls = {
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_COUNT_READY_INDEX,
        PhotoColumn::CREATE_SCHPT_YEAR_COUNT_READY_INDEX,
        PhotoColumn::CREATE_SCHPT_MONTH_COUNT_READY_INDEX,
    };
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end add ready count index");
}

void MediaLibraryRdbStore::RevertFixDateAddedIndex(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start revert fix date added index");
    const vector<string> sqls = {
        PhotoColumn::DROP_INDEX_SCTHP_ADDTIME,
        PhotoColumn::INDEX_SCTHP_ADDTIME,
        PhotoColumn::DROP_INDEX_SCHPT_ADDTIME_ALBUM,
    };
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end revert fix date added index");
}

void MediaLibraryRdbStore::AddCloudEnhancementAlbumIndex(const shared_ptr<MediaLibraryRdbStore> store)
{
    const vector<string> sqls = {
        PhotoColumn::CREATE_SCHPT_CLOUD_ENHANCEMENT_ALBUM_INDEX
    };
    MEDIA_INFO_LOG("start create idx_schpt_cloud_enhancement_album_index");
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end create idx_schpt_cloud_enhancement_album_index");
}

void MediaLibraryRdbStore::AddAlbumIndex(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start add album index");
    const vector<string> sqls = {
        PhotoColumn::INDEX_SCHPT_ALBUM_GENERAL,
        PhotoColumn::INDEX_SCHPT_ALBUM,
    };
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end add album index");
}

void MediaLibraryRdbStore::UpdateLocationKnowledgeIdx(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start update location knowledge index");
    const vector<string> sqls = {
        DROP_KNOWLEDGE_INDEX,
        CREATE_NEW_KNOWLEDGE_INDEX
    };
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end update location knowledge index");
}

void MediaLibraryRdbStore::AddAlbumSubtypeAndNameIdx(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start to add album subtype and name index");
    const vector<string> sqls = {
        CREATE_ANALYSIS_ALBUM_SUBTYPE_NAME_INDEX,
        CREATE_ANALYSIS_ALBUM_TAG_ID_INDEX
    };
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end add album subtype and name index");
}

void MediaLibraryRdbStore::UpdateMediaTypeAndThumbnailReadyIdx(const shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    bool cond = (rdbStore == nullptr || !rdbStore->CheckRdbStore());
    CHECK_AND_RETURN_LOG(!cond, "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");

    const vector<string> sqls = {
        PhotoColumn::DROP_SCHPT_MEDIA_TYPE_COUNT_READY_INDEX,
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_COUNT_READY_INDEX,
        PhotoColumn::DROP_INDEX_SCHPT_READY,
        PhotoColumn::INDEX_SCHPT_READY,
    };

    MEDIA_INFO_LOG("start update idx_schpt_media_type_ready and idx_schpt_thumbnail_ready");
    ExecSqls(sqls, *rdbStore->GetRaw().get());
    MEDIA_INFO_LOG("end update idx_schpt_media_type_ready and idx_schpt_thumbnail_ready");
}

int32_t MediaLibraryRdbStore::Init()
{
    MEDIA_INFO_LOG("Init rdb store: [version: %{public}d]", MEDIA_RDB_VERSION);
    CHECK_AND_RETURN_RET(rdbStore_ == nullptr, E_OK);

    int32_t errCode = 0;
    MediaLibraryDataCallBack rdbDataCallBack;
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::Init GetRdbStore");
    rdbStore_ = RdbHelper::GetRdbStore(config_, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    tracer.Finish();
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, errCode, "GetRdbStore is failed");
    int version = 0;
    NativeRdb::RebuiltType rebuilt;
    bool isRebuilt = rdbStore_->GetRebuilt(rebuilt) == NativeRdb::E_OK && rebuilt == NativeRdb::RebuiltType::REBUILT;
    bool isInitVersion = rdbStore_->GetVersion(version) == NativeRdb::E_OK && version == 0;
    if (isRebuilt || isInitVersion) {
        MEDIA_INFO_LOG("MediaLibraryRdbStore::Init, OnCreate, isRebuilt: %{public}d isInitVersion: %{public}d",
            static_cast<uint32_t>(isRebuilt), static_cast<uint32_t>(isInitVersion));
        rdbDataCallBack.OnCreate(*rdbStore_);
    }
    MEDIA_INFO_LOG("MediaLibraryRdbStore::Init(), SUCCESS");
    return E_OK;
}

void MediaLibraryRdbStore::AddPhotoDateAddedIndex(const shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start AddPhotoDateAddedIndex");
    const vector<string> sqls = {
        PhotoColumn::INDEX_SCTHP_PHOTO_DATEADDED,
    };
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end AddPhotoDateAddedIndex");
}

void MediaLibraryRdbStore::UpdateLatitudeAndLongitudeDefaultNull(const std::shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start Update LatitudeAndLongitude Default Null");
    const vector<string> sqls = {
        PhotoColumn::INDEX_LATITUDE,
        PhotoColumn::INDEX_LONGITUDE,
        PhotoColumn::UPDATE_LATITUDE_AND_LONGITUDE_DEFAULT_NULL,
    };
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end  Update LatitudeAndLongitude Default Null");
}

void MediaLibraryRdbStore::UpdatePhotoQualityCloned(const std::shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start UpdatePhotoQualityCloned");
    const vector<string> sqls = {
        PhotoColumn::UPDATE_PHOTO_QUALITY_OF_NULL_PHOTO_ID,
    };
    ExecSqls(sqls, *store->GetRaw().get());
    MEDIA_INFO_LOG("end UpdatePhotoQualityCloned");
}

void MediaLibraryRdbStore::UpdateMdirtyTriggerForTdirty(const std::shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("start UpdateMdirtyTriggerForTdirty");
    const string dropMdirtyCreateTrigger = "DROP TRIGGER IF EXISTS photos_mdirty_trigger";
    int32_t ret = ExecSqlWithRetry([&]() { return store->ExecuteSql(dropMdirtyCreateTrigger); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("drop photos_mdirty_trigger fail, ret = %{public}d", ret);
        UpdateFail(__FILE__, __LINE__);
    }

    ret = ExecSqlWithRetry([&]() { return store->ExecuteSql(PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("add photos_mdirty_trigger fail, ret = %{public}d", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    MEDIA_INFO_LOG("end UpdateMdirtyTriggerForTdirty");
}

int32_t MediaLibraryRdbStore::Init(const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback)
{
    MEDIA_INFO_LOG("Init rdb store: [version: %{public}d]", version);
    if (rdbStore_ != nullptr) {
        return E_OK;
    }
    int32_t errCode = 0;
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::Init GetRdbStore with config");
    rdbStore_ = RdbHelper::GetRdbStore(config, version, openCallback, errCode);
    tracer.Finish();
    if (rdbStore_ == nullptr) {
        MEDIA_ERR_LOG("GetRdbStore with config is failed");
        return errCode;
    }
    MEDIA_INFO_LOG("MediaLibraryRdbStore::Init with config, SUCCESS");
    return E_OK;
}

MediaLibraryRdbStore::~MediaLibraryRdbStore() = default;

void MediaLibraryRdbStore::Stop()
{
    rdbStore_ = nullptr;
}

bool MediaLibraryRdbStore::CheckRdbStore()
{
    return rdbStore_ != nullptr;
}

shared_ptr<NativeRdb::RdbStore> MediaLibraryRdbStore::GetRaw()
{
    return rdbStore_;
}

static void AddDefaultPhotoValues(ValuesBucket& values)
{
    ValueObject tmpValue;
    if (values.GetObject(MediaColumn::MEDIA_NAME, tmpValue)) {
        string newDisplayName {};
        tmpValue.GetString(newDisplayName);
        values.PutString(PhotoColumn::PHOTO_MEDIA_SUFFIX, ScannerUtils::GetFileExtension(newDisplayName));
    }
}

int32_t MediaLibraryRdbStore::Insert(MediaLibraryCommand &cmd, int64_t &rowId)
{
    DfxTimer dfxTimer(DfxType::RDB_INSERT, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::Insert");
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    if (cmd.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        AddDefaultPhotoValues(cmd.GetValueBucket());
    }

    int32_t ret = ExecSqlWithRetry([&]() {
        return MediaLibraryRdbStore::GetRaw()->Insert(rowId, cmd.GetTableName(), cmd.GetValueBucket());
    });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Insert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }

    MEDIA_DEBUG_LOG("rdbStore_->Insert end, rowId = %d, ret = %{public}d", (int)rowId, ret);
    return ret;
}

int32_t MediaLibraryRdbStore::BatchInsert(int64_t &outRowId, const std::string &table,
    std::vector<NativeRdb::ValuesBucket> &values)
{
    DfxTimer dfxTimer(DfxType::RDB_INSERT, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::BatchInsert");
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    if (table == PhotoColumn::PHOTOS_TABLE) {
        for (auto& value : values) {
            AddDefaultPhotoValues(value);
        }
    }
    int32_t ret = ExecSqlWithRetry([&]() {
        return MediaLibraryRdbStore::GetRaw()->BatchInsert(outRowId, table, values);
    });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->BatchInsert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }

    MEDIA_DEBUG_LOG("rdbStore_->BatchInsert end, rowId = %d, ret = %{public}d", (int)outRowId, ret);
    return ret;
}

int32_t MediaLibraryRdbStore::BatchInsert(MediaLibraryCommand &cmd, int64_t& outInsertNum,
    std::vector<ValuesBucket>& values)
{
    DfxTimer dfxTimer(DfxType::RDB_BATCHINSERT, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::BatchInsert");
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    if (cmd.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        for (auto& value : values) {
            AddDefaultPhotoValues(value);
        }
    }
    int32_t ret = ExecSqlWithRetry([&]() {
        return MediaLibraryRdbStore::GetRaw()->BatchInsert(outInsertNum, cmd.GetTableName(), values);
    });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->BatchInsert failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    tracer.Finish();
    MEDIA_DEBUG_LOG("rdbStore_->BatchInsert end, rowId = %d, ret = %{public}d", (int)outInsertNum, ret);
    return ret;
}

int32_t MediaLibraryRdbStore::InsertInternal(int64_t &outRowId, const std::string &table,
    NativeRdb::ValuesBucket &row)
{
    return ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->Insert(outRowId, table, row); });
}

int32_t MediaLibraryRdbStore::DoDeleteFromPredicates(const AbsRdbPredicates &predicates, int32_t &deletedRows)
{
    DfxTimer dfxTimer(DfxType::RDB_DELETE, INVALID_DFX, RDB_TIME_OUT, false);
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    int32_t ret = NativeRdb::E_ERROR;
    string tableName = predicates.GetTableName();
    ValuesBucket valuesBucket;
    if (tableName == MEDIALIBRARY_TABLE || tableName == PhotoColumn::PHOTOS_TABLE) {
        valuesBucket.PutInt(MEDIA_DATA_DB_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        valuesBucket.PutInt(MEDIA_DATA_DB_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_UPLOAD));
        valuesBucket.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        ret = ExecSqlWithRetry([&]() {
            return MediaLibraryRdbStore::GetRaw()->Update(deletedRows, tableName, valuesBucket,
                predicates.GetWhereClause(), predicates.GetWhereArgs());
        });
        MEDIA_INFO_LOG("delete photos permanently, ret: %{public}d", ret);
    } else if (tableName == PhotoAlbumColumns::TABLE) {
        valuesBucket.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        ret = ExecSqlWithRetry([&]() {
            return MediaLibraryRdbStore::GetRaw()->Update(deletedRows, tableName, valuesBucket,
                predicates.GetWhereClause(), predicates.GetWhereArgs());
        });
    } else if (tableName == PhotoMap::TABLE) {
        valuesBucket.PutInt(PhotoMap::DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
        ret = ExecSqlWithRetry([&]() {
            return MediaLibraryRdbStore::GetRaw()->Update(deletedRows, tableName, valuesBucket,
                predicates.GetWhereClause(), predicates.GetWhereArgs());
        });
    } else {
        ret = ExecSqlWithRetry([&]() {
            return MediaLibraryRdbStore::GetRaw()->Delete(deletedRows, tableName, predicates.GetWhereClause(),
                predicates.GetWhereArgs());
        });
    }
    return ret;
}

int32_t MediaLibraryRdbStore::Delete(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->DeleteByCmd");
    /* local delete */
    int32_t ret = DoDeleteFromPredicates(*(cmd.GetAbsRdbPredicates()), deletedRows);
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
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
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
    int32_t ret = ExecSqlWithRetry([&]() {
        return MediaLibraryRdbStore::GetRaw()->Update(changedRows, cmd.GetTableName(), cmd.GetValueBucket(),
            cmd.GetAbsRdbPredicates()->GetWhereClause(), cmd.GetAbsRdbPredicates()->GetWhereArgs());
    });
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
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), nullptr, "rdbStore_ is nullptr");
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
    auto resultSet = MediaLibraryRdbStore::GetRaw()->QuerySql(sql, args);
    MediaLibraryRestore::GetInstance().CheckResultSet(resultSet);
    return resultSet;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::QueryEditDataExists(
    const NativeRdb::AbsRdbPredicates &predicates)
{
    vector<string> columns = { MediaColumn::MEDIA_FILE_PATH };
    shared_ptr<NativeRdb::ResultSet> resultSet = Query(predicates, columns);
    bool cond = (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK);
    CHECK_AND_RETURN_RET_LOG(!cond, nullptr, "query edit data err");

    CHECK_AND_RETURN_RET_LOG(CheckRdbStore(), nullptr, "rdbStore_ is nullptr. Maybe it didn't init successfully.");

    string photoPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);

    cond = MediaFileUtils::IsFileExists(PhotoFileUtils::GetEditDataPath(photoPath)) ||
        MediaFileUtils::IsFileExists(PhotoFileUtils::GetEditDataCameraPath(photoPath));
    CHECK_AND_RETURN_RET(!cond,
        MediaLibraryRdbStore::GetRaw()->QuerySql("SELECT 1 AS hasEditData"));
    return MediaLibraryRdbStore::GetRaw()->QuerySql("SELECT 0 AS hasEditData");
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::GetIndexOfUriForPhotos(const AbsRdbPredicates &predicates,
    const vector<string> &columns, const string &id)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), nullptr, "rdbStore_ is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("GetIndexOfUriForPhotos");
    string sql;
    sql.append(RdbSqlUtils::BuildQueryString(predicates, columns));
    MEDIA_DEBUG_LOG("sql = %{private}s", sql.c_str());
    const vector<string> &args = predicates.GetWhereArgs();
    for (const auto &arg : args) {
        MEDIA_DEBUG_LOG("arg = %{private}s", arg.c_str());
    }
    auto resultSet = MediaLibraryRdbStore::GetRaw()->QuerySql(sql, args);
    MediaLibraryRestore::GetInstance().CheckResultSet(resultSet);
    return resultSet;
}

int32_t MediaLibraryRdbStore::UpdateLastVisitTime(const string &id)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR, "rdbStore_ is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("UpdateLastVisitTime");
    ValuesBucket values;
    int32_t changedRows = 0;
    values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, MediaFileUtils::UTCTimeMilliSeconds());
    string whereClause = MediaColumn::MEDIA_ID + " = ?";
    vector<string> whereArgs = {id};
    int32_t ret = ExecSqlWithRetry([&]() {
        return MediaLibraryRdbStore::GetRaw()->Update(changedRows, PhotoColumn::PHOTOS_TABLE, values, whereClause,
            whereArgs);
    });
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
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
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
    auto resultSet = QueryWithFilter(*cmd.GetAbsRdbPredicates(), columns);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
    }
    return resultSet;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::QueryWithFilter(const AbsRdbPredicates &predicates,
    const vector<string> &columns)
{
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
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
    auto resultSet = MediaLibraryRdbStore::GetRaw()->QueryByStep(predicates, columns);
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
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }
    DfxTimer dfxTimer(RDB_EXECUTE_SQL, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->ExecuteSql");
    int32_t ret = ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->ExecuteSql(sql); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->ExecuteSql failed, ret = %{public}d", ret);
        MediaLibraryRestore::GetInstance().CheckRestore(ret);
        return E_HAS_DB_ERROR;
    }
    return ret;
}

int32_t MediaLibraryRdbStore::QueryPragma(const string &key, int64_t &value)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    std::shared_ptr<ResultSet> resultSet = MediaLibraryRdbStore::GetRaw()->QuerySql("PRAGMA " + key);
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

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::StepQueryWithoutCheck(const AbsRdbPredicates &predicates,
    const vector<string> &columns)
{
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
        MEDIA_ERR_LOG("rdbStore_ is nullptr");
        VariantMap map = { { KEY_ERR_FILE, __FILE__ },
            { KEY_ERR_LINE, __LINE__ },
            { KEY_ERR_CODE, E_HAS_DB_ERROR },
            { KEY_OPT_TYPE, OptType::QUERY } };
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }

    MediaLibraryRdbUtils::AddQueryFilter(const_cast<AbsRdbPredicates &>(predicates));
    DfxTimer dfxTimer(RDB_QUERY, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("StepQueryWithoutCheck");
    MEDIA_DEBUG_LOG("Predicates Statement is %{public}s", predicates.GetStatement().c_str());
    auto resultSet = MediaLibraryRdbStore::GetRaw()->QueryByStep(predicates, columns, false);
    if (resultSet == nullptr) {
        VariantMap map = { { KEY_ERR_FILE, __FILE__ },
            { KEY_ERR_LINE, __LINE__ },
            { KEY_ERR_CODE, E_HAS_DB_ERROR },
            { KEY_OPT_TYPE, OptType::QUERY } };
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
    }
    return resultSet;
}

/**
 * Returns last insert row id. If insert succeed but no new rows inserted, then return -1.
 * Return E_HAS_DB_ERROR on error cases.
 */
int32_t MediaLibraryRdbStore::ExecuteForLastInsertedRowId(const string &sql, const vector<ValueObject> &bindArgs)
{
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        return E_HAS_DB_ERROR;
    }

    int64_t lastInsertRowId = 0;
    int32_t err = ExecSqlWithRetry(
        [&]() { return MediaLibraryRdbStore::GetRaw()->ExecuteForLastInsertedRowId(lastInsertRowId, sql, bindArgs); });
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute insert, err: %{public}d", err);
        MediaLibraryRestore::GetInstance().CheckRestore(err);
        return E_HAS_DB_ERROR;
    }
    return lastInsertRowId;
}

int32_t MediaLibraryRdbStore::Delete(const AbsRdbPredicates &predicates)
{
    int err = E_ERR;
    int32_t deletedRows = 0;
    err = DoDeleteFromPredicates(predicates, deletedRows);
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
int32_t MediaLibraryRdbStore::UpdateWithDateTime(ValuesBucket &values,
    const AbsRdbPredicates &predicates)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");

    if (predicates.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        values.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
        values.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, MediaFileUtils::UTCTimeMilliSeconds());
    }

    DfxTimer dfxTimer(DfxType::RDB_UPDATE, INVALID_DFX, RDB_TIME_OUT, false);
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRdbStore::Update by predicates");
    int32_t changedRows = -1;
    int32_t err =
        ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->Update(changedRows, values, predicates); });
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to execute update, err: %{public}d", err);
        MediaLibraryRestore::GetInstance().CheckRestore(err);
        return E_HAS_DB_ERROR;
    }

    return changedRows;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::QuerySql(const string &sql, const vector<string> &selectionArgs)
{
    if (!MediaLibraryRdbStore::CheckRdbStore()) {
        MEDIA_ERR_LOG("Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return nullptr;
    }

    MediaLibraryTracer tracer;
    tracer.Start("RdbStore->QuerySql");
    auto resultSet = MediaLibraryRdbStore::GetRaw()->QuerySql(sql, selectionArgs);
    MediaLibraryRestore::GetInstance().CheckResultSet(resultSet);
    if (resultSet == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::QUERY}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
    }

    return resultSet;
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
    int32_t ret = albumPluginTableEventHander.OnCreate(store);
    // after initiate album_plugin table, add 2 default album into PhotoAlbum.
    ExecSqlWithRetry([&]() {
        return store.ExecuteSql(CREATE_DEFALUT_ALBUM_FOR_NO_RELATIONSHIP_ASSET);
    });
    ExecSqlWithRetry([&]() {
        return store.ExecuteSql(CREATE_HIDDEN_ALBUM_FOR_DUAL_ASSET);
    });
    return ret;
}

int32_t PrepareSystemAlbums(RdbStore &store)
{
    ValuesBucket values;
    int32_t err = E_FAIL;
    MEDIA_INFO_LOG("PrepareSystemAlbums start");
    auto [errCode, transaction] = store.CreateTransaction(OHOS::NativeRdb::Transaction::DEFERRED);
    DfxTransaction reporter{ __func__ };
    if (errCode != NativeRdb::E_OK || transaction == nullptr) {
        reporter.ReportError(DfxTransaction::AbnormalType::CREATE_ERROR, errCode);
        MEDIA_ERR_LOG("transaction failed, err:%{public}d", errCode);
        return errCode;
    }
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
        auto res = transaction->Execute(sql, bindArgs);
        err = res.first;
        if (err != E_OK) {
            reporter.ReportError(DfxTransaction::AbnormalType::EXECUTE_ERROR, err);
            transaction->Rollback();
            MEDIA_ERR_LOG("Execute sql failed, err: %{public}d", err);
            return err;
        }
        values.Clear();
    }
    err = transaction->Commit();
    if (err != NativeRdb::E_OK) {
        reporter.ReportError(DfxTransaction::AbnormalType::COMMIT_ERROR, err);
        MEDIA_ERR_LOG("transaction Commit failed, err: %{public}d", err);
    } else {
        reporter.ReportIfTimeout();
    }
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
        CHECK_AND_PRINT_LOG(insertResult == NativeRdb::E_OK,
            "insert failed, insertResult: %{public}d", insertResult);
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
    int32_t insertResult = ExecSqlWithRetry([&]() {
        return store.InsertWithConflictResolution(outRowId, MEDIATYPE_DIRECTORY_TABLE, valuesBucket,
            ConflictResolution::ON_CONFLICT_REPLACE);
    });
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
    int32_t insertResult = ExecSqlWithRetry([&]() {
        return store.InsertWithConflictResolution(outRowId, ANALYSIS_ALBUM_TABLE, valuesBucket,
            ConflictResolution::ON_CONFLICT_REPLACE);
    });
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
    int32_t insertResult = ExecSqlWithRetry([&]() {
        return store.InsertWithConflictResolution(outRowId, SMARTALBUM_TABLE, valuesBucket,
            ConflictResolution::ON_CONFLICT_REPLACE);
    });
    return insertResult;
}

static int32_t InsertUniqueMemberTableValues(const UniqueMemberValuesBucket &uniqueMemberValues,
    RdbStore &store)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutString(ASSET_MEDIA_TYPE, uniqueMemberValues.assetMediaType);
    valuesBucket.PutInt(UNIQUE_NUMBER, uniqueMemberValues.startNumber);
    int64_t outRowId = -1;
    int32_t insertResult = ExecSqlWithRetry([&]() {
        return store.InsertWithConflictResolution(outRowId, ASSET_UNIQUE_NUMBER_TABLE, valuesBucket,
            ConflictResolution::ON_CONFLICT_REPLACE);
    });
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

static const string& AddStatusColumnForRefreshAlbumTable()
{
    static const string ADD_STATUS_COLUMN_FOR_REFRESH_ALBUM_TABLE =
        "ALTER TABLE " + ALBUM_REFRESH_TABLE + " ADD COLUMN " +
        ALBUM_REFRESH_STATUS + " INT DEFAULT 0 NOT NULL";
    return ADD_STATUS_COLUMN_FOR_REFRESH_ALBUM_TABLE;
}

static const vector<string> onCreateSqlStrs = {
    CREATE_MEDIA_TABLE,
    PhotoColumn::CREATE_PHOTO_TABLE,
    PhotoColumn::CREATE_CLOUD_ID_INDEX,
    PhotoColumn::INDEX_SCTHP_ADDTIME,
    PhotoColumn::INDEX_SCHPT_ALBUM_GENERAL,
    PhotoColumn::INDEX_SCHPT_ALBUM,
    PhotoColumn::INDEX_SCTHP_PHOTO_DATEADDED,
    PhotoColumn::INDEX_CAMERA_SHOT_KEY,
    PhotoColumn::INDEX_SCHPT_READY,
    PhotoColumn::CREATE_YEAR_INDEX,
    PhotoColumn::CREATE_MONTH_INDEX,
    PhotoColumn::CREATE_DAY_INDEX,
    PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
    PhotoColumn::CREATE_SCHPT_DAY_INDEX,
    PhotoColumn::CREATE_SCHPT_YEAR_COUNT_READY_INDEX,
    PhotoColumn::CREATE_SCHPT_MONTH_COUNT_READY_INDEX,
    PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_COUNT_READY_INDEX,
    PhotoColumn::CREATE_HIDDEN_TIME_INDEX,
    PhotoColumn::CREATE_SCHPT_HIDDEN_TIME_INDEX,
    PhotoColumn::CREATE_PHOTO_FAVORITE_INDEX,
    PhotoColumn::CREATE_PHOTOS_DELETE_TRIGGER,
    PhotoColumn::CREATE_PHOTOS_FDIRTY_TRIGGER,
    PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER,
    PhotoColumn::CREATE_PHOTOS_INSERT_CLOUD_SYNC,
    PhotoColumn::CREATE_PHOTOS_UPDATE_CLOUD_SYNC,
    PhotoColumn::CREATE_PHOTOS_METADATA_DIRTY_TRIGGER,
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
    TriggerDeleteAlbumClearMap(),
    TriggerDeletePhotoClearMap(),
    CREATE_TAB_ANALYSIS_OCR,
    CREATE_TAB_ANALYSIS_LABEL,
    CREATE_TAB_ANALYSIS_VIDEO_LABEL,
    CREATE_TAB_ANALYSIS_AESTHETICS,
    CREATE_TAB_VIDEO_ANALYSIS_AESTHETICS,
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
    CREATE_IMAGE_FACE_TAG_ID_INDEX,
    CREATE_VIDEO_FACE_INDEX,
    CREATE_OBJECT_INDEX,
    CREATE_RECOMMENDATION_INDEX,
    CREATE_COMPOSITION_INDEX,
    CREATE_HEAD_INDEX,
    CREATE_POSE_INDEX,
    CREATE_GEO_KNOWLEDGE_TABLE,
    CREATE_GEO_DICTIONARY_TABLE,
    CREATE_ANALYSIS_ALBUM_FOR_ONCREATE,
    CREATE_ANALYSIS_ALBUM_GROUP_TAG_INDEX,
    CREATE_ANALYSIS_ALBUM_SUBTYPE_NAME_INDEX,
    CREATE_ANALYSIS_ALBUM_TAG_ID_INDEX,
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
    DROP_KNOWLEDGE_INDEX,
    CREATE_NEW_KNOWLEDGE_INDEX,
    CREATE_CITY_NAME_INDEX,
    CREATE_LOCATION_KEY_INDEX,
    CREATE_IDX_FILEID_FOR_ANALYSIS_TOTAL,
    CREATE_IDX_FILEID_FOR_ANALYSIS_PHOTO_MAP,
    CREATE_TAB_ANALYSIS_ALBUM_TOTAL,
    CREATE_TOTAL_INSERT_TRIGGER_FOR_ADD_ANALYSIS_ALBUM_TOTAL,
    CREATE_VISION_UPDATE_TRIGGER_FOR_UPDATE_ANALYSIS_ALBUM_TOTAL_STATUS,
    CREATE_ANALYSIS_ALBUM_ASET_MAP_TABLE,
    CREATE_ANALYSIS_ASSET_SD_MAP_TABLE,
    CREATE_TAB_ASSET_ALBUM_OPERATION,
    CREATE_OPERATION_ASSET_INSERT_TRIGGER,
    CREATE_OPERATION_ASSET_DELETE_TRIGGER,
    CREATE_OPERATION_ASSET_UPDATE_TRIGGER,
    CREATE_OPERATION_ALBUM_INSERT_TRIGGER,
    CREATE_OPERATION_ALBUM_DELETE_TRIGGER,
    CREATE_OPERATION_ALBUM_UPDATE_TRIGGER,
    CREATE_ANALYSIS_PHOTO_MAP_MAP_ASSET_INDEX,

    // search
    CREATE_SEARCH_TOTAL_TABLE,
    CREATE_SEARCH_INSERT_TRIGGER,
    CREATE_SEARCH_UPDATE_TRIGGER,
    CREATE_SEARCH_UPDATE_STATUS_TRIGGER,
    CREATE_SEARCH_DELETE_TRIGGER,
    CREATE_IDX_FILEID_FOR_SEARCH_INDEX,
    CREATE_ALBUM_UPDATE_SEARCH_TRIGGER,
    CREATE_ANALYSIS_UPDATE_SEARCH_TRIGGER,
    CREATE_ANALYSIS_ALBUM_UPDATE_SEARCH_TRIGGER,
    MedialibraryBusinessRecordColumn::CREATE_TABLE,
    MedialibraryBusinessRecordColumn::CREATE_BUSINESS_KEY_INDEX,
    PhotoExtColumn::CREATE_PHOTO_EXT_TABLE,
    PhotoColumn::CREATE_PHOTO_DISPLAYNAME_INDEX,
    AppUriPermissionColumn::CREATE_APP_URI_PERMISSION_TABLE,
    AppUriPermissionColumn::CREATE_URI_URITYPE_TOKENID_INDEX,
    TriggerDeletePhotoClearAppUriPermission(),
    TriggerDeleteAudioClearAppUriPermission(),
    PhotoColumn::CREATE_PHOTO_BURSTKEY_INDEX,
    PhotoColumn::UPDATA_PHOTOS_DATA_UNIQUE,
    PhotoColumn::INSERT_GENERATE_HIGHLIGHT_THUMBNAIL,
    PhotoColumn::UPDATE_GENERATE_HIGHLIGHT_THUMBNAIL,
    PhotoColumn::INDEX_HIGHLIGHT_FILEID,
    PhotoColumn::CREATE_SCHPT_CLOUD_ENHANCEMENT_ALBUM_INDEX,
    AddStatusColumnForRefreshAlbumTable(),
    PhotoColumn::INDEX_LATITUDE,
    PhotoColumn::INDEX_LONGITUDE,
    CREATE_PHOTO_STATUS_FOR_SEARCH_INDEX,
    CustomRecordsColumns::CREATE_TABLE,
};

static int32_t ExecuteSql(RdbStore &store)
{
    for (const string& sqlStr : onCreateSqlStrs) {
        auto ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(sqlStr); });
        CHECK_AND_RETURN_RET(ret == NativeRdb::E_OK, NativeRdb::E_ERROR);
    }
    CHECK_AND_RETURN_RET(TabOldPhotosTableEventHandler().OnCreate(store) == NativeRdb::E_OK,
        NativeRdb::E_ERROR);
    if (TabFaCardPhotosTableEventHandler().OnCreate(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }
    TableEventHandler().OnCreate(MediaLibraryUnistoreManager::GetInstance().GetRdbStore());
    return NativeRdb::E_OK;
}

int32_t MediaLibraryDataCallBack::OnCreate(RdbStore &store)
{
    MEDIA_INFO_LOG("Rdb OnCreate");
#ifdef META_RECOVERY_SUPPORT
    NativeRdb::RebuiltType rebuilt = NativeRdb::RebuiltType::NONE;
    store.GetRebuilt(rebuilt);
#endif

    if (ExecuteSql(store) != NativeRdb::E_OK) {
        return NativeRdb::E_ERROR;
    }

#ifdef META_RECOVERY_SUPPORT
    if (rebuilt == NativeRdb::RebuiltType::REBUILT) {
        // set Rebuilt flag
        MediaLibraryMetaRecovery::GetInstance().SetRdbRebuiltStatus(true);
    }
#endif

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
    int32_t result = ExecSqlWithRetry([&]() { return store.ExecuteSql(alterCloudId); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb cloud_id error %{private}d", result);
    }
    const std::string alterDirty = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_DIRTY +" INT DEFAULT 0";
    result = ExecSqlWithRetry([&]() { return store.ExecuteSql(alterDirty); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb dirty error %{private}d", result);
    }
    const std::string alterSyncStatus = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_SYNC_STATUS +" INT DEFAULT 0";
    result = ExecSqlWithRetry([&]() { return store.ExecuteSql(alterSyncStatus); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb syncStatus error %{private}d", result);
    }
    const std::string alterPosition = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_POSITION +" INT DEFAULT 1";
    result = ExecSqlWithRetry([&]() { return store.ExecuteSql(alterPosition); });
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
    int32_t result = ExecSqlWithRetry([&]() { return store.ExecuteSql(alterMetaModified); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb meta_date_modified error %{private}d", result);
    }
    const std::string alterSyncStatus = "ALTER TABLE " + MEDIALIBRARY_TABLE +
        " ADD COLUMN " + MEDIA_DATA_DB_SYNC_STATUS + " INT DEFAULT 0";
    result = ExecSqlWithRetry([&]() { return store.ExecuteSql(alterSyncStatus); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb syncStatus error %{private}d", result);
    }
}

void AddTableType(RdbStore &store)
{
    const std::string alterTableName =
        "ALTER TABLE " + BUNDLE_PERMISSION_TABLE + " ADD COLUMN " + PERMISSION_TABLE_TYPE + " INT";
    int32_t result = ExecSqlWithRetry([&]() { return store.ExecuteSql(alterTableName); });
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
        auto result = ExecSqlWithRetry([&]() { return store.ExecuteSql(executeSqlStrs[i]); });
        if (result != NativeRdb::E_OK) {
            UpdateFail(__FILE__, __LINE__);
            MEDIA_ERR_LOG("upgrade fail idx:%{public}zu", i);
        }
    }
}

void ModifySyncStatus(RdbStore &store)
{
    const std::string dropSyncStatus = "ALTER TABLE " + MEDIALIBRARY_TABLE + " DROP column syncing";
    auto result = ExecSqlWithRetry([&]() { return store.ExecuteSql(dropSyncStatus); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb syncing error %{private}d", result);
    }

    const std::string addSyncStatus = "ALTER TABLE " + MEDIALIBRARY_TABLE + " ADD COLUMN " +
        MEDIA_DATA_DB_SYNC_STATUS +" INT DEFAULT 0";
    result = ExecSqlWithRetry([&]() { return store.ExecuteSql(addSyncStatus); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Upgrade rdb syncStatus error %{private}d", result);
    }
}

void ModifyDeleteTrigger(RdbStore &store)
{
    /* drop old delete trigger */
    const std::string dropDeleteTrigger = "DROP TRIGGER IF EXISTS photos_delete_trigger";
    if (ExecSqlWithRetry([&]() { return store.ExecuteSql(dropDeleteTrigger); }) != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("upgrade fail: drop old delete trigger");
    }

    /* create new delete trigger */
    if (ExecSqlWithRetry([&]() { return store.ExecuteSql(PhotoColumn::CREATE_PHOTOS_DELETE_TRIGGER); }) !=
        NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("upgrade fail: create new delete trigger");
    }
}

void AddCloudVersion(RdbStore &store)
{
    const std::string addSyncStatus = "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
        PhotoColumn::PHOTO_CLOUD_VERSION +" BIGINT DEFAULT 0";
    auto result = ExecSqlWithRetry([&]() { return store.ExecuteSql(addSyncStatus); });
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
    int32_t ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(dropMdirtyCreateTrigger); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("drop photos_mdirty_trigger fail, ret = %{public}d", ret);
        UpdateFail(__FILE__, __LINE__);
    }

    ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER); });
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
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP INDEX IF EXISTS idx_sthp_dateadded"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP INDEX IF EXISTS photo_album_types"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS photos_delete_trigger"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS photos_fdirty_trigger"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS photos_mdirty_trigger"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS photo_insert_cloud_sync_trigger"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS delete_trigger"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS mdirty_trigger"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS fdirty_trigger"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS insert_cloud_sync_trigger"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS photo_album_clear_map"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS photo_album_insert_asset"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS photo_album_delete_asset"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS delete_photo_clear_map"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TRIGGER IF EXISTS update_user_album_count"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TABLE IF EXISTS Photos"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TABLE IF EXISTS Audios"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TABLE IF EXISTS UniqueNumber"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TABLE IF EXISTS PhotoAlbum"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TABLE IF EXISTS PhotoMap"); });
    ExecSqlWithRetry([&]() { return store.ExecuteSql("DROP TABLE IF EXISTS FormMap"); });

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
    MediaLibraryRdbUtils::UpdateSourceAlbumInternal(MediaLibraryUnistoreManager::GetInstance().GetRdbStore());
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
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), false,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");

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
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), false,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");

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

    int32_t result = ExecSqlWithRetry([&]() { return store.ExecuteSql(ADD_PACKAGE_NAME_ON_PHOTOS); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to update PHOTOS");
    }
    result = ExecSqlWithRetry([&]() { return store.ExecuteSql(ADD_PACKAGE_NAME_ON_AUDIOS); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to update AUDIOS");
    }
    result = ExecSqlWithRetry([&]() { return store.ExecuteSql(ADD_PACKAGE_NAME_ON_FILES); });
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
    int32_t ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(addAlbumDirty); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: add ablum dirty", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    const std::string addAlbumCloudId = "ALTER TABLE " + PhotoAlbumColumns::TABLE +
        " ADD COLUMN " + PhotoAlbumColumns::ALBUM_CLOUD_ID + " TEXT;";
    ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(addAlbumCloudId); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: add ablum cloud id", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    /* album - add triggers */
    ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(PhotoAlbumColumns::CREATE_ALBUM_INSERT_TRIGGER); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: create album insert trigger", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(PhotoAlbumColumns::CREATE_ALBUM_MDIRTY_TRIGGER); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: create album modify trigger", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(PhotoAlbumColumns::CREATE_ALBUM_DELETE_TRIGGER); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: create album delete trigger", ret);
        UpdateFail(__FILE__, __LINE__);
    }
    /* album map - add columns */
    const std::string addAlbumMapColumns = "ALTER TABLE " + PhotoMap::TABLE +
        " ADD COLUMN " + PhotoMap::DIRTY +" INT DEFAULT " +
        to_string(static_cast<int32_t>(DirtyTypes::TYPE_NEW)) + ";";
    ret = ExecSqlWithRetry([&]() { return store.ExecuteSql(addAlbumMapColumns); });
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("upgrade fail %{public}d: add ablum columns", ret);
        UpdateFail(__FILE__, __LINE__);
    }
}

static void AddCameraShotKey(RdbStore &store)
{
    static const string ADD_CAMERA_SHOT_KEY_ON_PHOTOS = "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
        " ADD COLUMN " + PhotoColumn::CAMERA_SHOT_KEY + " TEXT";
    int32_t result = ExecSqlWithRetry([&]() { return store.ExecuteSql(ADD_CAMERA_SHOT_KEY_ON_PHOTOS); });
    if (result != NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to update PHOTOS");
    }
    result = ExecSqlWithRetry([&]() { return store.ExecuteSql(PhotoColumn::INDEX_CAMERA_SHOT_KEY); });
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
    CHECK_AND_PRINT_LOG(result == NativeRdb::E_OK,
        "Upgrade rdb need clean and thumb status error %{private}d", result);
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
    CHECK_AND_PRINT_LOG(result == NativeRdb::E_OK, "Upgrade rdb shooting_mode error %{private}d", result);
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
    CHECK_AND_PRINT_LOG(result == NativeRdb::E_OK, "Upgrade rdb shooting_mode error %{private}d", result);
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
    if (ExecSqlWithRetry([&]() { return store.ExecuteSql(PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER); }) !=
        NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("upgrade fail: create new photos mdirty trigger");
    }

    if (ExecSqlWithRetry([&]() { return store.ExecuteSql(CREATE_FILES_MDIRTY_TRIGGER); }) != NativeRdb::E_OK) {
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
    CHECK_AND_PRINT_LOG(result == NativeRdb::E_OK, "Upgrade rdb last_visit_time error %{private}d", result);
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
        " WHERE album_order > old.album_order;" +
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
    CHECK_AND_PRINT_LOG(result == NativeRdb::E_OK, "Upgrade rdb album order error %{private}d", result);
}

static void AddFormMap(RdbStore &store)
{
    int32_t result = ExecSqlWithRetry([&]() { return store.ExecuteSql(FormMap::CREATE_FORM_MAP_TABLE); });
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
        DROP_KNOWLEDGE_INDEX,
        CREATE_NEW_KNOWLEDGE_INDEX,
        CREATE_CITY_NAME_INDEX,
        CREATE_LOCATION_KEY_INDEX,
    };
    ExecSqls(sqls, store);
}

static void UpdatePhotosMdirtyTrigger(RdbStore& store)
{
    string dropSql = "DROP TRIGGER IF EXISTS photos_mdirty_trigger";
    if (ExecSqlWithRetry([&]() { return store.ExecuteSql(dropSql); }) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to drop old photos_mdirty_trigger: %{private}s", dropSql.c_str());
        UpdateFail(__FILE__, __LINE__);
    }

    if (ExecSqlWithRetry([&]() { return store.ExecuteSql(PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER); }) !=
        NativeRdb::E_OK) {
        UpdateFail(__FILE__, __LINE__);
        MEDIA_ERR_LOG("Failed to upgrade new photos_mdirty_trigger, %{private}s",
            PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER.c_str());
    }
}

static void AddIndexForFileId(RdbStore& store)
{
    const vector<string> sqls = {
        CREATE_IDX_FILEID_FOR_SEARCH_INDEX,
        CREATE_IDX_FILEID_FOR_ANALYSIS_TOTAL,
        CREATE_IDX_FILEID_FOR_ANALYSIS_PHOTO_MAP,
    };
    MEDIA_INFO_LOG("start AddIndexForFileId");
    ExecSqls(sqls, store);
}

static void AddMetaRecovery(RdbStore& store)
{
    const vector<string> sqls = {"ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
        " ADD COLUMN " + PhotoColumn::PHOTO_METADATA_FLAGS + " INT DEFAULT 0",
        PhotoColumn::CREATE_PHOTOS_METADATA_DIRTY_TRIGGER,
    };
    MEDIA_INFO_LOG("start AddMetaRecovery");
    ExecSqls(sqls, store);
}

void AddHighlightTriggerColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::HIGHLIGHT_TABLE + " ADD COLUMN " +
            PhotoColumn::MEDIA_DATA_DB_HIGHLIGHT_TRIGGER + " INT DEFAULT 0"
    };
    MEDIA_INFO_LOG("start add highlight trigger column");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end add highlight trigger column");
}

void AddHighlightInsertAndUpdateTrigger(RdbStore &store)
{
    const vector<string> sqls = {
        PhotoColumn::INSERT_GENERATE_HIGHLIGHT_THUMBNAIL,
        PhotoColumn::UPDATE_GENERATE_HIGHLIGHT_THUMBNAIL
    };
    MEDIA_INFO_LOG("start add highlight insert and update trigger");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end add highlight insert and update trigger");
}

void AddHighlightIndex(RdbStore &store)
{
    const vector<string> addHighlightIndex = { PhotoColumn::INDEX_HIGHLIGHT_FILEID };
    MEDIA_INFO_LOG("start add highlight index");
    ExecSqls(addHighlightIndex, store);
    MEDIA_INFO_LOG("end add highlight index");
}

static void UpdateSearchIndexTriggerForCleanFlag(RdbStore& store)
{
    const vector<string> sqls = {
        "DROP TRIGGER IF EXISTS update_search_status_trigger",
        CREATE_SEARCH_UPDATE_STATUS_TRIGGER,
    };
    MEDIA_INFO_LOG("start update search index for clean flag");
    ExecSqls(sqls, store);
}

static void UpdateAlbumRefreshTable(RdbStore &store)
{
    const vector<string> sqls = {
        CREATE_ALBUM_REFRESH_TABLE,
    };
    ExecSqls(sqls, store);
}

static void AddCoverPlayVersionColumns(RdbStore& store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + HIGHLIGHT_COVER_INFO_TABLE +
            " ADD COLUMN " + COVER_SERVICE_VERSION + " INT DEFAULT 0",
        "ALTER TABLE " + HIGHLIGHT_PLAY_INFO_TABLE +
            " ADD COLUMN " + PLAY_SERVICE_VERSION + " INT DEFAULT 0",
    };
    MEDIA_INFO_LOG("start add cover play version columns");
    ExecSqls(sqls, store);
}

static void AddMovingPhotoRelatedData(RdbStore &store)
{
    const vector<string> sqls = {
        CREATE_TAB_VIDEO_ANALYSIS_AESTHETICS,
    };
    MEDIA_INFO_LOG("start create video aesthetics score table");
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

void AddSourceAndTargetTokenForUriPermission(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + AppUriPermissionColumn::APP_URI_PERMISSION_TABLE + " ADD COLUMN " +
            AppUriPermissionColumn::SOURCE_TOKENID + " BIGINT",
        "ALTER TABLE " + AppUriPermissionColumn::APP_URI_PERMISSION_TABLE + " ADD COLUMN " +
            AppUriPermissionColumn::TARGET_TOKENID + " BIGINT",
        AppUriPermissionColumn::CREATE_URI_URITYPE_TOKENID_INDEX,
    };
    MEDIA_INFO_LOG("start add islocal column");
    ExecSqls(sqls, store);
}

void UpdateAOI(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + AOI + " TEXT ",
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + POI + " TEXT ",
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + FIRST_AOI + " TEXT ",
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + FIRST_POI + " TEXT ",
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + LOCATION_VERSION + " TEXT ",
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + FIRST_AOI_CATEGORY + " TEXT ",
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + FIRST_POI_CATEGORY + " TEXT ",
        "ALTER TABLE " + GEO_KNOWLEDGE_TABLE + " ADD COLUMN " + FILE_ID + " INT ",
        DROP_KNOWLEDGE_INDEX,
        CREATE_NEW_KNOWLEDGE_INDEX,
    };
    MEDIA_INFO_LOG("start init aoi info of geo db");
    ExecSqls(sqls, store);
}

void UpdateVideoFaceTable(RdbStore &store)
{
    const vector<string> sqls = {
        "DROP TABLE IF EXISTS " + VISION_VIDEO_FACE_TABLE,
        CREATE_TAB_VIDEO_FACE,
    };
    MEDIA_INFO_LOG("start update video face db");
    ExecSqls(sqls, store);
}

void AddHighlightChangeFunction(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + ANALYSIS_PHOTO_MAP_TABLE + " ADD COLUMN " + ORDER_POSITION + " INT ",
        "ALTER TABLE " + HIGHLIGHT_COVER_INFO_TABLE + " ADD COLUMN " + COVER_STATUS + " INT ",
        "ALTER TABLE " + HIGHLIGHT_PLAY_INFO_TABLE + " ADD COLUMN " + PLAY_INFO_STATUS + " INT ",
        "ALTER TABLE " + HIGHLIGHT_ALBUM_TABLE + " ADD COLUMN " + HIGHLIGHT_PIN_TIME + " BIGINT ",
    };
    MEDIA_INFO_LOG("start add highlight change function");
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
    string updateDirtyForShootingMode = "UPDATE Photos SET dirty = 2 WHERE position <> 1 AND " +
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

static void AddIsAutoColumns(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_IS_AUTO + " INT DEFAULT 0 NOT NULL",
    };
    MEDIA_INFO_LOG("start add is_auto column for auto cloud enhancement");
    ExecSqls(sqls, store);
}

static void AddThumbnailReady(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_THUMBNAIL_READY + " INT DEFAULT 0",
    };
    MEDIA_INFO_LOG("start add thumbnail ready columns");
    ExecSqls(sqls, store);
}

static void AddCheckFlag(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::PHOTO_CHECK_FLAG + " INT DEFAULT 0",
        "ALTER TABLE " + PhotoAlbumColumns::TABLE + " ADD COLUMN " +
            PhotoAlbumColumns::ALBUM_CHECK_FLAG + " INT DEFAULT 0",
    };
    MEDIA_INFO_LOG("start add check_flag columns");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end add check_flag columns");
}

static bool IsColumnExists(RdbStore &store, const std::string& tableName,
    const std::string& columnName)
{
    std::string checkSql = "PRAGMA table_info(" + tableName + ")";
    std::vector<NativeRdb::ValueObject> args;
    auto resultSet = store.QuerySql(checkSql, args);
    CHECK_AND_RETURN_RET(resultSet != nullptr, false);

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string name;
        resultSet->GetString(1, name);
        CHECK_AND_RETURN_RET(name != columnName, true);
    }

    return false;
}

static void CheckIfPhotoColumnExists(RdbStore &store, unordered_map<string, bool> &photoColumnExists)
{
    std::string checkSql = "PRAGMA table_info(" + PhotoColumn::PHOTOS_TABLE + ")";
    std::vector<NativeRdb::ValueObject> args;
    auto resultSet = store.QuerySql(checkSql, args);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Failed to query %{private}s", checkSql.c_str());

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string name;
        resultSet->GetString(1, name);
        if (photoColumnExists.find(name) != photoColumnExists.end()) {
            photoColumnExists[name] = true;
        }
    }
}

static void AddCloudEnhanceColumnsFix(RdbStore& store)
{
    MEDIA_INFO_LOG("Start checking cloud enhancement column");
    bool hasColumn = IsColumnExists(store, PhotoColumn::PHOTOS_TABLE, PhotoColumn::PHOTO_CE_AVAILABLE);
    MEDIA_INFO_LOG("End checking cloud enhancement column: %{public}d", hasColumn);
    if (!hasColumn) {
        AddCloudEnhancementColumns(store);
        MEDIA_INFO_LOG("Add Cloud Enhance Cols completed successfully");
    }
}

static void AddDynamicRangeColumnsFix(RdbStore& store)
{
    MEDIA_INFO_LOG("Start checking dynamic_range_type column");
    bool hasColumn = IsColumnExists(store, PhotoColumn::PHOTOS_TABLE, PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE);
    MEDIA_INFO_LOG("End checking dynamic_range_type column: %{public}d", hasColumn);
    if (!hasColumn) {
        AddDynamicRangeType(store);
        MEDIA_INFO_LOG("Add Dynamic Range Cols completed successfully");
    }
}

static void AddThumbnailReadyColumnsFix(RdbStore& store)
{
    MEDIA_INFO_LOG("Start checking thumbnail_ready column");
    bool hasColumn = IsColumnExists(store, PhotoColumn::PHOTOS_TABLE, PhotoColumn::PHOTO_THUMBNAIL_READY);
    MEDIA_INFO_LOG("End checking thumbnail_ready column: %{public}d", hasColumn);
    if (!hasColumn) {
        AddThumbnailReady(store);
        MEDIA_INFO_LOG("Add ThumbnailReady Column");
    }
}

static void UpdateSourcePhotoAlbumTrigger(RdbStore &store)
{
    MEDIA_INFO_LOG("start update source photo album trigger");
    const vector<string> sqls = {
        DROP_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER,
        CREATE_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER,
    };
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end update source photo album trigger");
}

static void UpdateSearchStatusTriggerForOwnerAlbumId(RdbStore &store)
{
    MEDIA_INFO_LOG("start update search status trigger for owner album id");
    const vector<string> sqls = {
        "DROP TRIGGER IF EXISTS " + UPDATE_SEARCH_STATUS_TRIGGER,
        CREATE_SEARCH_UPDATE_STATUS_TRIGGER,
    };
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end update search status trigger for owner album id");
}

static void UpdateSearchStatusTriggerForIsFavorite(RdbStore &store)
{
    MEDIA_INFO_LOG("start update search status trigger for is favorite");
    const vector<string> sqls = {
        "DROP TRIGGER IF EXISTS " + UPDATE_SEARCH_STATUS_TRIGGER,
        CREATE_SEARCH_UPDATE_STATUS_TRIGGER,
    };
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end update search status trigger for is favorite");
}

static void AddHighlightAnalysisProgress(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + HIGHLIGHT_ANALYSIS_PROGRESS + " TEXT"
    };
    MEDIA_INFO_LOG("start add highlight_analysis_progress column");
    ExecSqls(sqls, store);
}

static void AddRefreshAlbumStatusColumn(RdbStore &store)
{
    MEDIA_INFO_LOG("start add status column for refresh album table");
    const vector<string> sqls = {
        "ALTER TABLE " + ALBUM_REFRESH_TABLE + " ADD COLUMN " +
            ALBUM_REFRESH_STATUS + " INT DEFAULT 0 NOT NULL"
    };
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end add status column for refresh album table");
}

static void AddSupportedWatermarkType(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::SUPPORTED_WATERMARK_TYPE + " INT "
    };
    MEDIA_INFO_LOG("start add supported_watermark_type column");
    ExecSqls(sqls, store);
}

static void AddStageVideoTaskStatus(RdbStore &store)
{
    MEDIA_INFO_LOG("start add stage_video_task_status column");
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " +
            PhotoColumn::STAGE_VIDEO_TASK_STATUS + " INT NOT NULL DEFAULT 0 "
    };
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end add stage_video_task_status column");
}

static void AddHighlightUseSubtitle(RdbStore &store)
{
    MEDIA_INFO_LOG("start add use_subtitle column");
    const vector<string> sqls = {
        "ALTER TABLE " + HIGHLIGHT_ALBUM_TABLE + " ADD COLUMN " +
            HIGHLIGHT_USE_SUBTITLE + " INT DEFAULT 0"
    };
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("start add use_subtitle column");
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
        "DROP TRIGGER IF EXISTS album_map_delete_search_trigger",
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
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr,
        "MediaDataAbility insert functionality rebStore is null.");

    string querySql = "SELECT data FROM Photos GROUP BY data HAVING COUNT(*) > 1";
    auto result = rdbStore->QuerySql(querySql);
    int32_t count = 0;
    CHECK_AND_RETURN_LOG(result != nullptr, "result is null");
    CHECK_AND_PRINT_LOG(result->GetRowCount(count) == NativeRdb::E_OK, "GetRowCount fail");
    result->Close();
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    DfxReporter::ReportStartResult(DfxType::ADD_DATA_UNIQUE_INDEX_FAIL, count, startTime);
    bool ret = system::SetParameter("persist.multimedia.medialibrary.data_unique", "1");
    CHECK_AND_PRINT_LOG(ret, "Failed to set parameter, ret:%{public}d", ret);
    MEDIA_INFO_LOG("HasDirtyData count:%{public}d", count);
}

static void ReportFailInfo()
{
    MEDIA_INFO_LOG("Start ReportFailInfo");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_LOG(asyncWorker != nullptr, "Failed to get async worker instance!");
    shared_ptr<MediaLibraryAsyncTask> reportTask =
        make_shared<MediaLibraryAsyncTask>(ReportFailInfoAsync, nullptr);
    CHECK_AND_RETURN_LOG(reportTask != nullptr, "Failed to create async task for reportTask!");
    asyncWorker->AddTask(reportTask, false);
}

static void UpdateDataUniqueIndex(RdbStore &store)
{
    MEDIA_INFO_LOG("Start UpdateDataUniqueIndex");
    string sql = PhotoColumn::UPDATA_PHOTOS_DATA_UNIQUE;
    auto err = ExecSqlWithRetry([&]() { return store.ExecuteSql(sql); });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to exec: %{public}s", sql.c_str());
        ReportFailInfo();
    }
    MEDIA_INFO_LOG("End UpdateDataUniqueIndex");
}

static void FixPhotoSchptMediaTypeIndex(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        PhotoColumn::CREATE_SCHPT_MEDIA_TYPE_INDEX,
    };
    MEDIA_INFO_LOG("Fix idx_schpt_media_type index");
    ExecSqls(executeSqlStrs, store);
    MEDIA_INFO_LOG("End fix idx_schpt_media_type index.");
}

static void AddAnalysisAlbumTotalTable(RdbStore &store)
{
    static const vector<string> executeSqlStrs = {
        CREATE_TAB_ANALYSIS_ALBUM_TOTAL,
        INIT_TAB_ANALYSIS_ALBUM_TOTAL,
        CREATE_TOTAL_INSERT_TRIGGER_FOR_ADD_ANALYSIS_ALBUM_TOTAL,
        CREATE_VISION_UPDATE_TRIGGER_FOR_UPDATE_ANALYSIS_ALBUM_TOTAL_STATUS,
    };
    MEDIA_INFO_LOG("Start add analysis album total table");
    ExecSqls(executeSqlStrs, store);
}

static void CompatLivePhoto(RdbStore &store, int32_t oldVersion)
{
    MEDIA_INFO_LOG("Start configuring param for live photo compatibility");
    bool ret = false;
    // there is no need to ResetCursor() twice if album fusion is included
    if (oldVersion >= VERSION_ADD_OWNER_ALBUM_ID) {
        ret = system::SetParameter(REFRESH_CLOUD_LIVE_PHOTO_FLAG, CLOUD_LIVE_PHOTO_NOT_REFRESHED);
        MEDIA_INFO_LOG("Set parameter for refreshing cloud live photo, ret: %{public}d", ret);
    }

    ret = system::SetParameter(COMPAT_LIVE_PHOTO_FILE_ID, "1"); // start compating from file_id: 1
    MEDIA_INFO_LOG("Set parameter for compating local live photo, ret: %{public}d", ret);
}

static void ResetCloudCursorAfterInitFinish()
{
    MEDIA_INFO_LOG("Try reset cloud cursor after storage reconstruct");
    static uint32_t baseUserRange = 200000; // uid base offset
    uid_t uid = getuid() / baseUserRange;
    const string paramKey = "multimedia.medialibrary.startup." + to_string(uid);
    int32_t maxTryTimes = 10;
    if (WaitParameter(paramKey.c_str(), "true", maxTryTimes) == E_OK) {
        MEDIA_INFO_LOG("medialibrary init finish start reset cloud cursor");
        FileManagement::CloudSync::CloudSyncManager::GetInstance().ResetCursor();
        MEDIA_INFO_LOG("End reset cloud cursor");
    } else {
        MEDIA_INFO_LOG("try max time start reset cloud cursor");
        FileManagement::CloudSync::CloudSyncManager::GetInstance().ResetCursor();
        MEDIA_INFO_LOG("End reset cloud cursor");
    }
    MEDIA_INFO_LOG("Reset cloud cursor after storage reconstruct end");
}

static int32_t MatchedDataFusion(CompensateAlbumIdData* compensateData)
{
    int32_t matchedDataHandleResult = MediaLibraryAlbumFusionUtils::HandleMatchedDataFusion(
        compensateData->upgradeStore_);
    if (matchedDataHandleResult != E_OK) {
        MEDIA_ERR_LOG("Fatal err, handle matched relationship fail by %{public}d", matchedDataHandleResult);
        // This should not happen, try again
        matchedDataHandleResult = MediaLibraryAlbumFusionUtils::HandleMatchedDataFusion(
            compensateData->upgradeStore_);
        CHECK_AND_PRINT_LOG(matchedDataHandleResult == E_OK,
            "Fatal err, handle matched relationship again by %{public}d", matchedDataHandleResult);
    }
    return matchedDataHandleResult;
}

static void ReconstructMediaLibraryStorageFormatExecutor(AsyncTaskData *data)
{
    CHECK_AND_RETURN_LOG(data != nullptr, "task data is nullptr");
    MediaLibraryAlbumFusionUtils::SetParameterToStopSync();
    MediaLibraryAlbumFusionUtils::SetAlbumFuseUpgradeStatus(0); // 0: set upgrade status fail
    CompensateAlbumIdData* compensateData = static_cast<CompensateAlbumIdData*>(data);
    MEDIA_INFO_LOG("ALBUM_FUSE: Processing old data start");
    MEDIA_INFO_LOG("ALBUM_FUSE: Compensating album id for old asset start");
    int64_t beginTime = MediaFileUtils::UTCTimeMilliSeconds();
    CHECK_AND_PRINT_LOG(MediaLibraryAlbumFusionUtils::RemoveMisAddedHiddenData(compensateData->upgradeStore_) == E_OK,
        "Failed to remove misadded hidden data");
    int64_t cleanDataBeginTime = MediaFileUtils::UTCTimeMilliSeconds();
    MediaLibraryAlbumFusionUtils::ReportAlbumFusionData(cleanDataBeginTime, AlbumFusionState::START,
        compensateData->upgradeStore_);
    if (MatchedDataFusion(compensateData) != E_OK) {
        MediaLibraryAlbumFusionUtils::ReportAlbumFusionData(cleanDataBeginTime, AlbumFusionState::FAILED,
            compensateData->upgradeStore_);
        return;
    }
    int32_t notMatchedDataHandleResult = MediaLibraryAlbumFusionUtils::HandleNotMatchedDataFusion(
        compensateData->upgradeStore_);
    if (notMatchedDataHandleResult != E_OK) {
        MEDIA_ERR_LOG("Fatal err, handle not matched relationship fail by %{public}d", notMatchedDataHandleResult);
        // This should not happen, and if it does, avoid cleaning up more data.
        MediaLibraryAlbumFusionUtils::ReportAlbumFusionData(cleanDataBeginTime, AlbumFusionState::FAILED,
            compensateData->upgradeStore_);
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
    MediaLibraryAlbumFusionUtils::SetAlbumFuseUpgradeStatus(1); // 1: set upgrade status success
    ResetCloudCursorAfterInitFinish();
    MediaLibraryAlbumFusionUtils::RefreshAllAlbums();
    MediaLibraryAlbumFusionUtils::ReportAlbumFusionData(cleanDataBeginTime, AlbumFusionState::SUCCESS,
        compensateData->upgradeStore_);
    MEDIA_INFO_LOG("ALBUM_FUSE: Processing old data end, cost %{public}ld",
        (long)(MediaFileUtils::UTCTimeMilliSeconds() - beginTime));
}

static void ReconstructMediaLibraryStorageFormatWithLock(AsyncTaskData *data)
{
    CHECK_AND_RETURN_LOG(data != nullptr, "task data is nullptr");
    CompensateAlbumIdData *compensateData = static_cast<CompensateAlbumIdData *>(data);
    CHECK_AND_RETURN_LOG(compensateData != nullptr, "compensateData is nullptr");
    std::unique_lock<std::mutex> reconstructLock(compensateData->lock_, std::defer_lock);
    if (reconstructLock.try_lock()) {
        ReconstructMediaLibraryStorageFormatExecutor(data);
    } else {
        MEDIA_WARN_LOG("Failed to acquire lock, skipping task Reconstruct.");
    }
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
        int32_t err = ExecSqlWithRetry([&]() { return store.ExecuteSql(CREATE_HIDDEN_ALBUM_FOR_DUAL_ASSET); });
        CHECK_AND_PRINT_LOG(err == NativeRdb::E_OK,
            "Failed to exec: %{private}s", CREATE_HIDDEN_ALBUM_FOR_DUAL_ASSET.c_str());
    }
}

int32_t MediaLibraryRdbStore::ReconstructMediaLibraryStorageFormat(const std::shared_ptr<MediaLibraryRdbStore> store)
{
    MEDIA_INFO_LOG("ALBUM_FUSE: Start reconstruct medialibrary storage format task!");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker !=  nullptr, E_FAIL, "Failed to get aysnc worker instance!");

    auto *taskData = new (std::nothrow) CompensateAlbumIdData(store, MediaLibraryRdbStore::reconstructLock_);
    CHECK_AND_RETURN_RET_LOG(taskData != nullptr, E_NO_MEMORY, "Failed to alloc async data for compensate album id");

    auto asyncTask = std::make_shared<MediaLibraryAsyncTask>(ReconstructMediaLibraryStorageFormatWithLock, taskData);
    asyncWorker->AddTask(asyncTask, false);
    return E_OK;
}

void AddHighlightMapTable(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        CREATE_ANALYSIS_ASSET_SD_MAP_TABLE,
        CREATE_ANALYSIS_ALBUM_ASET_MAP_TABLE,
        "ALTER TABLE " + HIGHLIGHT_PLAY_INFO_TABLE + " ADD COLUMN " + HIGHLIGHTING_ALGO_VERSION + " TEXT",
        "ALTER TABLE " + HIGHLIGHT_PLAY_INFO_TABLE + " ADD COLUMN " + CAMERA_MOVEMENT_ALGO_VERSION + " TEXT",
        "ALTER TABLE " + HIGHLIGHT_PLAY_INFO_TABLE + " ADD COLUMN " + TRANSITION_ALGO_VERSION + " TEXT",
    };
    MEDIA_INFO_LOG("add analysis map table of highlight db");
    ExecSqls(executeSqlStrs, store);
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

static void UpgradeUriPermissionTable(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_UPDATE_URIPERMISSION_SOURCE_TOKEN_AND_TARGET_TOKEN) {
        AddSourceAndTargetTokenForUriPermission(store);
    }
}

static void UpgradeHighlightAlbumChange(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_HIGHLIGHT_CHANGE_FUNCTION) {
        AddHighlightChangeFunction(store);
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

static void AddGeoDefaultValue(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + VISION_TOTAL_TABLE + " DROP COLUMN " + GEO,
        "ALTER TABLE " + VISION_TOTAL_TABLE + " ADD COLUMN " + GEO + " INT DEFAULT 0",
    };
    MEDIA_INFO_LOG("Add geo deault value start");
    ExecSqls(sqls, store);
}

static void AddOCRCardColumns(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + VISION_OCR_TABLE + " ADD COLUMN " + OCR_CARD_TEXT + " TEXT",
        "ALTER TABLE " + VISION_OCR_TABLE + " ADD COLUMN " + OCR_CARD_TEXT_MSG + " TEXT",
    };
    MEDIA_INFO_LOG("Add video face table start");
    ExecSqls(sqls, store);
}

static void AddThumbnailVisible(RdbStore& store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_THUMBNAIL_VISIBLE +
        " INT DEFAULT 0",
        "UPDATE " + PhotoColumn::PHOTOS_TABLE +
        " SET thumbnail_visible = "
        " CASE "
            " WHEN thumbnail_ready > 0 THEN 1 "
            " ELSE 0 "
        " END ",
        PhotoColumn::DROP_INDEX_SCHPT_READY,
        PhotoColumn::INDEX_SCHPT_READY,
    };
    MEDIA_INFO_LOG("Add video face table start");
    ExecSqls(sqls, store);
}

static void AlterThumbnailVisible(RdbStore& store)
{
    const vector<string> sqls = {
        PhotoColumn::DROP_INDEX_SCHPT_READY,
        PhotoColumn::INDEX_SCHPT_READY,
    };
    MEDIA_INFO_LOG("Add AlterThumbnailVisible");
    ExecSqls(sqls, store);
}

static void AddHighlightVideoCountCanPack(RdbStore& store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + HIGHLIGHT_ALBUM_TABLE + " ADD COLUMN " + HIGHLIGHT_VIDEO_COUNT_CAN_PACK + " INT",
    };
    MEDIA_INFO_LOG("Add key: hilghlight video count can pack Start");
    ExecSqls(sqls, store);
}

static void FixSourceAlbumUpdateTriggerToUseLPath(RdbStore& store)
{
    const vector<string> sqls = {
        DROP_INSERT_SOURCE_PHOTO_UPDATE_ALBUM_ID_TRIGGER,
        CREATE_INSERT_SOURCE_UPDATE_ALBUM_ID_TRIGGER
    };
    MEDIA_INFO_LOG("Fix source album update trigger to use lpath start");
    ExecSqls(sqls, store);
}

static void AddMediaSuffixColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_MEDIA_SUFFIX + " TEXT",
    };
    ExecSqls(sqls, store);
}

static void AddVisitCountColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
            " ADD COLUMN " + PhotoColumn::PHOTO_REAL_LCD_VISIT_TIME  + " BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
            " ADD COLUMN " + PhotoColumn::PHOTO_VISIT_COUNT  + " INT NOT NULL DEFAULT 0",
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE +
            " ADD COLUMN " + PhotoColumn::PHOTO_LCD_VISIT_COUNT  + " INT NOT NULL DEFAULT 0"
    };
    MEDIA_INFO_LOG("add real_lcd_visit_time/visit_count/lcd_visit_count column start");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("add real_lcd_visit_time/visit_count/lcd_visit_count column end");
}

static void AddIsRecentShow(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_IS_RECENT_SHOW  +
            " INT NOT NULL DEFAULT 1",
    };
    MEDIA_INFO_LOG("add is_recent_show column start");
    ExecSqls(sqls, store);
}

static void AddFrontAnalysisColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + FRONT_INDEX_LIMIT + " INT DEFAULT 0",
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + FRONT_INDEX_MODIFIED + " BIGINT DEFAULT 0",
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + FRONT_INDEX_COUNT + " INT DEFAULT 0",
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + FRONT_CV_MODIFIED + " BIGINT DEFAULT 0",
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + FRONT_CV_COUNT + " INT DEFAULT 0",
        CREATE_PHOTO_STATUS_FOR_SEARCH_INDEX,
    };
    MEDIA_INFO_LOG("Add front analysis column start");
    ExecSqls(sqls, store);
}

static void AddDcAnalysisColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + DC_INDEX_COUNT + " INT DEFAULT 0",
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + DC_OCR_COUNT + " INT DEFAULT 0",
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + DC_LABEL_COUNT + " INT DEFAULT 0",
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + DC_MODIFY_TIME_STAMP + " BIGINT DEFAULT 0",
    };
    MEDIA_INFO_LOG("Add DC analysis column start");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("Add DC analysis column end");
}

static void AddDcAnalysisIndexUpdateColumn(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + USER_PHOTOGRAPHY_INFO_TABLE + " ADD COLUMN " + DC_INDEX_UPDATE_COUNT + " INT DEFAULT 0",
    };
    MEDIA_INFO_LOG("Add DC analysis index update column start");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("Add DC analysis index update column end");
}

static void FixSourceAlbumCreateTriggersToUseLPath(RdbStore& store)
{
    const vector<string> sqls = {
        DROP_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER,
        CREATE_INSERT_SOURCE_PHOTO_CREATE_SOURCE_ALBUM_TRIGGER
    };
    MEDIA_INFO_LOG("Fix source album other triggers to use lpath start");
    ExecSqls(sqls, store);
}

static void AddAlbumPluginBundleName(RdbStore &store)
{
    MEDIA_INFO_LOG("Start updating album plugin");
    const vector<string> sqls = {
        "DROP TABLE IF EXISTS album_plugin;"
    };
    ExecSqls(sqls, store);
    AlbumPluginTableEventHandler().OnCreate(store);
    MEDIA_INFO_LOG("End updating album plugin");
}

static void FixMdirtyTriggerToUploadDetailTime(RdbStore &store)
{
    MEDIA_INFO_LOG("Start updating mdirty trigger to upload detail_time");
    const vector<string> sqls = {
        "DROP TRIGGER IF EXISTS photos_mdirty_trigger",
        PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER,
    };
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("End updating mdirty trigger to upload detail_time");
}

static void UpgradeFromAPI15(RdbStore &store, unordered_map<string, bool> &photoColumnExists)
{
    MEDIA_INFO_LOG("Start VERSION_UPDATE_SOURCE_PHOTO_ALBUM_TRIGGER_AGAIN");
    UpdateSourcePhotoAlbumTrigger(store);
    MEDIA_INFO_LOG("End VERSION_UPDATE_SOURCE_PHOTO_ALBUM_TRIGGER_AGAIN");

    MEDIA_INFO_LOG("Start VERSION_ADD_MEDIA_IS_RECENT_SHOW_COLUMN");
    if (photoColumnExists.find(PhotoColumn::PHOTO_IS_RECENT_SHOW) == photoColumnExists.end() ||
        !photoColumnExists.at(PhotoColumn::PHOTO_IS_RECENT_SHOW)) {
        AddIsRecentShow(store);
    }
    MEDIA_INFO_LOG("End VERSION_ADD_MEDIA_IS_RECENT_SHOW_COLUMN");

    MEDIA_INFO_LOG("Start VERSION_FIX_SOURCE_ALBUM_CREATE_TRIGGERS_TO_USE_LPATH");
    FixSourceAlbumCreateTriggersToUseLPath(store);
    MEDIA_INFO_LOG("End VERSION_FIX_SOURCE_ALBUM_CREATE_TRIGGERS_TO_USE_LPATH");

    MEDIA_INFO_LOG("Start VERSION_ADD_IS_AUTO");
    if (photoColumnExists.find(PhotoColumn::PHOTO_IS_AUTO) == photoColumnExists.end() ||
        !photoColumnExists.at(PhotoColumn::PHOTO_IS_AUTO)) {
        AddIsAutoColumns(store);
    }
    MEDIA_INFO_LOG("End VERSION_ADD_IS_AUTO");

    MEDIA_INFO_LOG("Start VERSION_ADD_ALBUM_PLUGIN_BUNDLE_NAME");
    AddAlbumPluginBundleName(store);
    MEDIA_INFO_LOG("End VERSION_ADD_ALBUM_PLUGIN_BUNDLE_NAME");

    MEDIA_INFO_LOG("Start VERSION_ADD_MEDIA_SUFFIX_COLUMN");
    if (photoColumnExists.find(PhotoColumn::PHOTO_MEDIA_SUFFIX) == photoColumnExists.end() ||
        !photoColumnExists.at(PhotoColumn::PHOTO_MEDIA_SUFFIX)) {
        AddMediaSuffixColumn(store);
    }
    MEDIA_INFO_LOG("End VERSION_ADD_MEDIA_SUFFIX_COLUMN");

    MEDIA_INFO_LOG("Start VERSION_HIGHLIGHT_SUBTITLE");
    if (!IsColumnExists(store, HIGHLIGHT_ALBUM_TABLE, HIGHLIGHT_USE_SUBTITLE)) {
        AddHighlightUseSubtitle(store);
    }
    MEDIA_INFO_LOG("End VERSION_HIGHLIGHT_SUBTITLE");
}

static void UpgradeAPI18(RdbStore &store, unordered_map<string, bool> &photoColumnExists)
{
    MEDIA_INFO_LOG("Start VERSION_ADD_METARECOVERY");
    if (photoColumnExists.find(PhotoColumn::PHOTO_METADATA_FLAGS) == photoColumnExists.end() ||
        !photoColumnExists.at(PhotoColumn::PHOTO_METADATA_FLAGS)) {
        AddMetaRecovery(store);
    }
    MEDIA_INFO_LOG("End VERSION_ADD_METARECOVERY");

    MEDIA_INFO_LOG("Start VERSION_ADD_HIGHLIGHT_TRIGGER");
    if (!IsColumnExists(store, PhotoColumn::HIGHLIGHT_TABLE, PhotoColumn::MEDIA_DATA_DB_HIGHLIGHT_TRIGGER)) {
        AddHighlightTriggerColumn(store);
        AddHighlightInsertAndUpdateTrigger(store);
        AddHighlightIndex(store);
    }
    MEDIA_INFO_LOG("End VERSION_ADD_HIGHLIGHT_TRIGGER");

    MEDIA_INFO_LOG("Start VERSION_UPDATE_SEARCH_STATUS_TRIGGER_FOR_OWNER_ALBUM_ID");
    UpdateSearchStatusTriggerForOwnerAlbumId(store);
    MEDIA_INFO_LOG("End VERSION_UPDATE_SEARCH_STATUS_TRIGGER_FOR_OWNER_ALBUM_ID");

    MEDIA_INFO_LOG("Start VERSION_HIGHLIGHT_MOVING_PHOTO");
    AddMovingPhotoRelatedData(store);
    MEDIA_INFO_LOG("End VERSION_HIGHLIGHT_MOVING_PHOTO");

    MEDIA_INFO_LOG("Start VERSION_CREATE_TAB_FACARD_PHOTOS");
    TabFaCardPhotosTableEventHandler().OnCreate(store);
    MEDIA_INFO_LOG("End VERSION_CREATE_TAB_FACARD_PHOTOS");

    MEDIA_INFO_LOG("Start VERSION_ADD_FOREGROUND_ANALYSIS");
    if (!IsColumnExists(store, USER_PHOTOGRAPHY_INFO_TABLE, FRONT_INDEX_LIMIT)) {
        AddFrontAnalysisColumn(store);
    }
    MEDIA_INFO_LOG("End VERSION_ADD_FOREGROUND_ANALYSIS");
}

static void AddAssetAlbumOperationTable(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        "DROP TABLE IF EXISTS tab_asset_and_album_operation",
        CREATE_TAB_ASSET_ALBUM_OPERATION,
        "DROP TABLE IF EXISTS operation_asset_insert_trigger",
        CREATE_OPERATION_ASSET_INSERT_TRIGGER,
        "DROP TABLE IF EXISTS operation_asset_delete_trigger",
        CREATE_OPERATION_ASSET_DELETE_TRIGGER,
        "DROP TABLE IF EXISTS operation_asset_update_trigger",
        CREATE_OPERATION_ASSET_UPDATE_TRIGGER,
        "DROP TABLE IF EXISTS operation_album_insert_trigger",
        CREATE_OPERATION_ALBUM_INSERT_TRIGGER,
        "DROP TABLE IF EXISTS operation_album_delete_trigger",
        CREATE_OPERATION_ALBUM_DELETE_TRIGGER,
        "DROP TABLE IF EXISTS operation_album_update_trigger",
        CREATE_OPERATION_ALBUM_UPDATE_TRIGGER,
    };
    ExecSqls(executeSqlStrs, store);
    MEDIA_INFO_LOG("create asset and album operation table end");
}

static void AddAssetAlbumOperationTableForSync(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        CREATE_TAB_ASSET_ALBUM_OPERATION,
        "DROP TABLE IF EXISTS operation_asset_insert_trigger",
        CREATE_OPERATION_ASSET_INSERT_TRIGGER,
        "DROP TABLE IF EXISTS operation_asset_delete_trigger",
        CREATE_OPERATION_ASSET_DELETE_TRIGGER,
        "DROP TABLE IF EXISTS operation_asset_update_trigger",
        CREATE_OPERATION_ASSET_UPDATE_TRIGGER,
        "DROP TABLE IF EXISTS operation_album_insert_trigger",
        CREATE_OPERATION_ALBUM_INSERT_TRIGGER,
        "DROP TABLE IF EXISTS operation_album_delete_trigger",
        CREATE_OPERATION_ALBUM_DELETE_TRIGGER,
        "DROP TABLE IF EXISTS operation_album_update_trigger",
        CREATE_OPERATION_ALBUM_UPDATE_TRIGGER,
    };
    ExecSqls(executeSqlStrs, store);
    MEDIA_INFO_LOG("create asset and album operation table sync end");
}

static void UpgradeAnalysisUpdateSearchTrigger(RdbStore &store)
{
    MEDIA_INFO_LOG("start upgrade analysis update search trigger");
    const vector<string> sqls = {
        "DROP TRIGGER IF EXISTS " + ANALYSIS_UPDATE_SEARCH_TRIGGER,
        CREATE_ANALYSIS_UPDATE_SEARCH_TRIGGER,
    };
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end upgrade analysis update search trigger");
}

static void CreateTabCustomRecords(RdbStore &store)
{
    const vector<string> executeSqlStrs = {
        CustomRecordsColumns::CREATE_TABLE,
    };
    ExecSqls(executeSqlStrs, store);
    MEDIA_INFO_LOG("create custom and records end");
}

static void AddIsRectificationCover(RdbStore &store)
{
    const vector<string> sqls = {
        "ALTER TABLE " + PhotoColumn::PHOTOS_TABLE + " ADD COLUMN " + PhotoColumn::PHOTO_IS_RECTIFICATION_COVER +
            " INT NOT NULL DEFAULT 0",
    };
    MEDIA_INFO_LOG("start add is_rectification_cover column");
    ExecSqls(sqls, store);
    MEDIA_INFO_LOG("end add is_rectification_cover column");
}

static void UpgradeExtensionPart6(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_FIX_DB_UPGRADE_FROM_API15) {
        unordered_map<string, bool> photoColumnExists = {
            { PhotoColumn::PHOTO_IS_RECENT_SHOW, false },
            { PhotoColumn::PHOTO_IS_AUTO, false },
            { PhotoColumn::PHOTO_MEDIA_SUFFIX, false },
            { PhotoColumn::PHOTO_METADATA_FLAGS, false },
        };
        CheckIfPhotoColumnExists(store, photoColumnExists);
        UpgradeFromAPI15(store, photoColumnExists);
        UpgradeAPI18(store, photoColumnExists);
    }

    if (oldVersion < VERSION_CREATE_TAB_ASSET_ALBUM_OPERATION_FOR_SYNC) {
        AddAssetAlbumOperationTableForSync(store);
    }

    if (oldVersion < VERSION_CREATE_TAB_FACARD_PHOTOS_RETRY) {
        TabFaCardPhotosTableEventHandler().OnCreate(store);
    }
    
    if (oldVersion < VERSION_UPDATE_SEARCH_STATUS_TRIGGER_FOR_IS_FAVORITE) {
        UpdateSearchStatusTriggerForIsFavorite(store);
    }

    if (oldVersion < VERSION_UPGRADE_ANALYSIS_UPDATE_SEARCH_TRIGGER) {
        UpgradeAnalysisUpdateSearchTrigger(store);
    }

    if (oldVersion < VERSION_ADD_DC_ANALYSIS) {
        AddDcAnalysisColumn(store);
    }

    if (oldVersion < VERSION_ADD_VISIT_COUNT) {
        AddVisitCountColumn(store);
    }

    if (oldVersion < VERSION_CREATE_TAB_CUSTOM_RECORDS) {
        CreateTabCustomRecords(store);
    }

    if (oldVersion < VERSION_ADD_DC_ANALYSIS_INDEX_UPDATE) {
        AddDcAnalysisIndexUpdateColumn(store);
    }

    if (oldVersion < VERSION_ADD_IS_RECTIFICATION_COVER) {
        AddIsRectificationCover(store);
        UpdatePhotosMdirtyTrigger(store);
    }

    TableEventHandler().OnUpgrade(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStore(), oldVersion, MEDIA_RDB_VERSION);
}

static void UpgradeExtensionPart5(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_ADD_STAGE_VIDEO_TASK_STATUS) {
        AddStageVideoTaskStatus(store);
    }

    if (oldVersion < VERSION_HIGHLIGHT_SUBTITLE) {
        AddHighlightUseSubtitle(store);
    }

    if (oldVersion < VERSION_ADD_IS_AUTO) {
        AddIsAutoColumns(store);
    }

    if (oldVersion < VERSION_ADD_MEDIA_SUFFIX_COLUMN) {
        AddMediaSuffixColumn(store);
    }

    if (oldVersion < VERSION_UPDATE_SOURCE_PHOTO_ALBUM_TRIGGER_AGAIN) {
        UpdateSourcePhotoAlbumTrigger(store);
    }

    if (oldVersion < VERSION_ADD_MEDIA_IS_RECENT_SHOW_COLUMN) {
        AddIsRecentShow(store);
    }

    if (oldVersion < VERSION_CREATE_TAB_FACARD_PHOTOS) {
        TabFaCardPhotosTableEventHandler().OnCreate(store);
    }

    if (oldVersion < VERSION_FIX_SOURCE_ALBUM_CREATE_TRIGGERS_TO_USE_LPATH) {
        FixSourceAlbumCreateTriggersToUseLPath(store);
    }
    if (oldVersion < VERSION_ADD_ALBUM_PLUGIN_BUNDLE_NAME) {
        AddAlbumPluginBundleName(store);
    }

    if (oldVersion < VERSION_ADD_FOREGROUND_ANALYSIS) {
        AddFrontAnalysisColumn(store);
    }

    if (oldVersion < VERSION_HIGHLIGHT_MOVING_PHOTO) {
        AddMovingPhotoRelatedData(store);
    }

    if (oldVersion < VERSION_CREATE_TAB_ASSET_ALBUM_OPERATION) {
        AddAssetAlbumOperationTable(store);
    }

    if (oldVersion < VERSION_MDIRTY_TRIGGER_UPLOAD_DETAIL_TIME) {
        FixMdirtyTriggerToUploadDetailTime(store);
    }

    UpgradeExtensionPart6(store, oldVersion);
}

static void UpgradeExtensionPart4(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_CREATE_TAB_OLD_PHOTOS) {
        TabOldPhotosTableEventHandler().OnCreate(store);
    }

    if (oldVersion < VERSION_ADD_HIGHLIGHT_TRIGGER) {
        AddHighlightTriggerColumn(store);
        AddHighlightInsertAndUpdateTrigger(store);
        AddHighlightIndex(store);
    }

    if (oldVersion < VERSION_ALTER_THUMBNAIL_VISIBLE) {
        AlterThumbnailVisible(store);
    }

    if (oldVersion < VERSION_ADD_HIGHLIGHT_VIDEO_COUNT_CAN_PACK) {
        AddHighlightVideoCountCanPack(store);
    }

    if (oldVersion < VERSION_ADD_GEO_DEFAULT_VALUE) {
        AddGeoDefaultValue(store);
    }

    if (oldVersion < VERSION_HDR_AND_CLOUD_ENHANCEMENT_FIX) {
        AddDynamicRangeColumnsFix(store);
        AddCloudEnhanceColumnsFix(store);
    }

    if (oldVersion < VERSION_THUMBNAIL_READY_FIX) {
        AddThumbnailReadyColumnsFix(store);
    }

    if (oldVersion < VERSION_UPDATE_SOURCE_PHOTO_ALBUM_TRIGGER) {
        UpdateSourcePhotoAlbumTrigger(store);
    }

    if (oldVersion < VERSION_UPDATE_SEARCH_STATUS_TRIGGER_FOR_OWNER_ALBUM_ID) {
        UpdateSearchStatusTriggerForOwnerAlbumId(store);
    }

    if (oldVersion < VERSION_ADD_CHECK_FLAG) {
        AddCheckFlag(store);
    }

    if (oldVersion < VERSION_ADD_HIGHLIGHT_ANALYSIS_PROGRESS) {
        AddHighlightAnalysisProgress(store);
    }

    if (oldVersion < VERSION_FIX_SOURCE_PHOTO_ALBUM_DATE_MODIFIED) {
        UpdateSourcePhotoAlbumTrigger(store);
    }

    if (oldVersion < VERSION_ADD_REFRESH_ALBUM_STATUS_COLUMN) {
        AddRefreshAlbumStatusColumn(store);
    }

    if (oldVersion < VERSION_FIX_SOURCE_ALBUM_UPDATE_TRIGGER_TO_USE_LPATH) {
        FixSourceAlbumUpdateTriggerToUseLPath(store);
    }

    UpgradeExtensionPart5(store, oldVersion);
}

static void UpgradeExtensionPart3(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_CLOUD_ENAHCNEMENT) {
        AddCloudEnhancementColumns(store);
    }

    if (oldVersion < VERSION_UPDATE_MDIRTY_TRIGGER_FOR_UPLOADING_MOVING_PHOTO) {
        UpdatePhotosMdirtyTrigger(store);
    }

    if (oldVersion < VERSION_ADD_INDEX_FOR_FILEID) {
        AddIndexForFileId(store);
    }

    if (oldVersion < VERSION_ADD_OCR_CARD_COLUMNS) {
        AddOCRCardColumns(store);
    }

    if (oldVersion < VERSION_UPDATE_AOI) {
        UpdateAOI(store);
    }

    if (oldVersion < VERSION_UPDATE_VIDEO_FACE_TABLE) {
        UpdateVideoFaceTable(store);
    }

    if (oldVersion < VERSION_ADD_SUPPORTED_WATERMARK_TYPE) {
        AddSupportedWatermarkType(store);
    }

    if (oldVersion < VERSION_FIX_PHOTO_SCHPT_MEDIA_TYPE_INDEX) {
        FixPhotoSchptMediaTypeIndex(store);
    }

    if (oldVersion < VERSION_ADD_ANALYSIS_ALBUM_TOTAL_TABLE) {
        AddAnalysisAlbumTotalTable(store);
    }

    if (oldVersion < VERSION_ADD_THUMBNAIL_VISIBLE) {
        AddThumbnailVisible(store);
    }

    if (oldVersion < VERSION_ADD_METARECOVERY) {
        AddMetaRecovery(store);
    }
    if (oldVersion < VERSION_UPDATE_SEARCH_INDEX_TRIGGER_FOR_CLEAN_FLAG) {
        UpdateSearchIndexTriggerForCleanFlag(store);
    }
    if (oldVersion < VERSION_ADD_COVER_PLAY_SERVICE_VERSION) {
        AddCoverPlayVersionColumns(store);
    }
    if (oldVersion < VERSION_ADD_HIGHLIGHT_MAP_TABLES) {
        AddHighlightMapTable(store);
    }

    if (oldVersion < VERSION_COMPAT_LIVE_PHOTO) {
        CompatLivePhoto(store, oldVersion);
    }

    UpgradeExtensionPart4(store, oldVersion);
}

static void UpgradeExtensionPart2(RdbStore &store, int32_t oldVersion)
{
    if (oldVersion < VERSION_UPDATE_PHOTO_INDEX_FOR_ALBUM_COUNT_COVER) {
        UpdateIndexForAlbumQuery(store);
    }

    if (oldVersion < VERSION_UPDATE_VIDEO_LABEL_TABLE_FOR_SUB_LABEL_TYPE) {
        UpdateVideoLabelTableForSubLabelType(store);
    }

    // VERSION_UPGRADE_THUMBNAIL move to HandleUpgradeRdbAsync()

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
        MEDIA_INFO_LOG("ALBUM_FUSE: set album fuse upgrade status");
        MediaLibraryAlbumFusionUtils::SetAlbumFuseUpgradeStatus(0);
    }

    UpgradeExtensionPart3(store, oldVersion);
    // !! Do not add upgrade code here !!
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
    UpgradeUriPermissionTable(store, oldVersion);
    UpgradeHighlightAlbumChange(store, oldVersion);

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
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    prefs->PutInt(RDB_OLD_VERSION, oldVersion);
    prefs->FlushSync();
}

int32_t MediaLibraryRdbStore::GetOldVersion()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(RDB_CONFIG, errCode);
    CHECK_AND_RETURN_RET_LOG(prefs, oldVersion_, "get preferences error: %{public}d", errCode);
    return prefs->GetInt(RDB_OLD_VERSION, oldVersion_);
}

bool MediaLibraryRdbStore::HasColumnInTable(RdbStore &store, const string &columnName, const string &tableName)
{
    string querySql = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM pragma_table_info('" + tableName + "') WHERE name = '" +
        columnName + "'";
    auto resultSet = store.QuerySql(querySql);
    bool cond = (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK);
    CHECK_AND_RETURN_RET_LOG(!cond, false, "Get column count failed");

    int32_t count = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    MEDIA_DEBUG_LOG("%{private}s in %{private}s: %{public}d", columnName.c_str(), tableName.c_str(), count);
    return count > 0;
}

void MediaLibraryRdbStore::AddColumnIfNotExists(
    RdbStore &store, const string &columnName, const string &columnType, const string &tableName)
{
    if (!HasColumnInTable(store, columnName, tableName)) {
        string sql = "ALTER TABLE " + tableName + " ADD COLUMN " + columnName + " " + columnType;
        ExecSqlWithRetry([&]() { return store.ExecuteSql(sql); });
    }
}

int MediaLibraryRdbStore::Update(int &changedRows, const std::string &table, const ValuesBucket &row,
    const std::string &whereClause, const std::vector<std::string> &args)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry(
        [&]() { return MediaLibraryRdbStore::GetRaw()->Update(changedRows, table, row, whereClause, args); });
}

std::string MediaLibraryRdbStore::ObtainDistributedTableName(const std::string &device, const std::string &table,
    int &errCode)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), "",
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return MediaLibraryRdbStore::GetRaw()->ObtainDistributedTableName(device, table, errCode);
}

int MediaLibraryRdbStore::Backup(const std::string &databasePath, const std::vector<uint8_t> &encryptKey)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->Backup(databasePath, encryptKey); });
}

int MediaLibraryRdbStore::Sync(const DistributedRdb::SyncOption &option, const AbsRdbPredicates &predicate,
    const DistributedRdb::AsyncBrief &async)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->Sync(option, predicate, async); });
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::QueryByStep(const std::string &sql,
    const std::vector<ValueObject> &args)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), nullptr,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return MediaLibraryRdbStore::GetRaw()->QueryByStep(sql, args);
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::QueryByStep(const AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), nullptr,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return MediaLibraryRdbStore::GetRaw()->QueryByStep(predicates, columns);
}

int MediaLibraryRdbStore::Update(int &changedRows, const ValuesBucket &row, const AbsRdbPredicates &predicates)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->Update(changedRows, row, predicates); });
}

int MediaLibraryRdbStore::Insert(int64_t &outRowId, const std::string &table, ValuesBucket &row)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    if (table == PhotoColumn::PHOTOS_TABLE) {
        AddDefaultPhotoValues(row);
    }
    return ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->Insert(outRowId, table, row); });
}

int MediaLibraryRdbStore::Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
    const std::vector<std::string> &args)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry(
        [&]() { return MediaLibraryRdbStore::GetRaw()->Delete(deletedRows, table, whereClause, args); });
}

int MediaLibraryRdbStore::Delete(int &deletedRows, const AbsRdbPredicates &predicates)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->Delete(deletedRows, predicates); });
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryRdbStore::Query(const NativeRdb::AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), nullptr,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return MediaLibraryRdbStore::GetRaw()->Query(predicates, columns);
}

std::shared_ptr<AbsSharedResultSet> MediaLibraryRdbStore::QuerySql(const std::string &sql,
    const std::vector<ValueObject> &args)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), nullptr,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return MediaLibraryRdbStore::GetRaw()->QuerySql(sql, args);
}

int MediaLibraryRdbStore::InterruptBackup()
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->InterruptBackup(); });
}

bool MediaLibraryRdbStore::IsSlaveDiffFromMaster() const
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), false,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return MediaLibraryRdbStore::GetRaw()->IsSlaveDiffFromMaster();
}

int MediaLibraryRdbStore::Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey)
{
    CHECK_AND_RETURN_RET_LOG(MediaLibraryRdbStore::CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry([&]() { return MediaLibraryRdbStore::GetRaw()->Restore(backupPath, newKey); });
}

int32_t MediaLibraryRdbStore::DataCallBackOnCreate()
{
    MediaLibraryDataCallBack callback;
    int32_t ret = callback.OnCreate(*GetRaw());
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK,
        "MediaLibraryDataCallBack OnCreate error, ret: %{public}d", ret);
    return ret;
}

void MediaLibraryRdbStore::WalCheckPoint()
{
    std::unique_lock<std::mutex> lock(walCheckPointMutex_, std::defer_lock);
    if (!lock.try_lock()) {
        MEDIA_WARN_LOG("wal_checkpoint in progress, skip this operation");
        return;
    }

    struct stat fileStat;
    const std::string walFile = MEDIA_DB_DIR + "/rdb/media_library.db-wal";
    if (stat(walFile.c_str(), &fileStat) < 0) {
        CHECK_AND_PRINT_LOG(errno == ENOENT, "wal_checkpoint stat failed, errno: %{public}d", errno);
        return;
    }
    ssize_t size = fileStat.st_size;
    CHECK_AND_RETURN_LOG(size >= 0, "Invalid size for wal_checkpoint, size: %{public}zd", size);
    CHECK_AND_RETURN(size > RDB_CHECK_WAL_SIZE);

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "wal_checkpoint rdbStore is nullptr!");

    auto errCode = rdbStore->ExecuteSql("PRAGMA wal_checkpoint(TRUNCATE)");
    CHECK_AND_PRINT_LOG(errCode == NativeRdb::E_OK, "wal_checkpoint ExecuteSql failed, errCode: %{public}d", errCode);
}

int MediaLibraryRdbStore::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &args)
{
    CHECK_AND_RETURN_RET_LOG(CheckRdbStore(), E_HAS_DB_ERROR,
        "Pointer rdbStore_ is nullptr. Maybe it didn't init successfully.");
    return ExecSqlWithRetry([&]() { return GetRaw()->ExecuteForChangedRowCount(outValue, sql, args); });
}
} // namespace OHOS::Media
