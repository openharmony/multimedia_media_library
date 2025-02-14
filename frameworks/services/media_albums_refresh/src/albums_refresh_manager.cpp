/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "AlbumsRefreshManager"

#include "albums_refresh_manager.h"

#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "medialibrary_tracer.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_notify.h"
#include "userfilemgr_uri.h"
#include "media_refresh_album_column.h"
#include "albums_refresh_worker.h"
#include "albums_refresh_notify.h"
#include "rdb_sql_utils.h"
#include "result_set_utils.h"
#include "photo_album_column.h"
#include "medialibrary_rdb_utils.h"
#include "vision_column.h"
#include "medialibrary_restore.h"
#include "post_event_utils.h"
#ifdef HAS_POWER_MANAGER_PART
#include "power_mgr_client.h"
#endif

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
using ChangeType = DataShare::DataShareObserver::ChangeType;
static int64_t lastRefreshTimestamp_ = 0;
static int64_t lastAnalysisRefreshTimestamp_ = 0;
static const int32_t SCREEN_OFF = 0;
static const int32_t SCREEN_ON = 1;
static const int32_t E_EMPTY_ALBUM_ID = 1;

AlbumsRefreshManager::AlbumsRefreshManager()
{
    refreshWorker_ = make_shared<AlbumsRefreshWorker>();
}

AlbumsRefreshManager::~AlbumsRefreshManager()
{}

AlbumsRefreshManager &AlbumsRefreshManager::GetInstance()
{
    static AlbumsRefreshManager instance;
    return instance;
}

static shared_ptr<NativeRdb::ResultSet> QueryGoToFirst(
    const shared_ptr<MediaLibraryRdbStore> rdbStore, const RdbPredicates &predicates, const vector<string> &columns)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryGoToFirst");
    auto resultSet = rdbStore->StepQueryWithoutCheck(predicates, columns);
    CHECK_AND_RETURN_RET(resultSet != nullptr, nullptr);

    MediaLibraryTracer goToFirst;
    goToFirst.Start("GoToFirstRow");
    int32_t err = resultSet->GoToFirstRow();
    MediaLibraryRestore::GetInstance().CheckRestore(err);
    return resultSet;
}

static inline uint8_t GetScreenStatus()
{
#ifdef HAS_POWER_MANAGER_PART
    auto &powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    return powerMgrClient.IsScreenOn() ? SCREEN_ON : SCREEN_OFF;
#endif
    return SCREEN_OFF;
}

static inline int32_t GetRefreshTimeThreshold()
{
    const int32_t onDelay = 10;
    const int32_t offDelay = 600;
    return (GetScreenStatus() == SCREEN_ON) ? onDelay : offDelay;
}

void AlbumsRefreshManager::AddAlbumRefreshTask(SyncNotifyInfo &info)
{
    refreshWorker_->AddAlbumRefreshTask(info);
}

bool AlbumsRefreshManager::HasRefreshingSystemAlbums()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "Can not get rdb");
    RdbPredicates predicates(ALBUM_REFRESH_TABLE);
    vector<string> columns = {REFRESHED_ALBUM_ID};
    predicates.SetWhereClause(ALBUM_REFRESH_STATUS + " = 1");
    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "Can not query ALBUM_REFRESH_TABLE");
    int32_t count = 0;
    int32_t ret = resultSet->GetRowCount(count);
    resultSet->Close();
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, false, "Failed to execute sql");
    MEDIA_INFO_LOG("refreshing system albums count: %{public}d", count);
    return count != 0;
}

static int32_t GetSystemAlbumsFromRefreshAlbumTable(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    std::vector<RefreshAlbumData> &systemAlbums, ForceRefreshType forceRefreshType)
{
    vector<string> columns = {PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_SUBTYPE};
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    if (forceRefreshType == ForceRefreshType::NONE) {
        predicates.SetWhereClause(PhotoAlbumColumns::ALBUM_ID + " IN (SELECT " + REFRESHED_ALBUM_ID + " FROM " +
                                  ALBUM_REFRESH_TABLE + " WHERE " + ALBUM_REFRESH_STATUS + " = 0)");
    } else if (forceRefreshType == ForceRefreshType::EXCEPTION) {
        predicates.SetWhereClause(PhotoAlbumColumns::ALBUM_ID + " IN (SELECT " + REFRESHED_ALBUM_ID + " FROM " +
                                  ALBUM_REFRESH_TABLE + " WHERE " + ALBUM_REFRESH_STATUS + " = 1)");
    }
    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "Can not query ALBUM_REFRESH_TABLE");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        RefreshAlbumData data;
        data.albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        data.albumSubtype = static_cast<PhotoAlbumSubType>(GetInt32Val(PhotoAlbumColumns::ALBUM_SUBTYPE, resultSet));
        systemAlbums.push_back(data);
    }
    resultSet->Close();
    return E_SUCCESS;
}

static int32_t GetAnalysisRefreshAlbums(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    vector<RefreshAlbumData> &analysisAlbums, bool &isUpdateAllAnalysis, ForceRefreshType forceRefreshType)
{
    RdbPredicates refreshAlbumPredicates(ALBUM_REFRESH_TABLE);
    refreshAlbumPredicates.EqualTo(REFRESHED_ALBUM_ID, -1);
    vector<string> columns = { REFRESHED_ALBUM_ID };
    auto resultSet = rdbStore->Query(refreshAlbumPredicates, columns);
    if (resultSet != nullptr && resultSet->GoToFirstRow() == E_OK) {
        resultSet->Close();
        isUpdateAllAnalysis = true;
        return E_OK;
    }

    columns = {PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_SUBTYPE};
    RdbPredicates analysisPredicates(ANALYSIS_ALBUM_TABLE);
    if (forceRefreshType == ForceRefreshType::NONE || forceRefreshType == ForceRefreshType::EXCEPTION) {
        analysisPredicates.SetWhereClause(PhotoAlbumColumns::ALBUM_ID + " IN (SELECT " + REFRESHED_ALBUM_ID +
                                  " - 100000000 FROM " + ALBUM_REFRESH_TABLE + " WHERE refresh_album_id > 100000000)");
    }
    resultSet = rdbStore->Query(analysisPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "Can not query ALBUM_REFRESH_TABLE");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        RefreshAlbumData data;
        data.albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        data.albumSubtype = static_cast<PhotoAlbumSubType>(GetInt32Val(PhotoAlbumColumns::ALBUM_SUBTYPE, resultSet));
        if (data.albumId == -1) {
            isUpdateAllAnalysis = true;
        } else {
            analysisAlbums.push_back(data);
        }
    }
    resultSet->Close();
    return E_SUCCESS;
}

static void ConstructAlbumNotifyUris(SyncNotifyInfo &info, int32_t albumId)
{
    string extraUri = PhotoAlbumColumns::ALBUM_URI_PREFIX + std::to_string(albumId);
    MEDIA_DEBUG_LOG("#test extraUri: %{public}s", extraUri.c_str());
    info.extraUris.push_back(Uri(extraUri));
}

static int32_t RefreshAlbumInfoAndUris(
    const shared_ptr<MediaLibraryRdbStore> rdbStore, int32_t albumId, PhotoAlbumSubType subtype, SyncNotifyInfo &info)
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    if (info.forceRefreshType == ForceRefreshType::NONE) {
        string updateRefreshAlbumSql = "UPDATE " + ALBUM_REFRESH_TABLE + " SET " + ALBUM_REFRESH_STATUS +
                                       " = 1 WHERE " + REFRESHED_ALBUM_ID + " = " + std::to_string(albumId);
        int32_t ret = rdbStore->ExecuteSql(updateRefreshAlbumSql);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "#test Failed to execute update refresh album sql:%{public}s", updateRefreshAlbumSql.c_str());
    }
    string sql;
    int32_t ret = MediaLibraryRdbUtils::FillOneAlbumCountAndCoverUri(rdbStore, albumId, subtype, sql);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, ret);

    ret = rdbStore->ExecuteSql(sql);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_HAS_DB_ERROR, "Failed to execute sql:%{private}s", sql.c_str());
    MEDIA_DEBUG_LOG("Execute sql %{private}s success", sql.c_str());
    if (info.forceRefreshType == ForceRefreshType::NONE || info.forceRefreshType == ForceRefreshType::EXCEPTION) {
        string deleteRefreshAlbumSql = "DELETE FROM " + ALBUM_REFRESH_TABLE + " WHERE " + REFRESHED_ALBUM_ID + " = " +
                                       std::to_string(albumId) + " AND " + ALBUM_REFRESH_STATUS + " = 1";
        ret = rdbStore->ExecuteSql(deleteRefreshAlbumSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Failed to execute delete refresh album sql:%{private}s", deleteRefreshAlbumSql.c_str());
            return ret;
        }
        MEDIA_DEBUG_LOG("#test delete refresh album sql:%{public}s, albumId:%{public}d, albumSubtype:%{public}d",
            deleteRefreshAlbumSql.c_str(),
            albumId,
            subtype);
    }
    ConstructAlbumNotifyUris(info, albumId);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    VariantMap map;
    if (subtype == IMAGE || subtype == VIDEO) {
        map = {{KEY_REFRESH_IMAGEVIDEO_ALBUM_TOTAL_COUNT, 1},
            {KEY_REFRESH_IMAGEVIDEO_ALBUM_TOTAL_TIME, static_cast<int32_t>(end - start)}};
    } else if (subtype == USER_GENERIC || subtype == SOURCE_GENERIC) {
        map = {{KEY_REFRESH_USER_AND_SOURCE_ALBUM_TOTAL_COUNT, albumId},
            {KEY_REFRESH_USER_AND_SOURCE_ALBUM_TOTAL_TIME, static_cast<int32_t>(end - start)}};
    } else if (subtype >= ANALYSIS_START) {
        map = {{KEY_REFRESH_ANALYSIS_ALBUM_TOTAL_COUNT, albumId},
            {KEY_REFRESH_ANALYSIS_ALBUM_TOTAL_TIME, static_cast<int32_t>(end - start)}};
    }
    PostEventUtils::GetInstance().UpdateCloudDownloadSyncStat(map);
    return E_SUCCESS;
}

static inline uint32_t GetRefreshCountThreshold(NotifyType notifyType)
{
    const uint32_t addAssets = 150;
    const uint32_t updateOrRemoveAssets = 50;
    return (notifyType == NOTIFY_ADD) ? addAssets : updateOrRemoveAssets;
}

static bool IsImageOrVideoAlbum(PhotoAlbumSubType subtype)
{
    return (subtype == IMAGE || subtype == VIDEO);
}

static bool IsAddSmartAlbum(const SyncNotifyInfo &info, PhotoAlbumSubType subtype)
{
    return (info.notifyType == NOTIFY_ADD && subtype >= ANALYSIS_START);
}

static void ForceRefreshSystemAlbums(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    const std::vector<RefreshAlbumData> &systeAlbums, SyncNotifyInfo &info)
{
    MEDIA_INFO_LOG("ForceRefreshSystemAlbums");
    for (auto systeAlbum : systeAlbums) {
        PhotoAlbumSubType subtype = static_cast<PhotoAlbumSubType>(systeAlbum.albumSubtype);
        RefreshAlbumInfoAndUris(rdbStore, systeAlbum.albumId, subtype, info);
    }
    info.notifyAlbums = true;
    info.notifyAssets = false;
}

static void RefreshAlbumsForAssetsChange(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    const std::vector<RefreshAlbumData> &systeAlbums, SyncNotifyInfo &info)
{
    uint32_t countThreshold = GetRefreshCountThreshold(info.notifyType);
    int32_t timeThreshold = GetRefreshTimeThreshold();
    int32_t delayTime = static_cast<int32_t>(MediaFileUtils::UTCTimeSeconds() - lastRefreshTimestamp_);
    bool notifyAlbums = false;
    bool notifyAssets = false;
    for (auto systeAlbum : systeAlbums) {
        PhotoAlbumSubType subtype = static_cast<PhotoAlbumSubType>(systeAlbum.albumSubtype);
        MEDIA_DEBUG_LOG("#test notifyType: %{public}d, totalAssets:%{public}d, albumId:%{public}d, size:%{public}zu, "
                        "subtype:%{public}d",
            info.notifyType,
            info.totalAssets,
            systeAlbum.albumId,
            systeAlbums.size(),
            subtype);
        if (info.urisSize < countThreshold) {
            MEDIA_DEBUG_LOG(
                "#test info.urisSize: %{public}d, countThreshold: %{public}d", info.urisSize, countThreshold);
            RefreshAlbumInfoAndUris(rdbStore, systeAlbum.albumId, subtype, info);
            notifyAlbums = true;
            notifyAssets = true;
            lastRefreshTimestamp_ = MediaFileUtils::UTCTimeSeconds();
            continue;
        }
        if (delayTime > timeThreshold) {
            MEDIA_DEBUG_LOG("#test timeThreshold: %{public}d, delayTime: %{public}d", timeThreshold, delayTime);
            if (IsAddSmartAlbum(info, subtype)) {
                continue;
            }
            RefreshAlbumInfoAndUris(rdbStore, systeAlbum.albumId, subtype, info);
            notifyAlbums = true;
            lastRefreshTimestamp_ = MediaFileUtils::UTCTimeSeconds();
            continue;
        }
        if (IsImageOrVideoAlbum(subtype)) {
            MEDIA_DEBUG_LOG("#test subtype: %{public}d", subtype);
            RefreshAlbumInfoAndUris(rdbStore, systeAlbum.albumId, subtype, info);
            notifyAlbums = true;
            notifyAssets = true;
            continue;
        }
        MEDIA_DEBUG_LOG("#test RefreshAlbumsByAssetsChangeStrategy not refresh");
    }
    info.notifyAlbums = notifyAlbums;
    info.notifyAssets = notifyAssets;
    MEDIA_DEBUG_LOG("#test notifyAssets: %{public}d, notifyAlbums: %{public}d", notifyAssets, notifyAlbums);
}

static void HandleAnalysisAlbum(
    const shared_ptr<MediaLibraryRdbStore> rdbStore, vector<RefreshAlbumData> &albums, bool isUpdateAllAnalysis)
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t count = -1;
    if (isUpdateAllAnalysis) {
        MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore);
    } else {
        CHECK_AND_RETURN_LOG(!albums.empty(), "no album");
        count = static_cast<int32_t>(albums.size());
        std::vector<std::string> albumIds(count);
        for (int32_t i = 0; i < count; i++) {
            albumIds[i] = std::to_string(albums[i].albumId);
            MEDIA_DEBUG_LOG("analysis: %{public}s", albumIds[i].c_str());
        }
        MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore, albumIds);
    }
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("%{public}d analysis albums update cost %{public}ld", count, static_cast<long>(end - start));
}

static void DeleteAnalysisAlbumIds(const shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    // delete analysis album id from refresh album
    string deleteRefreshAlbumSql = "DELETE FROM " + ALBUM_REFRESH_TABLE + " WHERE " + REFRESHED_ALBUM_ID +
        " = -1 OR " + REFRESHED_ALBUM_ID + " > 100000000 ";
    int32_t ret = rdbStore->ExecuteSql(deleteRefreshAlbumSql);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "delete analysis album from refreshAlbum failed");
    MEDIA_DEBUG_LOG("delete analysis album from refreshAlbum");
}

void AlbumsRefreshManager::RefreshPhotoAlbumsBySyncNotifyInfo(const shared_ptr<MediaLibraryRdbStore> rdbStore,
    SyncNotifyInfo &info)
{
    MEDIA_DEBUG_LOG("#test RefreshPhotoAlbums4AssetsChange beigin");
    std::vector<RefreshAlbumData> systemAlbums;
    std::vector<RefreshAlbumData> analysisAlbums;
    bool isUpdateAllAnalysis = false;
    info.refershResult = GetSystemAlbumsFromRefreshAlbumTable(rdbStore, systemAlbums, info.forceRefreshType);
    CHECK_AND_RETURN_LOG(info.refershResult == E_SUCCESS, "failed to get refresh system albumids");
    info.refershResult = GetAnalysisRefreshAlbums(rdbStore, analysisAlbums, isUpdateAllAnalysis, info.forceRefreshType);
    if (isUpdateAllAnalysis || !analysisAlbums.empty()) {
        DeleteAnalysisAlbumIds(rdbStore);
    }
    CHECK_AND_RETURN_LOG(info.refershResult == E_SUCCESS, "failed to get refresh system albumids");
    if (systemAlbums.empty() && analysisAlbums.empty()) {
        MEDIA_INFO_LOG("all album are empty");
        info.refershResult = E_EMPTY_ALBUM_ID;
        return;
    }
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    if (info.forceRefreshType != ForceRefreshType::NONE) {
        ForceRefreshSystemAlbums(rdbStore, systemAlbums, info);
    } else {
        RefreshAlbumsForAssetsChange(rdbStore, systemAlbums, info);
    }
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("#test RefreshPhotoAlbums4AssetsChange end %{public}d system albums update cost %{public}ld",
        (int)systemAlbums.size(),
        (long)(end - start));
    int32_t timeThreshold = GetRefreshTimeThreshold();
    int32_t delayTime = static_cast<int32_t>(MediaFileUtils::UTCTimeSeconds() - lastAnalysisRefreshTimestamp_);
    if (delayTime > timeThreshold && !analysisAlbums.empty()) {
        HandleAnalysisAlbum(rdbStore, analysisAlbums, isUpdateAllAnalysis);
        lastAnalysisRefreshTimestamp_ = MediaFileUtils::UTCTimeSeconds();
    }
    info.refershResult = E_SUCCESS;
}

shared_ptr<NativeRdb::ResultSet> AlbumsRefreshManager::CovertCloudId2AlbumId(
    const shared_ptr<MediaLibraryRdbStore> rdbStore, vector<string> &cloudIds)
{
    const vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
    };
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.In(PhotoAlbumColumns::ALBUM_CLOUD_ID, cloudIds);
    return QueryGoToFirst(rdbStore, predicates, columns);
}

shared_ptr<NativeRdb::ResultSet> AlbumsRefreshManager::CovertCloudId2FileId(
    const shared_ptr<MediaLibraryRdbStore> rdbStore, vector<string> &cloudIds)
{
    const vector<string> columns = {
        PhotoColumn::MEDIA_ID,
    };
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(PhotoColumn::PHOTO_CLOUD_ID, cloudIds);
    return QueryGoToFirst(rdbStore, predicates, columns);
}

static void ConstructAssetsNotifyUris(const shared_ptr<MediaLibraryRdbStore> rdbStore, SyncNotifyInfo &info)
{
    unordered_set<string> uriIds = info.uriIds;
    MEDIA_DEBUG_LOG("#test uriIds size : %{public}zu, notify type : %{public}d", info.uriIds.size(), info.notifyType);
    if (info.notifyType == NOTIFY_ADD) {
        vector<string> cloudIds;
        for (auto cloudId : uriIds) {
            if (cloudId.empty()) {
                continue;
            }
            cloudIds.emplace_back(cloudId);
        }
        auto resultSet = AlbumsRefreshManager::GetInstance().CovertCloudId2FileId(rdbStore, cloudIds);
        if (resultSet == nullptr) {
            return;
        }
        do {
            int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
            string uri = PhotoColumn::PHOTO_URI_PREFIX + std::to_string(fileId);
            info.uris.push_back(Uri(uri));
            MEDIA_DEBUG_LOG(
                "#test info.notifyType: NOTIFY_ADD, Uri: %{public}s", uri.c_str());
        } while (resultSet->GoToNextRow() == E_OK);
    } else {
        for (auto it = uriIds.begin(); it != uriIds.end(); ++it) {
            string fileId = *it;
            string uri = PhotoColumn::PHOTO_URI_PREFIX + fileId;
            MEDIA_DEBUG_LOG("#test info.notifyType: %{public}d, Uri: %{public}s, fileId: %{public}s",
                info.notifyType,
                uri.c_str(),
                fileId.c_str());
            info.uris.push_back(Uri(uri));
        }
    }
}

void AlbumsRefreshManager::RefreshPhotoAlbums(SyncNotifyInfo &info)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "Can not get rdb");
    if (info.taskType == TIME_BEGIN_SYNC) {
        uint32_t count = 0;
        vector<string> columns = {PhotoAlbumColumns::ALBUM_COUNT};
        RdbPredicates predicates(PhotoAlbumColumns::TABLE);
        predicates.SetWhereClause("album_subtype = " + to_string(PhotoAlbumSubType::VIDEO) +
                                  " or album_subtype = " + to_string(PhotoAlbumSubType::IMAGE));
        auto resultSet = rdbStore->Query(predicates, columns);
        if (resultSet == nullptr) {
            VariantMap map = {{KEY_TOTAL_PHOTO_COUNT, count}};
            PostEventUtils::GetInstance().UpdateCloudDownloadSyncStat(map);
            return;
        }
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            count += static_cast<uint32_t>(GetInt32Val(PhotoAlbumColumns::ALBUM_COUNT, resultSet));
        }
        resultSet->Close();
        VariantMap map = {{KEY_TOTAL_PHOTO_COUNT, count}};
        PostEventUtils::GetInstance().UpdateCloudDownloadSyncStat(map);
        return;
    }
    MediaLibraryTracer tracer;
    tracer.Start("RefreshPhotoAlbums");
    RefreshPhotoAlbumsBySyncNotifyInfo(rdbStore, info);
    ConstructAssetsNotifyUris(rdbStore, info);
}

void AlbumsRefreshManager::NotifyPhotoAlbums(SyncNotifyInfo &info)
{
    std::vector<std::string> albumIds;
    refreshWorker_->GetSystemAlbumIds(info, albumIds);
    refreshWorker_->TryDeleteAlbum(info, albumIds);
    list<Uri> uris;
    for (auto &albumId : albumIds) {
        string uri = PhotoAlbumColumns::ALBUM_URI_PREFIX + albumId;
        uris.push_back(Uri(uri));
    }
    AlbumsRefreshNotify::SendBatchUris(info.notifyType, uris);
}

static void PrintSyncInfo(SyncNotifyInfo &info)
{
    MEDIA_DEBUG_LOG(
        "#test info.taskType: %{public}d, info.syncType: %{public}d, info.notifyType: %{public}d, info.syncId: "
        "%{public}s, info.totalAssets: %{public}d, info.totalAlbums: %{public}d, info.urisSize: %{public}d",
        info.taskType,
        info.syncType,
        info.notifyType,
        info.syncId.c_str(),
        info.totalAssets,
        info.totalAlbums,
        info.urisSize);
}

SyncNotifyInfo AlbumsRefreshManager::GetSyncNotifyInfo(CloudSyncNotifyInfo &notifyInfo, uint8_t uriType)
{
    SyncNotifyInfo info = {0};
    switch (notifyInfo.type) {
        case ChangeType::INSERT: {
            info.notifyType = NOTIFY_ADD;
            break;
        }
        case ChangeType::DELETE: {
            info.notifyType = NOTIFY_REMOVE;
            break;
        }
        case ChangeType::UPDATE: {
            info.notifyType = NOTIFY_UPDATE;
            break;
        }
        default: {
            info.notifyType = NOTIFY_INVALID;
        }
    }
    info.uriType = uriType;
    info.urisSize = notifyInfo.uris.size();
    info.uris = notifyInfo.uris;
    info.taskType = TIME_IN_SYNC;
    PrintSyncInfo(info);
    return info;
}
}  // namespace Media
}  // namespace OHOS
