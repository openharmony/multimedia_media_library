/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <sys/stat.h>

#include "shooting_mode_album_operation.h"

#include "directory_ex.h"

#include "abs_rdb_predicates.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_unistore_manager.h"
#include "metadata_extractor.h"
#include "result_set_utils.h"
#include "scanner_utils.h"
#include "values_bucket.h"
#include "medialibrary_type_const.h"
#include "photo_album_column.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_tracer.h"

using namespace OHOS::NativeRdb;

namespace OHOS::Media {
const std::string ORIGIN_SHOOTING_MODE_ASSETS_NUMBER = "origin_shooting_mode_assets_number";
const std::int32_t BATCH_SIZE = 500;
const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";

const std::string SQL_PHOTOS_TABLE_QUERY_SHOOTING_COUNT = "SELECT"
                                                          " COUNT( * ) AS Count "
                                                          "FROM"
                                                          " Photos "
                                                          "WHERE"
                                                          " (shooting_mode = '' OR front_camera = '')"
                                                          " AND position != 2"
                                                          " AND file_id > ?;";

const std::string SQL_PHOTOS_TABLE_QUERY_SHOOTING_ASSETS = "SELECT"
                                                           " file_id,"
                                                           " data,"
                                                           " media_type "
                                                           "FROM"
                                                           " Photos "
                                                           "WHERE"
                                                           " (shooting_mode = '' OR front_camera = '')"
                                                           " AND position != 2"
                                                           " AND file_id > ?"
                                                           " LIMIT ?;";

std::atomic<bool> ShootingModeAlbumOperation::isContinue_{true};

void ShootingModeAlbumOperation::Stop()
{
    isContinue_.store(false);
}

void ShootingModeAlbumOperation::UpdateShootingModeAlbum()
{
    isContinue_.store(true);
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    int32_t curFileId = prefs->GetInt(ORIGIN_SHOOTING_MODE_ASSETS_NUMBER, 0);
    while (MedialibrarySubscriber::IsCurrentStatusOn() && isContinue_.load()) {
        CHECK_AND_BREAK_INFO_LOG(QueryShootingAssetsCount(curFileId) > 0, "No shooting mode assets need to handle");
        MEDIA_INFO_LOG("handle shooting mode assets curFileId: %{public}d", curFileId);
        std::vector<CheckedShootingAssetsInfo> photoInfos = QueryShootingAssetsInfo(curFileId);
        HandleInfos(photoInfos, curFileId);
    }
    prefs->PutInt(ORIGIN_SHOOTING_MODE_ASSETS_NUMBER, curFileId);
    prefs->FlushSync();
    MEDIA_INFO_LOG(
        "end handle no origin photo! cost: %{public}" PRId64, MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    return;
}

int32_t ShootingModeAlbumOperation::QueryShootingAssetsCount(int32_t startFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "Failed to get rdbStore.");
    const std::vector<NativeRdb::ValueObject> bindArgs = {startFileId};
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_SHOOTING_COUNT, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, 0, "resultSet is null");
    int32_t count = 0;
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        count = get<int32_t>(ResultSetUtils::GetValFromColumn("Count", resultSet, TYPE_INT32));
    } else {
        MEDIA_DEBUG_LOG("No shooting mode assets found from file ID %{public}d.", startFileId);
    }
    resultSet->Close();
    return count;
}

std::vector<CheckedShootingAssetsInfo> ShootingModeAlbumOperation::QueryShootingAssetsInfo(int32_t startFileId)
{
    std::vector<CheckedShootingAssetsInfo> photoInfos;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, photoInfos, "Failed to get rdbstore!");

    const std::vector<NativeRdb::ValueObject> bindArgs = {startFileId, BATCH_SIZE};
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_SHOOTING_ASSETS, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, photoInfos, "resultSet is null");
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_DEBUG_LOG("resultSet count is 0");
        resultSet->Close();
        return photoInfos;
    }

    do {
        std::string path =
            get<std::string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));
        CHECK_AND_CONTINUE_ERR_LOG(!path.empty(), "Failed to get data path");
        CheckedShootingAssetsInfo photoInfo;
        photoInfo.fileId =
            get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
        photoInfo.path = path;
        photoInfo.mediaType =
            get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_TYPE, resultSet, TYPE_INT32));
        photoInfos.push_back(photoInfo);
    } while (MedialibrarySubscriber::IsCurrentStatusOn() && isContinue_.load() &&
        resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
    return photoInfos;
}

static void NotifyAnalysisAlbum(const vector<string>& changedAlbumIds)
{
    if (changedAlbumIds.size() <= 0) {
        return;
    }
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_LOG(watch != nullptr, "Can not get MediaLibraryNotify Instance");
    for (const string& albumId : changedAlbumIds) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(
            PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX, albumId), NotifyType::NOTIFY_UPDATE);
    }
}

void ShootingModeAlbumOperation::HandleInfos(const std::vector<CheckedShootingAssetsInfo> &photoInfos,
    int32_t &curFileId)
{
    bool hasUpdateShootingAssets = false;
    for (const CheckedShootingAssetsInfo &photoInfo : photoInfos) {
        CHECK_AND_BREAK_INFO_LOG(MedialibrarySubscriber::IsCurrentStatusOn() && isContinue_.load(),
            "current status is off, break");
        curFileId = photoInfo.fileId;
        if (UpdateShootingAlbum(photoInfo)) {
            hasUpdateShootingAssets = true;
        }
    }

    if (hasUpdateShootingAssets) {
        vector<string> albumIdsStr;
        for (int32_t type = static_cast<int32_t>(ShootingModeAlbumType::START);
            type <= static_cast<int32_t>(ShootingModeAlbumType::END); ++type) {
            int32_t albumId;
            ShootingModeAlbumType albumType = static_cast<ShootingModeAlbumType>(type);
            MediaLibraryRdbUtils::QueryShootingModeAlbumIdByType(albumType, albumId);
            albumIdsStr.push_back(to_string(albumId));
        }

        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr");
        MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore, albumIdsStr);
        NotifyAnalysisAlbum(albumIdsStr);
    }
}

bool ShootingModeAlbumOperation::UpdateShootingAlbum(const CheckedShootingAssetsInfo &photoInfo)
{
    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(photoInfo.path);
    data->SetFileName(MediaFileUtils::GetFileName(photoInfo.path));
    data->SetFileMediaType(photoInfo.mediaType);
    if (data->GetFileMediaType() == MediaType::MEDIA_TYPE_IMAGE) {
        int32_t ret = MetadataExtractor::ExtractImageMetadata(data);
        data->SetVideoMode(0);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, false, "Failed to extract image metadata");
    } else {
        MetadataExtractor::ExtractAVMetadata(data);
    }
    CHECK_AND_RETURN_RET_LOG(!(data->GetShootingMode() == "" && data->GetFrontCamera() == ""), false,
        "assets is not shooting mode");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "rdbStore is nullptr");
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(MediaColumn::MEDIA_ID, photoInfo.fileId);

    ValuesBucket value;
    value.PutString(PhotoColumn::PHOTO_SHOOTING_MODE, data->GetShootingMode());
    value.PutString(PhotoColumn::PHOTO_SHOOTING_MODE_TAG, data->GetShootingModeTag());
    value.PutString(PhotoColumn::PHOTO_FRONT_CAMERA, data->GetFrontCamera());
    value.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());

    int32_t updateCount = 0;
    int32_t err = rdbStore->Update(updateCount, value, predicates);

    CHECK_AND_RETURN_RET_LOG(err == NativeRdb::E_OK, false,
        "Update shooting assets failed, file_id=%{public}d, err=%{public}d", photoInfo.fileId, err);

    MEDIA_INFO_LOG("Update shooting assets success, file_id=%{public}d, updated_rows=%{public}d", photoInfo.fileId,
        updateCount);
    return updateCount > 0;
}
}  // namespace OHOS::Media