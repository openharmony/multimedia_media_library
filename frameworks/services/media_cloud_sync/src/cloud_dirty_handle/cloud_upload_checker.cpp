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

#define MLOG_TAG "MediaLibraryCloudUploadChecker"

#include "cloud_upload_checker.h"

#include "media_file_utils.h"
#include "media_file_uri.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "thumbnail_const.h"
#include "media_column.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "result_set_utils.h"
#include "thumbnail_const.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_photo_operations.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace NativeRdb;
const std::string BATCH_SIZE = "500";
const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
const std::string NO_ORIGIN_PHOTO_NUMBER = "no_origin_photo_number";

static const int32_t NO_ORIGIN_BUT_LCD = 100;
static const int32_t NO_ORIGIN_NO_LCD = 101;

void CloudUploadChecker::HandleNoOriginPhoto()
{
    MEDIA_INFO_LOG("start handle no origin photo!");
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    int32_t curFileId = prefs->GetInt(NO_ORIGIN_PHOTO_NUMBER, 0);
    MEDIA_INFO_LOG("start file id: %{public}d", curFileId);
    while (GetPhotoCount(curFileId) > 0) {
        MEDIA_INFO_LOG("start handle origin photo start: %{public}d", curFileId);
        int32_t nextFileId = curFileId;
        std::vector<CheckedPhotoInfo> photoInfos = QueryPhotoInfo(curFileId, nextFileId);
        HandlePhotoInfos(photoInfos);
        curFileId = nextFileId + 1;
        prefs->PutInt(NO_ORIGIN_PHOTO_NUMBER, curFileId);
        prefs->FlushSync();
    }
    MEDIA_INFO_LOG("end handle no origin photo!");
    return;
}

void CloudUploadChecker::HandlePhotoInfos(std::vector<CheckedPhotoInfo> photoInfos)
{
    std::vector<std::string> lcdList;
    std::vector<std::string> noLcdList;
    for (CheckedPhotoInfo photoInfo: photoInfos) {
        if (MediaFileUtils::IsFileExists(photoInfo.path)) {
            continue;
        }
        string lcdPath = GetThumbnailPath(photoInfo.path, THUMBNAIL_LCD_SUFFIX);
        if (MediaFileUtils::IsFileExists(lcdPath)) {
            lcdList.push_back(to_string(photoInfo.fileId));
        } else {
            noLcdList.push_back(to_string(photoInfo.fileId));
        }
    }
    UpdateDirty(lcdList, NO_ORIGIN_BUT_LCD);
    UpdateDirty(noLcdList, NO_ORIGIN_NO_LCD);
}

void CloudUploadChecker::UpdateDirty(std::vector<std::string> idList, int32_t dirtyType)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Failed to get rdbstore!");
        return;
    }
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(MediaColumn::MEDIA_ID, idList);
    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_DIRTY, dirtyType);
    int32_t updateCount = 0;
    int32_t err = rdbStore->Update(updateCount, values, predicates);
    MEDIA_INFO_LOG("dirty: %{public}d, idList size: %{public}d, update size: %{public}d, err: %{public}d", dirtyType,
        static_cast<int32_t>(idList.size()), updateCount, err);
}

int32_t CloudUploadChecker::GetPhotoCount(int32_t startFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Failed to get rdbstore!");
        return 0;
    }
    std::string queryCount = " COUNT(*) AS Count";
    std::string sql = GetQuerySql(startFileId, queryCount);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(sql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is null or count is 0");
        return 0;
    }
    int32_t count = get<int32_t>(ResultSetUtils::GetValFromColumn("Count", resultSet, TYPE_INT32));
    return count;
}

std::string CloudUploadChecker::GetQuerySql(int32_t startFileId, std::string mediaColumns)
{
    const std::string sql = "SELECT " + mediaColumns + " FROM Photos WHERE dirty = 1 AND thumbnail_ready >= 3 AND " +
        "lcd_visit_time >= 2 AND date_trashed = 0 AND file_id > " + to_string(startFileId) + " LIMIT " + BATCH_SIZE;
    return sql;
}

std::vector<CheckedPhotoInfo> CloudUploadChecker::QueryPhotoInfo(int32_t startFileId, int32_t &outFileId)
{
    std::vector<CheckedPhotoInfo> photoInfos;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Failed to get rdbstore!");
        return photoInfos;
    }
    const std::string mediaColumns = Media::PhotoColumn::MEDIA_ID + ", " + Media::PhotoColumn::MEDIA_FILE_PATH;
    std::string sql = GetQuerySql(startFileId, mediaColumns);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(sql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is null or count is 0");
        return photoInfos;
    }
    int32_t fileId = startFileId;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        CheckedPhotoInfo photoInfo;
        std::string path =
            get<std::string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));
        if (path.empty()) {
            MEDIA_WARN_LOG("Failed to get data path");
            continue;
        }
        fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
        photoInfo.fileId = fileId;
        photoInfo.path = path;
        photoInfos.push_back(photoInfo);
    }
    outFileId = fileId;
    return photoInfos;
}
} // namespace Media
} // namespace OHOS