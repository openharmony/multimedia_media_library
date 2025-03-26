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

#include <sys/stat.h>

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
#include "moving_photo_file_utils.h"
#include "medialibrary_subscriber.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace NativeRdb;

const std::int32_t BATCH_SIZE = 500;
const int32_t NO_ORIGIN_NO_LCD = 101;

const int SCANLINE_DEFAULT_VERSION = 0;
const int SCANLINE_CURRENT_VERSION = 1;

const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
const std::string NO_ORIGIN_PHOTO_NUMBER = "no_origin_photo_number";
const std::string NO_ORIGIN_BUT_LCD_PHOTO_NUMBER = "no_origin_but_lcd_photo_number";
const std::string SCANLINE_VERSION = "scanline_version";

std::mutex CloudUploadChecker::mutex_;

const std::string SQL_PHOTOS_TABLE_QUERY_NO_ORIGIN_BUT_LCD_COUNT = "SELECT"
                                                                   " COUNT( * ) AS Count "
                                                                   "FROM"
                                                                   " Photos "
                                                                   "WHERE"
                                                                   " ( dirty = 100 OR dirty = 1 )"
                                                                   " AND thumbnail_ready >= 3"
                                                                   " AND lcd_visit_time >= 2"
                                                                   " AND date_trashed = 0"
                                                                   " AND file_id > ?;";

const std::string SQL_PHOTOS_TABLE_QUERY_NO_ORIGIN_BUT_LCD_PHOTO = "SELECT"
                                                                   " file_id,"
                                                                   " data,"
                                                                   " size,"
                                                                   " subtype,"
                                                                   " moving_photo_effect_mode "
                                                                   "FROM"
                                                                   " Photos "
                                                                   "WHERE"
                                                                   " ( dirty = 100 OR dirty = 1 )"
                                                                   " AND thumbnail_ready >= 3"
                                                                   " AND lcd_visit_time >= 2"
                                                                   " AND date_trashed = 0"
                                                                   " AND file_id > ?"
                                                                   " LIMIT ?;";

void CloudUploadChecker::HandleNoOriginPhoto()
{
    MEDIA_INFO_LOG("start handle no origin photo!");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    int32_t curFileId = prefs->GetInt(NO_ORIGIN_PHOTO_NUMBER, 0);
    MEDIA_INFO_LOG("start file id: %{public}d", curFileId);
    while (MedialibrarySubscriber::IsCurrentStatusOn() && QueryLcdPhotoCount(curFileId) > 0) {
        MEDIA_INFO_LOG("handle origin photo curFileId: %{public}d", curFileId);
        std::vector<CheckedPhotoInfo> photoInfos = QueryPhotoInfo(curFileId);
        HandlePhotoInfos(photoInfos, curFileId);
        prefs->PutInt(NO_ORIGIN_PHOTO_NUMBER, curFileId);
        prefs->FlushSync();
    }
    MEDIA_INFO_LOG("end handle no origin photo!");
    return;
}

inline bool IsMovingPhoto(int32_t subtype, int32_t movingPhotoEffectMode)
{
    return subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO) ||
           movingPhotoEffectMode == static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY);
}

int32_t GetPhotoRealSize(const bool isMovingPhoto, const std::string &path, size_t &size)
{
    if (isMovingPhoto) {
        size = MovingPhotoFileUtils::GetMovingPhotoSize(path);
        return E_OK;
    }
    struct stat st {};
    CHECK_AND_RETURN_RET_LOG(stat(path.c_str(), &st) == 0,
        E_ERR,
        "stat syscall failed, path=%{public}s, errno=%{public}d",
        path.c_str(),
        errno);

    size = st.st_size;
    return E_OK;
}

void CloudUploadChecker::UpdateFileSize(const CheckedPhotoInfo &photoInfo, bool isMovingPhoto)
{
    size_t size = 0;
    if (GetPhotoRealSize(isMovingPhoto, photoInfo.path, size) != E_OK) {
        MEDIA_ERR_LOG("get photo real size failed, path=%{public}s", photoInfo.path.c_str());
        return;
    }

    if (photoInfo.size == size) {
        return;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr");

    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(MediaColumn::MEDIA_ID, photoInfo.fileId);

    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyTypes::TYPE_NEW));
    values.PutLong(MediaColumn::MEDIA_SIZE, static_cast<int64_t>(size));

    int32_t updateCount = 0;
    int32_t err = rdbStore->Update(updateCount, values, predicates);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("update db file size failed, file_id=%{public}d, err=%{public}d", photoInfo.fileId, err);
    }
}

void CloudUploadChecker::HandleMissingFile(
    const CheckedPhotoInfo &photoInfo, bool isMovingPhoto, std::vector<std::string> &noLcdList)
{
    std::string lcdPath = GetThumbnailPath(photoInfo.path, THUMBNAIL_LCD_SUFFIX);
    if (!MediaFileUtils::IsFileExists(lcdPath)) {
        MEDIA_WARN_LOG("lcd path does not exist, file_id: %{public}d", photoInfo.fileId);
        noLcdList.push_back(std::to_string(photoInfo.fileId));
        return;
    }

    MEDIA_INFO_LOG("lcd path exists but origin file not found, file_id: %{public}d", photoInfo.fileId);

    bool ret = MediaFileUtils::CopyFileUtil(lcdPath, photoInfo.path);
    if (!ret) {
        MEDIA_ERR_LOG("copy lcd to origin photo failed, file_id: %{public}d, ret: %{public}d", photoInfo.fileId, ret);
        return;
    }

    UpdateFileSize(photoInfo, isMovingPhoto);
}

void CloudUploadChecker::HandlePhotoInfos(const std::vector<CheckedPhotoInfo> &photoInfos, int32_t &curFileId)
{
    std::vector<std::string> noLcdList;

    for (const CheckedPhotoInfo &photoInfo : photoInfos) {
        if (!MedialibrarySubscriber::IsCurrentStatusOn()) {
            break;
        }
        curFileId = photoInfo.fileId;
        bool isMovingPhoto = IsMovingPhoto(photoInfo.subtype, photoInfo.movingPhotoEffectMode);
        if (MediaFileUtils::IsFileExists(photoInfo.path)) {
            UpdateFileSize(photoInfo, isMovingPhoto);
            continue;
        }
        HandleMissingFile(photoInfo, isMovingPhoto, noLcdList);
    }
    UpdateDirty(noLcdList, NO_ORIGIN_NO_LCD);
}

void CloudUploadChecker::UpdateDirty(const std::vector<std::string> &idList, int32_t dirtyType)
{
    CHECK_AND_RETURN_INFO_LOG(!idList.empty(), "idList is empty");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "Failed to get rdbstore!");
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(MediaColumn::MEDIA_ID, idList);
    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_DIRTY, dirtyType);
    int32_t updateCount = 0;
    int32_t err = rdbStore->Update(updateCount, values, predicates);
    MEDIA_INFO_LOG("dirty: %{public}d, idList size: %{public}d, update size: %{public}d, err: %{public}d",
        dirtyType,
        static_cast<int32_t>(idList.size()),
        updateCount,
        err);
}

std::vector<CheckedPhotoInfo> CloudUploadChecker::QueryPhotoInfo(int32_t startFileId)
{
    std::vector<CheckedPhotoInfo> photoInfos;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, photoInfos, "Failed to get rdbstore!");

    const std::vector<NativeRdb::ValueObject> bindArgs = {startFileId, BATCH_SIZE};
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_NO_ORIGIN_BUT_LCD_PHOTO, bindArgs);
    bool cond = resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK;
    CHECK_AND_RETURN_RET_LOG(cond, photoInfos, "resultSet is null or count is 0");

    do {
        CheckedPhotoInfo photoInfo;
        std::string path =
            get<std::string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));
        if (path.empty()) {
            MEDIA_WARN_LOG("Failed to get data path");
            continue;
        }
        photoInfo.fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
        photoInfo.path = path;
        photoInfo.size =
            get<std::int64_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_SIZE, resultSet, TYPE_INT64));
        photoInfo.subtype =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_SUBTYPE, resultSet, TYPE_INT32));
        photoInfo.movingPhotoEffectMode = get<int32_t>(
            ResultSetUtils::GetValFromColumn(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, resultSet, TYPE_INT32));
        photoInfos.push_back(photoInfo);
    } while (MedialibrarySubscriber::IsCurrentStatusOn() && resultSet->GoToNextRow() == NativeRdb::E_OK);
    return photoInfos;
}

int32_t CloudUploadChecker::QueryLcdPhotoCount(int32_t startFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "Failed to get rdbStore.");
    const std::vector<NativeRdb::ValueObject> bindArgs = {startFileId};
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_NO_ORIGIN_BUT_LCD_COUNT, bindArgs);
    CHECK_AND_RETURN_RET_LOG(
        resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK, 0, "resultSet is null or count is 0");
    return get<int32_t>(ResultSetUtils::GetValFromColumn("Count", resultSet, TYPE_INT32));
}

void CloudUploadChecker::RepairNoOriginPhoto()
{
    std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
    if (!lock.try_lock()) {
        MEDIA_WARN_LOG("Repairing no origin photos has started, skipping this operation");
        return;
    }
    MEDIA_INFO_LOG("start repair no origin photo!");
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    int scanlineVersion = prefs->GetInt(SCANLINE_VERSION, SCANLINE_DEFAULT_VERSION);
    MEDIA_INFO_LOG("scanline version: %{public}d", scanlineVersion);
    if (scanlineVersion != SCANLINE_CURRENT_VERSION) {
        prefs->PutInt(NO_ORIGIN_PHOTO_NUMBER, 0);
        prefs->PutInt(SCANLINE_VERSION, SCANLINE_CURRENT_VERSION);
        prefs->FlushSync();
    }
    HandleNoOriginPhoto();
    MEDIA_INFO_LOG("end repair no origin photo!");
}
}  // namespace Media
}  // namespace OHOS