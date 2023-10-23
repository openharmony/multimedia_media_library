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

#define MLOG_TAG "MediaLibraryUpdateRestore"

#include "update_restore.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_data_manager.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
const std::string UPDATE_FILE_DIR = "/storage/media/local/files/data";
const std::string UPDATE_DB_NAME = "gallery.db";
const std::string CLONE_TAG = "/data/storage/el2/backup/restore/cloneBackupData.json";

constexpr int32_t GALLERY_IMAGE_TYPE = 1;
constexpr int32_t GALLERY_VIDEO_TYPE = 3;

UpdateRestore::UpdateRestore(const std::string &galleryAppName, const std::string &mediaAppName)
{
    galleryAppName_ = galleryAppName;
    mediaAppName_ = mediaAppName;
}

int32_t UpdateRestore::Init(void)
{
    dbPath_ = ORIGIN_PATH + "/" + galleryAppName_ + "/ce/databases/gallery.db";
    appDataPath_ = ORIGIN_PATH;
    if (MediaFileUtils::IsFileExists(CLONE_TAG)) {
        filePath_ = ORIGIN_PATH;
    } else {
        filePath_ = UPDATE_FILE_DIR;
    }
    if (!MediaFileUtils::IsFileExists(dbPath_)) {
        MEDIA_ERR_LOG("Gallery media db is not exist.");
        return E_FAIL;
    }
    if (BaseRestore::Init() != E_OK) {
        return E_FAIL;
    }

    NativeRdb::RdbStoreConfig config(UPDATE_DB_NAME);
    config.SetPath(dbPath_);
    config.SetBundleName(galleryAppName_);
    config.SetReadConSize(CONNECT_SIZE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);

    int32_t err;
    RdbCallback cb;
    galleryRdb_ = NativeRdb::RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, cb, err);
    if (galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("gallyer data syncer init rdb fail, err = %{public}d", err);
        return E_FAIL;
    }
    MEDIA_INFO_LOG("Init db succ.");
    return E_OK;
}

void UpdateRestore::RestorePhoto(void)
{
    int32_t totalNumber = QueryTotalNumber();
    MEDIA_INFO_LOG("QueryTotalNumber, totalNumber = %{public}d", totalNumber);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        std::vector<FileInfo> infos = QueryFileInfos(offset);
        InsertPhoto(infos);
    }
    (void)NativeRdb::RdbHelper::DeleteRdbStore(dbPath_);
}

void UpdateRestore::HandleRestData(void)
{
    MEDIA_INFO_LOG("Start to handle rest data in native.");
    std::string photoData = appDataPath_ + "/" + galleryAppName_;
    std::string mediaData = appDataPath_ + "/" + mediaAppName_;
    if (MediaFileUtils::IsFileExists(photoData)) {
        MEDIA_DEBUG_LOG("Start to delete photo data.");
        (void)MediaFileUtils::DeleteDir(photoData);
    }
    if (MediaFileUtils::IsFileExists(mediaData)) {
        MEDIA_DEBUG_LOG("Start to delete media data.");
        (void)MediaFileUtils::DeleteDir(mediaData);
    }
    if (!MediaFileUtils::IsFileExists(CLONE_TAG) && MediaFileUtils::IsFileExists(UPDATE_FILE_DIR)) {
        (void)MediaFileUtils::RenameDir(UPDATE_FILE_DIR, DOCUMENT_PATH);
    }
}

int32_t UpdateRestore::QueryTotalNumber(void)
{
    if (galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr, Maybe init failed.");
        return 0;
    }
    std::string querySql = "SELECT count(1) as count FROM gallery_media \
        WHERE (local_media_id >= 0 OR local_media_id == -4) AND (storage_id = 65537) AND relative_bucket_id NOT IN ( \
        SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1)";
    auto resultSet = galleryRdb_->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return 0;
    }
    int32_t result = GetInt32Val("count", resultSet);
    return result;
}

std::vector<FileInfo> UpdateRestore::QueryFileInfos(int32_t offset)
{
    std::vector<FileInfo> result;
    result.reserve(QUERY_COUNT);
    if (galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr, Maybe init failed.");
        return result;
    }
    std::string querySql = "SELECT " + GALLERY_LOCAL_MEDIA_ID + "," + GALLERY_FILE_DATA + "," + GALLERY_DISPLAY_NAME +
        "," + GALLERY_DESCRIPTION + "," + GALLERY_IS_FAVORITE + "," + GALLERY_RECYCLED_TIME + "," + GALLERY_FILE_SIZE +
        "," + GALLERY_DURATION + "," + GALLERY_MEDIA_TYPE + "," + GALLERY_SHOW_DATE_TOKEN + "," + GALLERY_HEIGHT +
        "," + GALLERY_WIDTH + "," + GALLERY_TITLE + " FROM gallery_media WHERE (local_media_id>= 0 OR \
        local_media_id == -4) AND (storage_id = 65537) AND relative_bucket_id NOT IN ( \
        SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1 \
        ) ORDER BY showDateToken ASC limit " + std::to_string(offset) + ", " + std::to_string(QUERY_COUNT);
    auto resultSet = galleryRdb_->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo tmpInfo;
        if (ParseResultSet(resultSet, tmpInfo)) {
            result.emplace_back(tmpInfo);
        }
    }
    return result;
}

bool UpdateRestore::ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info)
{
    // only parse image and video
    int32_t mediaType = GetInt32Val(GALLERY_MEDIA_TYPE, resultSet);
    if (mediaType != GALLERY_IMAGE_TYPE && mediaType != GALLERY_VIDEO_TYPE) {
        MEDIA_ERR_LOG("Invalid media tyep: %{public}d.", mediaType);
        return false;
    }
    std::string oldPath = GetStringVal(GALLERY_FILE_DATA, resultSet);
    if (!ConvertPathToRealPath(oldPath, filePath_, info.filePath)) {
        return false;
    }

    int32_t localMediaId = GetInt32Val(GALLERY_LOCAL_MEDIA_ID, resultSet);
    info.displayName = GetStringVal(GALLERY_DISPLAY_NAME, resultSet);
    info.title = GetStringVal(GALLERY_TITLE, resultSet);
    info.userComment = GetStringVal(GALLERY_DESCRIPTION, resultSet);
    info.fileSize = GetInt64Val(GALLERY_FILE_SIZE, resultSet);
    info.duration = GetInt64Val(GALLERY_DURATION, resultSet);
    info.recycledTime = GetInt64Val(GALLERY_RECYCLED_TIME, resultSet) / MILLISECONDS;
    info.hidden = (localMediaId == GALLERY_HIDDEN_ID) ? 1 : 0;
    info.isFavorite = GetInt32Val(GALLERY_IS_FAVORITE, resultSet);
    info.fileType = (mediaType == GALLERY_VIDEO_TYPE) ? MediaType::MEDIA_TYPE_VIDEO : MediaType::MEDIA_TYPE_IMAGE;
    info.showDateToken = GetInt64Val(GALLERY_SHOW_DATE_TOKEN, resultSet) / MILLISECONDS;
    info.height = GetInt64Val(GALLERY_HEIGHT, resultSet);
    info.width = GetInt64Val(GALLERY_WIDTH, resultSet);
    return true;
}
} // namespace Media
} // namespace OHOS
