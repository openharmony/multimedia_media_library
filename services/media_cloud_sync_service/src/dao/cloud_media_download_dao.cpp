/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Cloud_Dao"

#include "cloud_media_download_dao.h"

#include <string>
#include <utime.h>
#include <vector>

#include "medialibrary_unistore_manager.h"
#include "result_set_reader.h"
#include "photos_po_writer.h"
#include "media_column.h"
#include "cloud_media_operation_code.h"
#include "cloud_media_dao_utils.h"
#include "cloud_media_sync_utils.h"
#include "moving_photo_file_utils.h"

namespace OHOS::Media::CloudSync {
NativeRdb::AbsRdbPredicates CloudMediaDownloadDao::GetDownloadThmsConditions(const int32_t type)
{
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE));
    predicates.EqualTo(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));
    predicates.NotEqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(CloudFilePosition::POSITION_LOCAL))
        ->And()
        ->BeginWrap();
    ThmLcdState state;
    if (type != static_cast<int32_t>(ThmLcdState::THM) && type != static_cast<int32_t>(ThmLcdState::THMLCD) &&
        type != static_cast<int32_t>(ThmLcdState::LCD)) {
        state = ThmLcdState::THMLCD;
    } else {
        state = static_cast<ThmLcdState>(type);
    }
    predicates.EqualTo(PhotoColumn::PHOTO_THUMB_STATUS, static_cast<int32_t>(ThumbState::TO_DOWNLOAD));
    predicates.Or()->EqualTo(PhotoColumn::PHOTO_THUMB_STATUS, static_cast<int32_t>(ThumbState::THM_TO_DOWNLOAD));
    if (state == ThmLcdState::LCD || state == ThmLcdState::THMLCD) {
        predicates.Or()->EqualTo(PhotoColumn::PHOTO_THUMB_STATUS, static_cast<int32_t>(ThumbState::LCD_TO_DOWNLOAD));
    }
    predicates.EndWrap();
    return predicates;
}

int32_t CloudMediaDownloadDao::GetDownloadThmNum(const int32_t type, int32_t &totalNum)
{
    MEDIA_INFO_LOG("GetDownloadThmNum begin %{public}d", type);
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Query Thumbs to Download Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = this->GetDownloadThmsConditions(type);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->Query(predicates, {"COUNT(1) AS count"});
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get nullptr Query Thumbs to Download");
        return E_RDB;
    }
    totalNum = GetInt32Val("count", resultSet);
    resultSet->Close();
    MEDIA_INFO_LOG("QueryThumbsToDownload end %{public}d", totalNum);
    return E_OK;
}

int32_t CloudMediaDownloadDao::GetDownloadThms(const DownloadThumbnailQueryDto &queryDto, std::vector<PhotosPo> &photos)
{
    MEDIA_INFO_LOG("QueryThumbsToDownload begin %{public}s", queryDto.ToString().c_str());
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "Query Thumbs to Download Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = this->GetDownloadThmsConditions(queryDto.type);
    if (queryDto.isDownloadDisplayFirst) {
        predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, 0);       // NOT_IN_TRASH
        predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, 0);       // NOT_IN_PENDING
        predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, 0);             // NOT_HIDDEN
        predicates.EqualTo(PhotoColumn::PHOTO_IS_TEMP, 0);            // NOT_TEMP_FILE
        predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, 1);  // IS_BURST_COVER
    }
    predicates.Limit(queryDto.offset, queryDto.size);
    predicates.OrderByDesc(PhotoColumn::MEDIA_DATE_TAKEN);

    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->Query(predicates, this->DOWNLOAD_THUMBNAIL_COLUMNS);
    int32_t ret = ResultSetReader<PhotosPoWriter, PhotosPo>(resultSet).ReadRecords(photos);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Query Thumbs to Download Failed to read records, ret: %{public}d", ret);
    MEDIA_INFO_LOG("GetDownloadThms, photos size: %{public}zu", photos.size());
    return E_OK;
}

int32_t CloudMediaDownloadDao::GetDownloadAsset(const std::vector<int32_t> &fileIds, std::vector<PhotosPo> &photos)
{
    MEDIA_INFO_LOG("enter GetDownloadAsset");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "GetDownloadAsset Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates queryPredicates = NativeRdb::AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    queryPredicates.In(PhotoColumn::MEDIA_ID, CloudMediaDaoUtils::GetStringVector(fileIds))
        ->And()
        ->EqualTo(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE))
        ->And()
        ->EqualTo(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));
    auto resultSet = rdbStore->Query(queryPredicates, this->COLUMNS_DOWNLOAD_ASSET_QUERY_BY_FILE_ID);
    int32_t ret = ResultSetReader<PhotosPoWriter, PhotosPo>(resultSet).ReadRecords(photos);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "GetDownloadAsset Failed to query, ret: %{public}d", ret);
    return ret;
}

int32_t CloudMediaDownloadDao::UpdateDownloadThm(const std::vector<std::string> &cloudIds)
{
    MEDIA_INFO_LOG("enter UpdateDownloadThm");
    CHECK_AND_RETURN_RET_LOG(!cloudIds.empty(), E_OK, "UpdateDownloadThm cloudIds is empty.");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Failed to get rdbStore.");
    CHECK_AND_PRINT_LOG(cloudIds.size() <= BATCH_LIMIT_SIZE,
        "UpdateDownloadThm cloudIds size: %{public}zu, limit: %{public}d",
        cloudIds.size(),
        BATCH_LIMIT_SIZE);
    std::string sql = "\
        UPDATE Photos \
            SET sync_status = 0, \
                thumb_status = thumb_status & ? \
        WHERE cloud_id IN ({0});";
    std::vector<std::string> params = {CloudMediaDaoUtils::ToStringWithCommaAndQuote(cloudIds)};
    std::string execSql = CloudMediaDaoUtils::FillParams(sql, params);
    std::vector<NativeRdb::ValueObject> bindArgs = {static_cast<int32_t>(~THM_TO_DOWNLOAD_MASK)};
    int32_t ret = rdbStore->ExecuteSql(execSql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to UpdateDownloadThm.");
    return ret;
}

int32_t CloudMediaDownloadDao::UpdateDownloadLcd(const std::vector<std::string> &cloudIds)
{
    MEDIA_INFO_LOG("enter UpdateDownloadLcd");
    CHECK_AND_RETURN_RET_LOG(!cloudIds.empty(), E_OK, "UpdateDownloadLcd cloudIds is empty.");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Failed to get rdbStore.");
    CHECK_AND_PRINT_LOG(cloudIds.size() <= BATCH_LIMIT_SIZE,
        "UpdateDownloadLcd cloudIds size: %{public}zu, limit: %{public}d",
        cloudIds.size(),
        BATCH_LIMIT_SIZE);
    std::string sql = "\
        UPDATE Photos \
            SET thumb_status = thumb_status & ? \
        WHERE cloud_id IN ({0});";
    std::vector<std::string> params = {CloudMediaDaoUtils::ToStringWithCommaAndQuote(cloudIds)};
    std::string execSql = CloudMediaDaoUtils::FillParams(sql, params);
    std::vector<NativeRdb::ValueObject> bindArgs = {static_cast<int32_t>(~LCD_TO_DOWNLOAD_MASK)};
    int32_t ret = rdbStore->ExecuteSql(execSql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to UpdateDownloadLcd.");
    return ret;
}

int32_t CloudMediaDownloadDao::UpdateDownloadThmAndLcd(const std::vector<std::string> &cloudIds)
{
    MEDIA_INFO_LOG("enter UpdateDownloadThmAndLcd");
    CHECK_AND_RETURN_RET_LOG(!cloudIds.empty(), E_OK, "UpdateDownloadThmAndLcd cloudIds is empty.");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(PhotoColumn::PHOTO_CLOUD_ID, cloudIds);
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE));
    values.PutInt(PhotoColumn::PHOTO_THUMB_STATUS, static_cast<int32_t>(ThumbState::DOWNLOADED));
    int32_t changedRows = DEFAULT_VALUE;
    int32_t ret = rdbStore->Update(changedRows, values, predicates);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to UpdateDownloadThmAndLcd.");
    CHECK_AND_PRINT_LOG(changedRows > 0, "Check updateRows: %{public}d.", changedRows);
    MEDIA_INFO_LOG("UpdateDownloadThmAndLcd, changedRows: %{public}d.", changedRows);
    return ret;
}

int32_t CloudMediaDownloadDao::GetFileIdFromCloudId(
    const std::vector<std::string> &cloudIds, std::vector<std::string> &fileIds)
{
    MEDIA_INFO_LOG("enter GetFileIdFromCloudId, cloudIds size: %{public}zu", cloudIds.size());
    CHECK_AND_RETURN_RET_LOG(cloudIds.size() > 0, E_OK, "GetFileIdFromCloudId cloudIds is empty.");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(PhotoColumn::PHOTO_CLOUD_ID, cloudIds);
    std::vector<std::string> columns = {MediaColumn::MEDIA_ID};
    auto resultSet = rdbStore->Query(predicates, columns);
    std::vector<PhotosPo> photos;
    int32_t ret = ResultSetReader<PhotosPoWriter, PhotosPo>(resultSet).ReadRecords(photos);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "GetFileIdFromCloudId Failed to query, ret: %{public}d", ret);
    for (auto photo : photos) {
        if (!photo.fileId.has_value()) {
            continue;
        }
        fileIds.emplace_back(std::to_string(photo.fileId.value_or(0)));
    }
    return ret;
}

int32_t CloudMediaDownloadDao::QueryDownloadAssetByCloudIds(
    const std::vector<std::string> &cloudIds, std::vector<PhotosPo> &result)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(PhotoColumn::PHOTO_CLOUD_ID, cloudIds);
    predicates.NotEqualTo(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
    auto resultSet = rdbStore->Query(predicates, this->COLUMNS_DOWNLOAD_ASSET_QUERY_BY_CLOUD_ID);
    int32_t ret = ResultSetReader<PhotosPoWriter, PhotosPo>(resultSet).ReadRecords(result);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Failed to query, ret: %{public}d", ret);
    MEDIA_INFO_LOG("QueryDownloadAssetByCloudId, rowCount: %{public}d", static_cast<int32_t>(result.size()));
    return E_OK;
}

int32_t CloudMediaDownloadDao::UpdateDownloadAsset(const bool fixFileType, const std::string &path)
{
    MEDIA_INFO_LOG("enter UpdateDownloadAsset %{public}d, %{public}s",
        fixFileType, path.c_str());
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_RDB_STORE_NULL, "UpdateDownloadAsset Failed to get rdbStore.");
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(MediaColumn::MEDIA_FILE_PATH, path);
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
    if (fixFileType) {
        MEDIA_INFO_LOG("UpdateDownloadAsset file is not real moving photo, need fix subtype");
        values.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::DEFAULT));
    }
    int32_t changedRows = -1;
    int32_t ret = rdbStore->Update(changedRows, values, predicates);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "UpdateDownloadAsset Failed to Update, ret: %{public}d.", ret);
    CHECK_AND_PRINT_LOG(changedRows > 0, "UpdateDownloadAsset changedRows: %{public}d.", changedRows);
    return ret;
}
}  // namespace OHOS::Media::CloudSync