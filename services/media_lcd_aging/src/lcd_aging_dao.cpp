/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Lcd_Aging"

#include "lcd_aging_dao.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "photo_owner_album_id_operation.h"
#include "photos_po_writer.h"
#include "result_set_reader.h"

namespace OHOS::Media {
using namespace OHOS::Media::CloudSync;

constexpr uint32_t LCD_TO_DOWNLOAD_MASK = 0x1;
constexpr int64_t TWELVE_HOUR_S = 12 * 60 * 60;

int32_t LcdAgingDao::GetCurrentNumberOfLcd(int64_t &lcdNumber)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetCurrentNumberOfLcd");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "GetCurrentNumberOfLcd Failed to get rdbStore.");
    auto resultSet = rdbStore->QuerySql(SQL_GET_TOTAL_NUMBER_OF_LCD);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK, E_ERR,
        "GetCurrentNumberOfLcd Failed to query number of lcd");
    lcdNumber = GetInt64Val("count", resultSet);
    resultSet->Close();
    return E_OK;
}

int32_t LcdAgingDao::QueryAgingLcdDataInternal(const int32_t size, const std::vector<std::string> &notAgingFileIds,
    std::vector<PhotosPo> &lcdAgingPoList, const std::string &sql, const char *logPrefix)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryAgingLcdDataInternal");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_DB_FAIL, "%{public}s Failed to get rdbStore.", logPrefix);

    int64_t currentTime = MediaFileUtils::UTCTimeSeconds();
    int64_t lcdFileTime = currentTime - TWELVE_HOUR_S;
    std::vector<NativeRdb::ValueObject> bindArgs = { lcdFileTime, size };
    std::string fileIdNotIn = PhotoOwnerAlbumIdOperation().ToStringWithCommaAndQuote(notAgingFileIds);
    std::string execSql = PhotoOwnerAlbumIdOperation().FillParams(sql, {fileIdNotIn});
    auto resultSet = rdbStore->QuerySql(execSql, bindArgs);

    int32_t ret = ResultSetReader<PhotosPoWriter, PhotosPo>(resultSet).ReadRecords(lcdAgingPoList);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "%{public}s Failed to query, ret: %{public}d", logPrefix, ret);
    MEDIA_INFO_LOG("size of lcdAgingPoList (%{public}s) is %{public}zu", logPrefix, lcdAgingPoList.size());
    return E_OK;
}

int32_t LcdAgingDao::QueryAgingLcdDataTrashed(const int32_t size,
    const std::vector<std::string> &notAgingFileIds, std::vector<PhotosPo> &lcdAgingPoList)
{
    return QueryAgingLcdDataInternal(size, notAgingFileIds, lcdAgingPoList,
        this->SQL_QUERY_AGING_LCD_DATA_TRASHED, "trashed");
}

int32_t LcdAgingDao::QueryAgingLcdDataNotTrashed(const int32_t size,
    const std::vector<std::string> &notAgingFileIds, std::vector<PhotosPo> &lcdAgingPoList)
{
    return QueryAgingLcdDataInternal(size, notAgingFileIds, lcdAgingPoList,
        this->SQL_QUERY_AGING_LCD_DATA_NOT_TRASHED, "notTrashed");
}

int32_t LcdAgingDao::SetLcdNotDownloadStatus(const std::vector<std::string> &fileIds)
{
    CHECK_AND_RETURN_RET_LOG(!fileIds.empty(), E_ERR, "fileIds is empty");
    MediaLibraryTracer tracer;
    tracer.Start("SetLcdNotDownloadStatus");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_DB_FAIL, "SetLcdNotDownloadStatus Failed to get rdbStore.");
    
    std::vector<std::string> params = { PhotoOwnerAlbumIdOperation().ToStringWithComma(fileIds) };
    std::string execSql = PhotoOwnerAlbumIdOperation().FillParams(this->SQL_UPDATE_THUMB_STATUS, params);
    std::vector<NativeRdb::ValueObject> bindArgs = {static_cast<int32_t>(LCD_TO_DOWNLOAD_MASK)};
    int32_t ret = rdbStore->ExecuteSql(execSql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to SetLcdNotDownloadStatus.");
    return E_OK;
}

int32_t LcdAgingDao::RevertToLcdDownloadStatus(const std::vector<std::string> &fileIds)
{
    CHECK_AND_RETURN_RET_LOG(!fileIds.empty(), E_ERR, "fileIds is empty");
    MediaLibraryTracer tracer;
    tracer.Start("RevertToLcdDownloadStatus");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_DB_FAIL, "RevertToLcdDownloadStatus Failed to get rdbStore.");

    std::vector<std::string> params = { PhotoOwnerAlbumIdOperation().ToStringWithComma(fileIds) };
    std::string execSql = PhotoOwnerAlbumIdOperation().FillParams(this->SQL_REVERT_THUMB_STATUS, params);
    std::vector<NativeRdb::ValueObject> bindArgs = {static_cast<int32_t>(~LCD_TO_DOWNLOAD_MASK)};
    int32_t ret = rdbStore->ExecuteSql(execSql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to RevertToLcdDownloadStatus.");
    return E_OK;
}

int32_t LcdAgingDao::UpdateLcdFileSize(const std::vector<LcdAgingFileInfo> &agingFileInfos)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdateLcdFileSize");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_DB_FAIL, "UpdateLcdFileSize Failed to get rdbStore.");

    std::string updateSql = "UPDATE Photos SET lcd_file_size = CASE file_id ";
    std::string fileIdList = "";
    for (const auto &agingFileInfo : agingFileInfos) {
        CHECK_AND_CONTINUE(agingFileInfo.needFixLcdFileSize);
        updateSql +=
            " WHEN " + std::to_string(agingFileInfo.fileId) + " THEN " + std::to_string(agingFileInfo.lcdFileSize);
        fileIdList += std::to_string(agingFileInfo.fileId) + ",";
    }
    CHECK_AND_RETURN_RET(!fileIdList.empty(), E_OK);
    fileIdList.pop_back();
    updateSql += " ELSE lcd_file_size END WHERE file_id IN ( " + fileIdList + " );";

    int32_t ret = rdbStore->ExecuteSql(updateSql);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "failed to execute sql: %{public}s, ret: %{public}d",
        updateSql.c_str(), ret);
    return ret;
}
}  // namespace OHOS::Media