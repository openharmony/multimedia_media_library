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
#define MLOG_TAG "Media_Operation"

#include "photo_album_upload_status_operation.h"

#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "settings_data_manager.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS::Media {
const static std::string SQL_QUERY_ALBUM_ALL_UPLOAD_STATUS = "\
    SELECT \
        CASE \
            WHEN NOT EXISTS (SELECT 1 FROM PhotoAlbum WHERE album_type IN (0, 2048) AND dirty <> 4) \
                THEN 0 \
            WHEN EXISTS \
                (SELECT 1 FROM PhotoAlbum WHERE album_type IN (0, 2048) AND dirty <> 4 AND upload_status = 0) \
                THEN 0 \
            ELSE 1 \
        END AS upload_status;";

int32_t PhotoAlbumUploadStatusOperation::GetAlbumUploadStatus()
{
    AlbumUploadSwitchStatus ret = SettingsDataManager::GetAllAlbumUploadStatus();
    if (ret != AlbumUploadSwitchStatus::NONE) {
        MEDIA_INFO_LOG("GetAlbumUploadStatus %{public}d", static_cast<int32_t>(ret));
        return static_cast<int32_t>(ret);
    }
    return static_cast<int32_t>(IsAllAlbumUploadOnInDb());
}

std::string PhotoAlbumUploadStatusOperation::ToLower(const std::string &str)
{
    std::string lowerStr;
    std::transform(
        str.begin(), str.end(), std::back_inserter(lowerStr), [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

int32_t PhotoAlbumUploadStatusOperation::GetAlbumUploadStatusWithLpath(const std::string lpath)
{
    constexpr int32_t UPLOAD_STATUS_ON = 1;
    const std::string lpathLower = ToLower(lpath);
    if (lpathLower == ToLower(PhotoAlbumColumns::LPATH_CAMERA) ||
        lpathLower == ToLower(PhotoAlbumColumns::LPATH_SCREENSHOT) ||
        lpathLower == ToLower(PhotoAlbumColumns::LPATH_SCREENRECORD)) {
        return UPLOAD_STATUS_ON;
    }
    return GetAlbumUploadStatus();
}

bool PhotoAlbumUploadStatusOperation::IsAllAlbumUploadOnInDb()
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, false, "Failed to get rdbStore");
    std::shared_ptr<ResultSet> resultSet = rdbStore->QuerySql(SQL_QUERY_ALBUM_ALL_UPLOAD_STATUS);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "queryResultSet is null!");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == E_OK, false, "Failed to GoToFirstRow");
    int32_t uploadStatus = GetInt32Val(PhotoAlbumColumns::UPLOAD_STATUS, resultSet);
    resultSet->Close();
    return uploadStatus == 1;
}
}  // namespace OHOS::Media