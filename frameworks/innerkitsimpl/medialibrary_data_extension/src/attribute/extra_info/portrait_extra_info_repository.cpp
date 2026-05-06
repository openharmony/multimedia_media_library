/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "PortraitExtraInfoRepo"

#include "portrait_extra_info_repository.h"

#include "analysis_album_attribute_const.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "analysis_album_accurate_refresh.h"
#include "medialibrary_notify.h"
#include "media_file_utils.h"
#include "photo_album_column.h"
#include "vision_album_column.h"
#include "medialibrary_analysis_album_operations.h"
#include "vision_column.h"
#include "vision_face_tag_column.h"

namespace OHOS::Media {
using namespace OHOS::NativeRdb;

PortraitExtraInfoRepository::PortraitExtraInfoRepository(const std::shared_ptr<MediaLibraryRdbStore> &rdbStore)
    : rdbStore_(rdbStore)
{
}

static void NotifyUpdateAlbum(const vector<int32_t> &changedAlbumIds)
{
    if (changedAlbumIds.size() <= 0) {
        return;
    }
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_LOG(watch != nullptr, "Can not get MediaLibraryNotify Instance");
    for (int32_t albumId : changedAlbumIds) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(
            PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX, to_string(albumId)), NotifyType::NOTIFY_UPDATE);
    }
}

bool PortraitExtraInfoRepository::Exists(const std::string &albumId) const
{
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, false, "rdbStore is nullptr");
    const std::string sql =
        "SELECT album_id FROM AnalysisAlbum WHERE album_id = ? AND album_type = ? AND album_subtype = ? LIMIT 1";
    std::vector<std::string> bindArgs = {
        albumId,
        std::to_string(static_cast<int32_t>(PhotoAlbumType::SMART)),
        std::to_string(static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT)),
    };
    auto resultSet = rdbStore_->QuerySql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "query portrait album failed");
    return resultSet->GoToFirstRow() == NativeRdb::E_OK;
}

static int32_t GetPortraitAlbumIds(const std::string &albumId, std::string &portraitAlbumIdStr,
    std::vector<int32_t> &portraitAlbumIdsInt)
{
    std::vector<std::string> portraitAlbumIds;
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_INNER_FAIL, "uniStore is nullptr! failed query album order");
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsValidInteger(albumId), E_INVALID_VALUES,
        "invalid albumId: %{public}s", albumId.c_str());
    const std::string queryPortraitAlbumIds = "SELECT " + ALBUM_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " +
        GROUP_TAG + " IN(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE " + ALBUM_ID + " = ?" + " AND " + ALBUM_SUBTYPE + " = ?" +");";
    std::vector<std::string> bindArgs = {
        albumId,
        std::to_string(static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT)),
    };
    auto resultSet = uniStore->QuerySql(queryPortraitAlbumIds, bindArgs);
    CHECK_AND_RETURN_RET(resultSet != nullptr, E_INNER_FAIL);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        portraitAlbumIds.push_back(to_string(GetInt32Val(ALBUM_ID, resultSet)));
        portraitAlbumIdsInt.push_back(GetInt32Val(ALBUM_ID, resultSet));
    }

    for (size_t i = 0; i < portraitAlbumIds.size(); i++) {
        if (i > 0) {
            portraitAlbumIdStr += ",";
        }
        portraitAlbumIdStr += portraitAlbumIds[i];
    }
    return E_OK;
}

int32_t PortraitExtraInfoRepository::UpdateExtraInfo(const std::string &albumId,
    const std::string &extraInfo) const
{
    MEDIA_INFO_LOG("UpdateExtraInfo start");
    std::string portraitAlbumIdStr;
    std::vector<int32_t> portraitAlbumIdsInt;
    CHECK_AND_RETURN_RET_LOG(GetPortraitAlbumIds(albumId, portraitAlbumIdStr, portraitAlbumIdsInt) == E_OK,
        E_INNER_FAIL, "Failed to get portrait album ids by albumId: %{public}s", albumId.c_str());
    CHECK_AND_RETURN_RET_LOG(!portraitAlbumIdStr.empty() && !portraitAlbumIdsInt.empty(),
        E_INNER_FAIL, "No portrait album found for albumId: %{public}s", albumId.c_str());
    std::string updateSql = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + EXTRA_INFO + " = '" + extraInfo +
        "' WHERE " + ALBUM_ID + " IN (" + portraitAlbumIdStr + ")";
    CHECK_AND_RETURN_RET_LOG(MediaLibraryAnalysisAlbumOperations::UpdateAnalysisAlbum(
        {updateSql}, portraitAlbumIdsInt) == E_OK,
        E_INNER_FAIL, "Failed to set extra info for portrait album, albumId: %{public}s", albumId.c_str());
    NotifyUpdateAlbum(portraitAlbumIdsInt);
    return NativeRdb::E_OK;
}

int32_t PortraitExtraInfoRepository::GetExtraInfo(const int32_t &albumId,
    std::string &extraInfo) const
{
    MEDIA_INFO_LOG("GetExtraInfo start");
    NativeRdb::RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, std::to_string(albumId));
    std::vector<std::string> fetchColumn{EXTRA_INFO};

    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(predicates, fetchColumn);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_INNER_FAIL, "query resultSet is nullptr");

    int count = 0;
    int ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK || count <= 0) {
        extraInfo = "";
        resultSet->Close();
        return NativeRdb::E_OK;
    }
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        extraInfo = get<std::string>(ResultSetUtils::GetValFromColumn(
            EXTRA_INFO, resultSet, TYPE_STRING));
    } else {
        extraInfo = "";
        resultSet->Close();
        return NativeRdb::E_OK;
    }
    resultSet->Close();
    return NativeRdb::E_OK;
}
} // namespace OHOS::Media
