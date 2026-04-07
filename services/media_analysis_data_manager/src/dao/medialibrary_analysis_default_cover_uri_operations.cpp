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

#include "medialibrary_analysis_default_cover_uri_operations.h"

#include "media_string_utils.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"
#include "vision_album_column.h"
#include "vision_face_tag_column.h"
#include "vision_image_face_column.h"
#include "vision_photo_map_column.h"
#include "medialibrary_analysis_album_operations.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;
namespace OHOS::Media {
constexpr int32_t IS_COVER_SATISFIED_DEFAULT_COVER = 1;

static void NotifyPortraitAlbum(const vector<int32_t> &changedAlbumIds)
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

bool CheckIsCoverSatisfied(const string &albumId, shared_ptr<MediaLibraryRdbStore> uniStore)
{
    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.EqualTo(ALBUM_ID, albumId);
    vector<string> columns = { IS_COVER_SATISFIED };
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, false, "uniStore is nullptr!");
    auto resultSet = uniStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "resultSet is nullptr");
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK, false, "resultSet is empty");
    int32_t satisFied = GetInt32Val(IS_COVER_SATISFIED, resultSet);
    return satisFied == 0 || satisFied == 1;
}

int32_t QueryGroupTag(const string &albumId, string &groupTag,
    shared_ptr<MediaLibraryRdbStore> uniStore)
{
    RdbPredicates queryPredicates(ANALYSIS_ALBUM_TABLE);
    queryPredicates.EqualTo(ALBUM_ID, albumId);
    vector<string> columns = { GROUP_TAG };
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_ERR, "uniStore is nullptr!");
    auto resultSet = uniStore->Query(queryPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_ERR, "resultSet is empty");
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        groupTag = GetStringVal(GROUP_TAG, resultSet);
    }
    return E_OK;
}

int32_t GetAlbumIdByGroupTag(const string &groupTag, std::vector<int32_t> &albumIds,
    shared_ptr<MediaLibraryRdbStore> uniStore)
{
    RdbPredicates queryPredicates(ANALYSIS_ALBUM_TABLE);
    queryPredicates.EqualTo(GROUP_TAG, groupTag);
    queryPredicates.And()->EqualTo(ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::PORTRAIT));
    vector<string> columns = { ALBUM_ID };

    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_ERR, "uniStore is nullptr!");
    auto resultSet = uniStore->Query(queryPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_ERR, "resultSet is empty");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        albumIds.push_back(GetInt32Val(ALBUM_ID, resultSet));
    }
    return E_OK;
}

int32_t NotifyAndUpdateForPortraitCoverUri(const string &albumId, const string &coverUri,
    shared_ptr<MediaLibraryRdbStore> uniStore)
{
    string groupTag;
    CHECK_AND_RETURN_RET_LOG(QueryGroupTag(albumId, groupTag, uniStore) == E_OK,
        E_ERR, "QueryGroupTag fail");
    if (groupTag.empty()) {
        MEDIA_ERR_LOG("QueryGroupTag GroupTag is empty");
        return E_ERR;
    }
    string updataUriSql = "UPDATE AnalysisAlbum SET is_cover_satisfied = " +
        to_string(IS_COVER_SATISFIED_DEFAULT_COVER) + ",cover_uri = '" + coverUri +
        "' WHERE group_tag IN ( '" + groupTag + "' );";
    vector<int32_t> changeAlbumIds;
    CHECK_AND_RETURN_RET_LOG(GetAlbumIdByGroupTag(groupTag, changeAlbumIds, uniStore) == E_OK,
        E_ERR, "SetPortraitCoverByUri fail");
    int32_t result = MediaLibraryAnalysisAlbumOperations::UpdateAnalysisAlbum({updataUriSql}, changeAlbumIds);
    CHECK_AND_RETURN_RET_LOG(result == E_OK, E_ERR, "update default cover uri fail");
    return result;
}

bool IsAssetInAlbum(const std::vector<string> &albumIds, const string &fileId,
    shared_ptr<MediaLibraryRdbStore> uniStore)
{
    RdbPredicates predicates(ANALYSIS_PHOTO_MAP_TABLE);
    predicates.EqualTo(MAP_ASSET, fileId);
    predicates.In(MAP_ALBUM, albumIds);
    vector<string> columns = { MAP_ALBUM };
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, false, "uniStore is nullptr!");
    auto resultSet = uniStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "resultSet is empty");
    return resultSet->GoToFirstRow() == NativeRdb::E_OK;
}

static int32_t GetPortraitAlbumIds(const string &albumId, vector<string> &portraitAlbumIds)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_HAS_DB_ERROR, "uniStore is nullptr! failed query album order");
    const std::string queryPortraitAlbumIds = "SELECT " + ALBUM_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " +
        GROUP_TAG + " IN(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE " + ALBUM_ID + " = " + albumId + " AND " + ALBUM_SUBTYPE + " = " + to_string(PORTRAIT) +")";

    auto resultSet = uniStore->QuerySql(queryPortraitAlbumIds);
    CHECK_AND_RETURN_RET(resultSet != nullptr, E_DB_FAIL);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        portraitAlbumIds.push_back(to_string(GetInt32Val(ALBUM_ID, resultSet)));
    }
    return E_OK;
}

bool CheckAssetInAlbum(const string &albumId, const string &coverUri,
    shared_ptr<MediaLibraryRdbStore> uniStore)
{
    string groupTag;
    string fileId = MediaLibraryDataManagerUtils::GetFileIdFromPhotoUri(coverUri);
    std::vector<string> albumIdsStr;
    CHECK_AND_RETURN_RET_LOG(GetPortraitAlbumIds(albumId, albumIdsStr) == E_OK,
        false, "QueryGroupTag fail");
    return IsAssetInAlbum(albumIdsStr, fileId, uniStore);
}

int32_t AnalysisSetDefaultCoverUriOperations::SetDefaultCoverUri(const string &albumId,
    const string &coverUri)
{
    MEDIA_INFO_LOG("SetAnalysisAlbumCoverUri start ");
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_ERR, "uniStore is nullptr!");
    CHECK_AND_RETURN_RET_LOG(CheckIsCoverSatisfied(albumId, uniStore),
        E_INVALID_VALUES, "only no setting or default setting can be changed");
    CHECK_AND_RETURN_RET_LOG(CheckAssetInAlbum(albumId, coverUri, uniStore),
        E_INVALID_VALUES, "coverUri is not found in this album");
    CHECK_AND_RETURN_RET_LOG(NotifyAndUpdateForPortraitCoverUri(albumId, coverUri, uniStore) == E_OK,
        E_ERR, "NotifyAndUpdateForPortraitCoverUri fail");
    vector<int32_t> changeAlbumIds;
    CHECK_AND_RETURN_RET_LOG(MediaStringUtils::ConvertToInt(albumId.c_str(), changeAlbumIds[0]),
        E_ERR, "convertToInt fail");
    NotifyPortraitAlbum(changeAlbumIds);
    return E_OK;
}
}
