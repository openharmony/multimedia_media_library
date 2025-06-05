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

#define MLOG_TAG "MediaAlbumsService"

#include "media_albums_service.h"

#include <string>

#include "medialibrary_album_operations.h"
#include "media_albums_rdb_operations.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "photo_album_column.h"
#include "media_file_utils.h"
#include "result_set_utils.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_analysis_album_operations.h"
#include "photo_map_operations.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_business_code.h"
#include "vision_photo_map_column.h"
#include "medialibrary_client_errno.h"
#include "rdb_utils.h"
#include "medialibrary_rdb_utils.h"
#include "photo_map_column.h"

using namespace std;

namespace OHOS::Media {
static const string USER_DISPLAY_LEVEL = "user_display_level";
static const string SUB_TITLE = "sub_title";

MediaAlbumsService &MediaAlbumsService::GetInstance()
{
    static MediaAlbumsService service;
    return service;
}

int32_t MediaAlbumsService::DeleteHighlightAlbums(const vector<string>& albumIds)
{
    // Only Highlight albums can be deleted by this way
    MEDIA_INFO_LOG("Delete highlight albums");
    int32_t changedRows = this->rdbOperation_.DeleteHighlightAlbums(albumIds);
    CHECK_AND_RETURN_RET_LOG(changedRows >= 0, E_HAS_DB_ERROR,
        "Delete highlight album failed, changedRows is %{private}d", changedRows);
    
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_RET_LOG(watch != nullptr, E_ERR, "Can not get MediaLibraryNotify Instance");

    if (changedRows > 0) {
        for (size_t i = 0; i < albumIds.size(); ++i) {
            watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX,
                albumIds[i]), NotifyType::NOTIFY_REMOVE);
        }
    }
    return changedRows;
}

int32_t MediaAlbumsService::DeletePhotoAlbums(const std::vector<std::string> &albumIds)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
    rdbPredicate.In(PhotoAlbumColumns::ALBUM_ID, albumIds);
    return MediaLibraryAlbumOperations::DeletePhotoAlbum(rdbPredicate);
}

int32_t MediaAlbumsService::CreatePhotoAlbum(const std::string& albumName)
{
    NativeRdb::ValuesBucket value;
    value.PutString(PhotoAlbumColumns::ALBUM_NAME, albumName);
    MediaLibraryCommand cmd(OperationObject::PHOTO_ALBUM, OperationType::CREATE, value);
    return MediaLibraryAlbumOperations::HandlePhotoAlbumOperations(cmd);
}

int32_t MediaAlbumsService::SetSubtitle(const string& highlightAlbumId, const string& albumSubtitle)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, highlightAlbumId);
    values.Put(SUB_TITLE, albumSubtitle);
    return MediaLibraryAlbumOperations::SetHighlightSubtitle(values, predicates);
}

int32_t MediaAlbumsService::SetHighlightUserActionData(const SetHighlightUserActionDataDto& dto)
{
    int32_t err = this->rdbOperation_.SetHighlightUserActionData(dto);
    return err;
}

int32_t MediaAlbumsService::SetPortraitAlbumName(const ChangeRequestSetAlbumNameDto& dto)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, dto.albumId);
    values.Put(PhotoAlbumColumns::ALBUM_NAME, dto.albumName);
    return MediaLibraryAlbumOperations::SetAlbumName(values, predicates);
}

int32_t MediaAlbumsService::SetGroupAlbumName(const ChangeRequestSetAlbumNameDto& dto)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, dto.albumId);
    values.Put(PhotoAlbumColumns::ALBUM_NAME, dto.albumName);
    return MediaLibraryAnalysisAlbumOperations::SetGroupAlbumName(values, predicates);
}

int32_t MediaAlbumsService::SetHighlightAlbumName(const ChangeRequestSetAlbumNameDto& dto)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, dto.albumId);
    values.Put(PhotoAlbumColumns::ALBUM_NAME, dto.albumName);
    return MediaLibraryAlbumOperations::SetHighlightAlbumName(values, predicates);
}

int32_t MediaAlbumsService::RenameUserAlbum(const string& albumId, const string &newAlbumName)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    values.Put(PhotoAlbumColumns::ALBUM_NAME, newAlbumName);
    return MediaLibraryAlbumOperations::HandleSetAlbumNameRequest(values, predicates);
}

int32_t MediaAlbumsService::ChangeRequestSetAlbumName(const ChangeRequestSetAlbumNameDto& dto)
{
    switch (dto.albumSubtype) {
        case PhotoAlbumSubType::PORTRAIT:
            return SetPortraitAlbumName(dto);
        case PhotoAlbumSubType::GROUP_PHOTO:
            return SetGroupAlbumName(dto);
        case PhotoAlbumSubType::HIGHLIGHT:
        case PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS:
            return SetHighlightAlbumName(dto);
        default:
            break;
    }
    return RenameUserAlbum(dto.albumId, dto.albumName);
}

int32_t MediaAlbumsService::SetPortraitCoverUri(const ChangeRequestSetCoverUriDto& dto)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, dto.albumId);
    values.Put(PhotoAlbumColumns::ALBUM_COVER_URI, dto.coverUri);
    return MediaLibraryAlbumOperations::SetCoverUri(values, predicates);
}

int32_t MediaAlbumsService::SetGroupAlbumCoverUri(const ChangeRequestSetCoverUriDto& dto)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, dto.albumId);
    values.Put(PhotoAlbumColumns::ALBUM_COVER_URI, dto.coverUri);
    return MediaLibraryAnalysisAlbumOperations::SetGroupCoverUri(values, predicates);
}

int32_t MediaAlbumsService::SetHighlightAlbumCoverUri(const ChangeRequestSetCoverUriDto& dto)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, dto.albumId);
    values.Put(PhotoAlbumColumns::ALBUM_COVER_URI, dto.coverUri);
    return MediaLibraryAlbumOperations::SetHighlightCoverUri(values, predicates);
}

int32_t MediaAlbumsService::SetUserAlbumCoverUri(const ChangeRequestSetCoverUriDto& dto)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, dto.albumId);
    values.Put(PhotoAlbumColumns::ALBUM_COVER_URI, dto.coverUri);
    return MediaLibraryAlbumOperations::UpdatePhotoAlbum(values, predicates);
}

int32_t MediaAlbumsService::ChangeRequestSetCoverUri(const ChangeRequestSetCoverUriDto& dto)
{
    switch (dto.albumSubtype) {
        case PhotoAlbumSubType::PORTRAIT:
            return SetPortraitCoverUri(dto);
        case PhotoAlbumSubType::GROUP_PHOTO:
            return SetGroupAlbumCoverUri(dto);
        case PhotoAlbumSubType::HIGHLIGHT:
        case PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS:
            return SetHighlightAlbumCoverUri(dto);
        default:
            break;
    }
    return SetUserAlbumCoverUri(dto);
}

int32_t MediaAlbumsService::ChangeRequestSetDisplayLevel(int32_t displayLevelValue,
    int32_t albumId)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    values.Put(USER_DISPLAY_LEVEL, displayLevelValue);
    return MediaLibraryAlbumOperations::SetDisplayLevel(values, predicates);
}

int32_t MediaAlbumsService::ChangeRequestSetIsMe(int32_t albumId)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    return MediaLibraryAlbumOperations::SetIsMe(values, predicates);
}

int32_t MediaAlbumsService::ChangeRequestDismiss(int32_t albumId)
{
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    return MediaLibraryAnalysisAlbumOperations::DismissGroupPhotoAlbum(values, predicates);
}

int32_t MediaAlbumsService::AlbumCommitModify(const AlbumCommitModifyDto& commitModifyDto, int32_t businessCode)
{
    DataShare::DataSharePredicates predicates;
    NativeRdb::ValuesBucket values;
    if (businessCode == static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_COMMIT_MODIFY)) {
        values.Put(PhotoAlbumColumns::ALBUM_NAME, commitModifyDto.albumName);
    }
    values.Put(PhotoAlbumColumns::ALBUM_COVER_URI, commitModifyDto.coverUri);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(commitModifyDto.albumId));

    int32_t changedRows = MediaLibraryAlbumOperations::UpdatePhotoAlbum(values, predicates);
    return changedRows;
}

static shared_ptr<NativeRdb::ResultSet> QueryPhoto(int32_t albumId, bool isSmartAlbum)
{
    NativeRdb::RdbPredicates querypred(PhotoAlbumColumns::TABLE);
    querypred.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    querypred.OrderByAsc(PhotoAlbumColumns::ALBUM_ORDER);

    auto whereClause = querypred.GetWhereClause();
    CHECK_AND_RETURN_RET_LOG(MediaLibraryCommonUtils::CheckWhereClause(whereClause), nullptr,
        "illegal query whereClause input %{private}s", whereClause.c_str());

    vector<string> fetchColumn = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_COUNT,
    };
    if (!isSmartAlbum) {
        fetchColumn.push_back(PhotoAlbumColumns::ALBUM_IMAGE_COUNT);
        fetchColumn.push_back(PhotoAlbumColumns::ALBUM_VIDEO_COUNT);
    }
    MediaLibraryRdbUtils::AddVirtualColumnsOfDateType(const_cast<vector<string> &>(fetchColumn));
    return MediaLibraryRdbStore::QueryWithFilter(querypred, fetchColumn);
}

static int32_t FetchNewCount(shared_ptr<NativeRdb::ResultSet> resultSet, AlbumPhotoQueryRespBody& respBody)
{
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet == nullptr");
        return E_ERR;
    }

    if (resultSet->GoToFirstRow() != 0) {
        MEDIA_ERR_LOG("go to first row failed");
        return E_ERR;
    }

    respBody.newCount =
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT, resultSet, TYPE_INT32));
    respBody.newImageCount =
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet, TYPE_INT32));
    respBody.newVideoCount =
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet, TYPE_INT32));
    return E_OK;
}

int32_t MediaAlbumsService::AlbumAddAssets(const AlbumAddAssetsDto& addAssetsDto, AlbumPhotoQueryRespBody& respBody)
{
    vector<DataShare::DataShareValuesBucket> valuesBuckets;
    for (const auto &assetId : addAssetsDto.assetsArray) {
        DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, addAssetsDto.albumId);
        valuesBucket.Put(PhotoColumn::MEDIA_ID, assetId);
        valuesBuckets.push_back(valuesBucket);
    }

    int32_t changedRows = PhotoMapOperations::AddPhotoAssets(valuesBuckets);
    if (changedRows < 0) {
        return changedRows;
    }

    auto resultSet = QueryPhoto(addAssetsDto.albumId, addAssetsDto.isSmartAlbum);
    if (FetchNewCount(resultSet, respBody) != E_OK) {
        return -1;
    }
    return changedRows;
}

int32_t MediaAlbumsService::AlbumRemoveAssets(const AlbumRemoveAssetsDto& removeAssetsDto,
    AlbumPhotoQueryRespBody& respBody)
{
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(removeAssetsDto.albumId));
    predicates.And()->In(PhotoColumn::MEDIA_ID, removeAssetsDto.assetsArray);

    auto whereClause = predicates.GetWhereClause();
    CHECK_AND_RETURN_RET_LOG(MediaLibraryCommonUtils::CheckWhereClause(whereClause), E_SQL_CHECK_FAIL,
        "illegal query whereClause input %{private}s", whereClause.c_str());

    NativeRdb::RdbPredicates rdbPredicate = RdbDataShareAdapter::RdbUtils::ToPredicates(predicates, PhotoMap::TABLE);
    int32_t changedRows = PhotoMapOperations::RemovePhotoAssets(rdbPredicate);
    if (changedRows < 0) {
        return changedRows;
    }

    auto resultSet = QueryPhoto(removeAssetsDto.albumId, removeAssetsDto.isSmartAlbum);
    if (FetchNewCount(resultSet, respBody) != E_OK) {
        return -1;
    }
    return changedRows;
}

int32_t MediaAlbumsService::AlbumRecoverAssets(const AlbumRecoverAssetsDto& recoverAssetsDto)
{
    DataShare::DataSharePredicates predicates;
    predicates.In(MediaColumn::MEDIA_ID, recoverAssetsDto.uris);

    return MediaLibraryAlbumOperations::RecoverPhotoAssets(predicates);
}
} // namespace OHOS::Media