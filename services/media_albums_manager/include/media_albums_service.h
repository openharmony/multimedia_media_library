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

#ifndef OHOS_MEDIA_ALBUMS_SERVICE_H
#define OHOS_MEDIA_ALBUMS_SERVICE_H

#include <stdint.h>
#include <string>

#include "media_albums_rdb_operations.h"
#include "change_request_set_album_name_dto.h"
#include "change_request_set_cover_uri_dto.h"
#include "set_highlight_user_action_data_dto.h"
#include "album_commit_modify_dto.h"
#include "album_add_assets_dto.h"
#include "album_remove_assets_dto.h"
#include "album_recover_assets_dto.h"
#include "album_photo_query_vo.h"
#include "album_get_assets_dto.h"
#include "get_order_position_dto.h"
#include "get_order_position_vo.h"
#include "get_photo_index_vo.h"
#include "query_result_vo.h"
#include "get_analysis_process_vo.h"
#include "get_highlight_album_info_vo.h"
#include "query_albums_dto.h"
#include "set_photo_album_order_dto.h"
#include "change_request_move_assets_vo.h"

namespace OHOS::Media {
class MediaAlbumsService {
public:
    static MediaAlbumsService &GetInstance();

    int32_t DeleteHighlightAlbums(const std::vector<std::string>& albumIds);
    int32_t DeletePhotoAlbums(const std::vector<std::string> &albumIds);
    int32_t CreatePhotoAlbum(const std::string& albumName);
    int32_t SetSubtitle(const std::string& highlightAlbumId, const std::string& albumSubtitle);
    int32_t SetHighlightUserActionData(const SetHighlightUserActionDataDto& dto);
    int32_t ChangeRequestSetAlbumName(const ChangeRequestSetAlbumNameDto& dto);
    int32_t ChangeRequestSetCoverUri(const ChangeRequestSetCoverUriDto& dto);
    int32_t ChangeRequestSetDisplayLevel(int32_t displayLevelValue, int32_t albumId);
    int32_t ChangeRequestSetIsMe(int32_t albumId);
    int32_t ChangeRequestDismiss(int32_t albumId);
    int32_t ChangeRequestResetCoverUri(int32_t albumId, PhotoAlbumSubType albumSubtype);
    int32_t AlbumCommitModify(const AlbumCommitModifyDto& commitModifyDto, int32_t businessCode);
    int32_t AlbumAddAssets(const AlbumAddAssetsDto& addAssetsDto, AlbumPhotoQueryRespBody& respBody);
    int32_t AlbumRemoveAssets(const AlbumRemoveAssetsDto& removeAssetsDto, AlbumPhotoQueryRespBody& respBody);
    int32_t AlbumRecoverAssets(const AlbumRecoverAssetsDto& recoverAssetsDto);
    std::shared_ptr<DataShare::DataShareResultSet> AlbumGetAssets(const AlbumGetAssetsDto &dto);
    int32_t QueryAlbums(QueryAlbumsDto &dto);
    int32_t QueryHiddenAlbums(QueryAlbumsDto &dto);
    int32_t GetOrderPosition(const GetOrderPositionDto& getOrderPositionDto, GetOrderPositionRespBody& resp);
    int32_t GetFaceId(int32_t albumId, std::string& groupTag);
    int32_t GetPhotoIndex(GetPhotoIndexReqBody &reqBody, QueryResultRspBody &rspBody);
    int32_t GetMediaAnalysisServiceProcess(GetAnalysisProcessReqBody &reqBody, QueryResultRspBody &rspBody);
    int32_t GetAnalysisProcess(GetAnalysisProcessReqBody &reqBody, QueryResultRspBody &rspBody);
    int32_t GetHighlightAlbumInfo(GetHighlightAlbumReqBody &reqBody, QueryResultRspBody &rspBody);
    int32_t UpdatePhotoAlbumOrder(const SetPhotoAlbumOrderDto& setPhotoAlbumOrderDto);
    int32_t MoveAssets(ChangeRequestMoveAssetsDto &moveAssetsDto);

private:
    int32_t SetPortraitAlbumName(const ChangeRequestSetAlbumNameDto& dto);
    int32_t SetGroupAlbumName(const ChangeRequestSetAlbumNameDto& dto);
    int32_t SetHighlightAlbumName(const ChangeRequestSetAlbumNameDto& dto);
    int32_t RenameUserAlbum(const std::string& oldAlbumId, const std::string& newAlbumName);
    int32_t SetPortraitCoverUri(const ChangeRequestSetCoverUriDto& dto);
    int32_t SetGroupAlbumCoverUri(const ChangeRequestSetCoverUriDto& dto);
    int32_t SetHighlightAlbumCoverUri(const ChangeRequestSetCoverUriDto& dto);
    int32_t SetUserAlbumCoverUri(const ChangeRequestSetCoverUriDto& dto);
    int32_t SetSourceAlbumCoverUri(const ChangeRequestSetCoverUriDto& dto);
    int32_t SetSystemAlbumCoverUri(const ChangeRequestSetCoverUriDto& dto);
    MediaAlbumsRdbOperations rdbOperation_;
};
} // namespace OHOS::Media
#endif // OHOS_MEDIA_ALBUMS_SERVICE_H