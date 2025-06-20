/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#define MLOG_TAG "MediaAlbumsControllerService"

#include "media_albums_controller_service.h"
#include "media_albums_service.h"

#include "media_log.h"
#include "parameter_utils.h"
#include "delete_albums_vo.h"
#include "create_album_vo.h"
#include "delete_highlight_albums_vo.h"
#include "set_subtitle_vo.h"
#include "media_file_utils.h"
#include "photo_album.h"
#include "set_highlight_user_action_data_dto.h"
#include "userfile_manager_types.h"
#include "story_album_column.h"
#include "set_highlight_user_action_data_vo.h"
#include "change_request_set_album_name_vo.h"
#include "change_request_set_cover_uri_vo.h"
#include "change_request_dismiss_vo.h"
#include "change_request_set_display_level_vo.h"
#include "change_request_set_is_me_vo.h"
#include "change_request_set_album_name_dto.h"
#include "medialibrary_data_manager_utils.h"
#include "change_request_add_assets_vo.h"
#include "change_request_remove_assets_vo.h"
#include "change_request_move_assets_vo.h"
#include "change_request_recover_assets_vo.h"
#include "change_request_delete_assets_vo.h"
#include "change_request_dismiss_assets_vo.h"
#include "change_request_merge_album_vo.h"
#include "change_request_place_before_vo.h"
#include "change_request_set_order_position_vo.h"
#include "vision_photo_map_column.h"
#include "photo_map_operations.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "result_set_utils.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_album_operations.h"
#include "vision_album_column.h"
#include "medialibrary_analysis_album_operations.h"
#include "rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_data_manager.h"
#include "album_commit_modify_vo.h"
#include "album_commit_modify_dto.h"
#include "album_add_assets_vo.h"
#include "album_add_assets_dto.h"
#include "album_remove_assets_vo.h"
#include "album_remove_assets_dto.h"
#include "album_recover_assets_vo.h"
#include "album_recover_assets_dto.h"
#include "album_photo_query_vo.h"
#include "query_albums_vo.h"
#include "query_albums_dto.h"
#include "get_order_position_dto.h"
#include "get_order_position_vo.h"
#include "get_face_id_vo.h"
#include "permission_common.h"
#include "photo_album_column.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_vision_operations.h"
#include "get_albums_by_ids_vo.h"
#include "rdb_utils.h"
#include "get_photo_album_object_vo.h"
#include "set_photo_album_order_vo.h"
#include "set_photo_album_order_dto.h"

namespace OHOS::Media {
using namespace std;
using SpecialRequestHandle = void (MediaAlbumsControllerService::*)(
    MessageParcel &, MessageParcel &, OHOS::Media::IPC::IPCContext &);

using RequestHandle = void (MediaAlbumsControllerService::*)(MessageParcel &, MessageParcel &);

const std::map<uint32_t, SpecialRequestHandle> SPECIAL_HANDLERS = {
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ALBUM_SYS_GET_ASSETS),
        &MediaAlbumsControllerService::AlbumGetAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ALBUM_GET_ASSETS),
        &MediaAlbumsControllerService::AlbumGetAssets
    },
};

const std::map<uint32_t, RequestHandle> HANDLERS = {
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::DELETE_HIGH_LIGHT_ALBUMS),
        &MediaAlbumsControllerService::DeleteHighlightAlbums
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_DELETE_PHOTO_ALBUMS),
        &MediaAlbumsControllerService::DeletePhotoAlbums
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ALBUM),
        &MediaAlbumsControllerService::CreatePhotoAlbum
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SET_HIGH_LIGHT_USER_ACTION_DATA),
        &MediaAlbumsControllerService::SetHighlightUserActionData
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SET_SUBTITLE),
        &MediaAlbumsControllerService::SetSubtitle
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_SET_ALBUM_NAME),
        &MediaAlbumsControllerService::ChangeRequestSetAlbumName
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_SET_COVER_URI),
        &MediaAlbumsControllerService::ChangeRequestSetCoverUri
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_SET_IS_ME),
        &MediaAlbumsControllerService::ChangeRequestSetIsMe
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_SET_DISPLAY_LEVEL),
        &MediaAlbumsControllerService::ChangeRequestSetDisplayLevel
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_DISMISS),
        &MediaAlbumsControllerService::ChangeRequestDismiss
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_RESET_COVER_URI),
        &MediaAlbumsControllerService::ChangeRequestResetCoverUri
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_ADD_ASSETS),
        &MediaAlbumsControllerService::AddAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_REMOVE_ASSETS),
        &MediaAlbumsControllerService::RemoveAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_MOVE_ASSETS),
        &MediaAlbumsControllerService::MoveAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_RECOVER_ASSETS),
        &MediaAlbumsControllerService::RecoverAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_DELETE_ASSETS),
        &MediaAlbumsControllerService::DeleteAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_DISMISS_ASSETS),
        &MediaAlbumsControllerService::DismissAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_MERGE_ALBUM),
        &MediaAlbumsControllerService::MergeAlbum
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_PLACE_BEFORE),
        &MediaAlbumsControllerService::PlaceBefore
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CHANGE_REQUEST_SET_ORDER_POSITION),
        &MediaAlbumsControllerService::SetOrderPosition
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_COMMIT_MODIFY),
        &MediaAlbumsControllerService::AlbumCommitModify
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_ADD_ASSETS),
        &MediaAlbumsControllerService::AlbumAddAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_REMOVE_ASSETS),
        &MediaAlbumsControllerService::AlbumRemoveAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_RECOVER_ASSETS),
        &MediaAlbumsControllerService::AlbumRecoverAssets
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SET_COVER_URI),
        &MediaAlbumsControllerService::AlbumCommitModify
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_QUERY_PHOTO_ALBUMS),
        &MediaAlbumsControllerService::QueryAlbums
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_QUERY_HIDDEN_ALBUMS),
        &MediaAlbumsControllerService::QueryHiddenAlbums
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_QUERY_GET_ALBUMS_BY_IDS),
        &MediaAlbumsControllerService::GetAlbumsByIds
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_GET_ORDER_POSITION),
        &MediaAlbumsControllerService::GetOrderPosition
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::GET_FACE_ID),
        &MediaAlbumsControllerService::GetFaceId
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::GET_PHOTO_INDEX),
        &MediaAlbumsControllerService::GetPhotoIndex
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::GET_ANALYSIS_PROCESS),
        &MediaAlbumsControllerService::GetAnalysisProcess
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::GET_HIGHLIGHT_ALBUM_INFO),
        &MediaAlbumsControllerService::GetHighlightAlbumInfo
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_GET_PHOTO_ALBUMS),
        &MediaAlbumsControllerService::GetPhotoAlbumObject
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_GET_PHOTO_ALBUM_ORDER),
        &MediaAlbumsControllerService::GetPhotoAlbumObject
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SET_PHOTO_ALBUM_ORDER),
        &MediaAlbumsControllerService::UpdatePhotoAlbumOrder
    },
};

bool MediaAlbumsControllerService::Accept(uint32_t code)
{
    return HANDLERS.find(code) != HANDLERS.end() || SPECIAL_HANDLERS.find(code) != SPECIAL_HANDLERS.end();
}

void MediaAlbumsControllerService::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, OHOS::Media::IPC::IPCContext &context)
{
    auto handlersIt = HANDLERS.find(code);
    if (handlersIt != HANDLERS.end()) {
        return (this->*(handlersIt->second))(data, reply);
    }
    auto specialHandlersIt = SPECIAL_HANDLERS.find(code);
    if (specialHandlersIt != SPECIAL_HANDLERS.end()) {
        return (this->*(specialHandlersIt->second))(data, reply, context);
    }
    return IPC::UserDefineIPC().WriteResponseBody(reply, E_IPC_SEVICE_NOT_FOUND);
}

static const map<int32_t, std::string> HIGHLIGHT_USER_ACTION_MAP = {
    { INSERTED_PIC_COUNT, HIGHLIGHT_INSERT_PIC_COUNT },
    { REMOVED_PIC_COUNT, HIGHLIGHT_REMOVE_PIC_COUNT },
    { SHARED_SCREENSHOT_COUNT, HIGHLIGHT_SHARE_SCREENSHOT_COUNT },
    { SHARED_COVER_COUNT, HIGHLIGHT_SHARE_COVER_COUNT },
    { RENAMED_COUNT, HIGHLIGHT_RENAME_COUNT },
    { CHANGED_COVER_COUNT, HIGHLIGHT_CHANGE_COVER_COUNT },
    { RENDER_VIEWED_TIMES, HIGHLIGHT_RENDER_VIEWED_TIMES },
    { RENDER_VIEWED_DURATION, HIGHLIGHT_RENDER_VIEWED_DURATION },
    { ART_LAYOUT_VIEWED_TIMES, HIGHLIGHT_ART_LAYOUT_VIEWED_TIMES },
    { ART_LAYOUT_VIEWED_DURATION, HIGHLIGHT_ART_LAYOUT_VIEWED_DURATION },
};

static inline PhotoAlbumType GetPhotoAlbumType(int32_t albumType)
{
    return static_cast<PhotoAlbumType>(albumType);
}

static inline PhotoAlbumSubType GetPhotoAlbumSubType(int32_t albumSubType)
{
    return static_cast<PhotoAlbumSubType>(albumSubType);
}

void MediaAlbumsControllerService::DeleteHighlightAlbums(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DeleteHighlightAlbums");
    DeleteHighLightAlbumsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DeleteHighlightAlbums Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    size_t albumIdSize = reqBody.albumIds.size();
    size_t photoAlbumTypeSize = reqBody.photoAlbumTypes.size();
    size_t photoAlbumSubtypeSize = reqBody.photoAlbumSubtypes.size();
    vector<string> albumIds;
    bool checkResult = ParameterUtils::CheckHighlightAlbum(reqBody, albumIds);

    bool cond = checkResult && (albumIdSize == photoAlbumTypeSize) && (photoAlbumTypeSize == photoAlbumSubtypeSize)
        && (albumIdSize > 0) && (photoAlbumTypeSize > 0) && (photoAlbumSubtypeSize > 0);
    if (!cond) {
        MEDIA_ERR_LOG("params is not valid, checkResult:%{public}d", checkResult);
        ret = E_GET_PRAMS_FAIL;
    }
    if (ret == E_OK) {
        ret = MediaAlbumsService::GetInstance().DeleteHighlightAlbums(albumIds);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}

void MediaAlbumsControllerService::DeletePhotoAlbums(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DeletePhotoAlbums");
    DeleteAlbumsReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DeletePhotoAlbums Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    if (reqBody.albumIds.empty()) {
        MEDIA_ERR_LOG("DeletePhotoAlbums albumIds is empty");
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        return;
    }
    ret = MediaAlbumsService::GetInstance().DeletePhotoAlbums(reqBody.albumIds);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::CreatePhotoAlbum(MessageParcel &data, MessageParcel &reply)
{
    CreateAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("CreatePhotoAlbum Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckCreatePhotoAlbum(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("CheckCreatePhotoAlbum ret:%{public}d", ret);
        return;
    }

    ret = MediaAlbumsService::GetInstance().CreatePhotoAlbum(reqBody.albumName);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::SetSubtitle(MessageParcel &data, MessageParcel &reply)
{
    SetSubtitleReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("SetSubtitle Read Request Error");
        return;
    }
    bool cond = MediaFileUtils::CheckHighlightSubtitle(reqBody.subtitle) == E_OK &&
        PhotoAlbum::IsHighlightAlbum(GetPhotoAlbumType(reqBody.albumType),
        GetPhotoAlbumSubType(reqBody.albumSubType));
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }
    ret = MediaAlbumsService::GetInstance().SetSubtitle(reqBody.albumId, reqBody.subtitle);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::SetHighlightUserActionData(MessageParcel &data, MessageParcel &reply)
{
    SetHighlightUserActionDataReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("SetHighlightUserActionData Read Request Error");
        return;
    }
    if (HIGHLIGHT_USER_ACTION_MAP.find(reqBody.userActionType) == HIGHLIGHT_USER_ACTION_MAP.end()) {
        MEDIA_ERR_LOG("Invalid highlightUserActionType");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }
    string userActionColumn = HIGHLIGHT_USER_ACTION_MAP.at(reqBody.userActionType);
    if (!PhotoAlbum::IsHighlightAlbum(GetPhotoAlbumType(reqBody.albumType),
        GetPhotoAlbumSubType(reqBody.albumSubType))) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }
    SetHighlightUserActionDataDto dto;
    dto.albumId = reqBody.albumId;
    dto.userActionType = userActionColumn;
    dto.actionData = reqBody.actionData;
    ret = MediaAlbumsService::GetInstance().SetHighlightUserActionData(dto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::ChangeRequestSetAlbumName(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequestSetAlbumNameReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("ChangeRequestSetAlbumName Read Request Error");
        return;
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    bool cond = (MediaFileUtils::CheckAlbumName(reqBody.albumName) == E_OK);
    cond = (PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype) ||
        PhotoAlbum::IsSmartPortraitPhotoAlbum(albumType, albumSubtype) ||
        PhotoAlbum::IsSmartGroupPhotoAlbum(albumType, albumSubtype) ||
        PhotoAlbum::IsHighlightAlbum(albumType, albumSubtype)) && cond;
    cond = cond && !reqBody.albumName.empty() && !reqBody.albumId.empty() &&
        MediaLibraryDataManagerUtils::IsNumber(reqBody.albumId);
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }
    ChangeRequestSetAlbumNameDto dto;
    dto.albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    dto.albumName = reqBody.albumName;
    dto.albumId = reqBody.albumId;
    ret = MediaAlbumsService::GetInstance().ChangeRequestSetAlbumName(dto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::ChangeRequestSetCoverUri(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequestSetCoverUriReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("ChangeRequestSetCoverUri Read Request Error");
        return;
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    bool cond = PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype) ||
        PhotoAlbum::IsSmartPortraitPhotoAlbum(albumType, albumSubtype) ||
        PhotoAlbum::IsSmartGroupPhotoAlbum(albumType, albumSubtype) ||
        PhotoAlbum::IsHighlightAlbum(albumType, albumSubtype);
    cond = cond && !reqBody.coverUri.empty() && !reqBody.albumId.empty() &&
        MediaLibraryDataManagerUtils::IsNumber(reqBody.albumId);
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }
    ChangeRequestSetCoverUriDto dto;
    dto.albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    dto.coverUri = reqBody.coverUri;
    dto.albumId = reqBody.albumId;
    ret = MediaAlbumsService::GetInstance().ChangeRequestSetCoverUri(dto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::ChangeRequestSetIsMe(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequestSetIsMeReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("ChangeRequestSetIsMe Read Request Error");
        return;
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    int32_t albumId = atoi(reqBody.albumId.c_str());
    bool cond = PhotoAlbum::IsSmartPortraitPhotoAlbum(albumType, albumSubtype);
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    ret = MediaAlbumsService::GetInstance().ChangeRequestSetIsMe(albumId);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::ChangeRequestSetDisplayLevel(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequestSetDisplayLevelReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("ChangeRequestSetIsMe Read Request Error");
        return;
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    int32_t albumId = atoi(reqBody.albumId.c_str());
    bool cond = PhotoAlbum::IsSmartPortraitPhotoAlbum(albumType, albumSubtype) &&
        MediaFileUtils::CheckDisplayLevel(reqBody.displayLevel) && albumId > 0;
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    ret = MediaAlbumsService::GetInstance().ChangeRequestSetDisplayLevel(reqBody.displayLevel, albumId);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::ChangeRequestDismiss(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequesDismissReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("ChangeRequestDismiss Read Request Error");
        return;
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    int32_t albumId = atoi(reqBody.albumId.c_str());
    bool cond = PhotoAlbum::IsSmartGroupPhotoAlbum(albumType, albumSubtype);
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    ret = MediaAlbumsService::GetInstance().ChangeRequestDismiss(albumId);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAlbumsControllerService::ChangeRequestResetCoverUri(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequesDismissReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("ChangeRequestResetCoverUri Read Request Error");
        return;
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    int32_t albumId = atoi(reqBody.albumId.c_str());
    bool cond = PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype) ||
        (PhotoAlbum::IsSystemAlbum(albumType) && !PhotoAlbum::IsHiddenAlbum(albumType, albumSubtype)) ||
        PhotoAlbum::IsSourceAlbum(albumType, albumSubtype);
    cond = cond && !reqBody.albumId.empty() && MediaLibraryDataManagerUtils::IsNumber(reqBody.albumId);
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    ret = MediaAlbumsService::GetInstance().ChangeRequestResetCoverUri(albumId, albumSubtype);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

std::shared_ptr<OHOS::NativeRdb::ResultSet>  QueryOperation(
    DataShare::DataSharePredicates &predicates, std::vector<std::string> &fetchColumns)
{
    NativeRdb::RdbPredicates rdbPredicates =
        RdbDataShareAdapter::RdbUtils::ToPredicates(predicates, PhotoAlbumColumns::TABLE);
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, fetchColumns);
    if (resultSet == nullptr) {
        return nullptr;
    }
    int32_t numRows = 0;
    resultSet->GetRowCount(numRows);
    if (numRows == 0) {
        return nullptr;
    }
    resultSet->GoToFirstRow();
    return resultSet;
}

void MediaAlbumsControllerService::AddAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AddAssets");
    ChangeRequestAddAssetsReqBody reqBody;
    ChangeRequestAddAssetsRspBody rspBody;
    std::vector<DataShare::DataShareValuesBucket> valuesBuckets;
    DataShare::DataSharePredicates predicates;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AddAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.isHighlight) {
        for (auto asset : reqBody.assets) {
            DataShare::DataShareValuesBucket pair;
            pair.Put(MAP_ALBUM, reqBody.albumId);
            pair.Put(MAP_ASSET, asset);
            valuesBuckets.push_back(pair);
        }
        ret = PhotoMapOperations::AddHighlightPhotoAssets(valuesBuckets);
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    } else {
        for (auto asset : reqBody.assets) {
            DataShare::DataShareValuesBucket pair;
            pair.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, reqBody.albumId);
            pair.Put(PhotoColumn::MEDIA_ID, asset);
            valuesBuckets.push_back(pair);
        }
        ret = PhotoMapOperations::AddPhotoAssets(valuesBuckets);
    }

    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, reqBody.albumId);
    std::vector<std::string> fetchColumns = { PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT, PhotoAlbumColumns::ALBUM_VIDEO_COUNT };
    auto resultSet = QueryOperation(predicates, fetchColumns);
    if (reqBody.isHiddenOnly) {
        rspBody.imageCount = -1;
        rspBody.videoCount = -1;
    } else {
        rspBody.imageCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet, TYPE_INT32));
        rspBody.videoCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet, TYPE_INT32));
    }
    rspBody.albumCount =
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT, resultSet, TYPE_INT32));
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
    return;
}

void MediaAlbumsControllerService::RemoveAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RemoveAssets");
    ChangeRequestRemoveAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RemoveAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ChangeRequestRemoveAssetsRspBody rspBody;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(reqBody.albumId));
    predicates.And()->In(PhotoColumn::MEDIA_ID, reqBody.assets);
    NativeRdb::RdbPredicates rdbPredicate = RdbDataShareAdapter::RdbUtils::ToPredicates(predicates, PhotoMap::TABLE);
    ret = PhotoMapOperations::RemovePhotoAssets(rdbPredicate);

    DataShare::DataSharePredicates queuePredicates;
    queuePredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, reqBody.albumId);
    std::vector<std::string> fetchColumns = { PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT, PhotoAlbumColumns::ALBUM_VIDEO_COUNT };
    auto resultSet = QueryOperation(queuePredicates, fetchColumns);

    if (reqBody.isHiddenOnly) {
        rspBody.imageCount = -1;
        rspBody.videoCount = -1;
    } else {
        rspBody.imageCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet, TYPE_INT32));
        rspBody.videoCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet, TYPE_INT32));
    }
    rspBody.albumCount =
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT, resultSet, TYPE_INT32));
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);

    return;
}

void MediaAlbumsControllerService::MoveAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter MoveAssets");
    ChangeRequestMoveAssetsReqBody reqBody;
    ChangeRequestMoveAssetsRspBody rspBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("MoveAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(reqBody.albumId));
    predicates.And()->In(PhotoColumn::MEDIA_ID, reqBody.assets);
    NativeRdb::RdbPredicates rdbPredicate = RdbDataShareAdapter::RdbUtils::ToPredicates(predicates, MEDIALIBRARY_TABLE);

    DataShare::DataShareValuesBucket valuesBuckets;
    valuesBuckets.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, reqBody.targetAlbumId);
    NativeRdb::ValuesBucket value = RdbDataShareAdapter::RdbUtils::ToValuesBucket(valuesBuckets);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MoveAssets:Input parameter is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    MediaLibraryCommand cmd(OperationObject::PAH_PHOTO, OperationType::UPDATE, MediaLibraryApi::API_10);
    cmd.SetValueBucket(value);
    cmd.SetDataSharePred(predicates);
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    ret = MediaLibraryPhotoOperations::BatchSetOwnerAlbumId(cmd);

    DataShare::DataSharePredicates queuePredicates;
    queuePredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, reqBody.albumId);
    std::vector<std::string> fetchColumns = { PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_COUNT,
        PhotoAlbumColumns::ALBUM_IMAGE_COUNT, PhotoAlbumColumns::ALBUM_VIDEO_COUNT };
    auto resultSet = QueryOperation(queuePredicates, fetchColumns);
    if (reqBody.isHiddenOnly) {
        rspBody.imageCount = -1;
        rspBody.videoCount = -1;
    } else {
        rspBody.imageCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet, TYPE_INT32));
        rspBody.videoCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet, TYPE_INT32));
    }
    rspBody.albumCount =
        get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT, resultSet, TYPE_INT32));
    MEDIA_ERR_LOG("MoveAssets rspBody.albumCount %{public}d", rspBody.albumCount);
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);

    return;
}

void MediaAlbumsControllerService::RecoverAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RecoverAssets");
    ChangeRequestRecoverAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RecoverAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    DataShare::DataSharePredicates predicates;
    predicates.In(PhotoColumn::MEDIA_ID, reqBody.assets);
    ret = MediaLibraryAlbumOperations::RecoverPhotoAssets(predicates);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);

    return;
}

void MediaAlbumsControllerService::DeleteAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DeleteAssets");
    ChangeRequestDeleteAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DeleteAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    DataShare::DataSharePredicates predicates;
    predicates.In(PhotoColumn::MEDIA_ID, reqBody.assets);
    predicates.GreaterThan(PhotoColumn::MEDIA_DATE_TRASHED, 0);
    ret = MediaLibraryAlbumOperations::DeletePhotoAssets(predicates, false, false);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);

    return;
}

void MediaAlbumsControllerService::DismissAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DismissAssets");
    const int32_t PORTRAIT_REMOVED = -3;
    const std::string TAG_ID = "tag_id";
    ChangeRequestDismissAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DismissAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MAP_ALBUM, to_string(reqBody.albumId));
    predicates.And()->In(MAP_ASSET, reqBody.assets);
    predicates.And()->EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(reqBody.photoAlbumSubType));
    NativeRdb::RdbPredicates rdbPredicate =
        RdbDataShareAdapter::RdbUtils::ToPredicates(predicates, ANALYSIS_PHOTO_MAP_TABLE);
    ret = PhotoMapOperations::DismissAssets(rdbPredicate);
    if (ret < 0) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("DismissAssets Error");
        return;
    }
    if (reqBody.photoAlbumSubType == PhotoAlbumSubType::PORTRAIT) {
        DataShare::DataShareValuesBucket updateValues;
        updateValues.Put(TAG_ID, std::to_string(PORTRAIT_REMOVED));
        NativeRdb::ValuesBucket value = RdbDataShareAdapter::RdbUtils::ToValuesBucket(updateValues);
        DataShare::DataSharePredicates updatePredicates;
        std::string selection = std::to_string(reqBody.albumId);
        for (size_t i = 0; i < reqBody.assets.size(); ++i) {
            selection += "," + reqBody.assets[i];
        }
        updatePredicates.SetWhereClause(selection);
        NativeRdb::RdbPredicates rdbPredicateUpdate =
            RdbDataShareAdapter::RdbUtils::ToPredicates(updatePredicates, VISION_IMAGE_FACE_TABLE);

        MediaLibraryCommand cmd(OperationObject::VISION_IMAGE_FACE, OperationType::UPDATE, MediaLibraryApi::API_10);
        cmd.SetValueBucket(value);
        cmd.SetDataSharePred(updatePredicates);
        cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicateUpdate.GetWhereClause());
        cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicateUpdate.GetWhereArgs());
        auto dataManager = MediaLibraryDataManager::GetInstance();
        dataManager->HandleAnalysisFaceUpdate(cmd, value, updatePredicates);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);

    return;
}

void MediaAlbumsControllerService::MergeAlbum(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter MergeAlbum");
    ChangeRequestMergeAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("MergeAlbum Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_ID, reqBody.albumId);
    valuesBucket.Put(TARGET_ALBUM_ID, reqBody.targetAlbumId);
    NativeRdb::ValuesBucket value = RdbDataShareAdapter::RdbUtils::ToValuesBucket(valuesBucket);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager Update:Input parameter is invalid ");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = MediaLibraryAlbumOperations::MergePortraitAlbums(value);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);

    return;
}

void MediaAlbumsControllerService::PlaceBefore(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter PlaceBefore");
    ChangeRequestPlaceBeforeReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("PlaceBefore Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_ID, reqBody.albumId);
    valuesBucket.Put(PhotoAlbumColumns::REFERENCE_ALBUM_ID, reqBody.referenceAlbumId);
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_TYPE, reqBody.albumType);
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_SUBTYPE, reqBody.albumSubType);
    NativeRdb::ValuesBucket value = RdbDataShareAdapter::RdbUtils::ToValuesBucket(valuesBucket);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("PlaceBefore:Input parameter is invalid ");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    ret = MediaLibraryAlbumOperations::OrderSingleAlbum(value);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);

    return;
}

void MediaAlbumsControllerService::SetOrderPosition(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter PlaceBefore");
    const string mapTable = ANALYSIS_PHOTO_MAP_TABLE;
    ChangeRequestSetOrderPositionReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("PlaceBefore Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    MediaLibraryCommand cmd(OperationObject::ANALYSIS_PHOTO_MAP, OperationType::UPDATE_ORDER, MediaLibraryApi::API_10);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ORDER_POSITION, reqBody.orderString);
    NativeRdb::ValuesBucket value = RdbDataShareAdapter::RdbUtils::ToValuesBucket(valuesBucket);
    if (value.IsEmpty()) {
        MEDIA_ERR_LOG("PlaceBefore:Input parameter is invalid ");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(mapTable + "." + MAP_ALBUM, reqBody.albumId)
        ->And()
        ->In(mapTable + "." + MAP_ASSET, reqBody.assetIds);
    NativeRdb::RdbPredicates rdbPredicate =
        RdbDataShareAdapter::RdbUtils::ToPredicates(predicates, ANALYSIS_PHOTO_MAP_TABLE);
    cmd.SetValueBucket(value);
    cmd.SetDataSharePred(predicates);
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    ret = MediaLibraryAnalysisAlbumOperations::SetAnalysisAlbumPortraitsOrder(cmd);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);

    return;
}

void MediaAlbumsControllerService::AlbumCommitModify(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CommitModify");
    AlbumCommitModifyReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CommitModify Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.businessCode == static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_COMMIT_MODIFY)) {
        PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
        PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);

        bool cond = PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype) &&
            MediaFileUtils::CheckAlbumName(reqBody.albumName) == E_OK;
        if (!cond) {
            MEDIA_ERR_LOG("params is invalid");
            IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
            return;
        }
    }

    if (reqBody.businessCode == static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SET_COVER_URI) &&
        reqBody.coverUri.empty()) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    AlbumCommitModifyDto commitModifyDto;
    commitModifyDto.albumName = reqBody.albumName;
    commitModifyDto.coverUri = reqBody.coverUri;
    commitModifyDto.albumId = reqBody.albumId;

    ret = MediaAlbumsService::GetInstance().AlbumCommitModify(commitModifyDto, reqBody.businessCode);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}

void MediaAlbumsControllerService::AlbumAddAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AddAssets");
    AlbumAddAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AddAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    if (!PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype)) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    if (reqBody.assetsArray.empty()) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    AlbumPhotoQueryRespBody respBody;
    AlbumAddAssetsDto addAssetsDto;
    addAssetsDto.albumId = reqBody.albumId;
    addAssetsDto.isSmartAlbum = reqBody.albumType == PhotoAlbumType::SMART;
    addAssetsDto.assetsArray = reqBody.assetsArray;

    ret = MediaAlbumsService::GetInstance().AlbumAddAssets(addAssetsDto, respBody);
    IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
    return;
}

void MediaAlbumsControllerService::AlbumRemoveAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RemoveAssets");
    AlbumRemoveAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AddAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    if (!PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype)) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    if (reqBody.assetsArray.empty()) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    AlbumRemoveAssetsDto removeAssetsDto;
    removeAssetsDto.albumId = reqBody.albumId;
    removeAssetsDto.isSmartAlbum = albumType == PhotoAlbumType::SMART;
    removeAssetsDto.assetsArray = reqBody.assetsArray;
    AlbumPhotoQueryRespBody respBody;

    ret = MediaAlbumsService::GetInstance().AlbumRemoveAssets(removeAssetsDto, respBody);
    IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
    return;
}

void MediaAlbumsControllerService::AlbumRecoverAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RecoverAssets");
    AlbumRecoverAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AddAssets Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    if (!PhotoAlbum::IsTrashAlbum(albumType, albumSubtype)) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    if (reqBody.uris.empty()) {
        MEDIA_ERR_LOG("params is invalid");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    AlbumRecoverAssetsDto recoverAssetsDto;
    recoverAssetsDto.uris = reqBody.uris;
    ret = MediaAlbumsService::GetInstance().AlbumRecoverAssets(recoverAssetsDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}

void MediaAlbumsControllerService::QueryAlbums(MessageParcel &data, MessageParcel &reply)
{
    QueryAlbumsReqBody reqBody;
    QueryAlbumsRspBody rspBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CreateAssetForApp Read Request Error");
        return;
    }

    QueryAlbumsDto dto;
    dto.albumType = reqBody.albumType;
    dto.albumSubType = reqBody.albumSubType;
    dto.columns = reqBody.columns;
    dto.predicates = reqBody.predicates;
    ret = MediaAlbumsService::GetInstance().QueryAlbums(dto);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("QueryAlbums failed, ret:%{public}d", ret);
        return;
    }

    rspBody.resultSet = dto.resultSet;
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody);
}

void MediaAlbumsControllerService::QueryHiddenAlbums(MessageParcel &data, MessageParcel &reply)
{
    QueryAlbumsReqBody reqBody;
    QueryAlbumsRspBody rspBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CreateAssetForApp Read Request Error");
        return;
    }

    QueryAlbumsDto dto;
    dto.columns = reqBody.columns;
    dto.predicates = reqBody.predicates;
    dto.hiddenAlbumFetchMode = reqBody.hiddenAlbumFetchMode;
    ret = MediaAlbumsService::GetInstance().QueryHiddenAlbums(dto);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("QueryHiddenAlbums failed, ret:%{public}d", ret);
        return;
    }

    rspBody.resultSet = dto.resultSet;
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody);
}

void MediaAlbumsControllerService::GetAlbumsByIds(MessageParcel &data, MessageParcel &reply)
{
    GetAlbumsByIdsReqBody reqBody;
    GetAlbumsByIdsRspBody rspBody;
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    std::vector<std::string> columns = reqBody.columns;
    MediaLibraryRdbUtils::AddVirtualColumnsOfDateType(columns);

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetAlbumsByIds Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    NativeRdb::RdbPredicates rdbPredicates =
        RdbDataShareAdapter::RdbUtils::ToPredicates(reqBody.predicates, PhotoAlbumColumns::TABLE);
    if (rdbPredicates.GetOrder().empty()) {
        rdbPredicates.OrderByAsc(PhotoAlbumColumns::ALBUM_ORDER);
    }
    resultSet = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
    if (resultSet != nullptr) {
        auto bridge = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(resultSet);
        rspBody.resultSet = make_shared<DataShare::DataShareResultSet>(bridge);
    }

    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAlbumsControllerService::GetOrderPosition(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter GetOrderPosition");
    GetOrderPositionReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetOrderPosition Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    if (!PhotoAlbum::IsAnalysisAlbum(albumType, albumSubtype)) {
        MEDIA_ERR_LOG("Only analysis album can get asset order positions");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    if (reqBody.assetIdArray.size() <= 0) {
        MEDIA_ERR_LOG("needs at least one asset id");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }
    std::set<std::string> idSet(reqBody.assetIdArray.begin(), reqBody.assetIdArray.end());
    if (reqBody.assetIdArray.size() != idSet.size()) {
        MEDIA_ERR_LOG("has same assets");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    GetOrderPositionRespBody respBody;
    GetOrderPositionDto getOrderPositionDto;
    getOrderPositionDto.albumId = reqBody.albumId;
    getOrderPositionDto.assetIdArray = reqBody.assetIdArray;

    ret = MediaAlbumsService::GetInstance().GetOrderPosition(getOrderPositionDto, respBody);
    IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
    return;
}

void MediaAlbumsControllerService::GetFaceId(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter GetFaceId");
    GetFaceIdReqBody reqBody;
    GetFaceIdRespBody respBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetFaceId Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.albumSubType != PhotoAlbumSubType::PORTRAIT && reqBody.albumSubType != PhotoAlbumSubType::GROUP_PHOTO) {
        MEDIA_WARN_LOG("albumSubType: %{public}d, not support getFaceId", reqBody.albumSubType);
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    string groupTag;
    ret = MediaAlbumsService::GetInstance().GetFaceId(reqBody.albumId, groupTag);
    respBody.groupTag = groupTag;
    IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

void MediaAlbumsControllerService::GetPhotoIndex(MessageParcel &data, MessageParcel &reply)
{
    GetPhotoIndexReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetPhotoIndex Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    QueryResultRspBody rspBody;
    ret = MediaAlbumsService::GetInstance().GetPhotoIndex(reqBody, rspBody);
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAlbumsControllerService::GetAnalysisProcess(MessageParcel &data, MessageParcel &reply)
{
    GetAnalysisProcessReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetAnalysisProcess Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    QueryResultRspBody rspBody;
    ret = MediaAlbumsService::GetInstance().GetAnalysisProcess(reqBody, rspBody);
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAlbumsControllerService::GetHighlightAlbumInfo(MessageParcel &data, MessageParcel &reply)
{
    GetHighlightAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetHighlightAlbumInfo Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    QueryResultRspBody rspBody;
    ret = MediaAlbumsService::GetInstance().GetHighlightAlbumInfo(reqBody, rspBody);
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAlbumsControllerService::AlbumGetAssets(
    MessageParcel &data, MessageParcel &reply, OHOS::Media::IPC::IPCContext &context)
{
    MEDIA_INFO_LOG("enter");
    AlbumGetAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    ret = ParameterUtils::CheckWhereClause(reqBody.predicates.GetWhereClause());
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CheckWhereClause fialed");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    AlbumGetAssetsDto dto = AlbumGetAssetsDto::Create(reqBody);
    if (context.GetByPassCode() == E_PERMISSION_DB_BYPASS) {
        string clientAppId = GetClientAppId();
        if (clientAppId.empty()) {
            MEDIA_ERR_LOG("clientAppId is empty");
            IPC::UserDefineIPC().WriteResponseBody(reply, Media::E_PERMISSION_DENIED);
            return;
        }
        dto.predicates.And()->EqualTo("owner_appid", clientAppId);
    }
    MediaLibraryRdbUtils::AddVirtualColumnsOfDateType(dto.columns);
    auto resultSet = MediaAlbumsService::GetInstance().AlbumGetAssets(dto);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_FAIL);
        return;
    }
    AlbumGetAssetsRespBody respBody;
    respBody.resultSet = resultSet;
    IPC::UserDefineIPC().WriteResponseBody(reply, respBody);
}

void MediaAlbumsControllerService::GetPhotoAlbumObject(MessageParcel &data, MessageParcel &reply)
{
    GetPhotoAlbumObjectReqBody reqBody;
    GetPhotoAlbumObjectRsqBody rsqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetPhotoAlbumObject Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    std::vector<std::string> columns = reqBody.columns;
    std::shared_ptr<NativeRdb::ResultSet> resultSet;

    NativeRdb::RdbPredicates rdbPredicates =
        RdbDataShareAdapter::RdbUtils::ToPredicates(reqBody.predicates, PhotoAlbumColumns::TABLE);
    resultSet = MediaLibraryRdbStore::QueryWithFilter(rdbPredicates, columns);
    if (resultSet != nullptr) {
        auto bridge = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(resultSet);
        rsqBody.resultSet = make_shared<DataShare::DataShareResultSet>(bridge);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, rsqBody, ret);
    return;
}

void MediaAlbumsControllerService::UpdatePhotoAlbumOrder(MessageParcel &data, MessageParcel &reply)
{
    SetPhotoAlbumOrderReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("UpdatePhotoAlbumOrder Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    SetPhotoAlbumOrderDto setPhotoAlbumOrderDto;
    setPhotoAlbumOrderDto.albumOrderColumn = reqBody.albumOrderColumn;
    setPhotoAlbumOrderDto.orderSectionColumn = reqBody.orderSectionColumn;
    setPhotoAlbumOrderDto.orderTypeColumn = reqBody.orderTypeColumn;
    setPhotoAlbumOrderDto.orderStatusColumn = reqBody.orderStatusColumn;
    setPhotoAlbumOrderDto.albumIds = reqBody.albumIds;
    setPhotoAlbumOrderDto.albumOrders = reqBody.albumOrders;
    setPhotoAlbumOrderDto.orderSection = reqBody.orderSection;
    setPhotoAlbumOrderDto.orderType = reqBody.orderType;
    setPhotoAlbumOrderDto.orderStatus = reqBody.orderStatus;
    MEDIA_INFO_LOG("Update photo album order include: %{public}s", setPhotoAlbumOrderDto.ToString().c_str());

    ret = MediaAlbumsService::GetInstance().UpdatePhotoAlbumOrder(setPhotoAlbumOrderDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}
} // namespace OHOS::Media