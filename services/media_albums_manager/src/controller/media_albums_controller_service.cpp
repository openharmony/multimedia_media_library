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
#include "photo_album.h"
#include "set_highlight_user_action_data_dto.h"
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
#include "get_albums_by_ids_vo.h"
#include "get_photo_album_object_vo.h"
#include "set_photo_album_order_vo.h"
#include "set_photo_album_order_dto.h"
#include "change_request_move_assets_dto.h"
#include "change_request_add_assets_dto.h"
#include "change_request_recover_assets_dto.h"
#include "change_request_delete_assets_dto.h"
#include "change_request_dismiss_assets_dto.h"
#include "change_request_merge_album_dto.h"
#include "change_request_place_before_dto.h"
#include "change_request_remove_assets_dto.h"
#include "change_request_set_order_position_dto.h"

namespace OHOS::Media {
using namespace std;
using SpecialRequestHandle = int32_t (MediaAlbumsControllerService::*)(
    MessageParcel &, MessageParcel &, OHOS::Media::IPC::IPCContext &);

using RequestHandle = int32_t (MediaAlbumsControllerService::*)(MessageParcel &, MessageParcel &);

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

int32_t MediaAlbumsControllerService::OnRemoteRequest(
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

int32_t MediaAlbumsControllerService::DeleteHighlightAlbums(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DeleteHighlightAlbums");
    DeleteHighLightAlbumsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DeleteHighlightAlbums Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
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
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::DeletePhotoAlbums(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DeletePhotoAlbums");
    DeleteAlbumsReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DeletePhotoAlbums Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    if (reqBody.albumIds.empty()) {
        MEDIA_ERR_LOG("DeletePhotoAlbums albumIds is empty");
        return IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
    }
    ret = MediaAlbumsService::GetInstance().DeletePhotoAlbums(reqBody.albumIds);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::CreatePhotoAlbum(MessageParcel &data, MessageParcel &reply)
{
    CreateAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CreatePhotoAlbum Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ret = ParameterUtils::CheckCreatePhotoAlbum(reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CheckCreatePhotoAlbum ret:%{public}d", ret);
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ret = MediaAlbumsService::GetInstance().CreatePhotoAlbum(reqBody.albumName);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::SetSubtitle(MessageParcel &data, MessageParcel &reply)
{
    SetSubtitleReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SetSubtitle Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    bool cond = MediaFileUtils::CheckHighlightSubtitle(reqBody.subtitle) == E_OK &&
        PhotoAlbum::IsHighlightAlbum(GetPhotoAlbumType(reqBody.albumType),
        GetPhotoAlbumSubType(reqBody.albumSubType));
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }
    ret = MediaAlbumsService::GetInstance().SetSubtitle(reqBody.albumId, reqBody.subtitle);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::SetHighlightUserActionData(MessageParcel &data, MessageParcel &reply)
{
    SetHighlightUserActionDataReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SetHighlightUserActionData Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    if (HIGHLIGHT_USER_ACTION_MAP.find(reqBody.userActionType) == HIGHLIGHT_USER_ACTION_MAP.end()) {
        MEDIA_ERR_LOG("Invalid highlightUserActionType");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }
    string userActionColumn = HIGHLIGHT_USER_ACTION_MAP.at(reqBody.userActionType);
    if (!PhotoAlbum::IsHighlightAlbum(GetPhotoAlbumType(reqBody.albumType),
        GetPhotoAlbumSubType(reqBody.albumSubType))) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }
    SetHighlightUserActionDataDto dto;
    dto.albumId = reqBody.albumId;
    dto.userActionType = userActionColumn;
    dto.actionData = reqBody.actionData;
    ret = MediaAlbumsService::GetInstance().SetHighlightUserActionData(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::ChangeRequestSetAlbumName(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequestSetAlbumNameReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ChangeRequestSetAlbumName Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
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
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }
    ChangeRequestSetAlbumNameDto dto;
    dto.albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    dto.albumName = reqBody.albumName;
    dto.albumId = reqBody.albumId;
    ret = MediaAlbumsService::GetInstance().ChangeRequestSetAlbumName(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::ChangeRequestSetCoverUri(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequestSetCoverUriReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ChangeRequestSetCoverUri Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
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
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }
    ChangeRequestSetCoverUriDto dto;
    dto.albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    dto.coverUri = reqBody.coverUri;
    dto.albumId = reqBody.albumId;
    ret = MediaAlbumsService::GetInstance().ChangeRequestSetCoverUri(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::ChangeRequestSetIsMe(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequestSetIsMeReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ChangeRequestSetIsMe Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    int32_t albumId = atoi(reqBody.albumId.c_str());
    bool cond = PhotoAlbum::IsSmartPortraitPhotoAlbum(albumType, albumSubtype);
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    ret = MediaAlbumsService::GetInstance().ChangeRequestSetIsMe(albumId);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::ChangeRequestSetDisplayLevel(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequestSetDisplayLevelReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ChangeRequestSetIsMe Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    int32_t albumId = atoi(reqBody.albumId.c_str());
    bool cond = (PhotoAlbum::IsSmartPortraitPhotoAlbum(albumType, albumSubtype) ||
        PhotoAlbum::IsSmartGroupPhotoAlbum(albumType, albumSubtype)) &&
        MediaFileUtils::CheckDisplayLevel(reqBody.displayLevel) && albumId > 0;
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    ret = MediaAlbumsService::GetInstance().ChangeRequestSetDisplayLevel(reqBody.displayLevel, albumId);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::ChangeRequestDismiss(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequesDismissReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ChangeRequestDismiss Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    int32_t albumId = atoi(reqBody.albumId.c_str());
    bool cond = PhotoAlbum::IsSmartGroupPhotoAlbum(albumType, albumSubtype);
    if (!cond) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    ret = MediaAlbumsService::GetInstance().ChangeRequestDismiss(albumId);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::ChangeRequestResetCoverUri(MessageParcel &data, MessageParcel &reply)
{
    ChangeRequesDismissReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ChangeRequestResetCoverUri Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
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
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    ret = MediaAlbumsService::GetInstance().ChangeRequestResetCoverUri(albumId, albumSubtype);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::AddAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AddAssets");
    ChangeRequestAddAssetsReqBody reqBody;
    ChangeRequestAddAssetsRespBody respBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AddAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ChangeRequestAddAssetsDto dto;
    dto.FromVo(reqBody);

    ret = MediaAlbumsService::GetInstance().AddAssets(dto, respBody);
    return  IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::RemoveAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RemoveAssets");
    ChangeRequestRemoveAssetsReqBody reqBody;
    ChangeRequestRemoveAssetsRespBody respBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RemoveAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ChangeRequestRemoveAssetsDto dto;
    dto.FromVo(reqBody);
    ret = MediaAlbumsService::GetInstance().RemoveAssets(dto, respBody);
    return  IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::MoveAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter MoveAssets");
    ChangeRequestMoveAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("MoveAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    ChangeRequestMoveAssetsDto dto;
    dto.FromVo(reqBody);
    ret = MediaAlbumsService::GetInstance().MoveAssets(dto);
    ChangeRequestMoveAssetsRespBody respBody;
    respBody.albumCount = dto.albumCount;
    respBody.albumImageCount = dto.albumImageCount;
    respBody.albumVideoCount = dto.albumVideoCount;
    respBody.targetAlbumCount = dto.targetAlbumCount;
    respBody.targetAlbumImageCount = dto.targetAlbumImageCount;
    respBody.targetAlbumVideoCount = dto.targetAlbumVideoCount;
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::RecoverAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RecoverAssets");
    ChangeRequestRecoverAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RecoverAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ChangeRequestRecoverAssetsDto dto;
    dto.assets = reqBody.assets;
    ret = MediaAlbumsService::GetInstance().RecoverAssets(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::DeleteAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DeleteAssets");
    ChangeRequestDeleteAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DeleteAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ChangeRequestDeleteAssetsDto dto;
    dto.assets = reqBody.assets;
    ret = MediaAlbumsService::GetInstance().DeleteAssets(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::DismissAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DismissAssets");
    ChangeRequestDismissAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DismissAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ChangeRequestDismissAssetsDto dto;
    dto.FromVo(reqBody);
    ret = MediaAlbumsService::GetInstance().DismissAssets(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::MergeAlbum(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter MergeAlbum");
    ChangeRequestMergeAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("MergeAlbum Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ChangeRequestMergeAlbumDto dto;
    dto.FromVo(reqBody);
    ret = MediaAlbumsService::GetInstance().MergeAlbum(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::PlaceBefore(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter PlaceBefore");
    ChangeRequestPlaceBeforeReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("PlaceBefore Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ChangeRequestPlaceBeforeDto dto;
    dto.FromVo(reqBody);
    ret = MediaAlbumsService::GetInstance().PlaceBefore(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::SetOrderPosition(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter PlaceBefore");
    ChangeRequestSetOrderPositionReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("PlaceBefore Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ChangeRequestSetOrderPositionDto dto;
    dto.FromVo(reqBody);
    ret = MediaAlbumsService::GetInstance().SetOrderPosition(dto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::AlbumCommitModify(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CommitModify");
    AlbumCommitModifyReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CommitModify Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    if (reqBody.businessCode == static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_COMMIT_MODIFY)) {
        PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
        PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);

        bool cond = PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype) &&
            MediaFileUtils::CheckAlbumName(reqBody.albumName) == E_OK;
        if (!cond) {
            MEDIA_ERR_LOG("params is invalid");
            return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        }
    }

    if (reqBody.businessCode == static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SET_COVER_URI) &&
        reqBody.coverUri.empty()) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    AlbumCommitModifyDto commitModifyDto;
    commitModifyDto.albumName = reqBody.albumName;
    commitModifyDto.coverUri = reqBody.coverUri;
    commitModifyDto.albumId = reqBody.albumId;

    ret = MediaAlbumsService::GetInstance().AlbumCommitModify(commitModifyDto, reqBody.businessCode);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::AlbumAddAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AddAssets");
    AlbumAddAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AddAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    if (!PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype)) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    if (reqBody.assetsArray.empty()) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    AlbumPhotoQueryRespBody respBody;
    AlbumAddAssetsDto addAssetsDto;
    addAssetsDto.albumId = reqBody.albumId;
    addAssetsDto.isSmartAlbum = reqBody.albumType == PhotoAlbumType::SMART;
    addAssetsDto.assetsArray = reqBody.assetsArray;

    ret = MediaAlbumsService::GetInstance().AlbumAddAssets(addAssetsDto, respBody);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::AlbumRemoveAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RemoveAssets");
    AlbumRemoveAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AddAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    if (!PhotoAlbum::IsUserPhotoAlbum(albumType, albumSubtype)) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    if (reqBody.assetsArray.empty()) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    AlbumRemoveAssetsDto removeAssetsDto;
    removeAssetsDto.albumId = reqBody.albumId;
    removeAssetsDto.isSmartAlbum = albumType == PhotoAlbumType::SMART;
    removeAssetsDto.assetsArray = reqBody.assetsArray;
    AlbumPhotoQueryRespBody respBody;

    ret = MediaAlbumsService::GetInstance().AlbumRemoveAssets(removeAssetsDto, respBody);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::AlbumRecoverAssets(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RecoverAssets");
    AlbumRecoverAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AddAssets Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    if (!PhotoAlbum::IsTrashAlbum(albumType, albumSubtype)) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    if (reqBody.uris.empty()) {
        MEDIA_ERR_LOG("params is invalid");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    AlbumRecoverAssetsDto recoverAssetsDto;
    recoverAssetsDto.uris = reqBody.uris;
    ret = MediaAlbumsService::GetInstance().AlbumRecoverAssets(recoverAssetsDto);
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

int32_t MediaAlbumsControllerService::QueryAlbums(MessageParcel &data, MessageParcel &reply)
{
    QueryAlbumsReqBody reqBody;
    QueryAlbumsRespBody respBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CreateAssetForApp Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
    }

    QueryAlbumsDto dto;
    dto.albumType = reqBody.albumType;
    dto.albumSubType = reqBody.albumSubType;
    dto.columns = reqBody.columns;
    dto.predicates = reqBody.predicates;
    ret = MediaAlbumsService::GetInstance().QueryAlbums(dto);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("QueryAlbums failed, ret:%{public}d", ret);
        return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
    }

    respBody.resultSet = dto.resultSet;
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody);
}

int32_t MediaAlbumsControllerService::QueryHiddenAlbums(MessageParcel &data, MessageParcel &reply)
{
    QueryAlbumsReqBody reqBody;
    QueryAlbumsRespBody respBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CreateAssetForApp Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
    }

    QueryAlbumsDto dto;
    dto.columns = reqBody.columns;
    dto.predicates = reqBody.predicates;
    dto.hiddenAlbumFetchMode = reqBody.hiddenAlbumFetchMode;
    ret = MediaAlbumsService::GetInstance().QueryHiddenAlbums(dto);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("QueryHiddenAlbums failed, ret:%{public}d", ret);
        return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
    }

    respBody.resultSet = dto.resultSet;
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody);
}

int32_t MediaAlbumsControllerService::GetAlbumsByIds(MessageParcel &data, MessageParcel &reply)
{
    GetAlbumsByIdsReqBody reqBody;
    GetAlbumsByIdsRespBody respBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetAlbumsByIds Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    GetAlbumsByIdsDto dto;
    dto.FromVo(reqBody);
    ret = MediaAlbumsService::GetInstance().GetAlbumsByIds(dto, respBody);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::GetOrderPosition(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter GetOrderPosition");
    GetOrderPositionReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetOrderPosition Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    PhotoAlbumType albumType = GetPhotoAlbumType(reqBody.albumType);
    PhotoAlbumSubType albumSubtype = GetPhotoAlbumSubType(reqBody.albumSubType);
    if (!PhotoAlbum::IsAnalysisAlbum(albumType, albumSubtype)) {
        MEDIA_ERR_LOG("Only analysis album can get asset order positions");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    if (reqBody.assetIdArray.size() <= 0) {
        MEDIA_ERR_LOG("needs at least one asset id");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }
    std::set<std::string> idSet(reqBody.assetIdArray.begin(), reqBody.assetIdArray.end());
    if (reqBody.assetIdArray.size() != idSet.size()) {
        MEDIA_ERR_LOG("has same assets");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    GetOrderPositionRespBody respBody;
    GetOrderPositionDto getOrderPositionDto;
    getOrderPositionDto.albumId = reqBody.albumId;
    getOrderPositionDto.assetIdArray = reqBody.assetIdArray;

    ret = MediaAlbumsService::GetInstance().GetOrderPosition(getOrderPositionDto, respBody);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::GetFaceId(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter GetFaceId");
    GetFaceIdReqBody reqBody;
    GetFaceIdRespBody respBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetFaceId Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    if (reqBody.albumSubType != PhotoAlbumSubType::PORTRAIT && reqBody.albumSubType != PhotoAlbumSubType::GROUP_PHOTO) {
        MEDIA_WARN_LOG("albumSubType: %{public}d, not support getFaceId", reqBody.albumSubType);
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
    }

    string groupTag;
    ret = MediaAlbumsService::GetInstance().GetFaceId(reqBody.albumId, groupTag);
    respBody.groupTag = groupTag;
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::GetPhotoIndex(MessageParcel &data, MessageParcel &reply)
{
    GetPhotoIndexReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetPhotoIndex Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    QueryResultRespBody respBody;
    ret = MediaAlbumsService::GetInstance().GetPhotoIndex(reqBody, respBody);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::GetAnalysisProcess(MessageParcel &data, MessageParcel &reply)
{
    GetAnalysisProcessReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetAnalysisProcess Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    QueryResultRespBody respBody;
    ret = MediaAlbumsService::GetInstance().GetAnalysisProcess(reqBody, respBody);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::GetHighlightAlbumInfo(MessageParcel &data, MessageParcel &reply)
{
    GetHighlightAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetHighlightAlbumInfo Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    QueryResultRespBody respBody;
    ret = MediaAlbumsService::GetInstance().GetHighlightAlbumInfo(reqBody, respBody);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::AlbumGetAssets(
    MessageParcel &data, MessageParcel &reply, OHOS::Media::IPC::IPCContext &context)
{
    MEDIA_INFO_LOG("enter");
    AlbumGetAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    ret = ParameterUtils::CheckWhereClause(reqBody.predicates.GetWhereClause());
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CheckWhereClause fialed");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    AlbumGetAssetsDto dto = AlbumGetAssetsDto::Create(reqBody);
    if (context.GetByPassCode() == E_PERMISSION_DB_BYPASS) {
        string clientAppId = GetClientAppId();
        if (clientAppId.empty()) {
            MEDIA_ERR_LOG("clientAppId is empty");
            return IPC::UserDefineIPC().WriteResponseBody(reply, Media::E_PERMISSION_DENIED);
        }
        dto.predicates.And()->EqualTo("owner_appid", clientAppId);
    }

    auto resultSet = MediaAlbumsService::GetInstance().AlbumGetAssets(dto);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is null");
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_FAIL);
    }
    AlbumGetAssetsRespBody respBody;
    respBody.resultSet = resultSet;
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody);
}

int32_t MediaAlbumsControllerService::GetPhotoAlbumObject(MessageParcel &data, MessageParcel &reply)
{
    GetPhotoAlbumObjectReqBody reqBody;
    GetPhotoAlbumObjectRespBody respBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetPhotoAlbumObject Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }

    GetPhotoAlbumObjectDto dto;
    dto.FromVo(reqBody);
    ret = MediaAlbumsService::GetInstance().GetPhotoAlbumObject(dto, respBody);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

int32_t MediaAlbumsControllerService::UpdatePhotoAlbumOrder(MessageParcel &data, MessageParcel &reply)
{
    SetPhotoAlbumOrderReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("UpdatePhotoAlbumOrder Read Request Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
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
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}
} // namespace OHOS::Media