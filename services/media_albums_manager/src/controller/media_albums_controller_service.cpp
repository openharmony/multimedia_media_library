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

namespace OHOS::Media {
using namespace std;
using RequestHandle = void (MediaAlbumsControllerService::*)(MessageParcel &, MessageParcel &);

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
};

bool MediaAlbumsControllerService::Accept(uint32_t code)
{
    return HANDLERS.find(code) != HANDLERS.end();
}

void MediaAlbumsControllerService::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, OHOS::Media::IPC::IPCContext &context)
{
    auto it = HANDLERS.find(code);
    if (it == HANDLERS.end()) {
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_IPC_SEVICE_NOT_FOUND);
    }
    return (this->*(it->second))(data, reply);
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
        MEDIA_ERR_LOG("StartDownloadCloudMedia Read Request Error");
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
} // namespace OHOS::Media