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
};

bool MediaAlbumsControllerService::Accept(uint32_t code)
{
    return HANDLERS.find(code) != HANDLERS.end();
}

void MediaAlbumsControllerService::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    auto it = HANDLERS.find(code);
    if (it == HANDLERS.end()) {
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_IPC_SEVICE_NOT_FOUND);
    }
    return (this->*(it->second))(data, reply);
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
        MEDIA_ERR_LOG("reqBody:%{public}s", reqBody.ToString().c_str());
        return;
    }

    ret = MediaAlbumsService::GetInstance().CreatePhotoAlbum(reqBody.albumName);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}
} // namespace OHOS::Media