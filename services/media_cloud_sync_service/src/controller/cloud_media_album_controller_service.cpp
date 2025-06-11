/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Cloud_Controller"

#include "cloud_media_album_controller_service.h"

#include "media_log.h"
#include "media_column.h"
#include "cloud_media_data_controller_processor.h"
#include "media_req_vo.h"
#include "media_resp_vo.h"
#include "cloud_media_data_service.h"
#include "medialibrary_errno.h"
#include "cloud_mdkrecord_photo_album_vo.h"
#include "on_create_records_album_vo.h"
#include "on_delete_records_album_vo.h"
#include "on_delete_albums_vo.h"
#include "on_mdirty_records_album_vo.h"
#include "get_check_records_album_vo.h"
#include "failed_size_resp_vo.h"

namespace OHOS::Media::CloudSync {
void CloudMediaAlbumControllerService::OnFetchRecords(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("OnFetchRecords enter");
    OnFetchRecordsAlbumReqBody req;
    OnFetchRecordsAlbumRespBody resp;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, req);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, IPC::UserDefineIPC().WriteResponseBody(reply, resp, ret),
        "OnFetchRecords Read Req Error");
    if (req.albums.empty()) {
        MEDIA_ERR_LOG("OnFetchRecords Param Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, resp, E_ERR);
    }
    MEDIA_INFO_LOG("OnFetchRecords Request: %{public}s", req.ToString().c_str());
    std::vector<PhotoAlbumDto> albumDtoList;
    for (const auto &album : req.albums) {
        PhotoAlbumDto albumDto;
        albumDto.albumId = album.albumId;
        albumDto.cloudId = album.cloudId;
        albumDto.lPath = album.localPath;
        albumDto.albumName = album.albumName;
        albumDto.bundleName = album.albumBundleName;
        albumDto.localLanguage = album.localLanguage;
        albumDto.priority = album.priority;
        albumDto.albumType = album.albumType;
        albumDto.albumSubType = album.albumSubType;
        albumDto.albumDateCreated = album.albumDateCreated;
        albumDto.albumDateAdded = album.albumDateAdded;
        albumDto.albumDateModified = album.albumDateModified;
        albumDto.isDelete = album.isDelete;
        albumDto.coverUriSource = album.coverUriSource;
        albumDtoList.emplace_back(albumDto);
        MEDIA_DEBUG_LOG("OnFetchRecords albumDto: %{public}s", albumDto.ToString().c_str());
        MEDIA_DEBUG_LOG("OnFetchRecords album: %{public}s", album.ToString().c_str());
    }
    ret = this->albumService_.OnFetchRecords(albumDtoList, resp);
    MEDIA_INFO_LOG("OnFetchRecords Resp: %{public}s", resp.ToString().c_str());
    return IPC::UserDefineIPC().WriteResponseBody(reply, resp, ret);
}

void CloudMediaAlbumControllerService::OnDentryFileInsert(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = this->albumService_.OnDentryFileInsert();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void CloudMediaAlbumControllerService::GetCheckRecords(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumControllerService::GetCheckRecords");
    GetCheckRecordsAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    GetCheckRecordsAlbumRespBody respBody;

    std::vector<PhotoAlbumPo> albumsPoList = this->albumService_.GetCheckRecords(reqBody.cloudIds);
    for (auto albumsPo : albumsPoList) {
        CheckDataAlbum checkData;
        checkData.cloudId = albumsPo.cloudId.value_or("");
        respBody.checkDataAlbumList[checkData.cloudId] = checkData;
    }
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody);
}

void CloudMediaAlbumControllerService::GetCreatedRecords(MessageParcel &data, MessageParcel &reply)
{
    CloudMdkRecordPhotoAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ReadRequestBody failed, ret: %{public}d", ret);
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    int32_t size = reqBody.size;
    if (size <= 0 || size > LIMIT_SIZE) {
        MEDIA_ERR_LOG("GetCreatedRecords param error, size: %{public}d", size);
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_MEDIA_CLOUD_ARGS_INVAILD);
    }
    MEDIA_INFO_LOG("enter CloudMediaAlbumControllerService::GetCreatedRecords size %{public}d", reqBody.size);
    std::vector<PhotoAlbumPo> photoAlbumPoList = this->albumService_.GetAlbumCreatedRecords(reqBody.size);
    std::vector<CloudMdkRecordPhotoAlbumVo> recordsList;
    for (const auto &record : photoAlbumPoList) {
        CloudMdkRecordPhotoAlbumVo recordVo = this->processor_.ConvertRecordPoToVo(record);
        recordsList.push_back(recordVo);
    }
    CloudMdkRecordPhotoAlbumRespBody respBody{recordsList};
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody);
}

void CloudMediaAlbumControllerService::GetMetaModifiedRecords(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumControllerService::GetMetaModifiedRecords");
    CloudMdkRecordPhotoAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    int32_t size = reqBody.size;
    if (size <= 0 || size > LIMIT_SIZE) {
        MEDIA_ERR_LOG("GetMetaModifiedRecords param error, size: %{public}d", size);
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_MEDIA_CLOUD_ARGS_INVAILD);
    }
    std::vector<PhotoAlbumPo> photoAlbumPoList = this->albumService_.GetAlbumMetaModifiedRecords(reqBody.size);
    std::vector<CloudMdkRecordPhotoAlbumVo> recordsList;
    for (const auto &record : photoAlbumPoList) {
        CloudMdkRecordPhotoAlbumVo recordVo = this->processor_.ConvertRecordPoToVo(record);
        recordsList.push_back(recordVo);
    }
    MEDIA_INFO_LOG("Enter CloudMediaAlbumControllerService::GetMetaModifiedRecords size: %{public}zu, %{public}zu",
        photoAlbumPoList.size(),
        recordsList.size());
    CloudMdkRecordPhotoAlbumRespBody respBody{recordsList};
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody);
}

void CloudMediaAlbumControllerService::GetDeletedRecords(MessageParcel &data, MessageParcel &reply)
{
    CloudMdkRecordPhotoAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("get album deleted records error %{public}d", ret);
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    int32_t size = reqBody.size;
    if (size <= 0 || size > LIMIT_SIZE) {
        MEDIA_ERR_LOG("GetDeletedRecords param error, size: %{public}d", size);
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_MEDIA_CLOUD_ARGS_INVAILD);
    }
    MEDIA_INFO_LOG("enter CloudMediaAlbumControllerService::GetDeletedRecords %{public}d", reqBody.size);
    std::vector<PhotoAlbumPo> photoAlbumPoList = this->albumService_.GetAlbumDeletedRecords(reqBody.size);
    std::vector<CloudMdkRecordPhotoAlbumVo> recordsList;
    for (const auto &record : photoAlbumPoList) {
        CloudMdkRecordPhotoAlbumVo recordVo = this->processor_.ConvertRecordPoToVo(record);
        recordsList.push_back(recordVo);
    }
    CloudMdkRecordPhotoAlbumRespBody respBody{recordsList};
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody);
}

void CloudMediaAlbumControllerService::OnCreateRecords(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumControllerService::OnCreateRecords");
    OnCreateRecordsAlbumReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("OnCreateRecords Read Req Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    MEDIA_INFO_LOG("OnCreateRecords %{public}zu", reqBody.albums.size());
    std::vector<PhotoAlbumDto> albumDtoList;
    for (const auto &album : reqBody.albums) {
        PhotoAlbumDto albumDto;
        albumDto.cloudId = album.cloudId;
        albumDto.newCloudId = album.newCloudId;
        albumDto.isSuccess = album.isSuccess;
        albumDtoList.emplace_back(albumDto);
        MEDIA_DEBUG_LOG("OnCreateRecords record:%{public}s", albumDto.ToString().c_str());
    }
    FailedSizeResp resp;
    ret = this->albumService_.OnCreateRecords(albumDtoList, resp.failedSize);
    return IPC::UserDefineIPC().WriteResponseBody(reply, resp, ret);
}

void CloudMediaAlbumControllerService::OnMdirtyRecords(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumControllerService::OnMdirtyRecords");
    OnMdirtyRecordsAlbumReqBody reqBody;
    OnMdirtyRecordsAlbumRespBody respBody;
    respBody.failSize = 0;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CloudMediaAlbumControllerService::OnMdirtyRecords Read Req Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    std::vector<OnMdirtyAlbumRecord> albumRecords = reqBody.GetMdirtyRecords();
    std::vector<PhotoAlbumDto> albumDtoList;
    for (const auto &album : albumRecords) {
        PhotoAlbumDto albumDto;
        albumDto.cloudId = album.cloudId;
        albumDto.isSuccess = album.isSuccess;
        albumDtoList.emplace_back(albumDto);
    }
    ret = this->albumService_.OnMdirtyRecords(albumDtoList, respBody.failSize);
    MEDIA_INFO_LOG("CloudMediaAlbumControllerService::OnMdirtyRecords end ret: %{public}d, failSize: %{public}d",
        ret,
        respBody.failSize);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

void CloudMediaAlbumControllerService::OnFdirtyRecords(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = this->albumService_.OnFdirtyRecords();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void CloudMediaAlbumControllerService::OnDeleteRecords(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumControllerService::OnDeleteRecords");
    OnDeleteRecordsAlbumReqBody reqBody;
    OnDeleteRecordsAlbumRespBody respBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CloudMediaAlbumControllerService::OnDeleteRecords Read Req Error");
        return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    }
    std::vector<PhotoAlbumDto> albumDtoList;
    for (const auto &album : reqBody.albums) {
        PhotoAlbumDto albumDto;
        albumDto.cloudId = album.cloudId;
        albumDto.isSuccess = album.isSuccess;
        albumDtoList.emplace_back(albumDto);
    }
    ret = this->albumService_.OnDeleteRecords(albumDtoList, respBody.failSize);
    MEDIA_INFO_LOG("CloudMediaAlbumControllerService::OnDeleteRecords ret: %{public}d, failSize: %{public}d",
        ret,
        respBody.failSize);
    return IPC::UserDefineIPC().WriteResponseBody(reply, respBody, ret);
}

void CloudMediaAlbumControllerService::OnCopyRecords(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = this->albumService_.OnCopyRecords();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void CloudMediaAlbumControllerService::OnStartSync(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = this->albumService_.OnStartSync();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void CloudMediaAlbumControllerService::OnCompleteSync(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = this->albumService_.OnCompleteSync();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void CloudMediaAlbumControllerService::OnCompletePull(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = this->albumService_.OnCompletePull();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void CloudMediaAlbumControllerService::OnCompletePush(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = this->albumService_.OnCompletePush();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void CloudMediaAlbumControllerService::OnCompleteCheck(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = this->albumService_.OnCompleteCheck();
    return IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}
}  // namespace OHOS::Media::CloudSync