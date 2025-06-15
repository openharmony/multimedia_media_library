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
#define MLOG_TAG "Media_Client"

#include "cloud_media_album_handler.h"

#include <string>

#include "media_log.h"
#include "user_define_ipc_client.h"
#include "media_req_vo.h"
#include "media_resp_vo.h"
#include "cloud_media_operation_code.h"
#include "medialibrary_errno.h"
#include "cloud_mdkrecord_photo_album_vo.h"
#include "on_create_records_album_vo.h"
#include "on_fetch_records_album_vo.h"
#include "on_delete_records_album_vo.h"
#include "on_delete_albums_vo.h"
#include "on_mdirty_records_album_vo.h"
#include "mdk_record_album_data.h"
#include "cloud_album_data_convert.h"
#include "get_check_records_album_vo.h"
#include "failed_size_resp_vo.h"

namespace OHOS::Media::CloudSync {
void CloudMediaAlbumHandler::SetTraceId(const std::string &traceId)
{
    this->traceId_ = traceId;
}

std::string CloudMediaAlbumHandler::GetTraceId() const
{
    return this->traceId_;
}

static void InitAlbumReqData(MDKRecordAlbumData &albumData, OnFetchRecordsAlbumReqBody::AlbumReqData &data)
{
    auto lpathOpt = albumData.GetlPath();
    if (lpathOpt.has_value()) {
        data.localPath = lpathOpt.value();
    }
    auto albumTypeOpt = albumData.GetAlbumType();
    if (albumTypeOpt.has_value()) {
        data.albumType = albumTypeOpt.value();
    } else {
        data.albumType = PhotoAlbumType::INVALID;
    }
    auto albumSubTypeOpt = albumData.GetAlbumSubType();
    if (albumSubTypeOpt.has_value()) {
        data.albumSubType = albumSubTypeOpt.value();
    }
    auto albumDateAddedOpt = albumData.GetDateAdded();
    if (albumDateAddedOpt.has_value()) {
        data.albumDateAdded = albumDateAddedOpt.value();
    }
    auto albumDateModifiedOpt = albumData.GetDateModified();
    if (albumDateModifiedOpt.has_value()) {
        data.albumDateModified = albumDateModifiedOpt.value();
    }
    auto albumNameOpt = albumData.GetAlbumName();
    if (albumNameOpt.has_value()) {
        data.albumName = albumNameOpt.value();
    }
    auto albumBundleNameOpt = albumData.GetBundleName();
    if (albumBundleNameOpt.has_value()) {
        data.albumBundleName = albumBundleNameOpt.value();
    }
    std::optional<std::string> cloudIdOpt = albumData.GetCloudId();
    if (cloudIdOpt.has_value()) {
        data.cloudId = cloudIdOpt.value();
    }
}

/**
 * stats: 引用入参，按照以下顺序进行返回 [新增，合一，元数据修改，文件修改，删除]:
 * stats: [100, 30, 50, 10, 10]
 */
int32_t CloudMediaAlbumHandler::OnFetchRecords(const std::vector<MDKRecord> &records,
    std::vector<CloudMetaData> &newData, std::vector<CloudMetaData> &fdirtyData,
    std::vector<std::string> &failedRecords, std::vector<int32_t> &stats)
{
    if (records.empty()) {
        MEDIA_ERR_LOG("OnFetchRecords param error");
        return E_ERR;
    }
    OnFetchRecordsAlbumReqBody req;
    OnFetchRecordsAlbumRespBody resp;
    MEDIA_INFO_LOG("OnFetchRecords %{public}zu records", records.size());
    Json::FastWriter writer;
    for (auto record : records) {
        std::string json = writer.write(record.ToJsonValue());
        auto cloudId = record.GetRecordId();
        OnFetchRecordsAlbumReqBody::AlbumReqData data;
        data.cloudId = cloudId;
        MDKRecordAlbumData albumData = MDKRecordAlbumData(record);
        InitAlbumReqData(albumData, data);
        data.albumDateCreated = record.GetCreateTime();
        data.isDelete = record.GetIsDelete();
        req.albums.emplace_back(data);
        MEDIA_INFO_LOG("OnFetchRecords AlbumReqData:%{public}s", data.ToString().c_str());
        MEDIA_INFO_LOG("OnFetchRecords Record:%{public}s", json.c_str());
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_FETCH_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode, req, resp);
    stats = resp.stats;
    failedRecords = resp.failedRecords;
    return ret;
}

int32_t CloudMediaAlbumHandler::OnDentryFileInsert(
    std::vector<MDKRecord> &records, std::vector<std::string> &failedRecords)
{
    MEDIA_INFO_LOG("OnDentryFileInsert, records size: %{public}zu", records.size());
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_DENTRY_FILE_INSERT);
    return IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode);
}

// album does not handle this operation <GetRetryRecords>.
int32_t CloudMediaAlbumHandler::GetRetryRecords(std::vector<std::string> &records)
{
    MEDIA_INFO_LOG("OnDentryFileInsert, records size: %{public}zu", records.size());
    return E_OK;
}

// album does not handle this operation <GetCheckRecords>.
int32_t CloudMediaAlbumHandler::GetCheckRecords(
    const std::vector<std::string> &cloudIds, std::unordered_map<std::string, CloudCheckData> &checkRecords)
{
    MEDIA_INFO_LOG("album does not handle this operation <GetCheckRecords>.");
    return E_OK;
}

int32_t CloudMediaAlbumHandler::GetCreatedRecords(std::vector<MDKRecord> &records, int32_t size)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumHandler::GetCreatedRecords");
    CloudMdkRecordPhotoAlbumReqBody reqBody;
    reqBody.size = size;
    CloudMdkRecordPhotoAlbumRespBody respBody;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_GET_CREATED_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode, reqBody, respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetCreatedRecords fail to call service function");
        return E_ERR;
    }
    std::vector<CloudMdkRecordPhotoAlbumVo> createdRecord = respBody.GetPhotoAlbumRecords();
    CloudAlbumDataConvert dataConvertor{CloudAlbumOperationType::PHOTO_ALBUM_CREATE};
    std::map<std::string, MDKRecordField> data;
    Json::FastWriter writer;
    for (auto it = createdRecord.begin(); it != createdRecord.end(); ++it) {
        std::shared_ptr<MDKRecord> dkRecord = dataConvertor.ConvertToMdkRecord(*it);
        if (dkRecord != nullptr) {
            dkRecord->GetRecordData(data);
            data["albumId"] = MDKRecordField(dkRecord->GetRecordId());
            dkRecord->SetRecordData(data);
            Json::Value json = dkRecord->ToJsonValue();
            std::string jsonStr = writer.write(json);
            MEDIA_INFO_LOG("GetCreatedRecords JSON: %{public}s", jsonStr.c_str());
            records.push_back(*dkRecord);
        } else {
            MEDIA_ERR_LOG("CloudMediaAlbumHandler::GetCreatedRecords ConvertToMdkRecord Error");
        }
        dkRecord = nullptr;
    }
    return E_OK;
}

int32_t CloudMediaAlbumHandler::GetMetaModifiedRecords(std::vector<MDKRecord> &records, int32_t size)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumHandler::GetMetaModifiedRecords");
    CloudMdkRecordPhotoAlbumReqBody reqBody;
    reqBody.size = size;
    CloudMdkRecordPhotoAlbumRespBody respBody;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_GET_META_MODIFIED_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode, reqBody, respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetMetaModifiedRecords fail to call service function");
        return E_ERR;
    }
    std::vector<CloudMdkRecordPhotoAlbumVo> createdRecord = respBody.GetPhotoAlbumRecords();
    MEDIA_INFO_LOG("Enter CloudMediaAlbumHandler::GetMetaModifiedRecords size: %{public}zu", createdRecord.size());
    CloudAlbumDataConvert dataConvertor{CloudAlbumOperationType::PHOTO_ALBUM_METADATA_MODIF};
    Json::FastWriter writer;
    for (auto it = createdRecord.begin(); it != createdRecord.end(); ++it) {
        std::shared_ptr<MDKRecord> dkRecord = dataConvertor.ConvertToMdkRecord(*it);
        if (dkRecord != nullptr) {
            Json::Value json = dkRecord->ToJsonValue();
            std::string jsonStr = writer.write(json);
            MEDIA_INFO_LOG("GetMetaModifiedRecords JSON: %{public}s", jsonStr.c_str());
            records.push_back(*dkRecord);
            dkRecord = nullptr;
        }
    }
    return E_OK;
}
// album does not handle this operation <GetFileModifiedRecords>.
int32_t CloudMediaAlbumHandler::GetFileModifiedRecords(std::vector<MDKRecord> &records, int32_t size)
{
    return E_OK;
}

int32_t CloudMediaAlbumHandler::GetDeletedRecords(std::vector<MDKRecord> &records, int32_t size)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumHandler::GetDeletedRecords %{public}d", size);
    CloudMdkRecordPhotoAlbumReqBody reqBody;
    reqBody.size = size;
    CloudMdkRecordPhotoAlbumRespBody respBody;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_GET_DELETED_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode, reqBody, respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetDeletedRecords fail to call service function");
        return E_ERR;
    }
    std::vector<CloudMdkRecordPhotoAlbumVo> createdRecord = respBody.GetPhotoAlbumRecords();
    CloudAlbumDataConvert dataConvertor{CloudAlbumOperationType::PHOTO_ALBUM_DELETE};
    Json::FastWriter writer;
    for (auto it = createdRecord.begin(); it != createdRecord.end(); ++it) {
        std::shared_ptr<MDKRecord> dkRecord = dataConvertor.ConvertToMdkRecord(*it);
        if (dkRecord != nullptr) {
            Json::Value json = dkRecord->ToJsonValue();
            std::string jsonStr = writer.write(json);
            MEDIA_INFO_LOG("GetDeletedRecords JSON: %{public}s", jsonStr.c_str());
            records.push_back(*dkRecord);
            dkRecord = nullptr;
        }
    }
    return E_OK;
}
// album does not handle this operation <GetRetryRecords>.
int32_t CloudMediaAlbumHandler::GetCopyRecords(std::vector<MDKRecord> &records, int32_t size)
{
    return E_OK;
}

int32_t CloudMediaAlbumHandler::OnCreateRecords(
    const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumHandler::OnCreateRecords %{public}zu", map.size());
    if (map.empty()) {
        return E_OK;
    }
    OnCreateRecordsAlbumReqBody reqBody;
    for (auto &entry : map) {
        const MDKRecordOperResult &result = entry.second;
        if (entry.first.empty()) {
            MEDIA_INFO_LOG("OnCreateRecords is failed");
            continue;
        }
        MDKRecordAlbumData data(result.GetDKRecord());
        std::string newCloudId = data.GetCloudId().value_or("");
        reqBody.AddAlbumData(entry.first, newCloudId, result.IsSuccess());
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_CREATE_RECORDS);
    FailedSizeResp resp;
    int32_t ret = IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode, reqBody, resp);
    failSize = resp.failedSize;
    return ret;
}

int32_t CloudMediaAlbumHandler::OnMdirtyRecords(
    const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumHandler::OnMdirtyRecords %{public}zu", map.size());
    OnMdirtyRecordsAlbumReqBody reqBody;
    OnMdirtyRecordsAlbumRespBody respBody;
    for (auto &entry : map) {
        const MDKRecordOperResult &result = entry.second;
        OnMdirtyAlbumRecord record;
        record.cloudId = entry.first;
        record.isSuccess = result.IsSuccess();
        reqBody.AddMdirtyRecord(record);
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_MDIRTY_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode, reqBody, respBody);
    failSize = respBody.failSize;
    return ret;
}

int32_t CloudMediaAlbumHandler::OnFdirtyRecords(
    const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("CloudMediaAlbumHandler::OnFdirtyRecords");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_FDIRTY_RECORDS);
    return IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaAlbumHandler::OnDeleteRecords(
    const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("enter CloudMediaAlbumHandler::OnDeleteRecords");
    if (map.empty()) {
        return E_OK;
    }
    OnDeleteRecordsAlbumReqBody reqBody;
    OnDeleteRecordsAlbumRespBody respBody;
    for (auto &entry : map) {
        const MDKRecordOperResult &result = entry.second;
        OnDeleteAlbumData album;
        album.cloudId = entry.first;
        album.isSuccess = result.IsSuccess();
        reqBody.AddSuccessResult(album);
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_DELETE_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode, reqBody, respBody);
    failSize = respBody.failSize;
    return ret;
}

int32_t CloudMediaAlbumHandler::OnCopyRecords(const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("OnCopyRecords, map size: %{public}zu", map.size());
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_COPY_RECORDS);
    return IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaAlbumHandler::OnStartSync()
{
    MEDIA_INFO_LOG("OnStartSync enter");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_START_SYNC);
    return IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaAlbumHandler::OnCompleteSync()
{
    MEDIA_INFO_LOG("OnCompleteSync enter");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_COMPLETE_SYNC);
    return IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaAlbumHandler::OnCompletePull()
{
    MEDIA_INFO_LOG("OnCompletePull enter");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_COMPLETE_PULL);
    return IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaAlbumHandler::OnCompletePush()
{
    MEDIA_INFO_LOG("OnCompletePush enter");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_COMPLETE_PUSH);
    return IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaAlbumHandler::OnCompleteCheck()
{
    MEDIA_INFO_LOG("CloudMediaDataClient::OnCompleteCheck begin");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaAlbumOperationCode::CMD_ON_COMPLETE_CHECK);
    return IPC::UserDefineIPCClient().SetTraceId(this->traceId_).Post(operationCode);
}
}  // namespace OHOS::Media::CloudSync