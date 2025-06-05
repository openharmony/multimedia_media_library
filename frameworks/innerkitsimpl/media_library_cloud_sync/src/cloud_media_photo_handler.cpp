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

#include "cloud_media_photo_handler.h"

#include <string>

#include "cloud_file_data_convert.h"
#include "cloud_media_operation_code.h"
#include "cloud_mdkrecord_photos_vo.h"
#include "get_retey_records_vo.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_req_vo.h"
#include "media_resp_vo.h"
#include "mdk_record_photos_data.h"
#include "on_copy_records_photos_vo.h"
#include "on_create_records_photos_vo.h"
#include "on_delete_records_photos_vo.h"
#include "on_modify_records_photos_vo.h"
#include "on_dentry_file_vo.h"
#include "on_fetch_records_vo.h"
#include "on_fetch_photos_vo.h"
#include "user_define_ipc_client.h"
#include "failed_size_resp_vo.h"
#include "get_check_records_vo.h"

namespace OHOS::Media::CloudSync {
void CloudMediaPhotoHandler::SetUserId(const int32_t &userId)
{
    this->userId_ = userId;
}

void CloudMediaPhotoHandler::SetTraceId(const std::string &traceId)
{
    this->traceId_ = traceId;
}

std::string CloudMediaPhotoHandler::GetTraceId() const
{
    return this->traceId_;
}

/**
 * stats: 引用入参，按照以下顺序进行返回 [新增，合一，元数据修改，文件修改，删除]:
 * stats: [100, 30, 50, 10, 10]
 */
int32_t CloudMediaPhotoHandler::OnFetchRecords(const std::vector<MDKRecord> &records,
    std::vector<CloudMetaData> &newData, std::vector<CloudMetaData> &fdirtyData,
    std::vector<std::string> &failedRecords, std::vector<int32_t> &stats)
{
    MEDIA_INFO_LOG("enter CloudMediaPhotoHandler::OnFetchRecords");
    int32_t ret;
    OnFetchRecordsReqBody reqBody;
    OnFetchRecordsRespBody respBody;
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_DATA_MODIFY, userId_};
    Json::FastWriter writer;
    for (auto record : records) {
        std::string json = writer.write(record.ToJsonValue());
        MEDIA_INFO_LOG("OnFetchRecords record json: %{private}s", json.c_str());
        OnFetchPhotosVo onFetchPhotoVo;
        if (dataConvertor.ConverMDKRecordToOnFetchPhotosVo(record, onFetchPhotoVo) != E_OK) {
            MEDIA_ERR_LOG("OnFetchRecords ConverMDKRecordToOnFetchPhotosVo error, recordId: %{public}s",
                record.GetRecordId().c_str());
            continue;
        }
        MEDIA_INFO_LOG("OnFetchRecords OnFetchPhotoVo: %{public}s", onFetchPhotoVo.ToString().c_str());
        reqBody.AddOnFetchPhotoData(onFetchPhotoVo);
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_FETCH_RECORDS);
    ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        respBody);
    failedRecords = respBody.failedRecords;
    stats = respBody.stats;
    newData = this->processor_.GetCloudNewData(respBody.newDatas);
    MEDIA_INFO_LOG("OnFetchRecords NewDataBody: %{public}s", respBody.ToString().c_str());
    fdirtyData = this->processor_.GetCloudFdirtyData(respBody.fdirtyDatas);
    return ret;
}

int32_t CloudMediaPhotoHandler::OnDentryFileInsert(
    std::vector<MDKRecord> &records, std::vector<std::string> &failedRecords)
{
    MEDIA_INFO_LOG("OnDentryFileInsert enter");
    int32_t ret;
    OnDentryFileReqBody reqBody;
    OnDentryFileRespBody respBody;
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_DATA_MODIFY, userId_};
    Json::FastWriter writer;
    for (auto record : records) {
        std::string json = writer.write(record.ToJsonValue());
        MEDIA_INFO_LOG("OnDentryFileInsert Record: %{private}s", json.c_str());
        OnFetchPhotosVo onDentryRecord;
        if (dataConvertor.ConverMDKRecordToOnFetchPhotosVo(record, onDentryRecord) != E_OK) {
            MEDIA_ERR_LOG("OnDentryFileInsert ConverMDKRecordToOnFetchPhotosVo error");
            continue;
        }
        MEDIA_INFO_LOG("OnDentryFileInsert OnFetchPhotosVo: %{public}s", onDentryRecord.ToString().c_str());
        reqBody.AddOnDentryFileRecord(onDentryRecord);
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_DENTRY_FILE_INSERT);
    ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        respBody);
    failedRecords = respBody.failedRecords;
    MEDIA_INFO_LOG("OnDentryFileInsert end");
    return ret;
}

int32_t CloudMediaPhotoHandler::GetRetryRecords(std::vector<std::string> &records)
{
    MEDIA_INFO_LOG("enter CloudMediaPhotoHandler::GetRetryRecords");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_GET_RETRY_RECORDS);
    GetRetryRecordsRespBody respBody;
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Get(operationCode,
        respBody);
    records = respBody.cloudIds;
    return ret;
}

int32_t CloudMediaPhotoHandler::GetCheckRecords(
    const std::vector<std::string> &cloudIds, std::unordered_map<std::string, CloudCheckData> &checkRecords)
{
    MEDIA_INFO_LOG("enter CloudMediaPhotoHandler::GetCheckRecords %{public}zu", cloudIds.size());
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_GET_CHECK_RECORDS);
    GetCheckRecordsReqBody reqBody;
    reqBody.cloudIds = cloudIds;
    GetCheckRecordsRespBody respBody;
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Failed to GetCheckRecords");
        return ret;
    }
    MEDIA_INFO_LOG("GetCheckRecords GetCheckRecordsRespBody: %{public}s", respBody.ToString().c_str());
    checkRecords.clear();
    for (auto &[cloudId, info] : respBody.checkDataList) {
        CloudCheckData cloudCheckData;
        cloudCheckData.cloudId = cloudId;
        cloudCheckData.size = info.size;
        cloudCheckData.path = info.data;
        cloudCheckData.fileName = info.fileName;
        cloudCheckData.type = info.mediaType;
        cloudCheckData.version = info.cloudVersion;
        cloudCheckData.position = info.position;
        cloudCheckData.modifiedTime = info.dateModified;
        cloudCheckData.dirtyType = info.dirty;
        cloudCheckData.syncStatus = info.syncStatus;
        cloudCheckData.thmStatus = info.thmStatus;
        for (auto &[key, value] : info.attachment) {
            CloudFileData fileData;
            fileData.fileName = value.fileName;
            fileData.filePath = value.filePath;
            fileData.size = value.size;
            cloudCheckData.attachment[key] = fileData;
        }
        checkRecords[cloudId] = cloudCheckData;
        MEDIA_INFO_LOG("GetCheckRecords CloudCheckData: %{public}s", cloudCheckData.ToString().c_str());
    }
    return E_OK;
}

int32_t CloudMediaPhotoHandler::GetCreatedRecords(std::vector<MDKRecord> &records, int32_t size)
{
    MEDIA_INFO_LOG("CloudMediaPhotoHandler::GetCreatedRecords %{public}d", size);
    CloudMdkRecordPhotosReqBody reqBody;
    reqBody.size = size;
    CloudMdkRecordPhotosRespBody respBody;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_GET_CREATED_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetCreatedRecords fail to call service function");
        return ret;
    }
    std::vector<CloudMdkRecordPhotosVo> createdRecords = respBody.GetPhotosRecords();
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_CREATE, userId_};
    Json::FastWriter writer;
    for (auto &record : createdRecords) {
        MDKRecord dkRecord;
        ret = dataConvertor.ConvertToMdkRecord(record, dkRecord);
        if (ret == E_OK) {
            Json::Value json = dkRecord.ToJsonValue();
            std::string jsonStr = writer.write(json);
            MEDIA_INFO_LOG("GetCreatedRecords JSON: %{private}s", jsonStr.c_str());
            records.push_back(dkRecord);
        } else {
            MEDIA_ERR_LOG("GetCreatedRecords ReportFailure, ret: %{public}d, photosVo: %{public}s",
                ret,
                record.ToString().c_str());
            this->ReportFailure(
                ReportFailureReqBody()
                    .SetApiCode(static_cast<int32_t>(CloudMediaPhotoOperationCode::CMD_GET_CREATED_RECORDS))
                    .SetErrorCode(ret)
                    .SetFileId(record.fileId)
                    .SetCloudId(record.cloudId));
        }
    }
    return E_OK;
}

int32_t CloudMediaPhotoHandler::GetMetaModifiedRecords(std::vector<MDKRecord> &records, int32_t size)
{
    CloudMdkRecordPhotosReqBody reqBody;
    reqBody.size = size;
    CloudMdkRecordPhotosRespBody respBody;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_GET_META_MODIFIED_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CloudMediaPhotoHandler::GetMetaModifiedRecords Call IPC Error");
        return ret;
    }
    std::vector<CloudMdkRecordPhotosVo> metaModifiedRecord = respBody.GetPhotosRecords();
    MEDIA_INFO_LOG("Enter CloudMediaPhotoHandler::GetMetaModifiedRecords size: %{public}zu", metaModifiedRecord.size());
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_METADATA_MODIFY, userId_};
    Json::FastWriter writer;
    for (auto &record : metaModifiedRecord) {
        MDKRecord dkRecord;
        MEDIA_INFO_LOG("SetUpdateSourceAlbum CloudMdkRecordPhotosVo: %{public}s", record.ToString().c_str());
        ret = dataConvertor.ConvertToMdkRecord(record, dkRecord);
        MEDIA_INFO_LOG(
            "Enter CloudMediaPhotoHandler::GetMetaModifiedRecords ConvertToMdkRecord: %{public}s, ret: %{public}d",
            dkRecord.GetRecordId().c_str(),
            ret);
        if (ret == E_OK) {
            Json::Value json = dkRecord.ToJsonValue();
            std::string jsonStr = writer.write(json);
            MEDIA_INFO_LOG("GetMetaModifiedRecords JSON: %{private}s", jsonStr.c_str());
            records.push_back(dkRecord);
            if (!record.removeAlbumCloudId.empty()) {
                ret = dataConvertor.InsertAlbumIdChanges(dkRecord, records, record);
            }
        } else {
            MEDIA_ERR_LOG("GetMetaModifiedRecords ReportFailure, ret: %{public}d, photosVo: %{public}s",
                ret,
                record.ToString().c_str());
            this->ReportFailure(
                ReportFailureReqBody()
                    .SetApiCode(static_cast<int32_t>(CloudMediaPhotoOperationCode::CMD_GET_META_MODIFIED_RECORDS))
                    .SetErrorCode(ret)
                    .SetFileId(record.fileId)
                    .SetCloudId(record.cloudId));
        }
    }
    return E_OK;
}

int32_t CloudMediaPhotoHandler::GetFileModifiedRecords(std::vector<MDKRecord> &records, int32_t size)
{
    MEDIA_INFO_LOG("CloudMediaPhotoHandler::GetFileModifiedRecords");
    CloudMdkRecordPhotosReqBody reqBody;
    reqBody.size = size;
    CloudMdkRecordPhotosRespBody respBody;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_GET_FILE_MODIFIED_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetFileModifiedRecords fail to call service function");
        return ret;
    }
    std::vector<CloudMdkRecordPhotosVo> fileModifiedRecord = respBody.GetPhotosRecords();
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_DATA_MODIFY, userId_};
    Json::FastWriter writer;
    for (auto &record : fileModifiedRecord) {
        MDKRecord dkRecord;
        ret = dataConvertor.ConvertToMdkRecord(record, dkRecord);
        if (ret == E_OK) {
            records.push_back(dkRecord);
            Json::Value json = dkRecord.ToJsonValue();
            std::string jsonStr = writer.write(json);
            MEDIA_INFO_LOG("GetFileModifiedRecords JSON: %{private}s", jsonStr.c_str());
            if (!record.removeAlbumCloudId.empty()) {
                ret = dataConvertor.InsertAlbumIdChanges(dkRecord, records, record);
            }
        } else {
            MEDIA_ERR_LOG("GetFileModifiedRecords ReportFailure, ret: %{public}d, photosVo: %{public}s",
                ret,
                record.ToString().c_str());
            this->ReportFailure(
                ReportFailureReqBody()
                    .SetApiCode(static_cast<int32_t>(CloudMediaPhotoOperationCode::CMD_GET_FILE_MODIFIED_RECORDS))
                    .SetErrorCode(ret)
                    .SetFileId(record.fileId)
                    .SetCloudId(record.cloudId));
        }
    }
    return E_OK;
}

int32_t CloudMediaPhotoHandler::GetDeletedRecords(std::vector<MDKRecord> &records, int32_t size)
{
    MEDIA_INFO_LOG("CloudSync test info %{public}d", size);
    CloudMdkRecordPhotosReqBody reqBody;
    reqBody.size = size;
    CloudMdkRecordPhotosRespBody respBody;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_GET_DELETED_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetDeletedRecords fail to call service function");
        return ret;
    }
    std::vector<CloudMdkRecordPhotosVo> deletedRecord = respBody.GetPhotosRecords();
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_DELETE, userId_};
    Json::FastWriter writer;
    for (auto &record : deletedRecord) {
        MDKRecord dkRecord;
        ret = dataConvertor.ConvertToMdkRecord(record, dkRecord);
        if (ret == E_OK) {
            Json::Value json = dkRecord.ToJsonValue();
            std::string jsonStr = writer.write(json);
            MEDIA_INFO_LOG("GetDeletedRecords JSON: %{private}s", jsonStr.c_str());
            records.push_back(dkRecord);
        } else {
            MEDIA_ERR_LOG("GetDeletedRecords ReportFailure, ret: %{public}d, photosVo: %{public}s",
                ret,
                record.ToString().c_str());
            this->ReportFailure(
                ReportFailureReqBody()
                    .SetApiCode(static_cast<int32_t>(CloudMediaPhotoOperationCode::CMD_GET_DELETED_RECORDS))
                    .SetErrorCode(ret)
                    .SetFileId(record.fileId)
                    .SetCloudId(record.cloudId));
        }
    }
    return E_OK;
}

int32_t CloudMediaPhotoHandler::GetCopyRecords(std::vector<MDKRecord> &records, int32_t size)
{
    MEDIA_INFO_LOG("enter CloudMediaPhotoHandler::GetCopyRecords size:%{public}d", size);
    CloudMdkRecordPhotosReqBody reqBody;
    reqBody.size = size;
    CloudMdkRecordPhotosRespBody respBody;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_GET_COPY_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        respBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GetCopyRecords fail to call service function");
        return ret;
    }
    std::vector<CloudMdkRecordPhotosVo> copyRecord = respBody.GetPhotosRecords();
    MEDIA_INFO_LOG("CloudMediaPhotoHandler::GetCopyRecords result count: %{public}zu", copyRecord.size());
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_DATA_MODIFY, userId_};
    Json::FastWriter writer;
    for (auto &record : copyRecord) {
        MDKRecord dkRecord;
        ret = dataConvertor.ConvertToMdkRecord(record, dkRecord);
        if (ret == E_OK) {
            dkRecord.SetSrcRecordId(record.originalAssetCloudId);
            Json::Value json = dkRecord.ToJsonValue();
            std::string jsonStr = writer.write(json);
            MEDIA_INFO_LOG("GetCopyRecords JSON: %{private}s", jsonStr.c_str());
            records.push_back(dkRecord);
        } else {
            MEDIA_ERR_LOG(
                "GetCopyRecords ReportFailure, ret: %{public}d, photosVo: %{public}s", ret, record.ToString().c_str());
            this->ReportFailure(
                ReportFailureReqBody()
                    .SetApiCode(static_cast<int32_t>(CloudMediaPhotoOperationCode::CMD_GET_COPY_RECORDS))
                    .SetErrorCode(ret)
                    .SetFileId(record.fileId)
                    .SetCloudId(record.cloudId));
        }
    }
    return E_OK;
}

int32_t CloudMediaPhotoHandler::OnCreateRecords(
    const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("enter OnCreateRecords");
    if (map.empty()) {
        MEDIA_ERR_LOG("OnCreateRecords param error");
        return E_ERR;
    }
    OnCreateRecordsPhotosReqBody req;
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_CREATE, userId_};
    for (auto &entry : map) {
        OnCreateRecord record;
        if (dataConvertor.ConvertToOnCreateRecord(entry.first, entry.second, record) != E_OK) {
            MEDIA_ERR_LOG("OnCreateRecords ConvertToOnCreateRecord error");
            continue;
        }
        MEDIA_INFO_LOG("OnCreateRecords Record:%{public}s", record.ToString().c_str());
        req.records.emplace_back(record);
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_CREATE_RECORDS);
    FailedSizeResp resp;
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, req,
        resp);
    failSize = resp.failedSize;
    MEDIA_INFO_LOG("OnCreateRecords Resp:%{public}s", resp.ToString().c_str());
    return ret;
}

int32_t CloudMediaPhotoHandler::OnMdirtyRecords(
    const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("enter OnMdirtyRecords");
    if (map.empty()) {
        MEDIA_ERR_LOG("OnMdirtyRecords param error");
        return E_ERR;
    }
    OnModifyRecordsPhotosReqBody req;
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_DATA_MODIFY, userId_};
    for (auto &entry : map) {
        OnModifyRecord record;
        if (dataConvertor.BuildModifyRecord(entry.first, entry.second, record) != E_OK) {
            MEDIA_ERR_LOG("OnMdirtyRecords BuildModifyRecord error");
            continue;
        }
        MEDIA_INFO_LOG("enter OnMdirtyRecords Record:%{public}s", record.ToString().c_str());
        req.AddModifyRecord(record);
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_MDIRTY_RECORDS);
    FailedSizeResp resp;
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, req,
        resp);
    failSize = resp.failedSize;
    MEDIA_INFO_LOG("OnMdirtyRecords Resp:%{public}s", resp.ToString().c_str());
    return ret;
}

int32_t CloudMediaPhotoHandler::OnFdirtyRecords(
    const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("OnFdirtyRecords enter");
    OnFileDirtyRecordsReqBody req;
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_FDIRTY_RECORDS);
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_DATA_MODIFY, userId_};
    for (const auto &entry : map) {
        OnFileDirtyRecord record;
        if (dataConvertor.ConvertFdirtyRecord(entry.first, entry.second, record) != E_OK) {
            MEDIA_ERR_LOG("OnFdirtyRecords ConvertFdirtyRecord Error");
            continue;
        }
        MEDIA_INFO_LOG("OnFdirtyRecords Record: %{public}s", record.ToString().c_str());
        req.AddRecord(record);
    }
    FailedSizeResp resp;
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, req,
        resp);
    failSize = resp.failedSize;
    MEDIA_INFO_LOG("OnFdirtyRecords Resp:%{public}s", resp.ToString().c_str());
    return ret;
}

int32_t CloudMediaPhotoHandler::OnDeleteRecords(
    const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("CloudMediaPhotoHandler::OnDeleteRecords");
    if (map.empty()) {
        MEDIA_ERR_LOG("CloudMediaPhotoHandler::OnDeleteRecords param error");
        return E_OK;
    }
    OnDeleteRecordsPhotosReqBody reqBody;
    OnDeleteRecordsPhotosRespBody resp;
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_DATA_MODIFY, userId_};
    for (auto &entry : map) {
        const MDKRecordOperResult &result = entry.second;
        OnDeleteRecordsPhoto deleteRecord;
        deleteRecord.dkRecordId = entry.first;
        deleteRecord.cloudId = entry.first;
        deleteRecord.isSuccess = result.IsSuccess();
        reqBody.AddDeleteRecord(deleteRecord);
        MEDIA_INFO_LOG("CloudMediaPhotoHandler::OnDeleteRecords ID: %{public}s", deleteRecord.cloudId.c_str());
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_DELETE_RECORDS);
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody,
        resp);
    failSize = resp.failSize;
    return ret;
}

int32_t CloudMediaPhotoHandler::OnCopyRecords(const std::map<std::string, MDKRecordOperResult> &map, int32_t &failSize)
{
    MEDIA_INFO_LOG("OnCopyRecords enter");
    if (map.empty()) {
        MEDIA_ERR_LOG("OnCopyRecords param error");
        return E_ERR;
    }
    OnCopyRecordsPhotosReqBody req;
    CloudFileDataConvert dataConvertor{CloudOperationType::FILE_COPY, userId_};
    for (auto &entry : map) {
        OnCopyRecord copyRecord;
        if (dataConvertor.BuildCopyRecord(entry.first, entry.second, copyRecord) != E_OK) {
            MEDIA_ERR_LOG("OnCopyRecords BuildCopyRecord error");
            continue;
        }
        MEDIA_INFO_LOG("OnCopyRecords Record JSON:%{public}s", copyRecord.ToString().c_str());
        req.AddCopyRecord(copyRecord);
    }
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_COPY_RECORDS);
    FailedSizeResp resp;
    int32_t ret = IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, req,
        resp);
    failSize = resp.failedSize;
    MEDIA_INFO_LOG("OnCopyRecords Resp:%{public}s", resp.ToString().c_str());
    return ret;
}

int32_t CloudMediaPhotoHandler::OnStartSync()
{
    MEDIA_INFO_LOG("OnStartSync enter");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_START_SYNC);
    return IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaPhotoHandler::OnCompleteSync()
{
    MEDIA_INFO_LOG("OnCompleteSync enter");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_COMPLETE_SYNC);
    return IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaPhotoHandler::OnCompletePull()
{
    MEDIA_INFO_LOG("OnCompletePull enter");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_COMPLETE_PULL);
    return IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaPhotoHandler::OnCompletePush()
{
    MEDIA_INFO_LOG("OnCompletePush enter");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_COMPLETE_PUSH);
    return IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaPhotoHandler::OnCompleteCheck()
{
    MEDIA_INFO_LOG("OnCompleteCheck begin");
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_ON_COMPLETE_CHECK);
    return IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode);
}

int32_t CloudMediaPhotoHandler::ReportFailure(const ReportFailureReqBody &reqBody)
{
    uint32_t operationCode = static_cast<uint32_t>(CloudMediaPhotoOperationCode::CMD_REPORT_FAILURE);
    MEDIA_INFO_LOG("ReportFailure begin, reqBody: %{public}s", reqBody.ToString().c_str());
    return IPC::UserDefineIPCClient().SetUserId(userId_).SetTraceId(this->traceId_).Post(operationCode, reqBody);
}
}  // namespace OHOS::Media::CloudSync