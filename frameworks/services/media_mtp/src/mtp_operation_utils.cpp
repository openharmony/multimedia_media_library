/*
* Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MtpOperationUtils"
#include "mtp_operation_utils.h"
#include <fstream>
#include <cstdint>
#include <cinttypes>
#include <iremote_object.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "application_context.h"
#include "ability_manager_client.h"
#ifdef HAS_BATTERY_MANAGER_PART
#include "battery_srv_client.h"
#endif
#include "directory_ex.h"
#include "iservice_registry.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_file_observer.h"
#include "mtp_manager.h"
#include "mtp_medialibrary_manager.h"
#include "mtp_packet_tools.h"
#include "mtp_operation_context.h"
#include "mtp_storage_manager.h"
#include "mtp_store_observer.h"
#include "payload_data.h"
#include "payload_data/resp_common_data.h"
#include "payload_data/close_session_data.h"
#include "payload_data/copy_object_data.h"
#include "payload_data/delete_object_data.h"
#include "payload_data/get_device_info_data.h"
#include "payload_data/get_device_prop_desc_data.h"
#include "payload_data/get_device_prop_value_data.h"
#include "payload_data/get_num_objects_data.h"
#include "payload_data/get_object_data.h"
#include "payload_data/get_object_handles_data.h"
#include "payload_data/get_object_info_data.h"
#include "payload_data/get_object_prop_list_data.h"
#include "payload_data/get_object_prop_desc_data.h"
#include "payload_data/get_object_prop_value_data.h"
#include "payload_data/get_object_props_supported_data.h"
#include "payload_data/get_object_references_data.h"
#include "payload_data/get_partial_object_data.h"
#include "payload_data/get_storage_info_data.h"
#include "payload_data/get_storage_ids_data.h"
#include "payload_data/get_thumb_data.h"
#include "payload_data/move_object_data.h"
#include "payload_data/object_event_data.h"
#include "payload_data/open_session_data.h"
#include "payload_data/send_object_data.h"
#include "payload_data/send_object_info_data.h"
#include "payload_data/set_device_prop_value_data.h"
#include "payload_data/set_object_prop_value_data.h"
#include "payload_data/set_object_references_data.h"
#include "parameters.h"
#include "storage.h"
#include "system_ability_definition.h"
using namespace std;
namespace OHOS {
namespace Media {
#ifdef HAS_BATTERY_MANAGER_PART
static constexpr int MAX_BATTERY = 100;
static constexpr int ERROR_BATTERY = -1;
#endif
static constexpr int EMPTY_BATTERY = 0;
static constexpr int STORAGE_MANAGER_UID = 5003;
static constexpr int RECEVIE_OBJECT_CANCELLED = -20;
static constexpr int RECEVIE_OBJECT_FAILED = -17;
const std::string PUBLIC_DOC = "/storage/media/local/files/Docs";

static constexpr uint32_t HEADER_LEN = 12;
static constexpr uint32_t READ_LEN = 1024;
static constexpr uint32_t SEND_OBJECT_FILE_MAX_SIZE = 0xFFFFFFFF;

MtpOperationUtils::MtpOperationUtils(const shared_ptr<MtpOperationContext> &context) : context_(context)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_LOG(saManager != nullptr, "GetSystemAbilityManager failed, saManager is null");

    auto token = saManager->GetSystemAbility(STORAGE_MANAGER_UID);
    mtpMedialibraryManager_ = MtpMedialibraryManager::GetInstance();
    mtpMediaLibrary_ = MtpMediaLibrary::GetInstance();
    if (!MtpManager::GetInstance().IsMtpMode()) {
        CHECK_AND_RETURN_LOG(mtpMedialibraryManager_ != nullptr,
            "MtpMedialibraryManager failed, mtpMedialibraryManager_ is null");
        mtpMedialibraryManager_->Init(token, context);
    }
}

MtpOperationUtils::~MtpOperationUtils()
{
}

uint16_t MtpOperationUtils::GetDeviceInfo(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    shared_ptr<GetDeviceInfoData> getDeviceInfoData = make_shared<GetDeviceInfoData>();
    getDeviceInfoData->SetManufacturer(GetPropertyInner("const.product.manufacturer",
        DEFAULT_PRODUCT_MANUFACTURER));
    getDeviceInfoData->SetModel(GetPropertyInner("const.product.model", DEFAULT_PRODUCT_MODEL));
    getDeviceInfoData->SetVersion(GetPropertyInner("const.product.software.version",
        DEFAULT_PRODUCT_SOFTWARE_VERSION));
    getDeviceInfoData->SetSerialNum(GetPropertyInner("ohos.boot.sn", "0"));
    data = getDeviceInfoData;
    errorCode = MTP_SUCCESS;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetNumObjects(shared_ptr<PayloadData> &data)
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("GetNumObjects context_ is null");
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    if (!MtpStorageManager::GetInstance()->HasStorage(context_->storageID)) {
        return MTP_INVALID_STORAGEID_CODE;
    }

    shared_ptr<GetNumObjectsData> getNumObjects = make_shared<GetNumObjectsData>();
    data = getNumObjects;
    return CheckErrorCode(MTP_SUCCESS);
}

uint16_t MtpOperationUtils::HasStorage(int &errorCode)
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("GetObjectHandles context_ is null");
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return errorCode;
    }
    if (context_->sessionOpen == false) {
        MEDIA_ERR_LOG("GetObjectHandles session not open");
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return errorCode;
    }
    if (!MtpStorageManager::GetInstance()->HasStorage(context_->storageID)) {
        MEDIA_ERR_LOG("GetObjectHandles no this storage");
        errorCode = MTP_ERROR_INVALID_STORAGE_ID;
        return errorCode;
    }
    return MTP_SUCCESS;
}

uint16_t MtpOperationUtils::GetObjectHandles(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    uint16_t ret = HasStorage(errorCode);
    if (ret != MTP_SUCCESS) {
        return CheckErrorCode(ret);
    }
    if (context_->parent == MTP_ALL_HANDLE_ID) {
        context_->parent = 0;
    }
    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
    if (MtpManager::GetInstance().IsMtpMode()) {
        errorCode = mtpMediaLibrary_->GetHandles(context_, objectHandles);
        if (context_->parent == 0) {
            string path;
            string realPath;
            mtpMediaLibrary_->GetPathByContextParent(context_, path);
            mtpMediaLibrary_->GetRealPath(path, realPath);
            MtpFileObserver::GetInstance().AddFileInotify(path, realPath, context_);
        }
    } else {
        errorCode = mtpMedialibraryManager_->GetHandles(context_, objectHandles);
    }
    if (errorCode != MTP_SUCCESS) {
        MEDIA_ERR_LOG("GetObjectHandles GetHandles fail!");
        return CheckErrorCode(errorCode);
    }

    shared_ptr<GetObjectHandlesData> getObjectHandles = make_shared<GetObjectHandlesData>();
    getObjectHandles->SetObjectHandles(objectHandles);
    data = getObjectHandles;
    errorCode = MTP_SUCCESS;
    if (context_->parent != 0) {
        string path;
        string realPath;
        if (GetPathByHandle(context_->parent, path, realPath) != MTP_UNDEFINED_CODE) {
            MtpFileObserver::GetInstance().AddFileInotify(path, realPath, context_);
        }
    }
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetObjectInfo(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    uint16_t ret = HasStorage(errorCode);
    if (ret != MTP_SUCCESS) {
        return CheckErrorCode(ret);
    }

    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(context_->handle);
    if (MtpManager::GetInstance().IsMtpMode()) {
        errorCode = mtpMediaLibrary_->GetObjectInfo(context_, objectInfo);
    } else {
        errorCode = mtpMedialibraryManager_->GetObjectInfo(context_, objectInfo);
    }
    if (errorCode != MTP_SUCCESS) {
        MEDIA_ERR_LOG("GetObjectHandles GetObjectInfo fail!");
        return CheckErrorCode(errorCode);
    }
    shared_ptr<GetObjectInfoData> getObjectInfo = make_shared<GetObjectInfoData>();
    getObjectInfo->SetObjectInfo(objectInfo);
    data = getObjectInfo;
    errorCode = MTP_SUCCESS;
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetObjectPropDesc(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_ == nullptr) {
        MEDIA_ERR_LOG("GetObjectPropDesc context_ is null");
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return CheckErrorCode(errorCode);
    }

    data = make_shared<GetObjectPropDescData>(context_);
    errorCode = MTP_SUCCESS;
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetObjectPropValue(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_ == nullptr) {
        MEDIA_ERR_LOG("GetObjectPropValue context_ is null");
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return CheckErrorCode(errorCode);
    }
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    int type = MTP_TYPE_UNDEFINED_CODE;
    // GetObjectPropValue may have 3 types of return value, using params to return in one function
    uint64_t int64Value = 0;
    uint128_t int128Value = {0};
    string strValue;
    if (MtpManager::GetInstance().IsMtpMode()) {
        mtpMediaLibrary_->GetObjectPropValue(context_, int64Value, int128Value, strValue);
    } else {
        mtpMedialibraryManager_->GetObjectPropValue(context_, int64Value, int128Value, strValue);
    }
    shared_ptr<GetObjectPropValueData> getObjectPropValue = make_shared<GetObjectPropValueData>(context_);
    type = MtpPacketTool::GetObjectPropTypeByPropCode(context_->property);
    getObjectPropValue->SetPropValue(type, int64Value, int128Value, strValue);
    data = getObjectPropValue;
    errorCode = MTP_SUCCESS;
    return CheckErrorCode(errorCode);
}

void MtpOperationUtils::DoSetObjectPropValue(int &errorCode)
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("SetObjectPropValue context_ is null");
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return;
    }
    CHECK_AND_RETURN_LOG(mtpMediaLibrary_ != nullptr, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_LOG(mtpMedialibraryManager_ != nullptr, "mtpMedialibraryManager_ is null");

    if (MtpManager::GetInstance().IsMtpMode()) {
        errorCode = mtpMediaLibrary_->SetObjectPropValue(context_);
    } else {
        errorCode = mtpMedialibraryManager_->SetObjectPropValue(context_);
    }
    SendEventPacket(context_->handle, MTP_EVENT_OBJECT_ADDED_CODE);
}

void MtpOperationUtils::SendEventPacket(uint32_t objectHandle, uint16_t eventCode)
{
    CHECK_AND_RETURN_LOG(context_ != nullptr, "SendEventPacket context_ is null");

    EventMtp event;
    event.length = MTP_CONTAINER_HEADER_SIZE + sizeof(objectHandle);
    vector<uint8_t> outBuffer;
    MtpPacketTool::PutUInt32(outBuffer, event.length);
    MtpPacketTool::PutUInt16(outBuffer, EVENT_CONTAINER_TYPE);
    MtpPacketTool::PutUInt16(outBuffer, eventCode);
    MtpPacketTool::PutUInt32(outBuffer, context_->transactionID);
    MtpPacketTool::PutUInt32(outBuffer, objectHandle);

    event.data = outBuffer;
    CHECK_AND_RETURN_LOG(context_->mtpDriver != nullptr, "SendEventPacket mtpDriver is null");

    context_->mtpDriver->WriteEvent(event);
}

uint16_t MtpOperationUtils::GetObjectPropList(shared_ptr<PayloadData> &data,
    uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_ == nullptr) {
        MEDIA_ERR_LOG("GetObjectPropList context_ is null");
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return CheckErrorCode(errorCode);
    }
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    shared_ptr<vector<Property>> props = make_shared<vector<Property>>();
    if (MtpManager::GetInstance().IsMtpMode()) {
        errorCode = mtpMediaLibrary_->GetObjectPropList(context_, props);
        CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, CheckErrorCode(errorCode), "GetObjectPropList fail!");
    } else {
        mtpMedialibraryManager_->GetObjectPropList(context_, props);
    }

    shared_ptr<GetObjectPropListData> getObjectPropList = make_shared<GetObjectPropListData>(context_);
    getObjectPropList->SetProps(props);
    data = getObjectPropList;
    errorCode = MTP_SUCCESS;
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetObjectReferences(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    uint16_t ret = HasStorage(errorCode);
    if (ret != MTP_SUCCESS) {
        return CheckErrorCode(ret);
    }

    shared_ptr<UInt32List> objectHandles = nullptr;
    shared_ptr<GetObjectReferencesData> getObjectReferences = make_shared<GetObjectReferencesData>(context_);
    getObjectReferences->SetObjectHandles(objectHandles);
    data = getObjectReferences;
    errorCode = MTP_SUCCESS;
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::SetObjectReferences(shared_ptr<PayloadData> &data)
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("SetObjectReferences context_ is null");
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    uint16_t result = MTP_INVALID_OBJECTPROP_FORMAT_CODE;
    shared_ptr<SetObjectReferencesData> setObjectReferences = make_shared<SetObjectReferencesData>(context_);
    setObjectReferences->SetResult(result);
    data = setObjectReferences;
    return CheckErrorCode(MTP_SUCCESS);
}

uint16_t MtpOperationUtils::GetObjectDataDeal()
{
    CHECK_AND_RETURN_RET_LOG(context_ != nullptr, MTP_ERROR_CONTEXT_IS_NULL, "GetObjectDataDeal context_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    int fd = 0;
    int errorCode = 0;
    if (MtpManager::GetInstance().IsMtpMode()) {
        if (!mtpMediaLibrary_->IsExistObject(context_)) {
            SendEventPacket(context_->handle, MTP_EVENT_OBJECT_REMOVED_CODE);
            return MTP_INVALID_OBJECTHANDLE_CODE;
        }
        errorCode = mtpMediaLibrary_->GetFd(context_, fd);
    } else {
        errorCode = mtpMedialibraryManager_->GetFd(context_, fd, MEDIA_FILEMODE_READONLY);
    }
    CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, errorCode, "GetObjectDataDeal GetFd fail!");

    MtpFileRange object;
    object.fd = fd;
    struct stat sstat;
    int result = fstat(object.fd, &sstat);
    PreDealFd(result < 0, fd);
    CHECK_AND_RETURN_RET_LOG(result == MTP_SUCCESS, MTP_ERROR_INCOMPLETE_TRANSFER,
        "GetObjectDataDeal fstat error = %{public}d", errno);

    object.offset = context_->offset;
    if (context_->length == 0 || context_->length == MTP_ALL_HANDLE_ID) {
        object.length = sstat.st_size;
    } else {
        if (context_->offset + context_->length > static_cast<uint64_t>(sstat.st_size)) {
            context_->length = static_cast<uint32_t>(sstat.st_size - context_->offset);
        }
        object.length = context_->length;
    }
    object.command = context_->operationCode;
    object.transaction_id = context_->transactionID;
    result = context_->mtpDriver->SendObj(object);
    PreDealFd(result < 0, fd);
    CHECK_AND_RETURN_RET_LOG(result >= 0, MTP_ERROR_INCOMPLETE_TRANSFER,
        "GetObjectDataDeal SendObj error!");
    int32_t ret = MtpManager::GetInstance().IsMtpMode() ? mtpMediaLibrary_->CloseFd(context_, fd) :
        mtpMedialibraryManager_->CloseFdForGet(context_, fd);
    CHECK_AND_RETURN_RET_LOG(ret == MTP_SUCCESS, E_ERR, "DealFd CloseFd fail!");
    return MTP_SUCCESS;
}

uint16_t MtpOperationUtils::GetObject(shared_ptr<PayloadData> &data, int errorCode)
{
    data = make_shared<GetObjectData>();
    return CheckErrorCode(errorCode);
}

int32_t MtpOperationUtils::DoRecevieSendObject()
{
    CHECK_AND_RETURN_RET_LOG(context_ != nullptr, MTP_INVALID_PARAMETER_CODE, "DoRecevieSendObject context_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    vector<uint8_t> dataBuffer;
    uint32_t temp = READ_LEN;
    int errorCode = context_->mtpDriver->Read(dataBuffer, temp);
    CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, errorCode, "DoRecevieSendObject Read error!");

    int fd = 0;
    errorCode = MtpManager::GetInstance().IsMtpMode() ? mtpMediaLibrary_->GetFd(context_, fd, true) :
        mtpMedialibraryManager_->GetFdByOpenFile(context_, fd);
    CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, errorCode, "DoRecevieSendObject GetFd fail!");

    uint32_t initialData = dataBuffer.size() < HEADER_LEN  ? 0 : dataBuffer.size() - HEADER_LEN;
    errorCode = write(fd, &dataBuffer[HEADER_LEN], initialData);
    PreDealFd(errorCode < 0, fd);
    CHECK_AND_RETURN_RET_LOG(errorCode >= 0, MTP_ERROR_RESPONSE_GENERAL,
        "DoRecevieSendObject write error = %{public}d", errno);

    MtpFileRange object;
    object.fd = fd;
    object.offset = initialData;
    if (context_->sendObjectFileSize == SEND_OBJECT_FILE_MAX_SIZE) {
        // when file size is over 0xFFFFFFFF, driver will read until it receives a short packet
        object.length = SEND_OBJECT_FILE_MAX_SIZE;
    } else {
        object.length = static_cast<int64_t>(context_->sendObjectFileSize) - static_cast<int64_t>(initialData);
    }
    errorCode = RecevieSendObject(object, fd);
    CHECK_AND_RETURN_RET_LOG(errorCode != MTP_ERROR_TRANSFER_CANCELLED, MTP_ERROR_TRANSFER_CANCELLED,
        "DoRecevieSendObject ReceiveObj Cancelled = %{public}d", MTP_ERROR_TRANSFER_CANCELLED);
    CHECK_AND_RETURN_RET_LOG(errorCode != MTP_ERROR_TRANSFER_FAILED, MTP_ERROR_TRANSFER_FAILED,
        "DoRecevieSendObject ReceiveObj Failed = %{public}d", MTP_ERROR_TRANSFER_FAILED);
    CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, MTP_ERROR_RESPONSE_GENERAL,
        "DoRecevieSendObject ReceiveObj fail errorCode = %{public}d", errorCode);

    errorCode = fsync(fd);
    PreDealFd(errorCode != MTP_SUCCESS, fd);
    CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, MTP_ERROR_RESPONSE_GENERAL,
        "DoRecevieSendObject fsync eroor = %{public}d", errno);
    struct stat sstat;
    errorCode = fstat(fd, &sstat);
    PreDealFd(errorCode != MTP_SUCCESS, fd);
    CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, MTP_ERROR_RESPONSE_GENERAL,
        "DoRecevieSendObject fstat error = %{public}d", errno);

    errorCode = MtpManager::GetInstance().IsMtpMode() ? mtpMediaLibrary_->CloseFd(context_, fd) :
        mtpMedialibraryManager_->CloseFd(context_, fd);
    CHECK_AND_RETURN_RET_LOG(errorCode == MTP_SUCCESS, errorCode, "DoRecevieSendObject CloseFd fail!");

    return MTP_SUCCESS;
}

int32_t MtpOperationUtils::RecevieSendObject(MtpFileRange &object, int fd)
{
    MEDIA_DEBUG_LOG("RecevieSendObject begin");
    CHECK_AND_RETURN_RET_LOG(context_ != nullptr, MTP_INVALID_PARAMETER_CODE, "DoRecevieSendObject context_ is null");
    CHECK_AND_RETURN_RET_LOG(context_->mtpDriver != nullptr, MTP_INVALID_PARAMETER_CODE,
        "DoRecevieSendObject context_->mtpDriver is null");
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    int32_t errorCode = context_->mtpDriver->ReceiveObj(object);
    if (errorCode != RECEVIE_OBJECT_CANCELLED && errorCode != RECEVIE_OBJECT_FAILED) {
        return errorCode;
    }

    PreDealFd(errorCode != MTP_SUCCESS, fd);
    string filePath;
    if (MtpManager::GetInstance().IsMtpMode()) {
        mtpMediaLibrary_->GetPathById(context_->handle, filePath);
        CHECK_AND_RETURN_RET_LOG(!filePath.empty(), MTP_ERROR_TRANSFER_CANCELLED,
            "File path is invalid!");
        int ret = unlink(filePath.c_str());
        CHECK_AND_RETURN_RET_LOG(ret == 0, MTP_ERROR_TRANSFER_CANCELLED, "unlink file fail");
        mtpMediaLibrary_->DeleteHandlePathMap(filePath, context_->handle);
    } else {
        mtpMedialibraryManager_->DeleteCanceledObject(context_->handle);
    }
    if (errorCode == RECEVIE_OBJECT_FAILED) {
        return MTP_ERROR_TRANSFER_FAILED;
    }
    return MTP_ERROR_TRANSFER_CANCELLED;
}

void MtpOperationUtils::PreDealFd(const bool deal, const int fd)
{
    if (!deal || fd <= 0) {
        return;
    }
    CHECK_AND_RETURN_LOG(mtpMediaLibrary_ != nullptr, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_LOG(mtpMedialibraryManager_ != nullptr, "mtpMedialibraryManager_ is null");
    int32_t ret = MtpManager::GetInstance().IsMtpMode() ? mtpMediaLibrary_->CloseFd(context_, fd) :
        mtpMedialibraryManager_->CloseFdForGet(context_, fd);
    if (ret != MTP_SUCCESS) {
        MEDIA_ERR_LOG("DealFd CloseFd fail!");
    }
}

uint16_t MtpOperationUtils::GetThumb(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    CHECK_AND_RETURN_RET_LOG(context_ != nullptr, MTP_INVALID_PARAMETER_CODE, "DoRecevieSendObject context_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    uint16_t ret = HasStorage(errorCode);
    if (ret != MTP_SUCCESS) {
        return CheckErrorCode(ret);
    }

    shared_ptr<UInt8List> thumb = make_shared<UInt8List>();
    errorCode = MtpManager::GetInstance().IsMtpMode() ? mtpMediaLibrary_->GetThumb(context_, thumb) :
        mtpMedialibraryManager_->GetThumb(context_, thumb);
    if (errorCode != MTP_SUCCESS) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    shared_ptr<GetThumbData> getThumb = make_shared<GetThumbData>();
    getThumb->SetThumb(thumb);
    data = getThumb;
    errorCode = MTP_SUCCESS;
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::SendObjectInfo(shared_ptr<PayloadData> &data, int &errorCode)
{
    if (context_ == nullptr || mtpMediaLibrary_ == nullptr || mtpMedialibraryManager_ == nullptr) {
        MEDIA_ERR_LOG("MtpOperationUtils::SendObjectInfo param is null");
        data = make_shared<RespCommonData>();
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    auto manager = MtpStorageManager::GetInstance();
    CHECK_AND_RETURN_RET_LOG(manager != nullptr, MTP_INVALID_PARAMETER_CODE, "MtpStorageManager instance is nullptr");

    // should reserve the space for the frame of the cmd 0x100d
    if (context_->sendObjectFileSize + READ_LEN > manager->GetFreeSize()) {
        data = make_shared<RespCommonData>();
        MEDIA_DEBUG_LOG("SendObjectInfo run out of memory, sendObjectFileSize %{public}d",
            context_->sendObjectFileSize);
        MEDIA_DEBUG_LOG("SendObjectInfo run out of memory, FreeSpaceInBytes %{public}"
            PRId64, manager->GetFreeSize());
        return MTP_STORE_FULL_CODE;
    }

    uint32_t storageID = 0;
    uint32_t parent = 0;
    uint32_t handle = 0;
    if (MtpManager::GetInstance().IsMtpMode()) {
        errorCode = mtpMediaLibrary_->SendObjectInfo(context_, storageID, parent, handle);
    } else {
        errorCode = mtpMedialibraryManager_->SendObjectInfo(context_, storageID, parent, handle);
    }
    if (errorCode != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpOperationUtils::SendObjectInfo fail!");
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }
    context_->handle = handle;
    shared_ptr<SendObjectInfoData> sendObjectInfo = make_shared<SendObjectInfoData>();
    sendObjectInfo->SetSetParam(storageID, parent, handle);
    data = sendObjectInfo;
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetRespCommonData(shared_ptr<PayloadData> &data, int errorCode)
{
    data = make_shared<RespCommonData>();
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetPartialObject(shared_ptr<PayloadData> &data)
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("context_ is null");
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    shared_ptr<GetPartialObjectData> getPartialObject = make_shared<GetPartialObjectData>(context_);
    getPartialObject->SetLength(context_->length);
    data = getPartialObject;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetObjectPropsSupported(shared_ptr<PayloadData> &data)
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("context_ is null");
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    data = make_shared<GetObjectPropsSupportedData>(context_);
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::DeleteObject(shared_ptr<PayloadData> &data, int &errorCode)
{
    if (context_ == nullptr || mtpMediaLibrary_ == nullptr || mtpMedialibraryManager_ == nullptr) {
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
    } else {
        MEDIA_ERR_LOG("MtpOperationUtils::DeleteObject format=%{public}u", context_->format);
        if (MtpManager::GetInstance().IsMtpMode()) {
            errorCode = mtpMediaLibrary_->DeleteObject(context_);
        } else {
            errorCode = mtpMedialibraryManager_->DeleteObject(context_);
        }
    }
    data = make_shared<RespCommonData>();
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::MoveObject(shared_ptr<PayloadData> &data, int &errorCode)
{
    if (context_ == nullptr || mtpMediaLibrary_ == nullptr || mtpMedialibraryManager_ == nullptr) {
        MEDIA_ERR_LOG("param is null");
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    uint32_t repeatHandle = 0;
    if (MtpManager::GetInstance().IsMtpMode()) {
        errorCode = mtpMediaLibrary_->MoveObject(context_, repeatHandle);
    } else {
        errorCode = mtpMedialibraryManager_->MoveObject(context_);
    }

    data = make_shared<RespCommonData>();
    if (repeatHandle != 0) {
        SendEventPacket(repeatHandle, MTP_EVENT_OBJECT_REMOVED_CODE);
        MEDIA_INFO_LOG("MTP:Send Event MTP_EVENT_OBJECT_REMOVED_CODE,repeatHandle[%{public}d]", repeatHandle);
    }
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::CopyObject(shared_ptr<PayloadData> &data, int &errorCode)
{
    if (context_ == nullptr || mtpMediaLibrary_ == nullptr || mtpMedialibraryManager_ == nullptr) {
        MEDIA_ERR_LOG("param is null");
        data = make_shared<RespCommonData>();
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    uint32_t objectHandle = 0;
    uint32_t oldHandle = 0;
    if (MtpManager::GetInstance().IsMtpMode()) {
        errorCode = mtpMediaLibrary_->CopyObject(context_, objectHandle, oldHandle);
    } else {
        errorCode = mtpMedialibraryManager_->CopyObject(context_, objectHandle);
    }

    shared_ptr<CopyObjectData> copyObject = make_shared<CopyObjectData>();
    copyObject->SetObjectHandle(objectHandle);
    data = copyObject;
    if (oldHandle != 0) {
        SendEventPacket(oldHandle, MTP_EVENT_OBJECT_REMOVED_CODE);
        MEDIA_INFO_LOG("MTP:Send Event MTP_EVENT_OBJECT_REMOVED_CODE,oldHandle[%{public}d]", oldHandle);
    }
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetStorageIDs(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE || context_ == nullptr || mtpMediaLibrary_ == nullptr ||
        mtpMedialibraryManager_ == nullptr) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    if (context_->sessionOpen == false) {
        MEDIA_ERR_LOG("session isn't open");
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return CheckErrorCode(errorCode);
    }
    if (MtpManager::GetInstance().IsMtpMode()) {
        MtpStoreObserver::AttachContext(context_);
        mtpMediaLibrary_->GetStorageIds();
    } else {
        auto storage = make_shared<Storage>();
        CHECK_AND_RETURN_RET_LOG(storage != nullptr, E_ERR, "storage is nullptr");
        auto manager = MtpStorageManager::GetInstance();
        CHECK_AND_RETURN_RET_LOG(manager != nullptr, E_ERR, "MtpStorageManager instance is nullptr");
        storage->SetStorageID(DEFAULT_STORAGE_ID);
        storage->SetStorageType(MTP_STORAGE_FIXEDRAM);
        storage->SetFilesystemType(MTP_FILESYSTEM_GENERICHIERARCHICAL);
        storage->SetAccessCapability(MTP_ACCESS_READ_WRITE);
        storage->SetMaxCapacity(manager->GetTotalSize(PUBLIC_DOC));
        storage->SetFreeSpaceInBytes(manager->GetFreeSize(PUBLIC_DOC));
        storage->SetFreeSpaceInObjects(0);
        storage->SetStorageDescription(manager->GetStorageDescription(MTP_STORAGE_FIXEDRAM));
        MtpStorageManager::GetInstance()->AddStorage(storage);
    }

    shared_ptr<GetStorageIdsData> getStorageIdsData = make_shared<GetStorageIdsData>();
    getStorageIdsData->SetStorages(MtpStorageManager::GetInstance()->GetStorages());
    data = getStorageIdsData;
    errorCode = MTP_SUCCESS;
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetStorageInfo(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_->sessionOpen == false) {
        MEDIA_ERR_LOG("session isn't open error");
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return CheckErrorCode(errorCode);
    }

    shared_ptr<Storage> storage = MtpStorageManager::GetInstance()->GetStorage(context_->storageInfoID);
    if (storage == nullptr) {
        MEDIA_ERR_LOG("invalid storage id error");
        errorCode = MTP_ERROR_INVALID_STORAGE_ID;
        return CheckErrorCode(errorCode);
    }
    shared_ptr<GetStorageInfoData> getStorageInfoData = make_shared<GetStorageInfoData>();
    getStorageInfoData->SetStorage(storage);
    data = getStorageInfoData;
    errorCode = MTP_SUCCESS;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetOpenSession(shared_ptr<PayloadData> &data, int errorCode)
{
    shared_ptr<OpenSessionData> openSessionData = make_shared<OpenSessionData>(context_);
    uint16_t respCode = CheckErrorCode(errorCode);
    if (respCode == MTP_SESSION_ALREADY_OPEN_CODE) {
        openSessionData->SetSessionId(context_->sessionID);
    }
    if (respCode == MTP_OK_CODE) {
        context_->sessionOpen = true;
    }
    data = openSessionData;
    return respCode;
}

uint16_t MtpOperationUtils::CheckErrorCode(int errorCode)
{
    switch (errorCode) {
        case MTP_ERROR_PACKET_INCORRECT:
            return MTP_INVALID_PARAMETER_CODE;
        case MTP_ERROR_SESSION_ALREADY_OPEN:
            return MTP_SESSION_ALREADY_OPEN_CODE;
        case MTP_ERROR_NO_THIS_FILE:
            return MTP_INVALID_OBJECTHANDLE_CODE;
        case MTP_ERROR_INCOMPLETE_TRANSFER:
            return MTP_INCOMPLETE_TRANSFER_CODE;
        case MTP_ERROR_SESSION_NOT_OPEN:
            return MTP_SESSION_NOT_OPEN_CODE;
        case MTP_ERROR_INVALID_STORAGE_ID:
            return MTP_INVALID_STORAGEID_CODE;
        case MTP_ERROR_INVALID_OBJECTHANDLE:
            return MTP_INVALID_OBJECTHANDLE_CODE;
        case MTP_ERROR_DEVICEPROP_NOT_SUPPORTED:
            return MTP_DEVICEPROP_NOT_SUPPORTED_CODE;
        case MTP_ERROR_STORE_NOT_AVAILABLE:
            return MTP_STORE_NOT_AVAILABLE_CODE;
        case MTP_ERROR_INVALID_PARENTOBJECT:
            return MTP_INVALID_PARENTOBJECT_CODE;
        case MTP_ERROR_PARAMETER_NOT_SUPPORTED:
            return MTP_PARAMETER_NOT_SUPPORTED_CODE;
        case MTP_ERROR_INVALID_OBJECTPROP_VALUE:
            return MTP_INVALID_OBJECTPROP_VALUE_CODE;
        case MTP_ERROR_INVALID_OBJECTPROP_FORMAT:
            return MTP_INVALID_OBJECTPROP_FORMAT_CODE;
        case MTP_ERROR_INVALID_OBJECTPROPCODE:
            return MTP_INVALID_OBJECTPROPCODE_CODE;
        case MTP_ERROR_ACCESS_DENIED:
            return MTP_ACCESS_DENIED_CODE;
        case MTP_ERROR_SPECIFICATION_BY_GROUP_UNSUPPORTED:
            return MTP_SPECIFICATION_BY_GROUP_UNSUPPORTED_CODE;
        case MTP_ERROR_SPECIFICATION_BY_DEPTH_UNSUPPORTED:
            return MTP_SPECIFICATION_BY_DEPTH_UNSUPPORTED_CODE;
        case MTP_ERROR_TRANSFER_FAILED:
            return MTP_STORE_FULL_CODE;
        default:
            return MTP_OK_CODE;
    }
}

uint16_t MtpOperationUtils::GetCloseSession(shared_ptr<PayloadData> &data)
{
    data = make_shared<CloseSessionData>(context_);
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetPropDesc(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    shared_ptr<GetDevicePropDescData> devicePropDescData = make_shared<GetDevicePropDescData>();
    shared_ptr<Property> property = nullptr;
    switch (context_->property) {
        case MTP_DEVICE_PROPERTY_SYNCHRONIZATION_PARTNER_CODE:
            property = make_shared<Property>(context_->property, MTP_DEVICE_PROP_DESC_TYPE_STR, true);
            break;
        case MTP_DEVICE_PROPERTY_DEVICE_FRIENDLY_NAME_CODE:
            property = make_shared<Property>(context_->property, MTP_DEVICE_PROP_DESC_TYPE_STR, true);
            property->currentValue->str_ = make_shared<string>(GetPropertyInner("const.product.name",
                DEFAULT_PRODUCT_NAME));
            break;
        case MTP_DEVICE_PROPERTY_SESSION_INITIATOR_VERSION_INFO_CODE:
            property = make_shared<Property>(context_->property, MTP_DEVICE_PROP_DESC_TYPE_STR, true);
            break;
        case MTP_DEVICE_PROPERTY_IMAGE_SIZE_CODE:
            property = make_shared<Property>(context_->property, MTP_DEVICE_PROP_DESC_TYPE_STR, true);
            break;
        case MTP_DEVICE_PROPERTY_BATTERY_LEVEL_CODE:
            property = make_shared<Property>(context_->property, MTP_DEVICE_PROP_DESC_TYPE_UINT8);
            property->currentValue->bin_.ui8 = (uint8_t)MtpOperationUtils::GetBatteryLevel();
            property->SetFormRange(BATTERY_LEVEL_MIN, BATTERY_LEVEL_MAX, BATTERY_LEVEL_STEP);
            break;
        case MTP_DEVICE_PROPERTY_PERCEIVED_DEVICE_TYPE_CODE:
            property = make_shared<Property>(context_->property, MTP_DEVICE_PROP_DESC_TYPE_UINT32);
            break;
        default:
            MEDIA_INFO_LOG("property do not find");
            break;
    }

    devicePropDescData->SetProperty(property);
    data = devicePropDescData;
    errorCode = MTP_SUCCESS;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetPropValue(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    shared_ptr<GetDevicePropValueData> devicePropValueData = make_shared<GetDevicePropValueData>();
    shared_ptr<Property::Value> value = make_shared<Property::Value>();
    uint16_t valueType = MTP_DEVICE_PROP_DESC_TYPE_UNDEFINED;
    switch (context_->property) {
        case MTP_DEVICE_PROPERTY_SYNCHRONIZATION_PARTNER_CODE:
            valueType = MTP_DEVICE_PROP_DESC_TYPE_STR;
            value->str_ = make_shared<string>("");
            break;
        case MTP_DEVICE_PROPERTY_DEVICE_FRIENDLY_NAME_CODE:
            valueType = MTP_DEVICE_PROP_DESC_TYPE_STR;
            value->str_ = make_shared<string>(GetPropertyInner("persist.device.name", DEFAULT_PRODUCT_NAME));
            break;
        case MTP_DEVICE_PROPERTY_SESSION_INITIATOR_VERSION_INFO_CODE:
            valueType = MTP_DEVICE_PROP_DESC_TYPE_STR;
            value->str_ = make_shared<string>("");
            break;
        case MTP_DEVICE_PROPERTY_IMAGE_SIZE_CODE:
            valueType = MTP_DEVICE_PROP_DESC_TYPE_STR;
            value->str_ = make_shared<string>("");
            break;
        case MTP_DEVICE_PROPERTY_BATTERY_LEVEL_CODE:
            valueType = MTP_DEVICE_PROP_DESC_TYPE_UINT8;
            value->bin_.ui8 = (uint8_t)MtpOperationUtils::GetBatteryLevel();
            break;
        case MTP_DEVICE_PROPERTY_PERCEIVED_DEVICE_TYPE_CODE:
            valueType = MTP_DEVICE_PROP_DESC_TYPE_UINT32;
            value->bin_.ui32 = MTP_PERCEIVED_DEVICE_TYPE_GENERIC;
            break;
        default:
            MEDIA_INFO_LOG("property do not find");
            break;
    }

    devicePropValueData->SetValue(valueType, value);
    data = devicePropValueData;
    errorCode = MTP_SUCCESS;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::SetDevicePropValueResp(shared_ptr<PayloadData> &data)
{
    data = make_shared<RespCommonData>();
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::ResetDevicePropResp(shared_ptr<PayloadData> &data)
{
    if (!SetPropertyInner("persist.device.name", DEFAULT_PRODUCT_NAME)) {
        MEDIA_ERR_LOG("SetPropertyInner fail");
    }
    data = make_shared<RespCommonData>();
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::ObjectEvent(shared_ptr<PayloadData> &data, const int32_t payload)
{
    std::shared_ptr<ObjectEventData> eventData = make_shared<ObjectEventData>();
    eventData->SetPayload(payload);
    data = eventData;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetPathByHandle(const uint32_t &handle, string &path, string &realPath)
{
    CHECK_AND_RETURN_RET(handle != 0, MTP_UNDEFINED_CODE);
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");

    if (MtpManager::GetInstance().IsMtpMode()) {
        mtpMediaLibrary_->GetPathById(handle, path);
        mtpMediaLibrary_->GetRealPath(path, realPath);
        return MTP_OK_CODE;
    }
    mtpMedialibraryManager_->GetPathById(handle, path);

    size_t position = path.find("/local");
    string real = "100";
    if (position != string::npos) {
        realPath = path.substr(0, position + 1) + real + path.substr(position, path.size());
    }
    MEDIA_DEBUG_LOG("MtpOperationUtils GetPathByHandle new %{private}s", realPath.c_str());
    return MTP_OK_CODE;
}

int32_t MtpOperationUtils::GetHandleByPaths(string path, uint32_t &handle)
{
    CHECK_AND_RETURN_RET(!path.empty(), MTP_UNDEFINED_CODE);
    if (path.back() == '/') {
        path.pop_back();
    }
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, MTP_INVALID_PARAMETER_CODE, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET_LOG(mtpMedialibraryManager_ != nullptr, MTP_INVALID_PARAMETER_CODE,
        "mtpMedialibraryManager_ is null");
    CHECK_AND_RETURN_RET(!MtpManager::GetInstance().IsMtpMode(), mtpMediaLibrary_->GetIdByPath(path, handle));
    return mtpMedialibraryManager_->GetIdByPath(path, handle);
}

bool MtpOperationUtils::TryAddExternalStorage(const std::string &fsUuid, uint32_t &storageId)
{
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, false, "mtpMediaLibrary_ is null");
    CHECK_AND_RETURN_RET(!MtpManager::GetInstance().IsMtpMode(),
        mtpMediaLibrary_->TryAddExternalStorage(fsUuid, storageId));
    return false;
}

bool MtpOperationUtils::TryRemoveExternalStorage(const std::string &fsUuid, uint32_t &storageId)
{
    CHECK_AND_RETURN_RET_LOG(mtpMediaLibrary_ != nullptr, false, "mtpMediaLibrary_ is null");
    if (MtpManager::GetInstance().IsMtpMode()) {
        return mtpMediaLibrary_->TryRemoveExternalStorage(fsUuid, storageId);
    }
    return false;
}

int32_t MtpOperationUtils::GetBatteryLevel()
{
#ifdef HAS_BATTERY_MANAGER_PART
    auto &batterySrvClient = PowerMgr::BatterySrvClient::GetInstance();
    int32_t capacity = batterySrvClient.GetCapacity();
    if (capacity > MAX_BATTERY || capacity < EMPTY_BATTERY) {
        return ERROR_BATTERY;
    }
    return capacity;
#else
    return EMPTY_BATTERY;
#endif
}

std::string MtpOperationUtils::GetPropertyInner(const std::string &property, const std::string &defValue)
{
    return OHOS::system::GetParameter(property, defValue);
}

bool MtpOperationUtils::SetPropertyInner(const std::string &property, const std::string &defValue)
{
    return OHOS::system::SetParameter(property, defValue);
}
} // namespace Media
} // namespace OHOS
