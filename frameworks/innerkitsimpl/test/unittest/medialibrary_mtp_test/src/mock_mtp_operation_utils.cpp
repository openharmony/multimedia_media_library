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
#include <cinttypes>
#include <cstdint>
#include <fstream>
#include <iremote_object.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "mtp_operation_utils.h"
#include "directory_ex.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_file_observer.h"
#include "mtp_medialibrary_manager.h"
#include "mtp_operation_context.h"
#include "mtp_packet_tools.h"
#include "mtp_storage_manager.h"
#include "payload_data.h"
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
#include "payload_data/get_storage_ids_data.h"
#include "payload_data/get_storage_info_data.h"
#include "payload_data/get_thumb_data.h"
#include "payload_data/move_object_data.h"
#include "payload_data/object_event_data.h"
#include "payload_data/open_session_data.h"
#include "payload_data/resp_common_data.h"
#include "payload_data/send_object_data.h"
#include "payload_data/send_object_info_data.h"
#include "payload_data/set_device_prop_value_data.h"
#include "payload_data/set_object_prop_value_data.h"
#include "payload_data/set_object_references_data.h"
#include "storage.h"
#include "system_ability_definition.h"
#include "mtp_manager.h"
#include "mtp_media_library.h"
using namespace std;
namespace OHOS {
namespace Media {
static constexpr int32_t BATTERY_FULL = 100;
MtpOperationUtils::MtpOperationUtils(const std::shared_ptr<MtpOperationContext> &context) : context_(context) {}
MtpOperationUtils::~MtpOperationUtils() {}

uint16_t MtpOperationUtils::GetDeviceInfo(std::shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    data = make_shared<GetDeviceInfoData>(context_);
    errorCode = MTP_SUCCESS;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetNumObjects(std::shared_ptr<PayloadData> &data)
{
    if (context_ == nullptr) {
        return MTP_FAIL;
    }

    MEDIA_DEBUG_LOG("GetNumObjects storageID=%{public}u, format=%{public}u, parent=%{public}u",
        context_->storageID, context_->format, context_->parent);
    if (!MtpStorageManager::GetInstance()->HasStorage(context_->storageID)) {
        return MTP_INVALID_STORAGEID_CODE;
    }

    int num = 0;
    std::shared_ptr<GetNumObjectsData> getNumObjects = make_shared<GetNumObjectsData>(context_);
    getNumObjects->SetNum(num);
    data = getNumObjects;
    return MTP_SUCCESS;
}

uint16_t MtpOperationUtils::GetObjectHandles(std::shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_ == nullptr) {
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return MTP_GENERAL_ERROR_CODE;
    }
    if (context_->sessionOpen == false) {
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return MTP_GENERAL_ERROR_CODE;
    }

    MEDIA_DEBUG_LOG("GetObjectHandles storageID=%{public}u, format=%{public}u, parent=%{public}u",
        context_->storageID, context_->format, context_->parent);
    if (!MtpStorageManager::GetInstance()->HasStorage(context_->storageID)) {
        errorCode = MTP_ERROR_INVALID_STORAGE_ID;
        return MTP_GENERAL_ERROR_CODE;
    }
    if (context_->parent == 0xFFFFFFFF) {
        context_->parent = 0;
    }
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        std::shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
        std::shared_ptr<GetObjectHandlesData> getObjectHandles = make_shared<GetObjectHandlesData>();
        getObjectHandles->SetObjectHandles(objectHandles);
        data = getObjectHandles;
        errorCode = MTP_SUCCESS;
        return MTP_OK_CODE;
    } else {
        std::shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>();
        std::shared_ptr<GetObjectHandlesData> getObjectHandles = make_shared<GetObjectHandlesData>();
        getObjectHandles->SetObjectHandles(objectHandles);
        data = getObjectHandles;
        errorCode = MTP_SUCCESS;
        return MTP_OK_CODE;
    }
}

uint16_t MtpOperationUtils::GetObjectInfo(std::shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_ == nullptr) {
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return MTP_GENERAL_ERROR_CODE;
    }
    if (context_->sessionOpen == false) {
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return MTP_GENERAL_ERROR_CODE;
    }
    if (!MtpStorageManager::GetInstance()->HasStorage()) {
        errorCode = MTP_ERROR_INVALID_OBJECTHANDLE;
        return MTP_GENERAL_ERROR_CODE;
    }

    MEDIA_DEBUG_LOG("GetObjectInfo handle=%{public}u", context_->handle);
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        std::shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(context_->handle);
        std::shared_ptr<GetObjectInfoData> getObjectInfo = make_shared<GetObjectInfoData>();
        getObjectInfo->SetObjectInfo(objectInfo);
        data = getObjectInfo;
        errorCode = MTP_SUCCESS;
        return MTP_OK_CODE;
    } else {
        std::shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(context_->handle);
        std::shared_ptr<GetObjectInfoData> getObjectInfo = make_shared<GetObjectInfoData>();
        getObjectInfo->SetObjectInfo(objectInfo);
        data = getObjectInfo;
        errorCode = MTP_SUCCESS;
        return MTP_OK_CODE;
    }
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

    MEDIA_DEBUG_LOG("GetObjectPropDesc OUT property=%{public}u, format=%{public}u",
        context_->property, context_->format);
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

    MEDIA_DEBUG_LOG("GetObjectPropValue handle=%{public}u,"
        " property=%{public}s(%{public}x, %{public}u)",
        context_->handle,
        MtpPacketTool::GetObjectPropName(context_->property).c_str(), context_->property, context_->property);
    int type = MTP_TYPE_UNDEFINED_CODE;
    uint64_t int64Value = 0;
    uint128_t int128Value = { 0 };
    string strValue;
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        shared_ptr<GetObjectPropValueData> getObjectPropValue = make_shared<GetObjectPropValueData>(context_);
        type = MtpPacketTool::GetObjectPropTypeByPropCode(context_->property);
        getObjectPropValue->SetPropValue(type, int64Value, int128Value, strValue);
        data = getObjectPropValue;
        errorCode = MTP_SUCCESS;
        return CheckErrorCode(errorCode);
    } else {
        shared_ptr<GetObjectPropValueData> getObjectPropValue = make_shared<GetObjectPropValueData>(context_);
        type = MtpPacketTool::GetObjectPropTypeByPropCode(context_->property);
        getObjectPropValue->SetPropValue(type, int64Value, int128Value, strValue);
        data = getObjectPropValue;
        errorCode = MTP_SUCCESS;
        return CheckErrorCode(errorCode);
    }
}

void MtpOperationUtils::DoSetObjectPropValue(int &errorCode)
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("SetObjectPropValue context_ is null");
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return;
    }
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        MEDIA_DEBUG_LOG("SetObjectPropValue handle=%{public}u, property=%{public}u, properType=%{public}u,"
        " properIntValue=%{public}" PRIu64 ", properStrValue=[%{public}s]",
        context_->handle, context_->property, context_->properType,
        context_->properIntValue, context_->properStrValue.c_str());
        errorCode = MTP_SUCCESS;
        SendEventPacket(context_->handle, MTP_EVENT_OBJECT_ADDED_CODE);
    } else {
        MEDIA_DEBUG_LOG("SetObjectPropValue handle=%{public}u, property=%{public}u, properType=%{public}u,"
            " properIntValue=%{public}" PRIu64 ", properStrValue=[%{public}s]",
            context_->handle, context_->property, context_->properType,
            context_->properIntValue, context_->properStrValue.c_str());
        errorCode = MTP_SUCCESS;
        SendEventPacket(context_->handle, MTP_EVENT_OBJECT_ADDED_CODE);
    }
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
    shared_ptr<vector<Property>> props = make_shared<vector<Property>>();
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        MEDIA_DEBUG_LOG("GetObjectPropList handle=%{public}u, format=%{public}u, property=%{public}u,"
            " groupCode=%{public}d, depth=%{public}d",
            context_->handle, context_->format, context_->property, context_->groupCode, context_->depth);
        shared_ptr<GetObjectPropListData> getObjectPropList = make_shared<GetObjectPropListData>(context_);
        getObjectPropList->SetProps(props);
        data = getObjectPropList;
        errorCode = MTP_SUCCESS;
        return CheckErrorCode(errorCode);
    } else {
        MEDIA_DEBUG_LOG("GetObjectPropList handle=%{public}u, format=%{public}u, property=%{public}u,"
            " groupCode=%{public}d, depth=%{public}d",
            context_->handle, context_->format, context_->property, context_->groupCode, context_->depth);
        shared_ptr<GetObjectPropListData> getObjectPropList = make_shared<GetObjectPropListData>(context_);
        getObjectPropList->SetProps(props);
        data = getObjectPropList;
        errorCode = MTP_SUCCESS;
        return CheckErrorCode(errorCode);
    }
}

uint16_t MtpOperationUtils::GetObjectReferences(shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_ == nullptr) {
        MEDIA_ERR_LOG("GetObjectReferences context_ is null");
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return CheckErrorCode(errorCode);
    }
    if (!context_->sessionOpen) {
        MEDIA_ERR_LOG("GetObjectReferencesData::parser null or session");
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return CheckErrorCode(errorCode);
    }
    if (!MtpStorageManager::GetInstance()->HasStorage()) {
        MEDIA_ERR_LOG("GetObjectReferencesData::parser storage");
        errorCode = MTP_ERROR_INVALID_OBJECTHANDLE;
        return CheckErrorCode(errorCode);
    }

    MEDIA_DEBUG_LOG("GetObjectReferences handle=%{public}u", context_->handle);
    shared_ptr<UInt32List> objectHandles = nullptr;
    shared_ptr<GetObjectReferencesData> getObjectReferences = make_shared<GetObjectReferencesData>(context_);
    getObjectReferences->SetObjectHandles(objectHandles);
    data = getObjectReferences;
    errorCode = MTP_SUCCESS;
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::SetObjectReferences(std::shared_ptr<PayloadData> &data)
{
    if (context_ == nullptr) {
        return MTP_FAIL;
    }

    MEDIA_DEBUG_LOG("SetObjectReferences handle=%{public}u", context_->handle);
    if (context_->handles) {
        for (auto handle : *context_->handles) {
            MEDIA_DEBUG_LOG("SetObjectReferences data handle=%{public}u", handle);
        }
    }

    uint16_t result = MTP_INVALID_OBJECTPROP_FORMAT_CODE;
    std::shared_ptr<SetObjectReferencesData> setObjectReferences = make_shared<SetObjectReferencesData>(context_);
    setObjectReferences->SetResult(result);
    data = setObjectReferences;
    return MTP_SUCCESS;
}

uint16_t MtpOperationUtils::GetObject(std::shared_ptr<PayloadData> &data, int errorCode)
{
    if (context_ == nullptr) {
        return MTP_FAIL;
    }

    data = make_shared<GetObjectData>(context_);
    return CheckErrorCode(errorCode);
}

uint16_t MtpOperationUtils::GetThumb(std::shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_ == nullptr) {
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
        return MTP_GENERAL_ERROR_CODE;
    }
    if (context_->sessionOpen == false) {
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return MTP_GENERAL_ERROR_CODE;
    }
    if (!MtpStorageManager::GetInstance()->HasStorage()) {
        errorCode = MTP_ERROR_INVALID_OBJECTHANDLE;
        return MTP_GENERAL_ERROR_CODE;
    }

    MEDIA_DEBUG_LOG("GetThumb handle=%{public}u", context_->handle);
    std::shared_ptr<UInt8List> thumb = make_shared<UInt8List>();
    std::shared_ptr<GetThumbData> getThumb = make_shared<GetThumbData>();
    getThumb->SetThumb(thumb);
    data = getThumb;
    errorCode = MTP_SUCCESS;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::SendObjectInfo(std::shared_ptr<PayloadData> &data, int &errorCode)
{
    if (context_ == nullptr) {
        return MTP_ERROR_CONTEXT_IS_NULL;
    }

    MEDIA_DEBUG_LOG("SendObjectInfo storageID=%{public}u, parent=%{public}u, format=%{public}u,"
        " sendObjectFileSize=%{public}u, name=[%{public}s],"
        " created=[%{public}s], modified=[%{public}s]",
        context_->storageID, context_->parent, context_->format,
        context_->sendObjectFileSize, context_->name.c_str(),
        context_->created.c_str(), context_->modified.c_str());

    uint32_t storageID = 0;
    uint32_t parent = 0;
    uint32_t handle = 0;
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        context_->handle = handle;
        std::shared_ptr<SendObjectInfoData> sendObjectInfo = make_shared<SendObjectInfoData>();
        sendObjectInfo->SetSetParam(storageID, parent, handle);
        data = sendObjectInfo;
        errorCode = MTP_SUCCESS;
        return MTP_OK_CODE;
    } else {
        context_->handle = handle;
        std::shared_ptr<SendObjectInfoData> sendObjectInfo = make_shared<SendObjectInfoData>();
        sendObjectInfo->SetSetParam(storageID, parent, handle);
        data = sendObjectInfo;
        errorCode = MTP_SUCCESS;
        return MTP_OK_CODE;
    }
}

uint16_t MtpOperationUtils::GetPartialObject(std::shared_ptr<PayloadData> &data)
{
    if (context_ == nullptr) {
        return MTP_FAIL;
    }

    MEDIA_DEBUG_LOG("parser handle=%{public}u, offset=%{public}" PRIu64 ", length=%{public}u",
        context_->handle, context_->offset, context_->length);
    uint32_t length = 0;
    std::shared_ptr<GetPartialObjectData> getPartialObject = make_shared<GetPartialObjectData>(context_);
    getPartialObject->SetLength(length);
    data = getPartialObject;
    return MTP_SUCCESS;
}

uint16_t MtpOperationUtils::GetObjectPropsSupported(std::shared_ptr<PayloadData> &data)
{
    if (context_ == nullptr) {
        return MTP_FAIL;
    }

    MEDIA_DEBUG_LOG("GetObjectPropsSupported format=%{public}u", context_->format);
    data = make_shared<GetObjectPropsSupportedData>(context_);
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::DeleteObject(shared_ptr<PayloadData> &data, int &errorCode)
{
    if (context_ == nullptr) {
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
    } else {
        MEDIA_DEBUG_LOG("MtpOperationUtils::DeleteObject format=%{public}u", context_->format);
        errorCode = MTP_SUCCESS;
    }
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    } else {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }
}

uint16_t MtpOperationUtils::MoveObject(shared_ptr<PayloadData> &data, int &errorCode)
{
    if (context_ == nullptr) {
        errorCode = MTP_ERROR_CONTEXT_IS_NULL;
    } else {
        MEDIA_DEBUG_LOG("MoveObject OUT handle=%{public}u, storageID=%{public}u, parent=%{public}u",
            context_->handle, context_->storageID, context_->parent);
        errorCode = MTP_SUCCESS;
    }
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    } else {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }
}

uint16_t MtpOperationUtils::CopyObject(shared_ptr<PayloadData> &data, int &errorCode)
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("context_ is null");
        data = make_shared<RespCommonData>();
        return CheckErrorCode(MTP_ERROR_CONTEXT_IS_NULL);
    }

    MEDIA_DEBUG_LOG("CopyObject OUT handle=%{public}u, storageID=%{public}u, parent=%{public}u",
        context_->handle, context_->storageID, context_->parent);
    uint32_t objectHandle = 0;
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_INFO_LOG("MTP MODE");
        errorCode = MTP_SUCCESS;
        SendEventPacket(objectHandle, MTP_EVENT_OBJECT_ADDED_CODE);
        shared_ptr<CopyObjectData> copyObject = make_shared<CopyObjectData>();
        copyObject->SetObjectHandle(objectHandle);
        data = copyObject;
        return CheckErrorCode(errorCode);
    } else {
        errorCode = MTP_SUCCESS;
        SendEventPacket(objectHandle, MTP_EVENT_OBJECT_ADDED_CODE);
        shared_ptr<CopyObjectData> copyObject = make_shared<CopyObjectData>();
        copyObject->SetObjectHandle(objectHandle);
        data = copyObject;
        return CheckErrorCode(errorCode);
    }
}

uint16_t MtpOperationUtils::GetStorageIDs(std::shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_->sessionOpen == false) {
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return MTP_GENERAL_ERROR_CODE;
    }
    std::shared_ptr<GetStorageIdsData> getStorageIdsData = make_shared<GetStorageIdsData>();
    auto storage = make_shared<Storage>();
    storage->SetStorageID(1);
    storage->SetStorageType(MTP_STORAGE_FIXEDRAM);
    storage->SetFilesystemType(MTP_FILESYSTEM_GENERICHIERARCHICAL);
    storage->SetAccessCapability(MTP_ACCESS_READ_WRITE);
    storage->SetFreeSpaceInObjects(0);
    storage->SetStorageDescription("Inner Storage");
    MtpStorageManager::GetInstance()->AddStorage(storage);
    getStorageIdsData->SetStorages(MtpStorageManager::GetInstance()->GetStorages());
    data = getStorageIdsData;
    errorCode = MTP_SUCCESS;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetStorageInfo(std::shared_ptr<PayloadData> &data, uint16_t containerType, int &errorCode)
{
    if (containerType != DATA_CONTAINER_TYPE) {
        data = make_shared<RespCommonData>();
        return CheckErrorCode(errorCode);
    }

    if (context_->sessionOpen == false) {
        errorCode = MTP_ERROR_SESSION_NOT_OPEN;
        return MTP_GENERAL_ERROR_CODE;
    }

    std::shared_ptr<Storage> storage = MtpStorageManager::GetInstance()->GetStorage(context_->storageInfoID);
    if (storage == nullptr) {
        errorCode = MTP_ERROR_INVALID_STORAGE_ID;
        return MTP_GENERAL_ERROR_CODE;
    }
    std::shared_ptr<GetStorageInfoData> getStorageInfoData = make_shared<GetStorageInfoData>();
    getStorageInfoData->SetStorage(storage);
    data = getStorageInfoData;
    errorCode = MTP_SUCCESS;
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::GetOpenSession(std::shared_ptr<PayloadData> &data, int errorCode)
{
    std::shared_ptr<OpenSessionData> openSessionData = make_shared<OpenSessionData>(context_);
    uint16_t respCode = CheckErrorCode(errorCode);
    if (respCode == MTP_SESSION_ALREADY_OPEN_CODE) {
        openSessionData->SetSessionId(context_->sessionID);
    } else if (respCode == MTP_OK_CODE) {
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
        default:
            return MTP_OK_CODE;
    }
}

uint16_t MtpOperationUtils::GetCloseSession(std::shared_ptr<PayloadData> &data)
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
            value->str_ = make_shared<string>(GetPropertyInner("const.product.name", DEFAULT_PRODUCT_NAME));
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

uint16_t MtpOperationUtils::SetDevicePropValueResp(std::shared_ptr<PayloadData> &data)
{
    data = make_shared<RespCommonData>();
    return MTP_OK_CODE;
}

uint16_t MtpOperationUtils::ResetDevicePropResp(shared_ptr<PayloadData> &data)
{
    if (!SetPropertyInner("const.product.name", DEFAULT_PRODUCT_NAME)) {
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
    if (handle == 0) {
        return MTP_UNDEFINED_CODE;
    }
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_DEBUG_LOG("MtpOperationUtils GetPathByHandle old %{private}s", path.c_str());
        size_t position = path.find("/local");
        string real = "100";
        if (position != string::npos) {
            realPath = path.substr(0, position + 1) + real + path.substr(position, path.size());
        }
        MEDIA_DEBUG_LOG("MtpOperationUtils GetPathByHandle new %{private}s", realPath.c_str());
        return MTP_OK_CODE;
    } else {
        MEDIA_DEBUG_LOG("MtpOperationUtils GetPathByHandle old %{private}s", path.c_str());
        size_t position = path.find("/local");
        string real = "100";
        if (position != string::npos) {
            realPath = path.substr(0, position + 1) + real + path.substr(position, path.size());
        }
        MEDIA_DEBUG_LOG("MtpOperationUtils GetPathByHandle new %{private}s", realPath.c_str());
        return MTP_OK_CODE;
    }
}

int32_t MtpOperationUtils::GetHandleByPaths(string path, uint32_t &handle)
{
    if (path.empty()) {
        return MTP_UNDEFINED_CODE;
    }
    if (path.substr(path.length() - 1, path.length()) == "/") {
        MEDIA_DEBUG_LOG("MtpOperationUtils GetHandleByPaths @1 %{private}s", path.c_str());
        path = path.substr(0, path.length() - 1);
    }
    if (MtpManager::GetInstance().IsMtpMode()) {
        MEDIA_DEBUG_LOG("MtpOperationUtils GetHandleByPaths %{private}s", path.c_str());
        int32_t result = 0;
        MEDIA_DEBUG_LOG("MtpOperationUtils GetHandleByPaths %{public}d %{public}d", result, handle);
        return result;
    } else {
        MEDIA_DEBUG_LOG("MtpOperationUtils GetHandleByPaths %{private}s", path.c_str());
        int32_t result = 0;
        MEDIA_DEBUG_LOG("MtpOperationUtils GetHandleByPaths %{public}d %{public}d", result, handle);
        return result;
    }
}

int32_t MtpOperationUtils::GetBatteryLevel()
{
    return BATTERY_FULL;
}

int32_t MtpOperationUtils::DoRecevieSendObject()
{
    if (context_ == nullptr) {
        MEDIA_ERR_LOG("DoRecevieSendObject context_ is null");
        return MTP_GENERAL_ERROR_CODE;
    }
    int fd = 0;
    vector<uint8_t> dataBuffer;
    uint32_t temp = 1024;
    context_->mtpDriver->Read(dataBuffer, temp);
    uint32_t initialData = dataBuffer.size() < 12  ? 0 : dataBuffer.size() - 12;
    int ret = write(fd, &dataBuffer[12], initialData);
    if (ret < 0) {
        MEDIA_ERR_LOG("DoRecevieSendObject write error = %{public}d", errno);
        return MTP_GENERAL_ERROR_CODE;
    }
    if (MtpManager::GetInstance().IsMtpMode()) {
        MtpFileRange object;
        object.fd = fd;
        object.offset = initialData;
        object.length = static_cast<int64_t>(context_->sendObjectFileSize) - static_cast<int64_t>(initialData);
        context_->mtpDriver->ReceiveObj(object);
        fsync(fd);
        struct stat sstat;
        int result = fstat(fd, &sstat);
        if (result < 0) {
            MEDIA_ERR_LOG("DoRecevieSendObject fstat error = %{public}d", errno);
            return MTP_GENERAL_ERROR_CODE;
        }
        SendEventPacket(context_->handle, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
        return MTP_OK_CODE;
    } else {
        MtpFileRange object;
        object.fd = fd;
        object.offset = initialData;
        object.length = static_cast<int64_t>(context_->sendObjectFileSize) - static_cast<int64_t>(initialData);
        context_->mtpDriver->ReceiveObj(object);
        fsync(fd);
        struct stat sstat;
        int result = fstat(fd, &sstat);
        if (result < 0) {
            MEDIA_ERR_LOG("DoRecevieSendObject fstat error = %{public}d", errno);
            return MTP_GENERAL_ERROR_CODE;
        }
        SendEventPacket(context_->handle, MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
        return MTP_OK_CODE;
    }
}
} // namespace Media
} // namespace OHOS
