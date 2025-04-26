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
#include "medialibrary_mtpoperationutils_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "close_session_data.h"
#include "media_log.h"
#include "media_mtp_utils.h"

#define private public
#include "mtp_operation_utils.h"
#include "mtp_manager.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
const int32_t EVEN = 2;
const int32_t MTP_ERROR_DEFAULT = 0;
const string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
shared_ptr<MtpOperationUtils> mtpOperUtils_ = nullptr;
static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    return static_cast<int32_t>(*data);
}

static inline int64_t FuzzInt64(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return 0;
    }
    return static_cast<int64_t>(*data);
}

static inline bool FuzzBool(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return false;
    }
    return (data[0] % EVEN) == 0;
}

static inline uint16_t FuzzUInt16(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint16_t)) {
        return 0;
    }
    return static_cast<uint16_t>(*data);
}

static inline uint32_t FuzzUInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return 0;
    }
    return static_cast<uint32_t>(*data);
}

static inline vector<uint32_t> FuzzVectorUInt32(const uint8_t *data, size_t size)
{
    return {FuzzUInt32(data, size)};
}

static MtpFileRange FuzzMtpFileRange(const uint8_t *data, size_t size)
{
    MtpFileRange object;
    const int int64Count = 2;
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint16_t) +
        sizeof(uint32_t) + sizeof(int64_t) * int64Count) {
        return object;
    }
    int32_t offset = 0;
    object.fd = FuzzInt32(data + offset, size);
    offset += sizeof(int64_t);
    object.offset = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    object.length = FuzzInt64(data + offset, size);
    offset += sizeof(uint16_t);
    object.command = FuzzUInt16(data + offset, size);
    offset += sizeof(uint32_t);
    object.transaction_id = FuzzUInt32(data + offset, size);
    return object;
}

static MtpOperationContext FuzzMtpOperationContext(const uint8_t* data, size_t size)
{
    MtpOperationContext context;
    const int32_t uInt32Count = 13;
    const int32_t uInt16Count = 2;
    if (data == nullptr || size < (sizeof(uint32_t) * uInt32Count +
        sizeof(uint16_t) * uInt16Count + sizeof(int64_t))) {
        return context;
    }
    int32_t offset = 0;
    context.operationCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    context.transactionID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.devicePropertyCode = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.storageID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.format = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    context.parent = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.handle = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.property = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.groupCode = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.depth = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.properStrValue = FuzzString(data, size);
    context.properIntValue = FuzzInt64(data + offset, size);
    offset += sizeof(uint64_t);
    context.handles = make_shared<UInt32List>(FuzzVectorUInt32(data, size)),
    context.name = FuzzString(data, size);
    context.created = FuzzString(data, size);
    context.modified = FuzzString(data, size);

    context.indata = FuzzBool(data + offset, size);
    context.storageInfoID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);

    context.sessionOpen = FuzzBool(data + offset, size);
    context.sessionID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.tempSessionID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.eventHandle = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    context.eventProperty = FuzzUInt32(data + offset, size);
    return context;
}

// MtpOperationUtilsTest start
static void MtpOperationUtilsContainerTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    if (data == nullptr || size < sizeof(uint16_t) + sizeof(int32_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t containerType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    int errorCode = FuzzInt32(data + offset, size);
    mtpOperUtils_->SetIsDevicePropSet();
    mtpOperUtils_->GetDeviceInfo(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectInfo(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectHandles(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectPropValue(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectPropList(payData, containerType, errorCode);
    mtpOperUtils_->DeleteObject(payData, errorCode);
    mtpOperUtils_->CopyObject(payData, errorCode);
    mtpOperUtils_->GetStorageIDs(payData, containerType, errorCode);
    mtpOperUtils_->GetStorageInfo(payData, containerType, errorCode);

    MtpManager::GetInstance().mtpMode_ = MtpManager::MtpMode::MTP_MODE;
    containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils_->context_->sessionOpen = true;
    mtpOperUtils_->GetDeviceInfo(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectInfo(payData, containerType, errorCode);
    mtpOperUtils_->GetNumObjects(payData);
    mtpOperUtils_->DoSetObjectPropValue(errorCode);
    mtpOperUtils_->GetObjectHandles(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectPropValue(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectPropList(payData, containerType, errorCode);
    mtpOperUtils_->SendObjectInfo(payData, errorCode);
    mtpOperUtils_->GetPartialObject(payData);
    mtpOperUtils_->GetObjectPropsSupported(payData);
    mtpOperUtils_->GetOpenSession(payData, errorCode);
    errorCode = MTP_ERROR_SESSION_ALREADY_OPEN;
    mtpOperUtils_->GetOpenSession(payData, errorCode);
    errorCode = MTP_ERROR_DEFAULT;
    mtpOperUtils_->GetOpenSession(payData, errorCode);
    mtpOperUtils_->GetCloseSession(payData);
    mtpOperUtils_->DeleteObject(payData, errorCode);
    mtpOperUtils_->MoveObject(payData, errorCode);
    mtpOperUtils_->CopyObject(payData, errorCode);
    mtpOperUtils_->GetStorageIDs(payData, containerType, errorCode);
    mtpOperUtils_->GetStorageInfo(payData, containerType, errorCode);
}

static void MtpOperationUtilsGetPathByHandleTest(const uint8_t* data, size_t size)
{
    if (mtpOperUtils_ == nullptr) {
        shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
            FuzzMtpOperationContext(data, size));
        if (context == nullptr) {
            MEDIA_ERR_LOG("context is nullptr");
            return;
        }
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    string path = FILE_PATH + "/" + FuzzString(data, size);
    string realPath = FILE_PATH + "/" + FuzzString(data, size);
    uint32_t handle = FuzzUInt32(data, size);
    mtpOperUtils_->GetPathByHandle(handle, path, realPath);
    MtpManager::GetInstance().mtpMode_ = MtpManager::MtpMode::MTP_MODE;
    mtpOperUtils_->GetPathByHandle(handle, path, realPath);
    mtpOperUtils_->GetHandleByPaths(path, handle);
}

static void MtpOperationUtilsHandleTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }
    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    mtpOperUtils_->SetDevicePropValueResp(payData);
    mtpOperUtils_->ResetDevicePropResp(payData);

    const int int32Count = 3;
    const int uint16Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(uint16_t) * uint16Count + sizeof(uint32_t)) {
        return;
    }
    int32_t offset = 0;
    mtpOperUtils_->ObjectEvent(payData, FuzzInt32(data + offset, size));

    offset += sizeof(uint32_t);
    uint32_t objectHandle = FuzzUInt32(data + offset, size);
    offset += sizeof(uint16_t);
    uint16_t eventCode = FuzzUInt16(data + offset, size);
    mtpOperUtils_->context_->mtpDriver = make_shared<MtpDriver>();
    mtpOperUtils_->SendEventPacket(objectHandle, eventCode);

    offset += sizeof(int32_t);
    int errorCode = FuzzInt32(data + offset, size);
    mtpOperUtils_->GetRespCommonData(payData, errorCode);
    mtpOperUtils_->HasStorage(errorCode);

    offset += sizeof(uint16_t);
    uint16_t containerType = FuzzUInt16(data + offset, size);
    mtpOperUtils_->context_->sessionOpen = true;
    mtpOperUtils_->GetObjectReferences(payData, containerType, errorCode);

    mtpOperUtils_->SetObjectReferences(payData);
    mtpOperUtils_->GetObjectDataDeal();
    mtpOperUtils_->GetObject(payData, errorCode);
    mtpOperUtils_->ModifyObjectInfo();

    MtpManager::GetInstance().mtpMode_ = MtpManager::MtpMode::MTP_MODE;
    mtpOperUtils_->GetObjectDataDeal();
    mtpOperUtils_->ModifyObjectInfo();
    mtpOperUtils_->DoRecevieSendObject();

    offset += sizeof(int32_t);
    int fd = FuzzInt32(data + offset, size);
    MtpFileRange object = FuzzMtpFileRange(data, size);
    mtpOperUtils_->RecevieSendObject(object, fd);
    mtpOperUtils_->GetThumb(payData, containerType, errorCode);
    containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils_->GetObjectReferences(payData, containerType, errorCode);
    mtpOperUtils_->GetThumb(payData, containerType, errorCode);
    mtpOperUtils_->HasStorage(errorCode);
}

static void MtpOperationUtilsCheckErrorCodeTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }
    int errorCode = FuzzInt32(data, size);
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_PACKET_INCORRECT;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_SESSION_ALREADY_OPEN;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_NO_THIS_FILE;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_INCOMPLETE_TRANSFER;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_SESSION_NOT_OPEN;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_INVALID_STORAGE_ID;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_INVALID_OBJECTHANDLE;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_DEVICEPROP_NOT_SUPPORTED;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_STORE_NOT_AVAILABLE;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_INVALID_PARENTOBJECT;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_PARAMETER_NOT_SUPPORTED;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_INVALID_OBJECTPROP_VALUE;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_INVALID_OBJECTPROP_FORMAT;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_INVALID_OBJECTPROPCODE;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_ACCESS_DENIED;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_SPECIFICATION_BY_GROUP_UNSUPPORTED;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_SPECIFICATION_BY_DEPTH_UNSUPPORTED;
    mtpOperUtils_->CheckErrorCode(errorCode);
    errorCode = MTP_ERROR_TRANSFER_FAILED;
    mtpOperUtils_->CheckErrorCode(errorCode);
}

static void MtpOperationUtilsGetPropertyTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }
    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    uint16_t containerType = FuzzBool(data, size) ? DATA_CONTAINER_TYPE : FuzzUInt16(data, size);
    int errorCode = FuzzInt32(data, size);
    mtpOperUtils_->context_->property = MTP_DEVICE_PROPERTY_UNDEFINED_CODE;
    mtpOperUtils_->GetPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetPropValue(payData, containerType, errorCode);
    mtpOperUtils_->context_->property = MTP_DEVICE_PROPERTY_SYNCHRONIZATION_PARTNER_CODE;
    mtpOperUtils_->GetPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetPropValue(payData, containerType, errorCode);
    mtpOperUtils_->context_->property = MTP_DEVICE_PROPERTY_DEVICE_FRIENDLY_NAME_CODE;
    mtpOperUtils_->GetPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetPropValue(payData, containerType, errorCode);
    mtpOperUtils_->context_->property = MTP_DEVICE_PROPERTY_SESSION_INITIATOR_VERSION_INFO_CODE;
    mtpOperUtils_->GetPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetPropValue(payData, containerType, errorCode);
    mtpOperUtils_->context_->property = MTP_DEVICE_PROPERTY_IMAGE_SIZE_CODE;
    mtpOperUtils_->GetPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetPropValue(payData, containerType, errorCode);
    mtpOperUtils_->context_->property = MTP_DEVICE_PROPERTY_BATTERY_LEVEL_CODE;
    mtpOperUtils_->GetPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetPropValue(payData, containerType, errorCode);
    mtpOperUtils_->context_->property = MTP_DEVICE_PROPERTY_PERCEIVED_DEVICE_TYPE_CODE;
    mtpOperUtils_->GetPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetPropValue(payData, containerType, errorCode);
}

static void MtpOperationUtilsStorageIdTest(const uint8_t* data, size_t size)
{
    if (mtpOperUtils_ == nullptr) {
        shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
            FuzzMtpOperationContext(data, size));
        if (context == nullptr) {
            MEDIA_ERR_LOG("context is nullptr");
            return;
        }
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    string fsUuid = FuzzString(data, size);
    uint32_t storageId = FuzzUInt32(data, size);
    mtpOperUtils_->TryAddExternalStorage(fsUuid, storageId);
    mtpOperUtils_->TryRemoveExternalStorage(fsUuid, storageId);
    mtpOperUtils_->GetBatteryLevel();
}

static void MtpOperationUtilsTest(const uint8_t* data, size_t size)
{
    MtpOperationUtilsContainerTest(data, size);
    MtpOperationUtilsGetPathByHandleTest(data, size);
    MtpOperationUtilsHandleTest(data, size);
    MtpOperationUtilsCheckErrorCodeTest(data, size);
    MtpOperationUtilsGetPropertyTest(data, size);
    MtpOperationUtilsStorageIdTest(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MtpOperationUtilsTest(data, size);
    return 0;
}