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
#include <fuzzer/FuzzedDataProvider.h>

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
const int32_t MTP_ERROR_DEFAULT = 0;
static const int32_t NUM_BYTES = 1;
const string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
FuzzedDataProvider *provider = nullptr;
shared_ptr<MtpOperationUtils> mtpOperUtils_ = nullptr;

static inline vector<uint32_t> FuzzVectorUInt32()
{
    return {provider->ConsumeIntegral<uint32_t>()};
}

static MtpFileRange FuzzMtpFileRange()
{
    MtpFileRange object;
    object.fd = provider->ConsumeIntegral<int32_t>();
    object.offset = provider->ConsumeIntegral<int64_t>();
    object.length = provider->ConsumeIntegral<int64_t>();
    object.command = provider->ConsumeIntegral<uint16_t>();
    object.transaction_id = provider->ConsumeIntegral<uint32_t>();
    return object;
}

static MtpOperationContext FuzzMtpOperationContext()
{
    MtpOperationContext context;
    context.operationCode = provider->ConsumeIntegral<uint16_t>();
    context.transactionID = provider->ConsumeIntegral<uint32_t>();
    context.devicePropertyCode = provider->ConsumeIntegral<uint32_t>();
    context.storageID = provider->ConsumeIntegral<uint32_t>();
    context.format = provider->ConsumeIntegral<uint16_t>();
    context.parent = provider->ConsumeIntegral<uint32_t>();
    context.handle = provider->ConsumeIntegral<uint32_t>();
    context.property = provider->ConsumeIntegral<uint32_t>();
    context.groupCode = provider->ConsumeIntegral<uint32_t>();
    context.depth = provider->ConsumeIntegral<uint32_t>();
    context.properStrValue = provider->ConsumeBytesAsString(NUM_BYTES);
    context.properIntValue = provider->ConsumeIntegral<int64_t>();
    context.handles = make_shared<UInt32List>(FuzzVectorUInt32());
    context.name = provider->ConsumeBytesAsString(NUM_BYTES);
    context.created = provider->ConsumeBytesAsString(NUM_BYTES);
    context.modified = provider->ConsumeBytesAsString(NUM_BYTES);
    context.indata = provider->ConsumeBool();
    context.storageInfoID = provider->ConsumeIntegral<uint32_t>();
    context.sessionOpen = provider->ConsumeBool();
    context.sessionID = provider->ConsumeIntegral<uint32_t>();
    context.mtpDriver = make_shared<MtpDriver>();
    context.tempSessionID = provider->ConsumeIntegral<uint32_t>();
    context.eventHandle = provider->ConsumeIntegral<uint32_t>();
    context.eventProperty = provider->ConsumeIntegral<uint32_t>();
    return context;
}

// MtpOperationUtilsTest start
static void MtpOperationUtilsContainerTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext());
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    uint16_t containerType =  provider->ConsumeIntegral<uint16_t>();
    int errorCode =  provider->ConsumeIntegral<int32_t>();
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

static void MtpOperationUtilsGetPathByHandleTest()
{
    if (mtpOperUtils_ == nullptr) {
        shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
            FuzzMtpOperationContext());
        if (context == nullptr) {
            MEDIA_ERR_LOG("context is nullptr");
            return;
        }
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    string path = FILE_PATH + "/" + provider->ConsumeBytesAsString(NUM_BYTES);
    string realPath = FILE_PATH + "/" + provider->ConsumeBytesAsString(NUM_BYTES);
    uint32_t handle = provider->ConsumeIntegral<uint32_t>();
    mtpOperUtils_->GetPathByHandle(handle, path, realPath);
    MtpManager::GetInstance().mtpMode_ = MtpManager::MtpMode::MTP_MODE;
    mtpOperUtils_->GetPathByHandle(handle, path, realPath);
    mtpOperUtils_->GetHandleByPaths(path, handle);
}

static void MtpOperationUtilsHandleTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext());
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }
    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    mtpOperUtils_->SetDevicePropValueResp(payData);
    mtpOperUtils_->ResetDevicePropResp(payData);

    mtpOperUtils_->ObjectEvent(payData, provider->ConsumeIntegral<int32_t>());

    uint32_t objectHandle = provider->ConsumeIntegral<uint32_t>();
    uint16_t eventCode = provider->ConsumeIntegral<uint16_t>();
    mtpOperUtils_->context_->mtpDriver = make_shared<MtpDriver>();
    mtpOperUtils_->SendEventPacket(objectHandle, eventCode);

    int errorCode = provider->ConsumeIntegral<int32_t>();
    mtpOperUtils_->GetRespCommonData(payData, errorCode);
    mtpOperUtils_->HasStorage(errorCode);

    uint16_t containerType = provider->ConsumeIntegral<uint16_t>();
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

    int fd = provider->ConsumeIntegral<int32_t>();
    MtpFileRange object = FuzzMtpFileRange();
    mtpOperUtils_->RecevieSendObject(object, fd);
    mtpOperUtils_->GetThumb(payData, containerType, errorCode);
    containerType = DATA_CONTAINER_TYPE;
    mtpOperUtils_->GetObjectReferences(payData, containerType, errorCode);
    mtpOperUtils_->GetThumb(payData, containerType, errorCode);
    mtpOperUtils_->HasStorage(errorCode);
}

static void MtpOperationUtilsCheckErrorCodeTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }
    int errorCode = provider->ConsumeIntegral<int32_t>();
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

static void MtpOperationUtilsGetPropertyTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }
    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    uint16_t containerType = provider->ConsumeBool() ? DATA_CONTAINER_TYPE : provider->ConsumeIntegral<uint16_t>();
    int errorCode = provider->ConsumeIntegral<int32_t>();
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

static void MtpOperationUtilsStorageIdTest()
{
    if (mtpOperUtils_ == nullptr) {
        shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
            FuzzMtpOperationContext());
        if (context == nullptr) {
            MEDIA_ERR_LOG("context is nullptr");
            return;
        }
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    string fsUuid = provider->ConsumeBytesAsString(NUM_BYTES);
    uint32_t storageId = provider->ConsumeIntegral<uint32_t>();
    mtpOperUtils_->TryAddExternalStorage(fsUuid, storageId);
    mtpOperUtils_->TryRemoveExternalStorage(fsUuid, storageId);
    mtpOperUtils_->GetBatteryLevel();
}

static void MtpOperationUtilsTest()
{
    MtpOperationUtilsContainerTest();
    MtpOperationUtilsGetPathByHandleTest();
    MtpOperationUtilsHandleTest();
    MtpOperationUtilsCheckErrorCodeTest();
    MtpOperationUtilsGetPropertyTest();
    MtpOperationUtilsStorageIdTest();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::MtpOperationUtilsTest();
    return 0;
}