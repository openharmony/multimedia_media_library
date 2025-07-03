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
#include "medialibrary_mtp_payloaddata_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "medialibrary_errno.h"
#include "media_log.h"

#define private public
#include "close_session_data.h"
#include "copy_object_data.h"
#include "delete_object_data.h"
#include "get_device_info_data.h"
#include "get_device_prop_desc_data.h"
#include "get_device_prop_value_data.h"
#include "get_num_objects_data.h"
#include "get_object_data.h"
#include "get_object_handles_data.h"
#include "get_object_info_data.h"
#include "get_object_prop_desc_data.h"
#include "get_object_prop_list_data.h"
#include "get_object_prop_value_data.h"
#include "get_object_props_supported_data.h"
#include "get_object_references_data.h"
#include "get_partial_object_data.h"
#include "get_storage_ids_data.h"
#include "get_storage_info_data.h"
#include "get_thumb_data.h"
#include "move_object_data.h"
#include "object_event_data.h"
#include "open_session_data.h"
#include "resp_common_data.h"
#include "send_object_data.h"
#include "send_object_info_data.h"
#include "set_device_prop_value_data.h"
#include "set_object_prop_value_data.h"
#include "set_object_references_data.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
static const int32_t NUM_BYTES = 1;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
FuzzedDataProvider *provider = nullptr;

static inline vector<uint32_t> FuzzVectorUInt32()
{
    return {provider->ConsumeIntegral<uint32_t>()};
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

// PayloadDataTest start
static void CloseSessionDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    CloseSessionData closeSessionData(context);
    closeSessionData.CalculateSize();

    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    closeSessionData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    closeSessionData.Maker(outBuffer);
}

static void CopyObjectDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    CopyObjectData copyObjectData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    copyObjectData.Parser(buffer, readSize);
    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    copyObjectData.Maker(outBuffer);
    copyObjectData.CalculateSize();

    uint32_t objectHandle = provider->ConsumeIntegral<uint32_t>();
    copyObjectData.SetObjectHandle(objectHandle);

    copyObjectData.Parser(buffer, readSize);
    copyObjectData.Maker(outBuffer);
    copyObjectData.CalculateSize();
    copyObjectData.SetObjectHandle(objectHandle);
}

static void DeleteObjectDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    DeleteObjectData deleteObjectData(context);
    deleteObjectData.CalculateSize();

    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    deleteObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    deleteObjectData.Maker(outBuffer);
}

static void GetDeviceInfoDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetDeviceInfoData getDeviceInfoData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getDeviceInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getDeviceInfoData.Maker(outBuffer);
    getDeviceInfoData.CalculateSize();

    string manufacturer = provider->ConsumeBytesAsString(NUM_BYTES);
    getDeviceInfoData.SetManufacturer(manufacturer);
    getDeviceInfoData.SetModel(manufacturer);
    getDeviceInfoData.SetVersion(manufacturer);
    getDeviceInfoData.SetSerialNum(manufacturer);
}

static void GetDevicePropDescDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetDevicePropDescData getDevicePropDescData(context);
    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getDevicePropDescData.Maker(outBuffer);
    getDevicePropDescData.CalculateSize();

    shared_ptr<Property> property = make_shared<Property>();
    getDevicePropDescData.SetProperty(property);

    getDevicePropDescData.Maker(outBuffer);
    getDevicePropDescData.CalculateSize();
}

static void GetDevicePropValueDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetDevicePropValueData getDevicePropValueData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getDevicePropValueData.Maker(outBuffer);
    getDevicePropValueData.CalculateSize();

    uint16_t type = provider->ConsumeIntegral<uint16_t>();
    shared_ptr<Property::Value> value = make_shared<Property::Value>();
    getDevicePropValueData.SetValue(type, value);

    Property::Value writeValue;
    getDevicePropValueData.WriteValue(buffer, type, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_INT8_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_UINT8_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_INT16_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_UINT16_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_INT32_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_UINT32_CODE, writeValue);

    getDevicePropValueData.Maker(outBuffer);
    getDevicePropValueData.CalculateSize();

    int32_t readSize = buffer.size();
    getDevicePropValueData.Parser(buffer, readSize);
    getDevicePropValueData.context_ = context;
    getDevicePropValueData.Parser(buffer, readSize);
}

static void GetNumObjectsDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetNumObjectsData getNumObjectsData(context);
    getNumObjectsData.GetNum();
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getNumObjectsData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getNumObjectsData.Maker(outBuffer);
    getNumObjectsData.CalculateSize();

    int num = provider->ConsumeIntegral<int32_t>();
    getNumObjectsData.SetNum(num);

    getNumObjectsData.GetNum();
    getNumObjectsData.Maker(outBuffer);
    getNumObjectsData.CalculateSize();
}

static void GetObjectDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectData getObjectData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getObjectData.Maker(outBuffer);
    getObjectData.CalculateSize();

    uint32_t result = provider->ConsumeIntegral<uint32_t>();
    getObjectData.SetResult(result);
    getObjectData.Parser(buffer, readSize);
    getObjectData.Maker(outBuffer);
    getObjectData.CalculateSize();
}

static void GetObjectHandlesDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectHandlesData getObjectHandlesData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getObjectHandlesData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getObjectHandlesData.Maker(outBuffer);
    getObjectHandlesData.CalculateSize();
    getObjectHandlesData.GetObjectHandles();

    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>(FuzzVectorUInt32());
    getObjectHandlesData.SetObjectHandles(objectHandles);
    getObjectHandlesData.Parser(buffer, readSize);
    getObjectHandlesData.Maker(outBuffer);
    getObjectHandlesData.CalculateSize();
    getObjectHandlesData.GetObjectHandles();
}

static void GetObjectInfoDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectInfoData getObjectInfoData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getObjectInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getObjectInfoData.Maker(outBuffer);
    getObjectInfoData.CalculateSize();
    getObjectInfoData.GetObjectInfo();

    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(ObjectInfo(0));
    getObjectInfoData.SetObjectInfo(objectInfo);
    getObjectInfoData.Parser(buffer, readSize);
    getObjectInfoData.Maker(outBuffer);
    getObjectInfoData.CalculateSize();
    getObjectInfoData.GetObjectInfo();
}

static void GetObjectPropDescDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropDescData getObjectPropDescData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getObjectPropDescData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getObjectPropDescData.Maker(outBuffer);
    getObjectPropDescData.CalculateSize();
    getObjectPropDescData.GetProp();
    getObjectPropDescData.GetPropInt();
    getObjectPropDescData.GetPropStr();
    getObjectPropDescData.GetPropForm();
}

static void GetObjectPropListDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropListData getObjectPropListData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getObjectPropListData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getObjectPropListData.Maker(outBuffer);
    getObjectPropListData.CalculateSize();

    shared_ptr<vector<Property>> props = make_shared<vector<Property>>();
    getObjectPropListData.SetProps(props);

    getObjectPropListData.Parser(buffer, readSize);
    getObjectPropListData.Maker(outBuffer);
    getObjectPropListData.CalculateSize();

    Property prop;
    prop.type_ = provider->ConsumeIntegral<uint16_t>();
    getObjectPropListData.WriteProperty(outBuffer, prop);
    getObjectPropListData.WritePropertyStrValue(outBuffer, prop);
    getObjectPropListData.WritePropertyIntValue(outBuffer, prop);
}

static void GetObjectPropValueDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropValueData getObjectPropValueData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getObjectPropValueData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getObjectPropValueData.Maker(outBuffer);
    getObjectPropValueData.CalculateSize();

    int type = provider->ConsumeIntegral<int32_t>();
    uint64_t int64Value = provider->ConsumeIntegral<uint64_t>();
    uint32_t valueUInt32First = provider->ConsumeIntegral<uint32_t>();
    uint32_t valueUInt32Second = provider->ConsumeIntegral<uint32_t>();
    uint32_t valueUInt32Third = provider->ConsumeIntegral<uint32_t>();
    uint32_t valueUInt32Fourth = provider->ConsumeIntegral<uint32_t>();
    uint128_t int128Value = {valueUInt32First, valueUInt32Second,
        valueUInt32Third, valueUInt32Fourth};
    string strValue = provider->ConsumeBytesAsString(NUM_BYTES);
    getObjectPropValueData.SetPropValue(type, int64Value, int128Value, strValue);

    getObjectPropValueData.Parser(buffer, readSize);
    getObjectPropValueData.Maker(outBuffer);
    getObjectPropValueData.CalculateSize();
}

static void GetObjectPropsSupportedDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropsSupportedData getObjectPropsSupportedData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getObjectPropsSupportedData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getObjectPropsSupportedData.Maker(outBuffer);
    getObjectPropsSupportedData.CalculateSize();

    UInt16List properties = {provider->ConsumeIntegral<uint16_t>()};
    getObjectPropsSupportedData.GetObjectProps(properties);

    getObjectPropsSupportedData.Parser(buffer, readSize);
    getObjectPropsSupportedData.Maker(outBuffer);
    getObjectPropsSupportedData.CalculateSize();
}

static void GetObjectReferencesDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectReferencesData getObjectReferencesData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getObjectReferencesData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getObjectReferencesData.Maker(outBuffer);
    getObjectReferencesData.CalculateSize();

    getObjectReferencesData.GetObjectHandles();

    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>(FuzzVectorUInt32());
    getObjectReferencesData.SetObjectHandles(objectHandles);

    getObjectReferencesData.GetObjectHandles();
    getObjectReferencesData.Parser(buffer, readSize);
    getObjectReferencesData.Maker(outBuffer);
    getObjectReferencesData.CalculateSize();
}

static void GetPartialObjectDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetPartialObjectData getPartialObjectData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getPartialObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getPartialObjectData.Maker(outBuffer);
    getPartialObjectData.CalculateSize();

    uint32_t length = provider->ConsumeIntegral<uint32_t>();
    getPartialObjectData.SetLength(length);

    getPartialObjectData.Parser(buffer, readSize);
    getPartialObjectData.Maker(outBuffer);
    getPartialObjectData.CalculateSize();
}

static void GetStorageIdsDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetStorageIdsData getStorageIdsData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getStorageIdsData.Parser(buffer, readSize);

    vector<shared_ptr<Storage>> storages;
    getStorageIdsData.SetStorages(storages);
    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getStorageIdsData.Maker(outBuffer);
    getStorageIdsData.CalculateSize();
}

static void GetStorageInfoDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetStorageInfoData getStorageInfoData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getStorageInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getStorageInfoData.Maker(outBuffer);
    getStorageInfoData.CalculateSize();

    shared_ptr<Storage> storage = make_shared<Storage>();
    getStorageInfoData.SetStorage(storage);

    getStorageInfoData.Parser(buffer, readSize);
    getStorageInfoData.Maker(outBuffer);
    getStorageInfoData.CalculateSize();
}

static void GetThumbDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetThumbData getThumbData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    getThumbData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    getThumbData.Maker(outBuffer);
    getThumbData.CalculateSize();

    shared_ptr<UInt8List> thumb = make_shared<UInt8List>(provider->ConsumeBytes<uint8_t>(NUM_BYTES));
    getThumbData.SetThumb(thumb);

    getThumbData.Parser(buffer, readSize);
    getThumbData.Maker(outBuffer);
    getThumbData.CalculateSize();
}

static void MoveObjectDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    MoveObjectData moveObjectData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    moveObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    moveObjectData.Maker(outBuffer);
    moveObjectData.CalculateSize();
}

static void ObjectEventDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    ObjectEventData objectEventData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    objectEventData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    objectEventData.Maker(outBuffer);
    objectEventData.CalculateSize();

    const int32_t payload = provider->ConsumeIntegral<int32_t>();
    objectEventData.SetPayload(payload);

    objectEventData.Parser(buffer, readSize);
    objectEventData.Maker(outBuffer);
    objectEventData.CalculateSize();
}

static void OpenSessionDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    OpenSessionData OpenSessionData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    OpenSessionData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    OpenSessionData.Maker(outBuffer);
    OpenSessionData.CalculateSize();

    uint32_t sessionID = provider->ConsumeIntegral<uint32_t>();
    OpenSessionData.SetSessionId(sessionID);

    OpenSessionData.Parser(buffer, readSize);
    OpenSessionData.Maker(outBuffer);
    OpenSessionData.CalculateSize();
}

static void RespCommonDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    RespCommonData respCommonData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    respCommonData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    respCommonData.Maker(outBuffer);
    respCommonData.CalculateSize();

    int paramIndex = provider->ConsumeIntegral<int32_t>();
    uint32_t value = provider->ConsumeIntegral<uint32_t>();
    respCommonData.SetParam(paramIndex, value);

    respCommonData.Parser(buffer, readSize);
    respCommonData.Maker(outBuffer);
    respCommonData.CalculateSize();
}

static void SendObjectDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SendObjectData sendObjectData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    sendObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    sendObjectData.Maker(outBuffer);
    sendObjectData.CalculateSize();
}

static void SendObjectInfoDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SendObjectInfoData sendObjectInfoData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    sendObjectInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    sendObjectInfoData.Maker(outBuffer);
    sendObjectInfoData.CalculateSize();

    uint32_t storageID = provider->ConsumeIntegral<uint32_t>();
    uint32_t parent = provider->ConsumeIntegral<uint32_t>();
    uint32_t handle = provider->ConsumeIntegral<uint32_t>();
    sendObjectInfoData.SetSetParam(storageID, parent, handle);

    sendObjectInfoData.Parser(buffer, readSize);
    sendObjectInfoData.Maker(outBuffer);
    sendObjectInfoData.CalculateSize();

    size_t offsetTest = 1;
    buffer.push_back(provider->ConsumeIntegral<uint8_t>());
    sendObjectInfoData.ParserData(buffer, offsetTest);
    sendObjectInfoData.ParserDataForImageInfo(buffer, offsetTest);
    sendObjectInfoData.ParserDataForFileInfo(buffer, offsetTest);
}

static void SetDevicePropValueDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SetDevicePropValueData setDevicePropValueData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    setDevicePropValueData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    setDevicePropValueData.Maker(outBuffer);
    setDevicePropValueData.CalculateSize();
}

static void SetObjectPropValueDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    SetObjectPropValueData setObjectPropValueData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    setObjectPropValueData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    setObjectPropValueData.Maker(outBuffer);
    setObjectPropValueData.CalculateSize();

    uint16_t result = provider->ConsumeIntegral<uint16_t>();
    setObjectPropValueData.SetResult(result);

    setObjectPropValueData.Parser(buffer, readSize);
    setObjectPropValueData.Maker(outBuffer);
    setObjectPropValueData.CalculateSize();

    size_t offsetTest = 0;
    int type = provider->ConsumeIntegral<int32_t>();
    int64_t int64Value = -1;
    setObjectPropValueData.ReadIntValue(buffer, offsetTest, type, int64Value);
    type = provider->ConsumeIntegral<int32_t>();
    setObjectPropValueData.ReadInt8Value(buffer, offsetTest, type, int64Value);
    type = provider->ConsumeIntegral<int32_t>();
    setObjectPropValueData.ReadInt16Value(buffer, offsetTest, type, int64Value);
    type = provider->ConsumeIntegral<int32_t>();
    setObjectPropValueData.ReadInt32Value(buffer, offsetTest, type, int64Value);
    type = provider->ConsumeIntegral<int32_t>();
    setObjectPropValueData.ReadInt64Value(buffer, offsetTest, type, int64Value);
}

static void SetObjectReferencesDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SetObjectReferencesData setObjectReferencesData(context);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();
    setObjectReferencesData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    setObjectReferencesData.Maker(outBuffer);
    setObjectReferencesData.CalculateSize();

    uint16_t result = provider->ConsumeIntegral<uint16_t>();
    setObjectReferencesData.SetResult(result);

    setObjectReferencesData.Parser(buffer, readSize);
    setObjectReferencesData.Maker(outBuffer);
    setObjectReferencesData.CalculateSize();
}

static void PayloadDataTest()
{
    CloseSessionDataTest();
    CopyObjectDataTest();
    DeleteObjectDataTest();
    GetDeviceInfoDataTest();
    GetDevicePropDescDataTest();
    GetDevicePropValueDataTest();
    GetNumObjectsDataTest();
    GetObjectDataTest();
    GetObjectHandlesDataTest();
    GetObjectInfoDataTest();
    GetObjectPropDescDataTest();
    GetObjectPropListDataTest();
    GetObjectPropValueDataTest();
    GetObjectPropsSupportedDataTest();
    GetObjectReferencesDataTest();
    GetPartialObjectDataTest();
    GetStorageIdsDataTest();
    GetStorageInfoDataTest();
    GetThumbDataTest();
    MoveObjectDataTest();
    ObjectEventDataTest();
    OpenSessionDataTest();
    RespCommonDataTest();
    SendObjectDataTest();
    SendObjectInfoDataTest();
    SetDevicePropValueDataTest();
    SetObjectPropValueDataTest();
    SetObjectReferencesDataTest();
}

static int32_t AddSeed()
{
    char *seedData = new char[OHOS::SEED_SIZE];
    for (int i = 0; i < OHOS::SEED_SIZE; i++) {
        seedData[i] = static_cast<char>(i % MAX_BYTE_VALUE);
    }

    const char* filename = "corpus/seed.txt";
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    if (!file) {
        MEDIA_ERR_LOG("Cannot open file filename:%{public}s", filename);
        delete[] seedData;
        return Media::E_ERR;
    }
    file.write(seedData, OHOS::SEED_SIZE);
    file.close();
    delete[] seedData;
    MEDIA_INFO_LOG("seedData has been successfully written to file filename:%{public}s", filename);
    return Media::E_OK;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::AddSeed();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::PayloadDataTest();
    return 0;
}