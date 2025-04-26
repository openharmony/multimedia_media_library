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

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "close_session_data.h"
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
const int32_t EVEN = 2;
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

static inline uint8_t FuzzUInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint8_t)) {
        return 0;
    }
    return *data;
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

static inline uint64_t FuzzUInt64(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint64_t)) {
        return 0;
    }
    return static_cast<uint64_t>(*data);
}

static inline vector<uint8_t> FuzzVectorUInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint8_t)) {
        return {0};
    }
    return {*data};
}

static inline vector<uint32_t> FuzzVectorUInt32(const uint8_t *data, size_t size)
{
    return {FuzzUInt32(data, size)};
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

// PayloadDataTest start
static void GetObjectPropValueDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropValueData getObjectPropValueData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectPropValueData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectPropValueData.Maker(outBuffer);
    getObjectPropValueData.CalculateSize();

    const int32_t uInt32Count = 4;
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t) * uInt32Count +
        sizeof(uint64_t)) {
        return;
    }
    int32_t offset = 0;
    int type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    uint64_t int64Value = FuzzUInt64(data + offset, size);
    offset += sizeof(int64_t);
    uint32_t valueUInt32First = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Second = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Third = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Fourth = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint128_t int128Value = {valueUInt32First, valueUInt32Second,
        valueUInt32Third, valueUInt32Fourth};
    string strValue = FuzzString(data, size);
    getObjectPropValueData.SetPropValue(type, int64Value, int128Value, strValue);

    getObjectPropValueData.Parser(buffer, readSize);
    getObjectPropValueData.Maker(outBuffer);
    getObjectPropValueData.CalculateSize();
}

static void RespCommonDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    RespCommonData respCommonData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    respCommonData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    respCommonData.Maker(outBuffer);
    respCommonData.CalculateSize();

    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }
    int32_t offset = 0;
    int paramIndex = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    uint32_t value = FuzzUInt32(data + offset, size);
    respCommonData.SetParam(paramIndex, value);

    respCommonData.Parser(buffer, readSize);
    respCommonData.Maker(outBuffer);
    respCommonData.CalculateSize();
}

static void SendObjectInfoDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SendObjectInfoData sendObjectInfoData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    sendObjectInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    sendObjectInfoData.Maker(outBuffer);
    sendObjectInfoData.CalculateSize();

    const int32_t uInt32Count = 3;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count + sizeof(uint8_t)) {
        return;
    }
    int32_t offset = 0;
    uint32_t storageID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t parent = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t handle = FuzzUInt32(data + offset, size);
    sendObjectInfoData.SetSetParam(storageID, parent, handle);

    sendObjectInfoData.Parser(buffer, readSize);
    sendObjectInfoData.Maker(outBuffer);
    sendObjectInfoData.CalculateSize();

    size_t offsetTest = 1;
    offset += sizeof(uint32_t);
    buffer.push_back(FuzzUInt8(data + offset, size));
    sendObjectInfoData.ParserData(buffer, offsetTest);
    sendObjectInfoData.ParserDataForImageInfo(buffer, offsetTest);
    sendObjectInfoData.ParserDataForFileInfo(buffer, offsetTest);
}

static void SetObjectPropValueDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    SetObjectPropValueData setObjectPropValueData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    setObjectPropValueData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    setObjectPropValueData.Maker(outBuffer);
    setObjectPropValueData.CalculateSize();

    const int32_t int32Count = 5;
    const int32_t int64Count = 5;
    if (data == nullptr || size < sizeof(int32_t) * int32Count +
        sizeof(int64_t) * int64Count + sizeof(uint16_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t result = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    setObjectPropValueData.SetResult(result);

    setObjectPropValueData.Parser(buffer, readSize);
    setObjectPropValueData.Maker(outBuffer);
    setObjectPropValueData.CalculateSize();

    size_t offsetTest = 0;
    int type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64_t int64Value = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    setObjectPropValueData.ReadIntValue(buffer, offsetTest, type, int64Value);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64Value = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    setObjectPropValueData.ReadInt8Value(buffer, offsetTest, type, int64Value);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64Value = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    setObjectPropValueData.ReadInt16Value(buffer, offsetTest, type, int64Value);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64Value = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    setObjectPropValueData.ReadInt32Value(buffer, offsetTest, type, int64Value);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64Value = FuzzInt64(data + offset, size);
    setObjectPropValueData.ReadInt64Value(buffer, offsetTest, type, int64Value);
}

static void PayloadDataTest(const uint8_t* data, size_t size)
{
    GetObjectPropValueDataTest(data, size);
    RespCommonDataTest(data, size);
    SendObjectInfoDataTest(data, size);
    SetObjectPropValueDataTest(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::PayloadDataTest(data, size);
    return 0;
}