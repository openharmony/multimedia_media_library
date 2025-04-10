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
#include "medialibrary_mtppackettool_fuzzer.h"

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
#include "mtp_packet_tools.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int8_t FuzzInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int8_t)) {
        return 0;
    }
    return static_cast<int8_t>(*data);
}

static inline int16_t FuzzInt16(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int16_t)) {
        return 0;
    }
    return static_cast<int16_t>(*data);
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

// MtpPacketToolTest start
static void MtpPacketToolPutTest(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    const int32_t uInt32Count = 3;
    const int32_t uInt64Count = 2;
    const int32_t int32Count = 3;
    const int32_t int64Count = 2;
    if (data == nullptr || size < (sizeof(uint16_t) * uInt16Count +
        sizeof(uint32_t) * uInt32Count + sizeof(uint64_t) * uInt64Count +
        sizeof(int8_t) + sizeof(int16_t) + sizeof(int32_t) * int32Count +
        sizeof(int64_t) * int64Count)) {
        return;
    }
    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    int32_t offset = 0;
    MtpPacketTool::PutUInt8(outBuffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    MtpPacketTool::PutUInt16(outBuffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    MtpPacketTool::PutUInt32(outBuffer, FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    MtpPacketTool::PutUInt64(outBuffer, FuzzUInt64(data + offset, size));
    offset += sizeof(uint64_t);
    MtpPacketTool::PutUInt128(outBuffer, FuzzUInt64(data + offset, size));
    offset += sizeof(uint64_t);
    uint32_t valueUInt32First = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Second = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::PutUInt128(outBuffer, valueUInt128);

    MtpPacketTool::PutInt8(outBuffer, FuzzInt8(data + offset, size));
    offset += sizeof(int8_t);
    MtpPacketTool::PutInt16(outBuffer, FuzzInt16(data + offset, size));
    offset += sizeof(int16_t);
    MtpPacketTool::PutInt32(outBuffer, FuzzInt32(data + offset, size));
    offset += sizeof(int32_t);
    MtpPacketTool::PutInt64(outBuffer, FuzzInt64(data + offset, size));
    offset += sizeof(int64_t);
    MtpPacketTool::PutInt128(outBuffer, FuzzInt64(data + offset, size));
    offset += sizeof(int64_t);
    int32_t valueInt32First = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t valueInt32Second = FuzzInt32(data + offset, size);
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    MtpPacketTool::PutInt128(outBuffer, valueInt128);
    MtpPacketTool::PutString(outBuffer, FuzzString(data, size));
}

static void MtpPacketToolGetTest(const uint8_t* data, size_t size)
{
    const int32_t uInt8Count = 6;
    if (data == nullptr || size < sizeof(uint8_t) * uInt8Count) {
        return;
    }
    int32_t offset = 0;
    uint8_t numFirst = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    uint8_t numSecond = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    MtpPacketTool::GetUInt16(numFirst, numSecond);
    numFirst = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    numSecond = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    uint8_t numThird = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    uint8_t numFourth = FuzzUInt8(data + offset, size);
    MtpPacketTool::GetUInt32(numFirst, numSecond, numThird, numFourth);
}

static void MtpPacketToolGetUInt8Test(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count + sizeof(uint8_t)) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt8(buffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    MtpPacketTool::GetUInt8(buffer, offsetTest);
    MtpPacketTool::PutUInt8(buffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    uint8_t valueUInt8 = FuzzUInt8(data + offset, size);
    MtpPacketTool::GetUInt8(buffer, offsetTest, valueUInt8);
}

static void MtpPacketToolGetUInt16Test(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 3;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt16(buffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    MtpPacketTool::GetUInt16(buffer, offsetTest);
    MtpPacketTool::PutUInt16(buffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    uint16_t valueUInt16 = FuzzUInt16(data + offset, size);
    MtpPacketTool::GetUInt16(buffer, offsetTest, valueUInt16);
}

static void MtpPacketToolGetUInt32Test(const uint8_t* data, size_t size)
{
    const int32_t uInt32Count = 3;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt32(buffer, FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    MtpPacketTool::GetUInt32(buffer, offsetTest);
    MtpPacketTool::PutUInt32(buffer, FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    uint32_t valueUInt32 = FuzzUInt32(data + offset, size);
    MtpPacketTool::GetUInt32(buffer, offsetTest, valueUInt32);
}

static void MtpPacketToolGetUInt64Test(const uint8_t* data, size_t size)
{
    const int32_t uInt64Count = 2;
    if (data == nullptr || size < sizeof(uint64_t) * uInt64Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt64(buffer, FuzzUInt64(data + offset, size));
    offset += sizeof(uint64_t);
    uint64_t valueUInt64 = FuzzUInt64(data + offset, size);
    MtpPacketTool::GetUInt64(buffer, offsetTest, valueUInt64);
}

static void MtpPacketToolGetUInt128Test(const uint8_t* data, size_t size)
{
    const int32_t uInt32Count = 2;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    uint32_t valueUInt32First = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Second = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::PutUInt128(buffer, valueUInt128);
    uint128_t outUInt128 = {0, 1};
    MtpPacketTool::GetUInt128(buffer, offsetTest, outUInt128);
}

static void MtpPacketToolGetInt8Test(const uint8_t* data, size_t size)
{
    const int32_t int8Count = 2;
    if (data == nullptr || size < sizeof(int8_t) * int8Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt8(buffer, FuzzInt8(data + offset, size));
    offset += sizeof(int8_t);
    size_t offsetTest = 0;
    int8_t valueInt8 = FuzzInt8(data + offset, size);
    MtpPacketTool::GetInt8(buffer, offsetTest, valueInt8);
}

static void MtpPacketToolGetInt16Test(const uint8_t* data, size_t size)
{
    const int32_t int16Count = 2;
    if (data == nullptr || size < sizeof(int16_t) * int16Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutInt16(buffer, FuzzInt16(data + offset, size));
    offset += sizeof(int16_t);
    int16_t valueInt16 = FuzzInt16(data + offset, size);
    MtpPacketTool::GetInt16(buffer, offsetTest, valueInt16);
}

static void MtpPacketToolGetInt32Test(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    MtpPacketTool::PutUInt32(buffer, FuzzInt32(data + offset, size));
    offset += sizeof(int32_t);
    int32_t valueInt32 = FuzzInt32(data + offset, size);
    size_t offsetTest = 0;
    MtpPacketTool::GetInt32(buffer, offsetTest, valueInt32);
}

static void MtpPacketToolGetInt64Test(const uint8_t* data, size_t size)
{
    const int32_t int64Count = 2;
    if (data == nullptr || size < sizeof(int64_t) * int64Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt64(buffer, FuzzInt64(data + offset, size));
    offset += sizeof(int64_t);
    size_t offsetTest = 0;
    int64_t valueInt64 = FuzzInt64(data + offset, size);
    MtpPacketTool::GetInt64(buffer, offsetTest, valueInt64);
}

static void MtpPacketToolGetInt128Test(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t valueInt32First = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t valueInt32Second = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt128(buffer, valueInt128);
    size_t offsetTest = 0;
    int128_t outInt128 = {0, 1};
    MtpPacketTool::GetInt128(buffer, offsetTest, outInt128);
}

static void MtpPacketToolToStringTest(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 3;
    const int32_t uInt32Count = 3;
    if (data == nullptr || size < sizeof(int8_t) + sizeof(uint8_t) +
        sizeof(int16_t) + sizeof(uint16_t) + sizeof(int32_t) * int32Count +
        sizeof(uint32_t) * uInt32Count + sizeof(int64_t) +
        sizeof(uint64_t)) {
        return;
    }
    int32_t offset = 0;
    string outStr = "";
    int8_t valueInt8 = FuzzInt8(data + offset, size);
    offset += sizeof(int8_t);
    MtpPacketTool::Int8ToString(valueInt8, outStr);
    uint8_t valueUInt8 = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    MtpPacketTool::UInt8ToString(valueUInt8, outStr);
    int16_t valueInt16 = FuzzInt16(data + offset, size);
    offset += sizeof(int16_t);
    MtpPacketTool::Int16ToString(valueInt16, outStr);
    uint16_t valueUInt16 = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::UInt16ToString(valueUInt16, outStr);
    int32_t valueInt32 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MtpPacketTool::Int32ToString(valueInt32, outStr);
    uint32_t valueUInt32 = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    MtpPacketTool::UInt32ToString(valueUInt32, outStr);
    int64_t valueInt64 = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    MtpPacketTool::Int64ToString(valueInt64, outStr);
    uint64_t valueUInt64 = FuzzUInt64(data + offset, size);
    offset += sizeof(uint64_t);
    MtpPacketTool::UInt64ToString(valueUInt64, outStr);
    int32_t valueInt32First = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t valueInt32Second = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    MtpPacketTool::Int128ToString(valueInt128, outStr);
    uint32_t valueUInt32First = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Second = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::UInt128ToString(valueUInt128, outStr);
}

static void MtpPacketToolGetNameTest(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    const int32_t uInt16Count = 6;
    if (data == nullptr || size < sizeof(int32_t) * int32Count +
        sizeof(uint16_t) * uInt16Count) {
        return;
    }
    int32_t offset = 0;
    uint16_t code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetOperationName(code);
    code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetEventName(code);
    code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetFormatName(code);
    code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetObjectPropName(code);
    code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetEventName(code);

    time_t sec = 0;
    MtpPacketTool::FormatDateTime(sec);
    int type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MtpPacketTool::GetDataTypeName(type);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MtpPacketTool::GetAssociationName(type);

    uint16_t propCode = FuzzUInt16(data + offset, size);
    MtpPacketTool::GetObjectPropTypeByPropCode(propCode);
}

static void MtpPacketToolOtherTest(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(uint8_t)) {
        return;
    }
    MtpPacketTool::GetIndentBlank();
    size_t indent = size;
    MtpPacketTool::GetIndentBlank(indent);
    vector<uint8_t> dumpData = FuzzVectorUInt8(data, size);
    MtpPacketTool::Dump(dumpData);
    unique_ptr<char[]> hexBuf;
    int32_t offset = 0;
    int hexBufSize = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    unique_ptr<char[]> txtBuf;
    int txtBufSize = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);

    uint8_t u8 = FuzzUInt8(data + offset, size);
    MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);

    string str = FuzzString(data, size);
    hexBuf = make_unique<char[]>('a');
    txtBuf = make_unique<char[]>('a');
    MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);

    MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);

    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
    hexBuf[OFFSET_0] = '\0';
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
}

static void MtpPacketToolTest(const uint8_t* data, size_t size)
{
    MtpPacketToolPutTest(data, size);
    MtpPacketToolGetTest(data, size);
    MtpPacketToolGetUInt8Test(data, size);
    MtpPacketToolGetUInt16Test(data, size);
    MtpPacketToolGetUInt32Test(data, size);
    MtpPacketToolGetUInt64Test(data, size);
    MtpPacketToolGetUInt128Test(data, size);
    MtpPacketToolGetInt8Test(data, size);
    MtpPacketToolGetInt16Test(data, size);
    MtpPacketToolGetInt32Test(data, size);
    MtpPacketToolGetInt64Test(data, size);
    MtpPacketToolGetInt128Test(data, size);
    MtpPacketToolToStringTest(data, size);
    MtpPacketToolGetNameTest(data, size);
    MtpPacketToolOtherTest(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MtpPacketToolTest(data, size);
    return 0;
}