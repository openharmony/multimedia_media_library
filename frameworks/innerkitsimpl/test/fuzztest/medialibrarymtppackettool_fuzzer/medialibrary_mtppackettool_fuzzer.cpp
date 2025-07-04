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
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "close_session_data.h"
#include "medialibrary_errno.h"
#include "media_log.h"

#define private public
#include "mtp_packet_tools.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
static const int32_t NUM_BYTES = 1;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
FuzzedDataProvider *provider = nullptr;

// MtpPacketToolTest start
static void MtpPacketToolPutTest()
{
    vector<uint8_t> outBuffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    MtpPacketTool::PutUInt8(outBuffer, provider->ConsumeIntegral<uint16_t>());
    MtpPacketTool::PutUInt16(outBuffer, provider->ConsumeIntegral<uint16_t>());
    MtpPacketTool::PutUInt32(outBuffer, provider->ConsumeIntegral<uint32_t>());
    MtpPacketTool::PutUInt64(outBuffer, provider->ConsumeIntegral<uint64_t>());
    MtpPacketTool::PutUInt128(outBuffer, provider->ConsumeIntegral<uint64_t>());
    uint32_t valueUInt32First = provider->ConsumeIntegral<uint32_t>();
    uint32_t valueUInt32Second = provider->ConsumeIntegral<uint32_t>();
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::PutUInt128(outBuffer, valueUInt128);

    MtpPacketTool::PutInt8(outBuffer, provider->ConsumeIntegral<int8_t>());
    MtpPacketTool::PutInt16(outBuffer, provider->ConsumeIntegral<int16_t>());
    MtpPacketTool::PutInt32(outBuffer, provider->ConsumeIntegral<int32_t>());
    MtpPacketTool::PutInt64(outBuffer, provider->ConsumeIntegral<int64_t>());
    MtpPacketTool::PutInt128(outBuffer, provider->ConsumeIntegral<int64_t>());
    int32_t valueInt32First = provider->ConsumeIntegral<int32_t>();
    int32_t valueInt32Second = provider->ConsumeIntegral<int32_t>();
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    MtpPacketTool::PutInt128(outBuffer, valueInt128);
    MtpPacketTool::PutString(outBuffer, provider->ConsumeBytesAsString(NUM_BYTES));
}

static void MtpPacketToolGetTest()
{
    uint8_t numFirst = provider->ConsumeIntegral<uint8_t>();
    uint8_t numSecond = provider->ConsumeIntegral<uint8_t>();
    MtpPacketTool::GetUInt16(numFirst, numSecond);
    numFirst = provider->ConsumeIntegral<uint8_t>();
    numSecond = provider->ConsumeIntegral<uint8_t>();
    uint8_t numThird = provider->ConsumeIntegral<uint8_t>();
    uint8_t numFourth = provider->ConsumeIntegral<uint8_t>();
    MtpPacketTool::GetUInt32(numFirst, numSecond, numThird, numFourth);
}

static void MtpPacketToolGetUInt8Test()
{
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt8(buffer, provider->ConsumeIntegral<uint16_t>());
    MtpPacketTool::GetUInt8(buffer, offsetTest);
    MtpPacketTool::PutUInt8(buffer, provider->ConsumeIntegral<uint16_t>());
    uint8_t valueUInt8 = provider->ConsumeIntegral<uint8_t>();
    MtpPacketTool::GetUInt8(buffer, offsetTest, valueUInt8);
}

static void MtpPacketToolGetUInt16Test()
{
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt16(buffer, provider->ConsumeIntegral<uint16_t>());
    MtpPacketTool::GetUInt16(buffer, offsetTest);
    MtpPacketTool::PutUInt16(buffer, provider->ConsumeIntegral<uint16_t>());
    uint16_t valueUInt16 = provider->ConsumeIntegral<uint16_t>();
    MtpPacketTool::GetUInt16(buffer, offsetTest, valueUInt16);
}

static void MtpPacketToolGetUInt32Test()
{
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt32(buffer, provider->ConsumeIntegral<uint32_t>());
    MtpPacketTool::GetUInt32(buffer, offsetTest);
    MtpPacketTool::PutUInt32(buffer, provider->ConsumeIntegral<uint32_t>());
    uint32_t valueUInt32 = provider->ConsumeIntegral<uint32_t>();
    MtpPacketTool::GetUInt32(buffer, offsetTest, valueUInt32);
}

static void MtpPacketToolGetUInt64Test()
{
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt64(buffer, provider->ConsumeIntegral<uint64_t>());
    uint64_t valueUInt64 = provider->ConsumeIntegral<uint64_t>();
    MtpPacketTool::GetUInt64(buffer, offsetTest, valueUInt64);
}

static void MtpPacketToolGetUInt128Test()
{
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    uint32_t valueUInt32First = provider->ConsumeIntegral<uint32_t>();
    uint32_t valueUInt32Second = provider->ConsumeIntegral<uint32_t>();
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::PutUInt128(buffer, valueUInt128);
    uint128_t outUInt128 = {0, 1};
    MtpPacketTool::GetUInt128(buffer, offsetTest, outUInt128);
}

static void MtpPacketToolGetInt8Test()
{
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt8(buffer, provider->ConsumeIntegral<int8_t>());
    size_t offsetTest = 0;
    int8_t valueInt8 = provider->ConsumeIntegral<int8_t>();
    MtpPacketTool::GetInt8(buffer, offsetTest, valueInt8);
}

static void MtpPacketToolGetInt16Test()
{
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutInt16(buffer, provider->ConsumeIntegral<int16_t>());
    int16_t valueInt16 = provider->ConsumeIntegral<int16_t>();
    MtpPacketTool::GetInt16(buffer, offsetTest, valueInt16);
}

static void MtpPacketToolGetInt32Test()
{
    vector<uint8_t> buffer;
    MtpPacketTool::PutUInt32(buffer, provider->ConsumeIntegral<int32_t>());
    int32_t valueInt32 = provider->ConsumeIntegral<int32_t>();
    size_t offsetTest = 0;
    MtpPacketTool::GetInt32(buffer, offsetTest, valueInt32);
}

static void MtpPacketToolGetInt64Test()
{
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt64(buffer, provider->ConsumeIntegral<int64_t>());
    size_t offsetTest = 0;
    int64_t valueInt64 = provider->ConsumeIntegral<int64_t>();
    MtpPacketTool::GetInt64(buffer, offsetTest, valueInt64);
}

static void MtpPacketToolGetInt128Test()
{
    int32_t valueInt32First = provider->ConsumeIntegral<int32_t>();
    int32_t valueInt32Second = provider->ConsumeIntegral<int32_t>();
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt128(buffer, valueInt128);
    size_t offsetTest = 0;
    int128_t outInt128 = {0, 1};
    MtpPacketTool::GetInt128(buffer, offsetTest, outInt128);
}

static void MtpPacketToolGetStringTest()
{
    vector<uint8_t> buffer;
    MtpPacketTool::PutString(buffer, provider->ConsumeBytesAsString(NUM_BYTES));
    size_t offsetTest = 0;
    string str = "";
    MtpPacketTool::GetString(buffer, offsetTest);
    MtpPacketTool::PutString(buffer, provider->ConsumeBytesAsString(NUM_BYTES));
    MtpPacketTool::GetString(buffer, offsetTest, str);
    string valueString = provider->ConsumeBytesAsString(NUM_BYTES);
    MtpPacketTool::StrToString(valueString);
}

static void MtpPacketToolToStringTest()
{
    string outStr = "";
    int8_t valueInt8 = provider->ConsumeIntegral<int8_t>();
    MtpPacketTool::Int8ToString(valueInt8, outStr);
    uint8_t valueUInt8 = provider->ConsumeIntegral<uint8_t>();
    MtpPacketTool::UInt8ToString(valueUInt8, outStr);
    int16_t valueInt16 = provider->ConsumeIntegral<int16_t>();
    MtpPacketTool::Int16ToString(valueInt16, outStr);
    uint16_t valueUInt16 = provider->ConsumeIntegral<uint16_t>();
    MtpPacketTool::UInt16ToString(valueUInt16, outStr);
    int32_t valueInt32 = provider->ConsumeIntegral<int32_t>();
    MtpPacketTool::Int32ToString(valueInt32, outStr);
    uint32_t valueUInt32 = provider->ConsumeIntegral<uint32_t>();
    MtpPacketTool::UInt32ToString(valueUInt32, outStr);
    int64_t valueInt64 = provider->ConsumeIntegral<int64_t>();
    MtpPacketTool::Int64ToString(valueInt64, outStr);
    uint64_t valueUInt64 = provider->ConsumeIntegral<uint64_t>();
    MtpPacketTool::UInt64ToString(valueUInt64, outStr);
    int32_t valueInt32First = provider->ConsumeIntegral<int32_t>();
    int32_t valueInt32Second = provider->ConsumeIntegral<int32_t>();
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    MtpPacketTool::Int128ToString(valueInt128, outStr);
    uint32_t valueUInt32First = provider->ConsumeIntegral<uint32_t>();
    uint32_t valueUInt32Second = provider->ConsumeIntegral<uint32_t>();
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::UInt128ToString(valueUInt128, outStr);
}

static void MtpPacketToolGetNameTest()
{
    uint16_t code = provider->ConsumeIntegral<uint16_t>();
    MtpPacketTool::GetOperationName(code);
    code = provider->ConsumeIntegral<uint16_t>();
    MtpPacketTool::GetEventName(code);
    code = provider->ConsumeIntegral<uint16_t>();
    MtpPacketTool::GetFormatName(code);
    code = provider->ConsumeIntegral<uint16_t>();
    MtpPacketTool::GetObjectPropName(code);
    code = provider->ConsumeIntegral<uint16_t>();
    MtpPacketTool::GetEventName(code);

    time_t sec = 0;
    MtpPacketTool::FormatDateTime(sec);
    int type = provider->ConsumeIntegral<int32_t>();
    MtpPacketTool::GetDataTypeName(type);
    type = provider->ConsumeIntegral<int32_t>();
    MtpPacketTool::GetAssociationName(type);

    uint16_t propCode = provider->ConsumeIntegral<uint16_t>();
    MtpPacketTool::GetObjectPropTypeByPropCode(propCode);
}

static void MtpPacketToolOtherTest()
{
    MtpPacketTool::GetIndentBlank();
    size_t indent = provider->ConsumeIntegral<int32_t>();
    MtpPacketTool::GetIndentBlank(indent);
    vector<uint8_t> dumpData = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    MtpPacketTool::Dump(dumpData);
    unique_ptr<char[]> hexBuf;
    int hexBufSize = provider->ConsumeIntegral<int32_t>();
    unique_ptr<char[]> txtBuf;
    int txtBufSize = provider->ConsumeIntegral<int32_t>();
    MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);

    uint8_t u8 = provider->ConsumeIntegral<uint8_t>();
    MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);

    string str = provider->ConsumeBytesAsString(NUM_BYTES);
    hexBuf = make_unique<char[]>('a');
    txtBuf = make_unique<char[]>('a');
    MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);

    MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);

    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
    hexBuf[OFFSET_0] = '\0';
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
}

static void MtpPacketToolTest()
{
    MtpPacketToolPutTest();
    MtpPacketToolGetTest();
    MtpPacketToolGetUInt8Test();
    MtpPacketToolGetUInt16Test();
    MtpPacketToolGetUInt32Test();
    MtpPacketToolGetUInt64Test();
    MtpPacketToolGetUInt128Test();
    MtpPacketToolGetInt8Test();
    MtpPacketToolGetInt16Test();
    MtpPacketToolGetInt32Test();
    MtpPacketToolGetInt64Test();
    MtpPacketToolGetInt128Test();
    MtpPacketToolGetStringTest();
    MtpPacketToolToStringTest();
    MtpPacketToolGetNameTest();
    MtpPacketToolOtherTest();
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
    OHOS::MtpPacketToolTest();
    return 0;
}