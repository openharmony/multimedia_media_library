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
#include "medialibrary_mtp_headerdata_fuzzer.h"

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
#include "header_data.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
const int32_t EVEN = 2;
static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
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

static void HeaderDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(context);

    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();

    headerData->Parser(buffer, readSize);
    headerData->Maker(buffer);

    const int32_t uInt32Count = 2;
    const int32_t uInt16Count = 2;
    if (data == nullptr || size < (sizeof(uint32_t) * uInt32Count +
        sizeof(uint16_t) * uInt16Count)) {
        return;
    }
    int32_t offset = 0;
    headerData->SetCode(FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    headerData->SetContainerLength(FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    headerData->SetContainerType(FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    headerData->SetTransactionId(FuzzUInt32(data + offset, size));

    headerData->GetCode();
    headerData->GetContainerLength();
    headerData->GetContainerType();
    headerData->GetTransactionId();

    headerData->Reset();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::HeaderDataTest(data, size);
    return 0;
}