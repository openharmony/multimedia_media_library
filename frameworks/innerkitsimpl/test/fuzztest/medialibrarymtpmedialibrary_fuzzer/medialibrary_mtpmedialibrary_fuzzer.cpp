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
#include "medialibrary_mtpmedialibrary_fuzzer.h"

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
#include "mtp_media_library.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
const int32_t EVEN = 2;
// storage file
const std::string STORAGE_FILE = "/storage/media/local/files/Docs";
// file path
const string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
const shared_ptr<MtpMediaLibrary> mtpMediaLib_ = MtpMediaLibrary::GetInstance();
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

//MtpMediaLibraryTest start
static void GetThumbTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    if (data == nullptr || size < (sizeof(uint32_t) + sizeof(uint8_t))) {
        return;
    }
    int32_t offset = 0;
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>(FuzzVectorUInt8(data + offset, size));
    offset += sizeof(uint8_t);
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + FuzzString(data, size) +
        ".txt", FuzzUInt32(data + offset, size));
    mtpMediaLib_->GetThumb(context, outThumb);
}

static void SendObjectInfoTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    const int32_t uInt32Count = 3;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    uint32_t outStorageID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t outParent = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t outHandle = FuzzUInt32(data + offset, size);

    mtpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);

    context->format = MTP_FORMAT_ASSOCIATION_CODE;
    mtpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);
}

static void CopyObjectTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    const int32_t uInt32Count = 3;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + FuzzString(data, size), FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    uint32_t outObjectHandle = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t oldHandle = FuzzUInt32(data + offset, size);
    mtpMediaLib_->CopyObject(context, outObjectHandle, oldHandle);
    mtpMediaLib_->DeleteObject(context);
}

static void GetObjectPropValueTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    string outStrVal = "";
    const int32_t uInt32Count = 2;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    mtpMediaLib_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
    mtpMediaLib_->DeleteHandlePathMap(FuzzString(data, size), FuzzUInt32(data + offset, size));
}

static void ModifyHandlePathMapTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    const int32_t uInt32Count = 2;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);

    mtpMediaLib_->ModifyHandlePathMap(FuzzString(data, size), FuzzString(data, size));

    uint32_t id = FuzzUInt32(data + offset, size);
    mtpMediaLib_->ModifyPathHandleMap(FuzzString(data, size), id);
}

static void MoveObjectSubTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    const int32_t uInt32Count = 2;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);

    mtpMediaLib_->AddToHandlePathMap(FILE_PATH, 1);
    bool isDir = FuzzBool(data, size);
    uint32_t repeatHandle = FuzzUInt32(data + offset, size);
    mtpMediaLib_->MoveObjectSub(FILE_PATH, FuzzString(data, size), isDir, repeatHandle);
}

static void MtpMediaLibraryTest(const uint8_t* data, size_t size)
{
    GetThumbTest(data, size);
    SendObjectInfoTest(data, size);
    CopyObjectTest(data, size);
    GetObjectPropValueTest(data, size);
    ModifyHandlePathMapTest(data, size);
    MoveObjectSubTest(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MtpMediaLibraryTest(data, size);
    return 0;
}