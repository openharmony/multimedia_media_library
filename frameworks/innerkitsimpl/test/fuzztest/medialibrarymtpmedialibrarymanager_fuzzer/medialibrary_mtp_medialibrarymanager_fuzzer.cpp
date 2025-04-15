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
#include "medialibrary_mtp_medialibrarymanager_fuzzer.h"

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
#include "mtp_medialibrary_manager.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
const int32_t EVEN = 2;
constexpr int FUZZ_STORAGE_MANAGER_MANAGER_ID = 5003;
const shared_ptr<MtpMedialibraryManager> ptpMediaLib_ = MtpMedialibraryManager::GetInstance();
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

static inline vector<int32_t> FuzzVectorInt32(const uint8_t *data, size_t size)
{
    return {FuzzInt32(data, size)};
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

// MtpMedialibraryManagerTest start
static void PtpGetHandlesTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(uint32_t)) {
        return;
    }
    int32_t offset = 0;
    int32_t parentId = FuzzBool(data, size) ? 0 : FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MediaType mediaType = MediaType::MEDIA_TYPE_IMAGE;
    vector<int> outHandle = FuzzVectorInt32(data + offset, size);
    offset += sizeof(int32_t);
    ptpMediaLib_->GetHandles(parentId, outHandle, mediaType);

    uint32_t outId = 0;
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32(data + offset, size));
    ptpMediaLib_->GetIdByPath(FuzzString(data, size), outId);
    context->parent = outId;
    context->storageID = outId;
    ptpMediaLib_->GetHandles(context, outHandles);
}

static void PtpSendObjectInfoTest(const uint8_t* data, size_t size)
{
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

    ptpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);
}

static void PtpHaveMovingPhotesHandleTest(const uint8_t* data, size_t size)
{
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    const int32_t uInt32Count = 2;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    const uint32_t parent = FuzzUInt32(data + offset, size);
    ptpMediaLib_->HaveMovingPhotesHandle(resultSet, outHandles, parent);
    ptpMediaLib_->GetSizeFromOfft(size);
    ptpMediaLib_->GetBurstKeyFromPhotosInfo();
    ptpMediaLib_->Clear();
}

static void MtpMedialibraryManagerTest(const uint8_t* data, size_t size)
{
    PtpGetHandlesTest(data, size);
    PtpSendObjectInfoTest(data, size);
    PtpHaveMovingPhotesHandleTest(data, size);
}

static void InitMtpMedialibraryManager()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("Get system ability mgr failed.");
        return;
    }
    auto remoteObj = saManager->GetSystemAbility(FUZZ_STORAGE_MANAGER_MANAGER_ID);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service Failed.");
        return;
    }
    sptr<IRemoteObject> token = remoteObj;
    ptpMediaLib_->Init(token, context);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::InitMtpMedialibraryManager();
    OHOS::MtpMedialibraryManagerTest(data, size);
    return 0;
}