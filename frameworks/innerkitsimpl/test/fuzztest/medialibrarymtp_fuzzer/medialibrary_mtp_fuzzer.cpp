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
#include "medialibrary_mtp_fuzzer.h"

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
#include "media_log.h"

#define private public
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_driver.h"
#include "mtp_error_utils.h"
#include "mtp_event.h"
#include "mtp_file_observer.h"
#include "mtp_manager.h"
#include "mtp_monitor.h"
#include "mtp_operation.h"
#include "mtp_packet.h"
#include "mtp_service.h"
#include "mtp_storage_manager.h"
#include "mtp_store_observer.h"
#include "packet_payload_factory.h"
#include "ptp_album_handles.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;

static const int32_t NUM_BYTES = 1;
static const int32_t MAX_MTP_MODE = 2;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
FuzzedDataProvider *provider = nullptr;

static inline vector<uint32_t> FuzzVectorUInt32()
{
    return {provider->ConsumeIntegral<uint32_t>()};
}

static inline MtpManager::MtpMode FuzzMtpMode()
{
    int32_t mode = provider->ConsumeIntegralInRange<int32_t>(0, MAX_MTP_MODE);
    return static_cast<MtpManager::MtpMode>(mode);
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

static void MtpDriverTest()
{
    shared_ptr<MtpDriver> mtpDriver = make_shared<MtpDriver>();
    mtpDriver->OpenDriver();

    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    uint32_t sizeBuf = buffer.size();
    int32_t result = provider->ConsumeIntegral<int32_t>();
    mtpDriver->Read(buffer, sizeBuf);
    mtpDriver->Write(buffer, sizeBuf, result);
    MtpFileRange mfr;
    mtpDriver->SendObj(mfr);
    mtpDriver->ReceiveObj(mfr);

    EventMtp me;
    me.data = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    me.length = me.data.size();
    mtpDriver->WriteEvent(me);
    mtpDriver->CloseDriver();
}

static void MtpErrorUtilsTest()
{
    const int32_t mediaError = provider->ConsumeIntegral<int32_t>();
    MtpErrorUtils::SolveGetHandlesError(mediaError);
    MtpErrorUtils::SolveGetObjectInfoError(mediaError);
    MtpErrorUtils::SolveSendObjectInfoError(mediaError);
    MtpErrorUtils::SolveMoveObjectError(mediaError);
    MtpErrorUtils::SolveCopyObjectError(mediaError);
    MtpErrorUtils::SolveDeleteObjectError(mediaError);
    MtpErrorUtils::SolveObjectPropValueError(mediaError);
    MtpErrorUtils::SolveCloseFdError(mediaError);
}

static void MtpEventTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    string path = provider->ConsumeBytesAsString(NUM_BYTES);
    uint32_t handle = provider->ConsumeIntegral<uint32_t>();
    string fsUuid = provider->ConsumeBytesAsString(NUM_BYTES);
    mtpEvent->SendObjectAdded(path);
    mtpEvent->SendObjectRemoved(path);
    mtpEvent->SendObjectRemovedByHandle(handle);
    mtpEvent->SendObjectInfoChanged(path);
    mtpEvent->SendDevicePropertyChanged();
    mtpEvent->SendStoreAdded(fsUuid);
    mtpEvent->SendStoreRemoved(fsUuid);
}

static void MtpFileObserverTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<MtpFileObserver> mtpFileObserver = make_shared<MtpFileObserver>();
    string path = provider->ConsumeBytesAsString(NUM_BYTES);
    string realPath = provider->ConsumeBytesAsString(NUM_BYTES);
    mtpFileObserver->StartFileInotify();
    mtpFileObserver->AddFileInotify(path, realPath, context);
    mtpFileObserver->AddPathToWatchMap(path);
    mtpFileObserver->StopFileInotify();
}

static void MtpManagerTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    MtpManager::GetInstance().Init();
    MtpManager::GetInstance().StartMtpService(FuzzMtpMode());
    MtpManager::GetInstance().IsMtpMode();
    string key = "persist.edm.mtp_server_disable";
    string value = provider->ConsumeBytesAsString(NUM_BYTES);
    MtpManager::GetInstance().OnMtpParamDisableChanged(key.c_str(), value.c_str(), context.get());
    MtpManager::GetInstance().StopMtpService();
}

static void MtpMonitorTest()
{
    shared_ptr<MtpMonitor> mtpMonitor = make_shared<MtpMonitor>();
    mtpMonitor->Start();
    mtpMonitor->Stop();
}

static void MtpOperationTest()
{
    shared_ptr<MtpOperation> mtpOperation = make_shared<MtpOperation>();
    mtpOperation->mtpContextPtr_->operationCode = provider->ConsumeIntegral<int32_t>();
    mtpOperation->Execute();
    mtpOperation->Stop();
    for (size_t i = 0; i < MTP_OPERATIONS_LIST.size(); ++i) {
        mtpOperation->mtpContextPtr_->operationCode = MTP_OPERATIONS_LIST[i];
        mtpOperation->Execute();
        mtpOperation->Stop();
    }
}

static void MtpPacketTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<MtpPacket> mtpPacket = make_shared<MtpPacket>(context);
    mtpPacket->Parser();
    mtpPacket->ParserHead();
    mtpPacket->ParserPayload();
    mtpPacket->MakeHead();
    mtpPacket->MakerPayload();
    mtpPacket->GetOperationCode();
    mtpPacket->GetTransactionId();
    mtpPacket->GetSessionID();

    uint16_t operationCode = provider->ConsumeIntegral<uint16_t>();
    mtpPacket->IsNeedDataPhase(operationCode);
    mtpPacket->IsI2R(operationCode);
    mtpPacket->Reset();
}

static void MtpServiceTest()
{
    shared_ptr<MtpService> mtpService = make_shared<MtpService>();
    mtpService->StartService();
    mtpService->StopService();
}

static void MtpStoreObserverTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    EventFwk::CommonEventData eventData;
    EventFwk::MatchingSkills matchingSkills;
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    shared_ptr<MtpStoreObserver> mtpStoreObserver = make_shared<MtpStoreObserver>(subscriberInfo);
    mtpStoreObserver->StartObserver();
    mtpStoreObserver->AttachContext(context);
    mtpStoreObserver->OnReceiveEvent(eventData);
    mtpStoreObserver->StopObserver();
}

static void PacketPayloadFactoryTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<PacketPayloadFactory> packetPayloadFactory = make_shared<PacketPayloadFactory>();
    uint16_t stage = provider->ConsumeIntegral<uint16_t>();
    for (size_t i = 0; i < MTP_OPERATIONS_LIST.size(); ++i) {
        uint16_t code = MTP_OPERATIONS_LIST[i];
        packetPayloadFactory->CreatePayload(context, code, stage);
    }
}

static void PtpAlbumHandlesTest()
{
    shared_ptr<PtpAlbumHandles> ptpAlbumHandles = PtpAlbumHandles::GetInstance();
    int32_t value = provider->ConsumeIntegral<int32_t>();
    ptpAlbumHandles->AddHandle(value);
    ptpAlbumHandles->RemoveHandle(value);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    ptpAlbumHandles->AddAlbumHandles(resultSet);
    ptpAlbumHandles->FindHandle(value);
    std::set<int32_t> albumIds;
    albumIds.insert(0);
    ptpAlbumHandles->dataHandles_.push_back(provider->ConsumeIntegral<int32_t>());
    std::vector<int32_t> removeIds;
    ptpAlbumHandles->UpdateHandle(albumIds, removeIds);
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
    OHOS::MtpDriverTest();
    OHOS::MtpErrorUtilsTest();
    OHOS::MtpEventTest();
    OHOS::MtpFileObserverTest();
    OHOS::MtpManagerTest();
    OHOS::MtpMonitorTest();
    OHOS::MtpOperationTest();
    OHOS::MtpPacketTest();
    OHOS::MtpServiceTest();
    OHOS::MtpStoreObserverTest();
    OHOS::PacketPayloadFactoryTest();
    OHOS::PtpAlbumHandlesTest();
    return 0;
}
