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
#include "medialibrary_mtpptpproxy_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "mtp_ptp_const.h"
#include "close_session_data.h"
#include "media_log.h"
#include "medialibrary_errno.h"

#define private public
#include "mtp_ptp_proxy.h"
#include "mtp_manager.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;

static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
const int32_t NUM_BYTES = 1;
FuzzedDataProvider *provider = nullptr;
const uint32_t OFFSET = 5;

constexpr int FUZZ_STORAGE_MANAGER_MANAGER_ID = 5003;

static MtpOperationContext FuzzMtpOperationContext()
{
    MtpOperationContext context;

    context.operationCode = provider->ConsumeIntegral<uint32_t>();
    context.transactionID = provider->ConsumeIntegral<uint32_t>();
    context.devicePropertyCode = provider->ConsumeIntegral<uint32_t>();
    context.storageID = provider->ConsumeIntegral<uint32_t>();
    context.format = provider->ConsumeIntegral<uint16_t>();
    context.parent = provider->ConsumeIntegralInRange<uint32_t>(PTP_IN_MTP_ID - OFFSET, PTP_IN_MTP_ID + OFFSET);
    context.handle = provider->ConsumeIntegralInRange<uint32_t>(PTP_IN_MTP_ID - OFFSET, PTP_IN_MTP_ID + OFFSET);
    context.property = provider->ConsumeIntegral<uint32_t>();
    context.groupCode = provider->ConsumeIntegral<uint32_t>();
    context.depth = provider->ConsumeIntegral<uint32_t>();
    context.properStrValue = provider->ConsumeBytesAsString(NUM_BYTES);
    context.properIntValue = provider->ConsumeIntegral<int64_t>();
    vector<uint32_t> handles = {provider->ConsumeIntegral<uint32_t>()};
    context.handles = make_shared<UInt32List>(handles),
    context.name = provider->ConsumeBytesAsString(NUM_BYTES);
    context.created = provider->ConsumeBytesAsString(NUM_BYTES);
    context.modified = provider->ConsumeBytesAsString(NUM_BYTES);
    context.indata = provider->ConsumeBool();
    context.storageInfoID = provider->ConsumeIntegral<uint32_t>();
    context.sessionOpen = provider->ConsumeBool();
    context.sessionID = provider->ConsumeIntegral<uint32_t>();
    context.tempSessionID = provider->ConsumeIntegral<uint32_t>();
    context.eventHandle = provider->ConsumeIntegral<uint32_t>();
    context.eventProperty = provider->ConsumeIntegral<uint32_t>();
    return context;
}

// proxy test
static void ProxyInit(std::shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
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
    const sptr<OHOS::IRemoteObject> token = remoteObj;
    proxy.Init(remoteObj, context);
}

static void ProxyGetHandlesTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::shared_ptr<UInt32List> handles = std::make_shared<UInt32List>();
    bool isMac = provider->ConsumeBool();
    proxy.GetHandles(context, handles, isMac);
}

static void ProxyGetObjectInfoTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::shared_ptr<ObjectInfo> objectInfo = std::make_shared<ObjectInfo>(0);
    proxy.GetObjectInfo(context, objectInfo);
}

static void ProxyGetObjectPropValueTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint64_t intVal;
    uint128_t longVal;
    std::string strVal;
    proxy.GetObjectPropValue(context, intVal, longVal, strVal);
}

static void ProxySetObjectPropValueTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    proxy.SetObjectPropValue(context);
}

static void ProxyGetObjectPropListTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext());
    auto proxy = MtpPtpProxy::GetInstance();
    ProxyInit(context, proxy);
    std::shared_ptr<std::vector<Property>> properties;
    proxy.GetObjectPropList(context, properties);
}

static void ProxyGetReadFdTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t fd;
    proxy.GetReadFd(context, fd);
}

static void ProxyCloseReadFdTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t fd = provider->ConsumeIntegral<int32_t>();
    proxy.CloseReadFd(context, fd);
}

static void ProxyGetWriteFdTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t fd = 0;
    proxy.GetWriteFd(context, fd);
}

static void ProxyCloseWriteFdTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t fd = provider->ConsumeIntegral<int32_t>();
    proxy.CloseWriteFd(context, fd);
}

static void ProxyGetModifyObjectInfoPathByIdTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t handle = provider->ConsumeIntegral<int32_t>();
    std::string path = "";
    proxy.GetModifyObjectInfoPathById(handle, path);
}

static void ProxyGetMtpPathByIdTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t handle = provider->ConsumeIntegral<int32_t>();
    std::string path = "";
    proxy.GetMtpPathById(handle, path);
}

static void ProxyGetThumbTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::shared_ptr<UInt8List> outThumb;
    proxy.GetThumb(context, outThumb);
}

static void ProxySendObjectInfoTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t storageId = provider->ConsumeIntegral<uint32_t>();
    uint32_t parent = provider->ConsumeIntegral<uint32_t>();
    uint32_t handle = provider->ConsumeIntegral<uint32_t>();
    proxy.SendObjectInfo(context, storageId, parent, handle);
}

static void ProxyDeleteObjectTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    proxy.DeleteObject(context);
}

static void ProxyMoveObjectTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t repeatHandle = 0;
    proxy.MoveObject(context, repeatHandle);
}

static void ProxyCopyObjectTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t oldHandle = provider->ConsumeIntegral<uint32_t>();
    uint32_t outHandle = 0;
    proxy.CopyObject(context, outHandle, oldHandle);
}

static void ProxyGetMtpStorageIdsTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    proxy.GetMtpStorageIds();
}

static void ProxyGetIdByPathTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::string path = provider->ConsumeBytesAsString(NUM_BYTES);
    uint32_t outId = 0;
    proxy.GetIdByPath(path, outId);
}

static void ProxyGetPathByHandleTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t handle = provider->ConsumeIntegral<uint32_t>();
    std::string outPath = "";
    std::string outRealPath = "";
    proxy.GetPathByHandle(handle, outPath, outRealPath);
}

static void ProxyDeleteCanceledObjectTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t handle = provider->ConsumeIntegral<uint32_t>();
    std::string path = provider->ConsumeBytesAsString(NUM_BYTES);
    proxy.DeleteCanceledObject(path, handle);
}

static void ProxyIsMtpExistObjectTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    proxy.IsMtpExistObject(context);
}

static void ProxyMtpTryAddExternalStorageTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t storageId = provider->ConsumeIntegral<uint32_t>();
    std::string fsUuid = provider->ConsumeBytesAsString(NUM_BYTES);
    proxy.MtpTryAddExternalStorage(fsUuid, storageId);
}

static void ProxyMtpTryRemoveExternalStorageTest(shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t storageId = provider->ConsumeIntegral<uint32_t>();
    std::string fsUuid = provider->ConsumeBytesAsString(NUM_BYTES);
    proxy.MtpTryRemoveExternalStorage(fsUuid, storageId);
}

static void MtpPtpProxyTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext());
    auto proxy = MtpPtpProxy::GetInstance();
    ProxyInit(context, proxy);

    uint32_t mode = provider->ConsumeIntegralInRange<uint32_t>(0, 2);
    MtpManager::GetInstance().mtpMode_ = MtpManager::MtpMode(mode);

    ProxyGetHandlesTest(context, proxy);
    ProxyGetObjectInfoTest(context, proxy);
    ProxyGetObjectPropValueTest(context, proxy);
    ProxySetObjectPropValueTest(context, proxy);
    ProxyGetObjectPropListTest();
    ProxyGetReadFdTest(context, proxy);
    ProxyCloseReadFdTest(context, proxy);
    ProxyGetWriteFdTest(context, proxy);
    ProxyCloseWriteFdTest(context, proxy);
    ProxyGetModifyObjectInfoPathByIdTest(context, proxy);
    ProxyGetMtpPathByIdTest(context, proxy);
    ProxyGetThumbTest(context, proxy);
    ProxySendObjectInfoTest(context, proxy);
    ProxyDeleteObjectTest(context, proxy);
    ProxyMoveObjectTest(context, proxy);
    ProxyCopyObjectTest(context, proxy);
    ProxyGetMtpStorageIdsTest(context, proxy);
    ProxyGetIdByPathTest(context, proxy);
    ProxyGetPathByHandleTest(context, proxy);
    ProxyDeleteCanceledObjectTest(context, proxy);
    ProxyIsMtpExistObjectTest(context, proxy);
    ProxyMtpTryAddExternalStorageTest(context, proxy);
    ProxyMtpTryRemoveExternalStorageTest(context, proxy);
}

static int32_t AddSeed()
{
    char *seedData = new char[OHOS::SEED_SIZE];
    for (int i = 0; i < OHOS::SEED_SIZE; i++) {
        seedData[i] = static_cast<char>(i % MAX_BYTE_VALUE);
    }

    std::string filename = "corpus/seed.txt";
    std::ofstream file(filename.c_str(), std::ios::binary | std::ios::trunc);
    if (!file) {
        MEDIA_ERR_LOG("Cannot open file filename:%{public}s", filename.c_str());
        delete[] seedData;
        return Media::E_ERR;
    }
    file.write(seedData, OHOS::SEED_SIZE);
    file.close();
    delete[] seedData;
    MEDIA_INFO_LOG("seedData has been successfully written to file filename:%{public}s", filename.c_str());
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
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    
    OHOS::MtpPtpProxyTest();
    return 0;
}
