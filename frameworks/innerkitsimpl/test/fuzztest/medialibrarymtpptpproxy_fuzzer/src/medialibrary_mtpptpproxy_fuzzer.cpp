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

constexpr int FUZZ_STORAGE_MANAGER_MANAGER_ID = 5003;

static MtpOperationContext FuzzMtpOperationContext(const uint8_t* data, size_t size)
{
    MtpOperationContext context;

    context.operationCode = provider->ConsumeIntegral<u_int32_t>();
    context.transactionID = provider->ConsumeIntegral<u_int32_t>();
    context.devicePropertyCode = provider->ConsumeIntegral<u_int32_t>();
    context.storageID = provider->ConsumeIntegral<u_int32_t>();
    context.format = provider->ConsumeIntegral<u_int16_t>();
    context.parent = provider->ConsumeIntegralInRange<uint32_t>(PTP_IN_MTP_ID - 5, PTP_IN_MTP_ID + 5);
    context.handle = provider->ConsumeIntegralInRange<uint32_t>(PTP_IN_MTP_ID - 5, PTP_IN_MTP_ID + 5);
    context.property = provider->ConsumeIntegral<u_int32_t>();
    context.groupCode = provider->ConsumeIntegral<u_int32_t>();
    context.depth = provider->ConsumeIntegral<u_int32_t>();
    context.properStrValue = provider->ConsumeBytesAsString(NUM_BYTES);
    context.properIntValue = provider->ConsumeIntegral<int64_t>();
    vector<uint32_t> handles = {provider->ConsumeIntegral<u_int32_t>()};
    context.handles = make_shared<UInt32List>(handles),
    context.name = provider->ConsumeBytesAsString(NUM_BYTES);
    context.created = provider->ConsumeBytesAsString(NUM_BYTES);
    context.modified = provider->ConsumeBytesAsString(NUM_BYTES);
    context.indata = provider->ConsumeBool();
    context.storageInfoID = provider->ConsumeIntegral<u_int32_t>();
    context.sessionOpen = provider->ConsumeBool();
    context.sessionID = provider->ConsumeIntegral<u_int32_t>();
    context.tempSessionID = provider->ConsumeIntegral<u_int32_t>();
    context.eventHandle = provider->ConsumeIntegral<u_int32_t>();
    context.eventProperty = provider->ConsumeIntegral<u_int32_t>();
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

static void ProxyGetHandlesTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::shared_ptr<UInt32List> handles = std::make_shared<UInt32List>();
    bool isMac = provider->ConsumeBool();
    proxy.GetHandles(context, handles, isMac);
}

static void ProxyGetObjectInfoTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::shared_ptr<ObjectInfo> objectInfo = std::make_shared<ObjectInfo>(0);
    proxy.GetObjectInfo(context, objectInfo);
}

static void ProxyGetObjectPropValueTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint64_t intVal;
    uint128_t longVal;
    std::string strVal;
    proxy.GetObjectPropValue(context, intVal, longVal, strVal);
}

static void ProxySetObjectPropValueTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    proxy.SetObjectPropValue(context);
}

static void ProxyGetObjectPropListTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::shared_ptr<std::vector<Property>> properties;
    proxy.GetObjectPropList(context, properties);
}

static void ProxyGetReadFdTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t fd;
    proxy.GetReadFd(context, fd);
}

static void ProxyCloseReadFdTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t fd = provider->ConsumeIntegral<int32_t>();
    proxy.CloseReadFd(context, fd);
}

static void ProxyGetWriteFdTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t fd = 0;
    proxy.GetWriteFd(context, fd);
}

static void ProxyCloseWriteFdTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t fd = provider->ConsumeIntegral<int32_t>();
    proxy.CloseWriteFd(context, fd);
}

static void ProxyGetModifyObjectInfoPathByIdTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t handle = provider->ConsumeIntegral<int32_t>();
    std::string path = "";
    proxy.GetModifyObjectInfoPathById(handle, path);
}

static void ProxyGetMtpPathByIdTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    int32_t handle = provider->ConsumeIntegral<int32_t>();
    std::string path = "";
    proxy.GetMtpPathById(handle, path);
}

static void ProxyGetThumbTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::shared_ptr<UInt8List> outThumb;
    proxy.GetThumb(context, outThumb);
}

static void ProxySendObjectInfoTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t storageId = provider->ConsumeIntegral<u_int32_t>();
    uint32_t parent = provider->ConsumeIntegral<u_int32_t>();
    uint32_t handle = provider->ConsumeIntegral<u_int32_t>();
    proxy.SendObjectInfo(context, storageId, parent, handle);
}

static void ProxyDeleteObjectTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    proxy.DeleteObject(context);
}

static void ProxyMoveObjectTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t repeatHandle = 0;
    proxy.MoveObject(context, repeatHandle);
}

static void ProxyCopyObjectTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t oldHandle = provider->ConsumeIntegral<u_int32_t>();
    uint32_t outHandle = 0;
    proxy.CopyObject(context, outHandle, oldHandle);
}

static void ProxyGetMtpStorageIdsTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    proxy.GetMtpStorageIds();
}

static void ProxyGetIdByPathTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    std::string path = provider->ConsumeBytesAsString(NUM_BYTES);
    uint32_t outId = 0;
    proxy.GetIdByPath(path, outId);
}

static void ProxyGetPathByHandleTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t handle = provider->ConsumeIntegral<u_int32_t>();
    std::string outPath = "";
    std::string outRealPath = "";
    proxy.GetPathByHandle(handle, outPath, outRealPath);
}

static void ProxyDeleteCanceledObjectTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t handle = provider->ConsumeIntegral<u_int32_t>();
    std::string path = provider->ConsumeBytesAsString(NUM_BYTES);
    proxy.DeleteCanceledObject(path, handle);
}

static void ProxyIsMtpExistObjectTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    proxy.IsMtpExistObject(context);
}

static void ProxyMtpTryAddExternalStorageTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t storageId = provider->ConsumeIntegral<u_int32_t>();
    std::string fsUuid = provider->ConsumeBytesAsString(NUM_BYTES);
    proxy.MtpTryAddExternalStorage(fsUuid, storageId);
}

static void ProxyMtpTryRemoveExternalStorageTest(const uint8_t* data, size_t size,
    shared_ptr<MtpOperationContext> context, MtpPtpProxy& proxy)
{
    uint32_t storageId = provider->ConsumeIntegral<u_int32_t>();
    std::string fsUuid = provider->ConsumeBytesAsString(NUM_BYTES);
    proxy.MtpTryRemoveExternalStorage(fsUuid, storageId);
}

static void MtpPtpProxyTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    auto proxy = MtpPtpProxy::GetInstance();
    ProxyInit(context, proxy);

    uint32_t mode = provider->ConsumeIntegralInRange<uint32_t>(0, 2);
    MEDIA_INFO_LOG("MtpMode: %{public}d, parent: %{public}d, handle: %{public}d,", mode, context->parent, context->handle);
    MtpManager::GetInstance().mtpMode_ = MtpManager::MtpMode(mode);

    ProxyGetHandlesTest(data, size, context, proxy);
    ProxyGetObjectInfoTest(data, size, context, proxy);
    ProxyGetObjectPropValueTest(data, size, context, proxy);
    ProxySetObjectPropValueTest(data, size, context, proxy);
    ProxyGetObjectPropListTest(data, size, context, proxy);
    ProxyGetReadFdTest(data, size, context, proxy);
    ProxyCloseReadFdTest(data, size, context, proxy);
    ProxyGetWriteFdTest(data, size, context, proxy);
    ProxyCloseWriteFdTest(data, size, context, proxy);
    ProxyGetModifyObjectInfoPathByIdTest(data, size, context, proxy);
    ProxyGetMtpPathByIdTest(data, size, context, proxy);
    ProxyGetThumbTest(data, size, context, proxy);
    ProxySendObjectInfoTest(data, size, context, proxy);
    ProxyDeleteObjectTest(data, size, context, proxy);
    ProxyMoveObjectTest(data, size, context, proxy);
    ProxyCopyObjectTest(data, size, context, proxy);
    ProxyGetMtpStorageIdsTest(data, size, context, proxy);
    ProxyGetIdByPathTest(data, size, context, proxy);
    ProxyGetPathByHandleTest(data, size, context, proxy);
    ProxyDeleteCanceledObjectTest(data, size, context, proxy);
    ProxyIsMtpExistObjectTest(data, size, context, proxy);
    ProxyMtpTryAddExternalStorageTest(data, size, context, proxy);
    ProxyMtpTryRemoveExternalStorageTest(data, size, context, proxy);
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
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    
    OHOS::MtpPtpProxyTest(data, size);
    return 0;
}
