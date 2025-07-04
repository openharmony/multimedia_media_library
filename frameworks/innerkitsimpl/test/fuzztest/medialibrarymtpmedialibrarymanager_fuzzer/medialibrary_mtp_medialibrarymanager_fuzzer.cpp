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
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>

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
static const int32_t NUM_BYTES = 1;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
constexpr int FUZZ_STORAGE_MANAGER_MANAGER_ID = 5003;
// file path
const string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
const shared_ptr<MtpMedialibraryManager> ptpMediaLib_ = MtpMedialibraryManager::GetInstance();
FuzzedDataProvider *provider = nullptr;

static inline vector<int32_t> FuzzVectorInt32()
{
    return {provider->ConsumeIntegral<int32_t>()};
}

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

static ObjectInfo FuzzObjectInfo()
{
    ObjectInfo objectInfo(0);
    objectInfo.handle = provider->ConsumeIntegral<uint32_t>();
    objectInfo.storageID = provider->ConsumeIntegral<uint32_t>();
    objectInfo.format = provider->ConsumeIntegral<uint16_t>();
    objectInfo.protectionStatus = provider->ConsumeIntegral<uint16_t>();
    objectInfo.compressedSize = provider->ConsumeIntegral<uint32_t>();
    objectInfo.size = provider->ConsumeIntegral<uint32_t>();
    objectInfo.thumbFormat = provider->ConsumeIntegral<uint16_t>();
    objectInfo.thumbCompressedSize = provider->ConsumeIntegral<uint32_t>();
    objectInfo.thumbPixelWidth = provider->ConsumeIntegral<uint32_t>();
    objectInfo.thumbPixelHeight = provider->ConsumeIntegral<uint32_t>();
    objectInfo.imagePixelWidth = provider->ConsumeIntegral<uint32_t>();
    objectInfo.imagePixelHeight = provider->ConsumeIntegral<uint32_t>();
    objectInfo.imagePixelDepth = provider->ConsumeIntegral<uint32_t>();
    objectInfo.parent = provider->ConsumeIntegral<uint32_t>();
    objectInfo.associationType = provider->ConsumeIntegral<uint16_t>();
    objectInfo.associationDesc = provider->ConsumeIntegral<uint32_t>();
    objectInfo.sequenceNumber = provider->ConsumeIntegral<uint32_t>();
    objectInfo.name = provider->ConsumeBytesAsString(NUM_BYTES);
    objectInfo.keywords = provider->ConsumeBytesAsString(NUM_BYTES);
    return objectInfo;
}

// MtpMedialibraryManagerTest start
static void PtpGetHandlesTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    int32_t parentId = provider->ConsumeBool() ? 0 : provider->ConsumeIntegral<int32_t>();
    MediaType mediaType = MediaType::MEDIA_TYPE_IMAGE;
    vector<int> outHandle = FuzzVectorInt32();
    ptpMediaLib_->GetHandles(parentId, outHandle, mediaType);

    uint32_t outId = 0;
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32());
    ptpMediaLib_->GetIdByPath(provider->ConsumeBytesAsString(NUM_BYTES), outId);
    context->parent = outId;
    context->storageID = outId;
    ptpMediaLib_->GetHandles(context, outHandles);
}

static void PtpGetObjectInfoTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(FuzzObjectInfo());
    ptpMediaLib_->GetObjectInfo(context, objectInfo);

    context->handle = COMMON_PHOTOS_OFFSET;
    ptpMediaLib_->GetObjectInfo(context, objectInfo);
}

static void PtpGetFdTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = nullptr;
    bool condition = false;
    int fd = 0;
    ptpMediaLib_->CondCloseFd(condition, fd);

    int32_t outFd = provider->ConsumeIntegral<int32_t>();
    string mode = provider->ConsumeBytesAsString(NUM_BYTES);
    ptpMediaLib_->GetFd(context, outFd, mode);
}

static void PtpGetThumbTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>(provider->ConsumeBytes<uint8_t>(NUM_BYTES));
    ptpMediaLib_->GetThumb(context, outThumb);
}

static void PtpSendObjectInfoTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    uint32_t outStorageID = provider->ConsumeIntegral<uint32_t>();
    uint32_t outParent = provider->ConsumeIntegral<uint32_t>();
    uint32_t outHandle = provider->ConsumeIntegral<uint32_t>();
    ptpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);
}

static void PtpMoveObjectTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    ptpMediaLib_->MoveObject(context);
}

static void PtpCopyObjectTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    uint32_t outObjectHandle = provider->ConsumeIntegral<uint32_t>();
    context->handle = EDITED_PHOTOS_OFFSET;
    ptpMediaLib_->CopyObject(context, outObjectHandle);
    ptpMediaLib_->DeleteObject(context);
}

static void PtpSetObjectPropValueTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    ptpMediaLib_->SetObjectPropValue(context);
}

static void PtpCloseFdTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    uint32_t handle = 0;
    ptpMediaLib_->GetIdByPath(provider->ConsumeBytesAsString(NUM_BYTES), handle);
    context->handle = handle;
    int32_t outFd = provider->ConsumeIntegral<int32_t>();
    string mode = provider->ConsumeBytesAsString(NUM_BYTES);
    ptpMediaLib_->GetFd(context, outFd, mode);
    ptpMediaLib_->CloseFd(context, outFd);
}

static void PtpGetObjectPropListTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();

    ptpMediaLib_->GetObjectPropList(context, outProps);

    context->parent = provider->ConsumeIntegral<uint32_t>();
    ptpMediaLib_->GetObjectPropList(context, outProps);
}

static void PtpGetObjectPropValueTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    string outStrVal = "";
    ptpMediaLib_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
}

static void PtpGetPictureThumbTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    ptpMediaLib_->GetPictureThumb(context, outThumb);
}

static void PtpGetVideoThumbTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    ptpMediaLib_->GetVideoThumb(context, outThumb);
}

static void PtpGetFdByOpenFileTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    int32_t outFd = provider->ConsumeIntegral<int32_t>();
    ptpMediaLib_->GetFdByOpenFile(context, outFd);
}

static void PtpSetObjectInfoTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    const unique_ptr<FileAsset> fileAsset = make_unique<FileAsset>();
    fileAsset->SetMediaType(MediaType::MEDIA_TYPE_ALBUM);
    shared_ptr<ObjectInfo> outObjectInfo = make_shared<ObjectInfo>(FuzzObjectInfo());
    ptpMediaLib_->SetObjectInfo(fileAsset, outObjectInfo);

    fileAsset->SetMediaType(MediaType::MEDIA_TYPE_IMAGE);
    ptpMediaLib_->SetObjectInfo(fileAsset, outObjectInfo);

    fileAsset->SetMediaType(MediaType::MEDIA_TYPE_VIDEO);
    ptpMediaLib_->SetObjectInfo(fileAsset, outObjectInfo);
}

static void PtpSetObjectTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    ptpMediaLib_->SetObject(resultSet, context, outObjectInfo);
}

static void PtpCompressImageTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    unique_ptr<PixelMap> pixelMap = nullptr;
    vector<uint8_t> imageDdata  = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    ptpMediaLib_->CompressImage(pixelMap, imageDdata);
}

static void PtpGetAlbumInfoTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    bool isHandle = provider->ConsumeBool();
    ptpMediaLib_->GetAlbumInfo(context, isHandle);
}

static void PtpGetPhotosInfoTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    bool isHandle = provider->ConsumeBool();
    ptpMediaLib_->GetPhotosInfo(context, isHandle);
}

static void PtpGetAlbumCloudTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    ptpMediaLib_->GetAlbumCloud();
    vector<string> ownerAlbumIds = {provider->ConsumeBytesAsString(NUM_BYTES)};
    ptpMediaLib_->GetAlbumCloudDisplay(ownerAlbumIds);
}

static void PtpHaveMovingPhotesHandleTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32());
    const uint32_t parent = provider->ConsumeIntegral<uint32_t>();
    int64_t size = provider->ConsumeIntegral<int64_t>();
    FileCountInfo fileCountInfo;
    ptpMediaLib_->HaveMovingPhotesHandle(resultSet, outHandles, parent, fileCountInfo);
    ptpMediaLib_->GetSizeFromOfft(size);
    ptpMediaLib_->GetBurstKeyFromPhotosInfo();
    ptpMediaLib_->Clear();
}

static void PtpGetThumbUriTest()
{
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    const int32_t handle = provider->ConsumeIntegral<int32_t>();
    const string thumbSizeValue = provider->ConsumeBytesAsString(NUM_BYTES);
    const string dataPath = FILE_PATH + "/" + provider->ConsumeBytesAsString(NUM_BYTES);
    ptpMediaLib_->GetThumbUri(handle, thumbSizeValue, dataPath);
}

static void DeleteCanceledObjectTest()
{
    uint32_t id = provider->ConsumeIntegral<uint32_t>();
    ptpMediaLib_->DeleteCanceledObject(id);
    ptpMediaLib_->Clear();
}

static void MtpMedialibraryManagerTest()
{
    PtpGetHandlesTest();
    PtpGetObjectInfoTest();
    PtpGetFdTest();
    PtpGetThumbTest();
    PtpSendObjectInfoTest();
    PtpMoveObjectTest();
    PtpCopyObjectTest();
    PtpSetObjectPropValueTest();
    PtpCloseFdTest();
    PtpGetObjectPropListTest();
    PtpGetObjectPropValueTest();
    PtpGetPictureThumbTest();
    PtpGetVideoThumbTest();
    PtpGetFdByOpenFileTest();
    PtpSetObjectInfoTest();
    PtpSetObjectTest();
    PtpCompressImageTest();
    PtpGetAlbumInfoTest();
    PtpGetPhotosInfoTest();
    PtpGetAlbumCloudTest();
    PtpHaveMovingPhotesHandleTest();
    PtpGetThumbUriTest();
    DeleteCanceledObjectTest();
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
    if (ptpMediaLib_ == nullptr) {
        MEDIA_ERR_LOG("ptpMediaLib_ is nullptr");
        return;
    }
    ptpMediaLib_->Init(token, context);
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
    OHOS::InitMtpMedialibraryManager();
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
    OHOS::MtpMedialibraryManagerTest();
    return 0;
}