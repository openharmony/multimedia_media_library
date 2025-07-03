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
#include "mtp_media_library.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
static const int32_t NUM_BYTES = 1;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
// storage file
const std::string STORAGE_FILE = "/storage/media/local/files/Docs";
// file path
const string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
const shared_ptr<MtpMediaLibrary> mtpMediaLib_ = MtpMediaLibrary::GetInstance();
FuzzedDataProvider *provider = nullptr;

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

static void AddPathToMapTest()
{
    mtpMediaLib_->AddPathToMap(provider->ConsumeBytesAsString(NUM_BYTES));
    mtpMediaLib_->Clear();
}

static void ObserverAddPathToMapTest()
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->ObserverAddPathToMap(provider->ConsumeBytesAsString(NUM_BYTES));

    uint32_t parentId = 0;
    mtpMediaLib_->GetIdByPath(provider->ConsumeBytesAsString(NUM_BYTES), parentId);
    vector<int> outHandles;
    mtpMediaLib_->GetHandles(parentId, outHandles, MEDIA_TYPE_FILE);
}

static void GetHandlesTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + "/" + provider->ConsumeBytesAsString(NUM_BYTES) + ".txt");

    uint32_t parentId = 0;
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32());
    mtpMediaLib_->GetIdByPath(FILE_PATH, parentId);
    context->parent = parentId;
    context->storageID = parentId;
    mtpMediaLib_->GetHandles(context, outHandles);
}

static void GetObjectInfoTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(FuzzObjectInfo());
    context->handle = 1;
    mtpMediaLib_->GetObjectInfo(context, objectInfo);
}

static void GetFdTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = nullptr;
    bool condition = false;
    int fd = 0;
    mtpMediaLib_->CondCloseFd(condition, fd);

    int32_t outFd = provider->ConsumeIntegral<int32_t>();
    mtpMediaLib_->GetFd(context, outFd);
}

static void GetThumbTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>(provider->ConsumeBytes<uint8_t>(NUM_BYTES));
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + provider->ConsumeBytesAsString(NUM_BYTES) +
        ".txt", provider->ConsumeIntegral<uint32_t>());
    mtpMediaLib_->GetThumb(context, outThumb);
}

static void SendObjectInfoTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    uint32_t outStorageID = provider->ConsumeIntegral<uint32_t>();
    uint32_t outParent = provider->ConsumeIntegral<uint32_t>();
    uint32_t outHandle = provider->ConsumeIntegral<uint32_t>();

    mtpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);

    context->format = MTP_FORMAT_ASSOCIATION_CODE;
    mtpMediaLib_->SendObjectInfo(context, outStorageID, outParent, outHandle);
}

static void MoveObjectTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    mtpMediaLib_->ObserverAddPathToMap(provider->ConsumeBytesAsString(NUM_BYTES));
    string from = provider->ConsumeBytesAsString(NUM_BYTES);
    mtpMediaLib_->ObserverAddPathToMap(from);
    string to = provider->ConsumeBytesAsString(NUM_BYTES);
    uint32_t fromId = 0;
    mtpMediaLib_->GetIdByPath(from, fromId);
    uint32_t parentId = 0;
    mtpMediaLib_->GetIdByPath(from, parentId);
    context->handle = fromId;
    context->parent = parentId;
    mtpMediaLib_->MoveObject(context, parentId);
}

static void CopyObjectTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + provider->ConsumeBytesAsString(NUM_BYTES),
        provider->ConsumeIntegral<uint32_t>());
    uint32_t outObjectHandle = provider->ConsumeIntegral<uint32_t>();
    uint32_t oldHandle = provider->ConsumeIntegral<uint32_t>();
    mtpMediaLib_->CopyObject(context, outObjectHandle, oldHandle);
    mtpMediaLib_->DeleteObject(context);
}

static void SetObjectPropValueTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + provider->ConsumeBytesAsString(NUM_BYTES) + ".txt",
        provider->ConsumeIntegral<uint32_t>());

    mtpMediaLib_->SetObjectPropValue(context);
}

static void CloseFdTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    mtpMediaLib_->ObserverAddPathToMap(provider->ConsumeBytesAsString(NUM_BYTES));

    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(provider->ConsumeBytesAsString(NUM_BYTES), handle);
    context->handle = handle;
    int32_t outFd = provider->ConsumeIntegral<int32_t>();
    mtpMediaLib_->GetFd(context, outFd);
    mtpMediaLib_->CloseFd(context, outFd);
}

static void GetObjectPropListTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    context->groupCode = 0;
    mtpMediaLib_->GetObjectPropList(context, outProps);

    context->property = provider->ConsumeIntegral<uint32_t>();
    context->depth = MTP_ALL_DEPTH;
    context->handle = 0;
    mtpMediaLib_->GetObjectPropList(context, outProps);
}

static void GetObjectPropValueTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    string outStrVal = "";
    mtpMediaLib_->AddToHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeIntegral<uint32_t>());
    mtpMediaLib_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
    mtpMediaLib_->DeleteHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeIntegral<uint32_t>());
}

static void GetRealPathTest()
{
    mtpMediaLib_->Clear();
    string outPath = "";
    mtpMediaLib_->GetRealPath(provider->ConsumeBytesAsString(NUM_BYTES), outPath);
}


static void MtpMediaLibraryStorageTest()
{
    mtpMediaLib_->Clear();
    string fsUuid = provider->ConsumeBytesAsString(NUM_BYTES);
    uint32_t storageId = provider->ConsumeIntegral<uint32_t>();
    mtpMediaLib_->TryAddExternalStorage(fsUuid, storageId);
    mtpMediaLib_->TryRemoveExternalStorage(fsUuid, storageId);
    mtpMediaLib_->GetStorageIds();
}

static void ObserverDeletePathToMapTest()
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->ObserverAddPathToMap(provider->ConsumeBytesAsString(NUM_BYTES));
    mtpMediaLib_->ObserverDeletePathToMap(provider->ConsumeBytesAsString(NUM_BYTES));
}

static void ModifyHandlePathMapTest()
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->AddToHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeIntegral<uint32_t>());

    mtpMediaLib_->ModifyHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES),
        provider->ConsumeBytesAsString(NUM_BYTES));

    uint32_t id = provider->ConsumeIntegral<uint32_t>();
    mtpMediaLib_->ModifyPathHandleMap(provider->ConsumeBytesAsString(NUM_BYTES), id);
}

static void StartsWithTest()
{
    mtpMediaLib_->Clear();

    string str = provider->ConsumeBytesAsString(NUM_BYTES);
    string prefix = provider->ConsumeBytesAsString(NUM_BYTES);
    mtpMediaLib_->StartsWith(str, prefix);
}

static void MoveHandlePathMapTest()
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->AddToHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeIntegral<uint32_t>());
    mtpMediaLib_->MoveHandlePathMap(FILE_PATH, provider->ConsumeBytesAsString(NUM_BYTES));
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH, 1);
    mtpMediaLib_->MoveRepeatDirHandlePathMap(FILE_PATH, provider->ConsumeBytesAsString(NUM_BYTES));
}

static void MoveObjectSubTest()
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->AddToHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeIntegral<uint32_t>());

    mtpMediaLib_->AddToHandlePathMap(FILE_PATH, 1);
    bool isDir = provider->ConsumeBool();
    uint32_t repeatHandle = provider->ConsumeIntegral<uint32_t>();
    mtpMediaLib_->MoveObjectSub(FILE_PATH, provider->ConsumeBytesAsString(NUM_BYTES), isDir, repeatHandle);
}

static void GetIdTest()
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->GetId();
    mtpMediaLib_->GetParentId(provider->ConsumeBytesAsString(NUM_BYTES));
}

static void ScanDirNoDepthTest()
{
    mtpMediaLib_->Clear();
    string root = provider->ConsumeBytesAsString(NUM_BYTES);
    shared_ptr<UInt32List> out = make_shared<UInt32List>();
    mtpMediaLib_->ScanDirNoDepth(root, out);
}

static void ScanDirWithTypeTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<unordered_map<uint32_t, string>> out =
        make_shared<unordered_map<uint32_t, string>>();

    mtpMediaLib_->ScanDirWithType(STORAGE_FILE, out);
    mtpMediaLib_->ScanDirTraverseWithType(STORAGE_FILE, out);

    string root = FILE_PATH + "/" + provider->ConsumeBytesAsString(NUM_BYTES);
    int64_t size = provider->ConsumeIntegral<int64_t>();
    mtpMediaLib_->ScanDirWithType(root, out);
    mtpMediaLib_->ScanDirTraverseWithType(root, out);
    mtpMediaLib_->GetSizeFromOfft(size);
}

static void GetHandlesMapTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    mtpMediaLib_->AddToHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeIntegral<uint32_t>());
    context->handle = 0;
    context->depth = MTP_ALL_DEPTH;
    mtpMediaLib_->GetHandlesMap(context);

    context->handle = MTP_ALL_DEPTH;
    mtpMediaLib_->GetHandlesMap(context);

    context->depth = DEFAULT_STORAGE_ID;
    mtpMediaLib_->GetHandlesMap(context);

    context->handle = MTP_ALL_HANDLE_ID;
    mtpMediaLib_->GetHandlesMap(context);
}

static void GetExternalStoragesTest()
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->GetExternalStorages();
}

static void ErasePathInfoTest()
{
    mtpMediaLib_->Clear();

    mtpMediaLib_->ObserverAddPathToMap(provider->ConsumeBytesAsString(NUM_BYTES));
    uint32_t handle = provider->ConsumeIntegral<uint32_t>();
    mtpMediaLib_->GetIdByPath(provider->ConsumeBytesAsString(NUM_BYTES), handle);
    mtpMediaLib_->ErasePathInfo(handle, FILE_PATH);
}

static void GetVideoThumbTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    mtpMediaLib_->AddToHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeIntegral<uint32_t>());

    mtpMediaLib_->GetVideoThumb(context, outThumb);
}

static void GetPictureThumbTest()
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    mtpMediaLib_->AddToHandlePathMap(provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeIntegral<uint32_t>());

    mtpMediaLib_->GetPictureThumb(context, outThumb);
}

static void CorrectStorageIdTest()
{
    mtpMediaLib_->Clear();
    const shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext());
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    mtpMediaLib_->CorrectStorageId(context);
}

static void MtpMediaLibraryTest()
{
    AddPathToMapTest();
    ObserverAddPathToMapTest();
    GetHandlesTest();
    GetObjectInfoTest();
    GetFdTest();
    GetThumbTest();
    SendObjectInfoTest();
    MoveObjectTest();
    CopyObjectTest();
    SetObjectPropValueTest();
    CloseFdTest();
    GetObjectPropListTest();
    GetObjectPropValueTest();
    GetRealPathTest();
    MtpMediaLibraryStorageTest();
    ObserverDeletePathToMapTest();
    ModifyHandlePathMapTest();
    StartsWithTest();
    MoveHandlePathMapTest();
    MoveObjectSubTest();
    GetIdTest();
    ScanDirNoDepthTest();
    ScanDirWithTypeTest();
    GetHandlesMapTest();
    GetExternalStoragesTest();
    ErasePathInfoTest();
    GetVideoThumbTest();
    GetPictureThumbTest();
    CorrectStorageIdTest();
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
    OHOS::MtpMediaLibraryTest();
    return 0;
}