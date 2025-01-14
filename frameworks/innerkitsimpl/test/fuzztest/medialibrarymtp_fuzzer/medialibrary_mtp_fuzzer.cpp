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

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "close_session_data.h"

#define private public
#include "header_data.h"
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_packet_tools.h"
#include "mtp_data_utils.h"
#include "mtp_driver.h"
#include "mtp_error_utils.h"
#include "mtp_event.h"
#include "mtp_file_observer.h"
#include "mtp_manager.h"
#include "mtp_media_library.h"
#include "mtp_medialibrary_manager.h"
#include "mtp_monitor.h"
#include "mtp_operation_utils.h"
#include "mtp_operation.h"
#include "mtp_packet_tools.h"
#include "mtp_packet.h"
#include "mtp_service.h"
#include "mtp_storage_manager.h"
#include "property.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
// using namespace testing::ext;

const shared_ptr<MtpMediaLibrary> mtpMediaLib_ = MtpMediaLibrary::GetInstance();
const shared_ptr<MtpMedialibraryManager> ptpMediaLib_ = MtpMedialibraryManager::GetInstance();
// file path
const string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
const int32_t EVEN = 2;

static constexpr int TEST_UID = 5003;


static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    return static_cast<int32_t>(*data);
}

static inline int64_t FuzzInt64(const uint8_t *data, size_t size)
{
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
    return static_cast<uint16_t>(*data);
}

static inline uint32_t FuzzUInt32(const uint8_t *data, size_t size)
{
    return static_cast<uint32_t>(*data);
}

static inline uint64_t FuzzUInt64(const uint8_t *data, size_t size)
{
    return static_cast<uint64_t>(*data);
}

static inline vector<int32_t> FuzzVectorInt32(const uint8_t *data, size_t size)
{
    return {*data};
}

static inline vector<uint8_t> FuzzVectorUInt8(const uint8_t *data, size_t size)
{
    return {*data};
}

static inline vector<uint16_t> FuzzVectorUInt16(const uint8_t *data, size_t size)
{
    return {*data};
}

static inline vector<uint32_t> FuzzVectorUInt32(const uint8_t *data, size_t size)
{
    return {*data};
}

static inline vector<string> FuzzVectorString(const uint8_t *data, size_t size)
{
    return {FuzzString(data, size)};
}

static MtpOperationContext FuzzMtpOperationContext(const uint8_t* data, size_t size)
{
    return {
        .operationCode = FuzzUInt16(data, size),
        .transactionID = FuzzUInt32(data, size),
        .devicePropertyCode = FuzzUInt32(data, size),
        .storageID = FuzzUInt32(data, size),
        .format = FuzzUInt16(data, size),
        .parent = FuzzUInt32(data, size),
        .handle = FuzzUInt32(data, size),
        .property = FuzzUInt32(data, size),
        .groupCode = FuzzUInt32(data, size),
        .depth = FuzzUInt32(data, size),
        .properStrValue = FuzzString(data, size),
        .properIntValue = FuzzInt64(data, size),
        .handles = make_shared<UInt32List>(FuzzVectorUInt32(data, size)),
        .sendObjectFileSize = FuzzUInt32(data, size),
        .name = FuzzString(data, size),
        .created = FuzzString(data, size),
        .modified = FuzzString(data, size),
        .length = FuzzUInt32(data, size),

        .indata = FuzzBool(data, size),
        .storageInfoID = FuzzUInt32(data, size),

        .sessionOpen = FuzzBool(data, size),
        .sessionID = FuzzUInt32(data, size),
        .tempSessionID = FuzzUInt32(data, size),
        .eventHandle = FuzzUInt32(data, size),
        .eventProperty = FuzzUInt32(data, size),
    };
}

static void HeaderDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(context);

    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = FuzzUInt32(data, size);

    headerData->Parser(buffer, readSize);
    headerData->Maker(buffer);
    headerData->SetCode(FuzzUInt16(data, size));
    headerData->SetContainerLength(FuzzUInt32(data, size));
    headerData->SetContainerType(FuzzUInt16(data, size));
    headerData->SetTransactionId(FuzzUInt32(data, size));

    headerData->GetCode();
    headerData->GetContainerLength();
    headerData->GetContainerType();
    headerData->GetTransactionId();

    headerData->Reset();
}

static void SolveHandlesFormatDataTest(const uint8_t* data, size_t size)
{
    uint16_t format = FuzzUInt16(data, size);
    MediaType outMediaType = MEDIA_TYPE_FILE;
    string outExtension = FuzzString(data, size);
    MtpDataUtils::SolveHandlesFormatData(format, outExtension, outMediaType);
}

static void SolveSendObjectFormatDataTest(const uint8_t* data, size_t size)
{
    uint16_t format = FuzzUInt16(data, size);
    MediaType outMediaType = MEDIA_TYPE_FILE;
    MtpDataUtils::SolveSendObjectFormatData(format, outMediaType);
}

static void SolveSetObjectPropValueDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    context->property = FuzzUInt32(data, size);
    string outColName = FuzzString(data, size);
    variant<int64_t, string> outColVal;
    MtpDataUtils::SolveSetObjectPropValueData(context, outColName, outColVal);
}

static void GetMediaTypeByformatTest(const uint8_t* data, size_t size)
{
    uint16_t format = FuzzUInt16(data, size);
    MediaType outMediaType = MEDIA_TYPE_FILE;
    MtpDataUtils::GetMediaTypeByformat(format, outMediaType);
}

static void GetPropListBySetTest(const uint8_t* data, size_t size)
{
    const shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpDataUtils::GetPropListBySet(context, resultSet, outProps);
}

static void GetPropValueBySetTest(const uint8_t* data, size_t size)
{
    uint32_t property = FuzzUInt16(data, size);
    PropertyValue outPropValue;
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    MtpDataUtils::GetPropValueBySet(property, resultSet, outPropValue);
}

static void GetMediaTypeByNameTest(const uint8_t* data, size_t size)
{
    string displayName = FuzzString(data, size);
    MediaType outMediaType = MEDIA_TYPE_FILE;
    MtpDataUtils::GetMediaTypeByName(displayName, outMediaType);
}

static void GetPropListTest(const uint8_t* data, size_t size)
{
    const shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    shared_ptr<UInt16List> properties = make_shared<UInt16List>(FuzzVectorUInt16(data, size));
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpDataUtils::GetPropList(context, resultSet, properties, outProps);
}

static void GetFormatTest(const uint8_t* data, size_t size)
{
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    uint16_t outFormat = FuzzUInt16(data, size);
    MtpDataUtils::GetFormat(resultSet, outFormat);

    uint32_t handle = FuzzUInt32(data, size);
    shared_ptr<UInt16List> properties =  make_shared<UInt16List>(FuzzVectorUInt16(data, size));
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();

    MtpDataUtils::GetOneRowPropList(handle, resultSet, properties, outProps);
}

static void SetOneDefaultlPropListTest(const uint8_t* data, size_t size)
{
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpDataUtils::SetOneDefaultlPropList(0, MTP_PROPERTY_PROTECTION_STATUS_CODE, outProps);
    MtpDataUtils::SetOneDefaultlPropList(0, MTP_PROPERTY_PERSISTENT_UID_CODE, outProps);
    MtpDataUtils::SetOneDefaultlPropList(0, MTP_PROPERTY_ALBUM_NAME_CODE, outProps);
    MtpDataUtils::SetOneDefaultlPropList(0, MTP_PROPERTY_STORAGE_ID_CODE, outProps);
    string column = FuzzString(data, size);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    Property prop;
    ResultSetDataType type = TYPE_NULL;
    MtpDataUtils::SetProperty(column, resultSet, type, prop);
    ResultSetDataType typeOne = TYPE_STRING;
    MtpDataUtils::SetProperty(column, resultSet, typeOne, prop);
    ResultSetDataType typeTwo = TYPE_INT32;
    MtpDataUtils::SetProperty(column, resultSet, typeTwo, prop);
    ResultSetDataType typeThree = TYPE_INT64;
    MtpDataUtils::SetProperty(column, resultSet, typeThree, prop);
    ResultSetDataType typeFour = TYPE_DOUBLE;
    MtpDataUtils::SetProperty(column, resultSet, typeFour, prop);
    uint16_t outFormat = 0;
    MtpDataUtils::GetFormatByPath("", outFormat);
    string path = FuzzString(data, size);
    MtpDataUtils::GetFormatByPath(path, outFormat);
}

static void MtpDataUtilsTest(const uint8_t* data, size_t size)
{
    SolveHandlesFormatDataTest(data, size);
    SolveSendObjectFormatDataTest(data, size);
    SolveSetObjectPropValueDataTest(data, size);
    GetMediaTypeByformatTest(data, size);
    GetPropListBySetTest(data, size);
    GetPropValueBySetTest(data, size);
    GetMediaTypeByNameTest(data, size);
    GetPropListTest(data, size);
    GetFormatTest(data, size);
    SetOneDefaultlPropListTest(data, size);
}

static void MtpDriverTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpDriver> mtpDriver = make_shared<MtpDriver>();
    mtpDriver->OpenDriver();

    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    uint32_t sizeBuf = FuzzUInt32(data, size);
    mtpDriver->Read(buffer, sizeBuf);
    mtpDriver->Write(buffer, sizeBuf);

    MtpFileRange mfr;
    mfr.fd = FuzzInt32(data, size);
    mfr.length = FuzzInt64(data, size);
    mfr.command = FuzzUInt16(data, size);
    mfr.transaction_id = FuzzUInt32(data, size);
    mtpDriver->SendObj(mfr);
    mtpDriver->ReceiveObj(mfr);

    EventMtp me;
    me.data = FuzzVectorUInt8(data, size);
    me.length = me.data.size();
    mtpDriver->WriteEvent(me);
    mtpDriver->CloseDriver();
}

static void MtpErrorUtilsTest(const uint8_t* data, size_t size)
{
    MtpErrorUtils::SolveGetHandlesError(E_SUCCESS);
    MtpErrorUtils::SolveGetObjectInfoError(E_SUCCESS);
    MtpErrorUtils::SolveSendObjectInfoError(E_SUCCESS);
    MtpErrorUtils::SolveMoveObjectError(E_SUCCESS);
    MtpErrorUtils::SolveCopyObjectError(E_SUCCESS);
    MtpErrorUtils::SolveDeleteObjectError(E_SUCCESS);
    MtpErrorUtils::SolveObjectPropValueError(E_SUCCESS);
    MtpErrorUtils::SolveCloseFdError(E_SUCCESS);
}

static void MtpEventTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    string path = FuzzString(data, size);
    mtpEvent->SendObjectAdded(path);
    mtpEvent->SendObjectRemoved(path);
    mtpEvent->SendObjectInfoChanged(path);
    shared_ptr<PayloadData> eventData = make_shared<CloseSessionData>(context);
    mtpEvent->EventPayloadData(FuzzUInt16(data, size), eventData);

    mtpEvent->SendObjectRemovedByHandle(FuzzUInt32(data, size));
    mtpEvent->SendStoreAdded(FuzzString(data, size));
    mtpEvent->SendStoreRemoved(FuzzString(data, size));
    mtpEvent->SendEvent(FuzzInt32(data, size));
}

static void MtpManagerTest(const uint8_t* data, size_t size)
{
    MtpManager::GetInstance().Init();
    MtpManager::GetInstance().StartMtpService(MtpManager::MtpMode::PTP_MODE);
    MtpManager::GetInstance().IsMtpMode();
    MtpManager::GetInstance().StopMtpService();
}

//MtpMediaLibraryTest start
static void AddPathToMapTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->AddPathToMap(FuzzString(data, size));
    mtpMediaLib_->Clear();
}

static void ObserverAddPathToMapTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->ObserverAddPathToMap(FuzzString(data, size));

    uint32_t parentId = 0;
    mtpMediaLib_->GetIdByPath(FuzzString(data, size), parentId);
    vector<int> outHandles;
    mtpMediaLib_->GetHandles(parentId, outHandles, MEDIA_TYPE_FILE);
}

static void GetHandlesTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH + "/" + FuzzString(data, size) + ".txt");

    uint32_t parentId = 0;
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32(data, size));
    mtpMediaLib_->GetIdByPath(FILE_PATH, parentId);
    context->parent = parentId;
    context->storageID = parentId;
    mtpMediaLib_->GetHandles(context, outHandles);
}

static void GetObjectInfoTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(0);

    mtpMediaLib_->GetObjectInfo(context, objectInfo);
}

static void GetFdTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = nullptr;
    bool condition = false;
    int fd = 0;
    mtpMediaLib_->CondCloseFd(condition, fd);

    int32_t outFd = FuzzInt32(data, size);
    mtpMediaLib_->GetFd(context, outFd);
}
static void GetThumbTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>(FuzzVectorUInt8(data, size));
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + FuzzString(data, size) + ".txt", FuzzUInt32(data, size));
    mtpMediaLib_->GetThumb(context, outThumb);
}
static void SendObjectInfoTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    uint32_t outStorageID = FuzzUInt32(data, size);
    uint32_t outParent = FuzzUInt32(data, size);
    uint32_t outHandle = FuzzUInt32(data, size);

    mtpMediaLib_->SendObjectInfo(nullptr, outStorageID, outParent, outHandle);
}

static void MoveObjectTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    mtpMediaLib_->ObserverAddPathToMap(FuzzString(data, size));
    string from = FuzzString(data, size);
    mtpMediaLib_->ObserverAddPathToMap(from);
    string to = FuzzString(data, size);
    uint32_t fromId = 0;
    mtpMediaLib_->GetIdByPath(from, fromId);
    uint32_t parentId = 0;
    mtpMediaLib_->GetIdByPath(from, parentId);
    context->handle = fromId;
    context->parent = parentId;
    mtpMediaLib_->MoveObject(context, parentId);
}

static void CopyObjectTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + FuzzString(data, size), FuzzUInt32(data, size));

    uint32_t outObjectHandle = FuzzUInt32(data, size);
    uint32_t oldHandle = FuzzUInt32(data, size);
    mtpMediaLib_->CopyObject(context, outObjectHandle, oldHandle);
    mtpMediaLib_->DeleteObject(context);
}

static void SetObjectPropValueTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + FuzzString(data, size) + ".txt", FuzzUInt32(data, size));

    mtpMediaLib_->SetObjectPropValue(context);
}

static void CloseFdTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    uint32_t handle = 0;
    mtpMediaLib_->GetIdByPath(FuzzString(data, size), handle);
    context->handle = handle;
    int32_t outFd = FuzzInt32(data, size);
    mtpMediaLib_->GetFd(context, outFd);
    mtpMediaLib_->CloseFd(context, outFd);
}

static void GetObjectPropListTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();

    mtpMediaLib_->GetObjectPropList(context, outProps);
}

static void GetObjectPropValueTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    string outStrVal = "";
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));
    mtpMediaLib_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
    mtpMediaLib_->DeleteHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));
}

static void GetRealPathTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    string outPath = "";
    mtpMediaLib_->GetRealPath(FuzzString(data, size), outPath);
}

static void MtpMediaLibraryStorageTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    string fsUuid = FuzzString(data, size);
    uint32_t storageId = FuzzUInt32(data, size);
    mtpMediaLib_->TryAddExternalStorage(fsUuid, storageId);
    mtpMediaLib_->TryRemoveExternalStorage(fsUuid, storageId);
    mtpMediaLib_->GetStorageIds();
}

static void ObserverDeletePathToMapTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->ObserverAddPathToMap(FuzzString(data, size));
    mtpMediaLib_->ObserverDeletePathToMap(FuzzString(data, size));
}

static void ModifyHandlePathMapTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));

    mtpMediaLib_->ModifyHandlePathMap(FuzzString(data, size), FuzzString(data, size));

    uint32_t id = FuzzUInt32(data, size) + 1;
    mtpMediaLib_->ModifyPathHandleMap(FuzzString(data, size), id);
}

static void StartsWithTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();

    string str = FuzzString(data, size);
    string prefix = FuzzString(data, size);
    mtpMediaLib_->StartsWith(str, prefix);
}

static void MoveHandlePathMapTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));
    mtpMediaLib_->MoveHandlePathMap(FILE_PATH, FuzzString(data, size));
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH, 1);
    mtpMediaLib_->MoveRepeatDirHandlePathMap(FILE_PATH, FuzzString(data, size));
}

static void MoveObjectSubTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));

    mtpMediaLib_->AddToHandlePathMap(FILE_PATH, 1);
    bool isDir = FuzzBool(data, size);
    uint32_t repeatHandle = FuzzUInt32(data, size);
    mtpMediaLib_->MoveObjectSub(FILE_PATH, FuzzString(data, size), isDir, repeatHandle);
}

static void GetIdTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->GetId();
    mtpMediaLib_->GetParentId(FuzzString(data, size));
}

static void ScanDirNoDepthTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    string root = FuzzString(data, size);
    shared_ptr<UInt32List> out = make_shared<UInt32List>();
    mtpMediaLib_->ScanDirNoDepth(root, out);
}

static void ScanDirWithTypeTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    string root = FuzzString(data, size);
    shared_ptr<unordered_map<uint32_t, string>> out =
        make_shared<unordered_map<uint32_t, string>>();
    mtpMediaLib_->ScanDirWithType(root, out);
    mtpMediaLib_->ScanDirTraverseWithType(root, out);
}

static void GetSizeFromOfftTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->GetSizeFromOfft(size);
}

static void GetHandlesMapTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));

    mtpMediaLib_->GetHandlesMap(context);
}

static void GetExternalStoragesTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    mtpMediaLib_->GetExternalStorages();
}

static void ErasePathInfoTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();

    mtpMediaLib_->ObserverAddPathToMap(FuzzString(data, size));
    uint32_t handle = FuzzUInt32(data, size);
    mtpMediaLib_->GetIdByPath(FuzzString(data, size), handle);
    mtpMediaLib_->ErasePathInfo(handle, FILE_PATH);
}

static void GetVideoThumbTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));

    mtpMediaLib_->GetVideoThumb(context, outThumb);
}

static void GetPictureThumbTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));

    mtpMediaLib_->GetPictureThumb(context, outThumb);
}

static void CorrectStorageIdTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    const shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    mtpMediaLib_->CorrectStorageId(context);
}

static void MtpMediaLibraryTest(const uint8_t* data, size_t size)
{
    AddPathToMapTest(data, size);
    ObserverAddPathToMapTest(data, size);
    GetHandlesTest(data, size);
    GetObjectInfoTest(data, size);
    GetFdTest(data, size);
    GetThumbTest(data, size);
    SendObjectInfoTest(data, size);
    MoveObjectTest(data, size);
    CopyObjectTest(data, size);
    SetObjectPropValueTest(data, size);
    CloseFdTest(data, size);
    GetObjectPropListTest(data, size);
    GetObjectPropValueTest(data, size);
    GetRealPathTest(data, size);
    MtpMediaLibraryStorageTest(data, size);
    ObserverDeletePathToMapTest(data, size);
    ModifyHandlePathMapTest(data, size);
    StartsWithTest(data, size);
    MoveHandlePathMapTest(data, size);
    MoveObjectSubTest(data, size);
    GetIdTest(data, size);
    ScanDirNoDepthTest(data, size);
    ScanDirWithTypeTest(data, size);
    GetSizeFromOfftTest(data, size);
    GetHandlesMapTest(data, size);
    GetExternalStoragesTest(data, size);
    ErasePathInfoTest(data, size);
    GetVideoThumbTest(data, size);
    GetPictureThumbTest(data, size);
    CorrectStorageIdTest(data, size);
}

// MtpMedialibraryManagerTest start
static void PtpClearTest(const uint8_t* data, size_t size)
{
    shared_ptr <MtpMedialibraryManager> mtpMedialibraryManager = MtpMedialibraryManager::GetInstance();
    (void) mtpMedialibraryManager->Clear();
}

static void PtpGetHandlesTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    int32_t parentId = FuzzInt32(data, size);
    MediaType mediaType = MediaType::MEDIA_TYPE_IMAGE;
    vector<int> outHandle = FuzzVectorInt32(data, size);
    ptpMediaLib_->GetHandles(parentId, outHandle, mediaType);

    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    uint32_t outId = 0;
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32(data, size));
    ptpMediaLib_->GetIdByPath(FuzzString(data, size), outId);
    context->parent = outId;
    context->storageID = outId;
    ptpMediaLib_->GetHandles(context, outHandles);
}

static void PtpGetObjectInfoTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(0);

    ptpMediaLib_->GetObjectInfo(context, objectInfo);
}

static void PtpGetFdTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = nullptr;
    bool condition = false;
    int fd = 0;
    ptpMediaLib_->CondCloseFd(condition, fd);

    int32_t outFd = FuzzInt32(data, size);
    string mode = FuzzString(data, size);
    ptpMediaLib_->GetFd(context, outFd, mode);
}

static void PtpGetThumbTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>(FuzzVectorUInt8(data, size));
    ptpMediaLib_->GetThumb(context, outThumb);
}

static void PtpSendObjectInfoTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    uint32_t outStorageID = FuzzUInt32(data, size);
    uint32_t outParent = FuzzUInt32(data, size);
    uint32_t outHandle = FuzzUInt32(data, size);

    ptpMediaLib_->SendObjectInfo(nullptr, outStorageID, outParent, outHandle);
}

static void PtpMoveObjectTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    ptpMediaLib_->MoveObject(context);
}

static void PtpCopyObjectTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    uint32_t outObjectHandle = FuzzUInt32(data, size);
    ptpMediaLib_->CopyObject(context, outObjectHandle);
    ptpMediaLib_->DeleteObject(context);
}

static void PtpSetObjectPropValueTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    ptpMediaLib_->SetObjectPropValue(context);
}

static void PtpCloseFdTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    uint32_t handle = 0;
    ptpMediaLib_->GetIdByPath(FuzzString(data, size), handle);
    context->handle = handle;
    int32_t outFd = FuzzInt32(data, size);
    string mode = FuzzString(data, size);
    ptpMediaLib_->GetFd(context, outFd, mode);
    ptpMediaLib_->CloseFd(context, outFd);
}

static void PtpCloseFdForGetTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    int32_t fd = FuzzInt32(data, size);
    ptpMediaLib_->CloseFdForGet(context, fd);
}

static void PtpGetObjectPropListTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();

    ptpMediaLib_->GetObjectPropList(context, outProps);
}

static void PtpGetObjectPropValueTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    string outStrVal = "";
    ptpMediaLib_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
}

static void PtpGetPictureThumbTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    ptpMediaLib_->GetPictureThumb(context, outThumb);
}

static void PtpGetVideoThumbTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    ptpMediaLib_->GetVideoThumb(context, outThumb);
}

static void PtpGetFdByOpenFileTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    int32_t outFd = FuzzInt32(data, size);
    ptpMediaLib_->GetFdByOpenFile(context, outFd);
}

static void PtpSetObjectInfoTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();

    const unique_ptr<FileAsset> fileAsset = make_unique<FileAsset>();
    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    ptpMediaLib_->SetObjectInfo(fileAsset, outObjectInfo);
}

static void PtpSetObjectTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    ptpMediaLib_->SetObject(resultSet, context, outObjectInfo);
}

static void PtpCompressImageTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    unique_ptr<PixelMap> pixelMap = nullptr;
    vector<uint8_t> imageDdata  = FuzzVectorUInt8(data, size);
    ptpMediaLib_->CompressImage(pixelMap, imageDdata);
}

static void PtpGetAlbumInfoTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    bool isHandle = FuzzBool(data, size);
    ptpMediaLib_->GetAlbumInfo(context, isHandle);
}

static void PtpGetPhotosInfoTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    bool isHandle = FuzzBool(data, size);
    ptpMediaLib_->GetPhotosInfo(context, isHandle);
}

static void PtpGetAlbumCloudTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    ptpMediaLib_->GetAlbumCloud();
    vector<string> ownerAlbumIds = FuzzVectorString(data, size);
    ptpMediaLib_->GetAlbumCloudDisplay(ownerAlbumIds);
}

static void PtpHaveMovingPhotesHandleTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32(data, size));
    const uint32_t parent = FuzzUInt32(data, size);
    ptpMediaLib_->HaveMovingPhotesHandle(resultSet, outHandles, parent);
}

static void PtpGetSizeFromOfftTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    ptpMediaLib_->GetSizeFromOfft(size);
}

static void PtpGetBurstKeyFromPhotosInfoTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    ptpMediaLib_->GetBurstKeyFromPhotosInfo();
    ptpMediaLib_->GetOwnerAlbumIdList();
}

static void PtpGetThumbUriTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    const int32_t handle = FuzzInt32(data, size);
    const std::string thumbSizeValue = FuzzString(data, size);
    const std::string dataPath = FuzzString(data, size);
    ptpMediaLib_->GetThumbUri(handle, thumbSizeValue, dataPath);
}

static void PtpGetFileAssetFromPhotosInfoTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<FileAsset> fileAsset = make_shared<FileAsset>();
    ptpMediaLib_->GetFileAssetFromPhotosInfo(context, fileAsset);
}

static void PtpCopyAndDumpFileTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));

    string oldDataPath = FuzzString(data, size);
    string newDataPath = FuzzString(data, size);
    ptpMediaLib_->CopyAndDumpFile(context, oldDataPath, newDataPath);

    string dataPath = FuzzString(data, size);
    string displayName = FuzzString(data, size);
    string movingPhotoDataPath = FuzzString(data, size);
    MediaType mediaType = MEDIA_TYPE_FILE;
    ptpMediaLib_->GetMovingPhotoVideoPath(dataPath, displayName,
        movingPhotoDataPath, mediaType);
    ptpMediaLib_->InsertCopyObject(displayName, mediaType);
}

static void MtpMedialibraryManagerTest(const uint8_t* data, size_t size)
{
    PtpClearTest(data, size);
    PtpGetHandlesTest(data, size);
    PtpGetObjectInfoTest(data, size);
    PtpGetFdTest(data, size);
    PtpGetThumbTest(data, size);
    PtpSendObjectInfoTest(data, size);
    PtpMoveObjectTest(data, size);
    PtpCopyObjectTest(data, size);
    PtpSetObjectPropValueTest(data, size);
    PtpCloseFdTest(data, size);
    PtpCloseFdForGetTest(data, size);
    PtpGetObjectPropListTest(data, size);
    PtpGetObjectPropValueTest(data, size);
    PtpGetPictureThumbTest(data, size);
    PtpGetVideoThumbTest(data, size);
    PtpGetFdByOpenFileTest(data, size);
    PtpSetObjectInfoTest(data, size);
    PtpSetObjectTest(data, size);
    PtpCompressImageTest(data, size);
    PtpGetAlbumInfoTest(data, size);
    PtpGetPhotosInfoTest(data, size);
    PtpGetAlbumCloudTest(data, size);
    PtpHaveMovingPhotesHandleTest(data, size);
    PtpGetSizeFromOfftTest(data, size);
    PtpGetBurstKeyFromPhotosInfoTest(data, size);
    PtpGetThumbUriTest(data, size);
    PtpGetFileAssetFromPhotosInfoTest(data, size);
    PtpCopyAndDumpFileTest(data, size);
}

static void MtpMonitorTest(const uint8_t* data, size_t size)
{
    MtpMonitor mtpMonitor;
    mtpMonitor.Start();
    mtpMonitor.Stop();
}

// MtpOperationUtilsTest start
static void MtpOperationUtilsPayloadDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj, context);
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    uint16_t containerType = FuzzUInt16(data, size);
    int errorCode = FuzzInt32(data, size);
    mtpOperUtils->GetDeviceInfo(payData, containerType, errorCode);
    mtpOperUtils->GetObjectInfo(payData, containerType, errorCode);
    mtpOperUtils->GetNumObjects(payData);
    mtpOperUtils->DoSetObjectPropValue(errorCode);
    mtpOperUtils->GetObjectHandles(payData, containerType, errorCode);
    mtpOperUtils->GetObjectPropDesc(payData, containerType, errorCode);
    mtpOperUtils->GetObjectPropValue(payData, containerType, errorCode);
    mtpOperUtils->GetObjectPropList(payData, containerType, errorCode);
    mtpOperUtils->SendObjectInfo(payData, errorCode);
    mtpOperUtils->GetPartialObject(payData);
    mtpOperUtils->GetObjectPropsSupported(payData);
    mtpOperUtils->GetOpenSession(payData, errorCode);
    mtpOperUtils->GetCloseSession(payData);
    mtpOperUtils->DeleteObject(payData, errorCode);
    mtpOperUtils->MoveObject(payData, errorCode);
    mtpOperUtils->CopyObject(payData, errorCode);
    mtpOperUtils->GetStorageIDs(payData, containerType, errorCode);
    mtpOperUtils->GetStorageInfo(payData, containerType, errorCode);
    string path = FuzzString(data, size);
    string realPath = FuzzString(data, size);
    uint32_t handle = FuzzUInt32(data, size);
    mtpOperUtils->GetPathByHandle(handle, path, realPath);
    mtpOperUtils->GetHandleByPaths(path, handle);

    mtpOperUtils->SetDevicePropValueResp(payData);
    mtpOperUtils->ResetDevicePropResp(payData);
    int32_t payload = FuzzInt32(data, size);
    mtpOperUtils->ObjectEvent(payData, payload);

    mtpOperUtils->CheckErrorCode(FuzzInt32(data, size));
    mtpOperUtils->SendEventPacket(FuzzUInt32(data, size), FuzzUInt16(data, size));

    mtpOperUtils->GetRespCommonData(payData, errorCode);
    mtpOperUtils->GetObjectReferences(payData, containerType, errorCode);
    
    mtpOperUtils->SetObjectReferences(payData);
    mtpOperUtils->GetObjectDataDeal();
    mtpOperUtils->GetObject(payData, errorCode);
    mtpOperUtils->DoRecevieSendObject();
    mtpOperUtils->GetThumb(payData, containerType, errorCode);
    mtpOperUtils->GetPropDesc(payData, containerType, errorCode);
    mtpOperUtils->GetPropValue(payData, containerType, errorCode);
    mtpOperUtils->HasStorage(errorCode);
}

static void MtpOperationUtilsCommonTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj, context);
    shared_ptr<MtpOperationUtils> mtpOperUtils = make_shared<MtpOperationUtils>(context);
    string fsUuid = FuzzString(data, size);
    uint32_t storageId = FuzzUInt32(data, size);
    mtpOperUtils->TryAddExternalStorage(fsUuid, storageId);
    mtpOperUtils->TryRemoveExternalStorage(fsUuid, storageId);
    mtpOperUtils->GetBatteryLevel();

    string property = FuzzString(data, size);
    string defValue = FuzzString(data, size);
    string value = FuzzString(data, size);
    mtpOperUtils->GetPropertyInner(property, defValue);
    mtpOperUtils->SetPropertyInner(property, value);

    uint32_t fd = FuzzInt32(data, size);
    bool deal = FuzzBool(data, size);
    MtpFileRange mfr;
    mfr.fd = FuzzInt32(data, size);
    mfr.length = FuzzInt64(data, size);
    mfr.command = FuzzUInt16(data, size);
    mfr.transaction_id = FuzzUInt32(data, size);

    mtpOperUtils->PreDealFd(deal, fd);
    mtpOperUtils->RecevieSendObject(mfr, fd);
}

static void MtpOperationUtilsTest(const uint8_t* data, size_t size)
{
    MtpOperationUtilsPayloadDataTest(data, size);
    MtpOperationUtilsCommonTest(data, size);
}

static void MtpOperationTest(const uint8_t* data, size_t size)
{
    MtpOperation mtpOperation;
    mtpOperation.Init();
    mtpOperation.ResetOperation();
    mtpOperation.Execute();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(FuzzMtpOperationContext(data, size));
    shared_ptr<PayloadData> payloadData = make_shared<CloseSessionData>(context);
    uint16_t containerType = FuzzUInt16(data, size);
    int errorCode = FuzzInt32(data, size);
    mtpOperation.GetPayloadData(context, payloadData, containerType, errorCode);
    mtpOperation.GetPayloadDataMore(context, payloadData, containerType, errorCode);

    mtpOperation.ReceiveRequestPacket(errorCode);
    mtpOperation.SendObjectData(errorCode);
    mtpOperation.RecevieObjectData(errorCode);
    mtpOperation.SendMakeResponsePacket(errorCode);
    mtpOperation.ReceiveI2Rdata(errorCode);
    mtpOperation.SendR2Idata(errorCode);
    shared_ptr<Storage> storage = make_shared<Storage>();
    mtpOperation.AddStorage(storage);
    mtpOperation.RemoveStorage(storage);
    uint16_t operationCode = FuzzUInt16(data, size);
    mtpOperation.DealRequest(operationCode, errorCode);
}

// MtpPacketToolTest start
static void MtpPacketToolIntTest(const uint8_t* data, size_t size)
{
    uint8_t numFirst = *data;
    MtpPacketTool::GetUInt16(numFirst, numFirst);
    MtpPacketTool::GetUInt32(numFirst, numFirst, numFirst, numFirst);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    size_t offset = 0;
    MtpPacketTool::PutUInt8(outBuffer, FuzzUInt16(data, size));
    MtpPacketTool::PutUInt16(outBuffer, FuzzUInt16(data, size));
    MtpPacketTool::PutUInt32(outBuffer, FuzzUInt32(data, size));
    MtpPacketTool::PutUInt64(outBuffer, FuzzUInt64(data, size));
    MtpPacketTool::PutUInt128(outBuffer, FuzzUInt64(data, size));
    uint128_t valueTeat = {FuzzUInt32(data, size), FuzzUInt32(data, size)};
    MtpPacketTool::PutUInt128(outBuffer, valueTeat);

    MtpPacketTool::GetUInt8(outBuffer, offset);
    size_t offsetTest = size;
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    MtpPacketTool::GetUInt8(buffer, offsetTest, numFirst);

    outBuffer.clear();
    MtpPacketTool::GetUInt8(outBuffer, offset, numFirst);
    MtpPacketTool::GetUInt16(outBuffer, offset);
    uint16_t numFirstTest = FuzzUInt16(data, size);
    MtpPacketTool::GetUInt16(outBuffer, offsetTest, numFirstTest);
    MtpPacketTool::GetUInt16(buffer, offsetTest, numFirstTest);
    MtpPacketTool::GetUInt32(outBuffer, offset);

    uint32_t valueOne = FuzzUInt32(data, size);
    MtpPacketTool::GetUInt32(buffer, offsetTest, valueOne);
    MtpPacketTool::GetUInt32(outBuffer, offsetTest, valueOne);

    uint64_t valueTwo = FuzzUInt64(data, size);
    MtpPacketTool::GetUInt64(buffer, offsetTest, valueTwo);
    MtpPacketTool::GetUInt64(outBuffer, offsetTest, valueTwo);
    MtpPacketTool::GetUInt128(buffer, offsetTest, valueTeat);
    MtpPacketTool::GetUInt128(outBuffer, offsetTest, valueTeat);
}

static void MtpPacketToolStringTest(const uint8_t* data, size_t size)
{
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    size_t offset = size;
    MtpPacketTool::GetString(buffer, offset);
    string str = FuzzString(data, size);
    MtpPacketTool::GetString(buffer, offset, str);
    string value = FuzzString(data, size);
    MtpPacketTool::StrToString(value);
}

static void MtpPacketToolOtherTest(const uint8_t* data, size_t size)
{
    MtpPacketTool::GetIndentBlank();
    size_t indent = size;
    MtpPacketTool::GetIndentBlank(indent);
    vector<uint8_t> dumpData = FuzzVectorUInt8(data, size);
    MtpPacketTool::Dump(dumpData);
    unique_ptr<char[]> hexBuf;
    int hexBufSize = FuzzInt32(data, size);
    unique_ptr<char[]> txtBuf;
    int txtBufSize = FuzzInt32(data, size);
    MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);

    uint8_t u8 = *data;
    MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);

    string str = FuzzString(data, size);
    hexBuf = make_unique<char[]>(str[0]);
    txtBuf = make_unique<char[]>(str[0]);
    MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);

    MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);

    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
    hexBuf[OFFSET_0] = '\0';
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
    time_t sec = 0;
    uint16_t code = FuzzUInt16(data, size);
    MtpPacketTool::FormatDateTime(sec);
    MtpPacketTool::GetOperationName(code);
    MtpPacketTool::GetEventName(code);
    MtpPacketTool::GetFormatName(code);
    MtpPacketTool::GetObjectPropName(code);
    MtpPacketTool::GetEventName(code);

    int type = FuzzInt32(data, size);
    MtpPacketTool::GetDataTypeName(type);
    MtpPacketTool::GetAssociationName(type);

    uint16_t propCode = FuzzUInt16(data, size);
    MtpPacketTool::GetObjectPropTypeByPropCode(propCode);
}

static void MtpPacketToolTest(const uint8_t* data, size_t size)
{
    MtpPacketToolIntTest(data, size);
    MtpPacketToolStringTest(data, size);
    MtpPacketToolOtherTest(data, size);
}

static void MtpPacketTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj, context);
    shared_ptr<MtpPacket> mtpPacket = make_shared<MtpPacket>(context);
    mtpPacket->Parser();
    mtpPacket->ParserHead();
    mtpPacket->ParserPayload();
    mtpPacket->MakeHead();
    mtpPacket->MakerPayload();
    mtpPacket->GetOperationCode();
    mtpPacket->GetTransactionId();
    mtpPacket->GetSessionID();

    uint16_t operationCode = FuzzUInt16(data, size);
    mtpPacket->IsNeedDataPhase(operationCode);
    mtpPacket->IsI2R(operationCode);
    mtpPacket->Reset();
}

static void MtpServiceTest(const uint8_t* data, size_t size)
{
    MtpService mtpService;
    mtpService.Init();
    mtpService.StartService();
    mtpService.StopService();
}

// PropertyTest start
static void PropertySetFormEnumTest(const uint8_t* data, size_t size)
{
    uint16_t propCode = FuzzUInt16(data, size);
    uint16_t propType = FuzzUInt16(data, size);
    bool propWriteable = FuzzBool(data, size);
    int value = FuzzInt32(data, size);
    Property property(propCode, propType, propWriteable, value);

    property.SetFormRange(0, 0, 0);
    vector<int> values = FuzzVectorInt32(data, size);
    property.SetFormEnum(values);
    property.Dump();
     
    property.GetPropertyCode();
    property.GetDataType();
    Property  propertyTest;
    propertyTest.GetDataType();

    property.SetFormDateTime();
    property.IsDeviceProperty();
    property.IsArrayType();
}

static void PropertyWriteTest(const uint8_t* data, size_t size)
{
    uint16_t propCode = FuzzUInt16(data, size);
    Property property(propCode, MTP_TYPE_UINT8_CODE);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    property.Write(buffer);
    size_t offsetTest = 0;
    property.Read(buffer, offsetTest);
    shared_ptr<string> str = make_shared<string>(FuzzString(data, size));
    property.SetDefaultValue(str);
    property.SetCurrentValue(str);
    property.GetCurrentValue();
    property.IsArrayType();
}

static void PropertyStringTest(const uint8_t* data, size_t size)
{
    uint16_t propCode = FuzzUInt16(data, size);
    Property property(propCode, MTP_TYPE_AINT8_CODE);
    uint8_t indent = *data;
    shared_ptr<vector<Property::Value>> values;
    string name = FuzzString(data, size);
    property.DumpValues(indent, values, name);
    values = make_shared<vector<Property::Value>>();
    property.DumpValues(indent, values, name);
    property.DumpForm(indent);
    property.SetFormRange(0, 0, 0);
    property.DumpForm(indent);

    shared_ptr<Property::Value> value = make_shared<Property::Value>();
    uint32_t valueType = FuzzUInt32(data, size);
    value->Dump(valueType);
    string outStr = value->ToString(valueType);
    value->BinToString(valueType, outStr);
}

static void PropertyReadValueTest(const uint8_t* data, size_t size)
{
    uint16_t propCode = FuzzUInt16(data, size);
    uint16_t propType = FuzzUInt16(data, size);
    bool propWriteable = FuzzBool(data, size);
    int values = FuzzInt32(data, size);
    Property property(propCode, propType, propWriteable, values);

    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    size_t offset = 0;
    Property::Value value;
    property.ReadValue(buffer, offset, value);
    property.WriteValue(buffer, value);
    property.ReadValue(buffer, offset, value);

    property.ReadValueEx(buffer, offset, value);
    property.WriteValue(buffer, value);
    property.WriteValueEx(buffer, value);
    property.ReadValueEx(buffer, offset, value);
}

static void PropertyReadArrayValuesTest(const uint8_t* data, size_t size)
{
    uint16_t propCode = FuzzUInt16(data, size);
    uint16_t propType = FuzzUInt16(data, size);
    bool propWriteable = FuzzBool(data, size);
    int value = FuzzInt32(data, size);
    Property property(propCode, propType, propWriteable, value);
    shared_ptr<vector<Property::Value>> values;

    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    MtpPacketTool::PutInt32(buffer, value);
    property.WriteValueData(buffer);
    size_t offset = 0;
    property.ReadArrayValues(buffer, offset, values);

    Property propertyOne(propCode, propType);
    propertyOne.WriteValueData(buffer);
    size_t offsetTest = size / 2;
    propertyOne.Write(buffer);
    property.ReadArrayValues(buffer, offsetTest, values);
}

static void PropertyDumpValueTest(const uint8_t* data, size_t size)
{
    uint16_t propCode = FuzzUInt16(data, size);
    uint16_t propType = FuzzUInt16(data, size);
    bool propWriteable = FuzzBool(data, size);
    int value = FuzzInt32(data, size);
    Property property(propCode, propType, propWriteable, value);
    uint8_t indent = *data;
    string name = FuzzString(data, size);
    shared_ptr<Property::Value> valueTest;
    property.DumpValue(indent, valueTest, name);
    valueTest = make_shared<Property::Value>();
    uint32_t valueType = FuzzUInt32(data, size);
    string outStr = FuzzString(data, size);
    valueTest->StrToString(valueType, outStr);

    valueTest->str_ = make_shared<string>(FuzzString(data, size));
    valueTest->StrToString(valueType, outStr);
    property.DumpValue(indent, valueTest, name);
}

static void PropertyWriteFormDataTest(const uint8_t* data, size_t size)
{
    uint16_t propCode = FuzzUInt16(data, size);
    uint16_t propType = FuzzUInt16(data, size);
    bool propWriteable = FuzzBool(data, size);
    int value = FuzzInt32(data, size);
    Property property(propCode, propType, propWriteable, value);
    property.SetFormRange(0, 0, 0);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    size_t offset = 0;
    property.ReadFormData(buffer, offset);

    property.WriteFormData(buffer);
    size_t offsetTest = size / 2;

    MtpPacketTool::PutInt8(buffer, offsetTest);
    property.ReadFormData(buffer, offsetTest);

    vector<int> values = FuzzVectorInt32(data, size);
    property.SetFormEnum(values);
    property.ReadFormData(buffer, offsetTest);
    property.WriteFormData(buffer);
}

static void PropertyTest(const uint8_t* data, size_t size)
{
    PropertySetFormEnumTest(data, size);
    PropertyWriteTest(data, size);
    PropertyStringTest(data, size);
    PropertyReadValueTest(data, size);
    PropertyReadArrayValuesTest(data, size);
    PropertyDumpValueTest(data, size);
    PropertyWriteFormDataTest(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::HeaderDataTest(data, size);
    OHOS::MtpDataUtilsTest(data, size);
    OHOS::MtpDriverTest(data, size);
    OHOS::MtpErrorUtilsTest(data, size);
    OHOS::MtpEventTest(data, size);
    OHOS::MtpManagerTest(data, size);
    OHOS::MtpMediaLibraryTest(data, size);
    OHOS::MtpMedialibraryManagerTest(data, size);
    OHOS::MtpMonitorTest(data, size);
    OHOS::MtpOperationUtilsTest(data, size);
    OHOS::MtpOperationTest(data, size);
    OHOS::MtpPacketToolTest(data, size);
    OHOS::MtpPacketTest(data, size);
    OHOS::MtpServiceTest(data, size);
    OHOS::PropertyTest(data, size);
    return 0;
}
