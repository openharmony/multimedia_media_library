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
#include "media_log.h"

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
#include "mtp_store_observer.h"
#include "packet_payload_factory.h"
#include "property.h"
#include "ptp_album_handles.h"
#include "close_session_data.h"
#include "copy_object_data.h"
#include "delete_object_data.h"
#include "get_device_info_data.h"
#include "get_device_prop_desc_data.h"
#include "get_device_prop_value_data.h"
#include "get_num_objects_data.h"
#include "get_object_data.h"
#include "get_object_handles_data.h"
#include "get_object_info_data.h"
#include "get_object_prop_desc_data.h"
#include "get_object_prop_list_data.h"
#include "get_object_prop_value_data.h"
#include "get_object_props_supported_data.h"
#include "get_object_references_data.h"
#include "get_partial_object_data.h"
#include "get_storage_ids_data.h"
#include "get_storage_info_data.h"
#include "get_thumb_data.h"
#include "move_object_data.h"
#include "object_event_data.h"
#include "open_session_data.h"
#include "resp_common_data.h"
#include "send_object_data.h"
#include "send_object_info_data.h"
#include "set_device_prop_value_data.h"
#include "set_object_prop_value_data.h"
#include "set_object_references_data.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;

const shared_ptr<MtpMediaLibrary> mtpMediaLib_ = MtpMediaLibrary::GetInstance();
const shared_ptr<MtpMedialibraryManager> ptpMediaLib_ = MtpMedialibraryManager::GetInstance();

// storage file
const std::string STORAGE_FILE = "/storage/media/local/files/Docs";
// file path
const string FILE_PATH = "/storage/media/local/files/Docs/Desktop";
const int32_t EVEN = 2;

shared_ptr<MtpOperationUtils> mtpOperUtils_ = nullptr;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int8_t FuzzInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int8_t)) {
        return 0;
    }
    return static_cast<int8_t>(*data);
}

static inline int16_t FuzzInt16(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int16_t)) {
        return 0;
    }
    return static_cast<int16_t>(*data);
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

static inline uint8_t FuzzUInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint8_t)) {
        return 0;
    }
    return *data;
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

static inline uint64_t FuzzUInt64(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint64_t)) {
        return 0;
    }
    return static_cast<uint64_t>(*data);
}

static inline vector<int32_t> FuzzVectorInt32(const uint8_t *data, size_t size)
{
    return {FuzzInt32(data, size)};
}

static inline vector<uint8_t> FuzzVectorUInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint8_t)) {
        return {0};
    }
    return {*data};
}

static inline vector<uint16_t> FuzzVectorUInt16(const uint8_t *data, size_t size)
{
    return {FuzzUInt16(data, size)};
}

static inline vector<uint32_t> FuzzVectorUInt32(const uint8_t *data, size_t size)
{
    return {FuzzUInt32(data, size)};
}

static inline vector<string> FuzzVectorString(const uint8_t *data, size_t size)
{
    return {FuzzString(data, size)};
}

static inline MtpManager::MtpMode FuzzMtpMode(const uint8_t* data, size_t size)
{
    int32_t mode = FuzzInt32(data, size);
    if (mode >= static_cast<int32_t>(MtpManager::MtpMode::NONE_MODE) &&
        mode <= static_cast<int32_t>(MtpManager::MtpMode::PTP_MODE)) {
        return static_cast<MtpManager::MtpMode>(mode);
    }
    return MtpManager::MtpMode::PTP_MODE;
}

static inline Media::ResultSetDataType FuzzResultSetDataType(const uint8_t* data, size_t size)
{
    int32_t dataType = FuzzInt32(data, size);
    if (dataType >= static_cast<int32_t>(Media::ResultSetDataType::TYPE_NULL) &&
        dataType <= static_cast<int32_t>(Media::ResultSetDataType::TYPE_DOUBLE)) {
        return static_cast<Media::ResultSetDataType>(dataType);
    }
    return Media::ResultSetDataType::TYPE_STRING;
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

static ObjectInfo FuzzObjectInfo(const uint8_t* data, size_t size)
{
    ObjectInfo objectInfo(0);
    const int32_t uInt32Count = 13;
    const int32_t uInt16Count = 4;
    if (data == nullptr || size < (sizeof(uint32_t) * uInt32Count +
        sizeof(uint16_t) * uInt16Count)) {
        return objectInfo;
    }
    int32_t offset = 0;
    objectInfo.handle = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.storageID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.format = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    objectInfo.protectionStatus = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    objectInfo.compressedSize = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.size = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.thumbFormat = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    objectInfo.thumbCompressedSize = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.thumbPixelWidth = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.thumbPixelHeight = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.imagePixelWidth = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.imagePixelHeight = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.imagePixelDepth = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.parent = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.associationType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    objectInfo.associationDesc = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    objectInfo.sequenceNumber = FuzzUInt32(data + offset, size);

    objectInfo.name = FuzzString(data, size);
    objectInfo.keywords = FuzzString(data, size);
    return objectInfo;
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

static void SolveHandlesFormatDataTest(const uint8_t* data, size_t size)
{
    uint16_t format = FuzzUInt16(data, size);
    MediaType outMediaType = MEDIA_TYPE_FILE;
    string outExtension = FuzzString(data, size);
    MtpDataUtils::SolveHandlesFormatData(format, outExtension, outMediaType);

    format = FuzzBool(data, size) ? MTP_FORMAT_UNDEFINED_CODE : FuzzUInt16(data, size);
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
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    context->property = MTP_PROPERTY_ALL_CODE;
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
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpDataUtils::GetPropListBySet(context, resultSet, outProps);

    context->property = FuzzBool(data, size) ? MTP_PROPERTY_ALL_CODE : FuzzInt32(data, size);
    MtpDataUtils::GetPropListBySet(context, resultSet, outProps);
}

static void GetPropValueBySetTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    uint32_t property = FuzzUInt32(data, size);
    PropertyValue outPropValue;
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    MtpDataUtils::GetPropValueBySet(property, resultSet, outPropValue, false);
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
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    shared_ptr<UInt16List> properties = make_shared<UInt16List>(FuzzVectorUInt16(data, size));
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpDataUtils::GetPropList(context, resultSet, properties, outProps);
}

static void ReturnErrorTest(const uint8_t* data, size_t size)
{
    string errMsg = "";
    ResultSetDataType type = FuzzResultSetDataType(data, size);
    MtpDataUtils::ReturnError(errMsg, type);
}

static void GetFormatTest(const uint8_t* data, size_t size)
{
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    if (data == nullptr || size < sizeof(uint16_t) + sizeof(uint32_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t outFormat = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpDataUtils::GetFormat(resultSet, outFormat);

    uint32_t handle = FuzzUInt32(data + offset, size);
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
    ReturnErrorTest(data, size);
    GetFormatTest(data, size);
    SetOneDefaultlPropListTest(data, size);
}

static void MtpDriverTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpDriver> mtpDriver = make_shared<MtpDriver>();
    mtpDriver->OpenDriver();

    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    uint32_t sizeBuf = buffer.size();
    mtpDriver->Read(buffer, sizeBuf);
    mtpDriver->Write(buffer, sizeBuf);

    MtpFileRange mfr;
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
    const int32_t mediaError = FuzzInt32(data, size);
    MtpErrorUtils::SolveGetHandlesError(mediaError);
    MtpErrorUtils::SolveGetObjectInfoError(mediaError);
    MtpErrorUtils::SolveSendObjectInfoError(mediaError);
    MtpErrorUtils::SolveMoveObjectError(mediaError);
    MtpErrorUtils::SolveCopyObjectError(mediaError);
    MtpErrorUtils::SolveDeleteObjectError(mediaError);
    MtpErrorUtils::SolveObjectPropValueError(mediaError);
    MtpErrorUtils::SolveCloseFdError(mediaError);
}

static void MtpEventTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<MtpEvent> mtpEvent = make_shared<MtpEvent>(context);
    string path = FuzzString(data, size);
    uint32_t handle = FuzzUInt32(data, size);
    string fsUuid = FuzzString(data, size);
    mtpEvent->SendObjectAdded(path);
    mtpEvent->SendObjectRemoved(path);
    mtpEvent->SendObjectRemovedByHandle(handle);
    mtpEvent->SendObjectInfoChanged(path);
    mtpEvent->SendDevicePropertyChanged();
    mtpEvent->SendStoreAdded(fsUuid);
    mtpEvent->SendStoreRemoved(fsUuid);
}

static void MtpFileObserverTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<MtpFileObserver> mtpFileObserver = make_shared<MtpFileObserver>();
    string path = FuzzString(data, size);
    string realPath = FuzzString(data, size);
    mtpFileObserver->StartFileInotify();
    mtpFileObserver->AddFileInotify(path, realPath, context);
    mtpFileObserver->AddPathToWatchMap(path);
    mtpFileObserver->StopFileInotify();
}

static void MtpManagerTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    MtpManager::GetInstance().Init();
    MtpManager::GetInstance().StartMtpService(FuzzMtpMode(data, size));
    MtpManager::GetInstance().IsMtpMode();
    string key = "persist.edm.mtp_server_disable";
    string value = FuzzString(data, size);
    MtpManager::GetInstance().OnMtpParamDisableChanged(key.c_str(), value.c_str(), context.get());
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
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
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
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(FuzzObjectInfo(data, size));
    context->handle = 1;
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

static void MoveObjectTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

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

static void SetObjectPropValueTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    mtpMediaLib_->AddToHandlePathMap(FILE_PATH + "/" + FuzzString(data, size) + ".txt", FuzzUInt32(data, size));

    mtpMediaLib_->SetObjectPropValue(context);
}

static void CloseFdTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    //storage file path
    mtpMediaLib_->ObserverAddPathToMap(FILE_PATH);
    //parent file path
    mtpMediaLib_->ObserverAddPathToMap(FuzzString(data, size));

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
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    context->groupCode = 0;
    mtpMediaLib_->GetObjectPropList(context, outProps);

    context->property = FuzzUInt32(data, size);
    context->depth = MTP_ALL_DEPTH;
    context->handle = 0;
    mtpMediaLib_->GetObjectPropList(context, outProps);
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
    shared_ptr<unordered_map<uint32_t, string>> out =
        make_shared<unordered_map<uint32_t, string>>();

    mtpMediaLib_->ScanDirWithType(STORAGE_FILE, out);
    mtpMediaLib_->ScanDirTraverseWithType(STORAGE_FILE, out);

    string root = FILE_PATH + "/" + FuzzString(data, size);
    mtpMediaLib_->ScanDirWithType(root, out);
    mtpMediaLib_->ScanDirTraverseWithType(root, out);
    mtpMediaLib_->GetSizeFromOfft(size);
}

static void GetHandlesMapTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));
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
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));

    mtpMediaLib_->GetVideoThumb(context, outThumb);
}

static void GetPictureThumbTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    mtpMediaLib_->AddToHandlePathMap(FuzzString(data, size), FuzzUInt32(data, size));

    mtpMediaLib_->GetPictureThumb(context, outThumb);
}

static void CorrectStorageIdTest(const uint8_t* data, size_t size)
{
    mtpMediaLib_->Clear();
    const shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
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
    GetHandlesMapTest(data, size);
    GetExternalStoragesTest(data, size);
    ErasePathInfoTest(data, size);
    GetVideoThumbTest(data, size);
    GetPictureThumbTest(data, size);
    CorrectStorageIdTest(data, size);
}

// MtpMedialibraryManagerTest start
static void PtpGetHandlesTest(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(uint32_t)) {
        return;
    }
    int32_t offset = 0;
    int32_t parentId = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MediaType mediaType = MediaType::MEDIA_TYPE_IMAGE;
    vector<int> outHandle = FuzzVectorInt32(data + offset, size);
    offset += sizeof(int32_t);
    ptpMediaLib_->GetHandles(parentId, outHandle, mediaType);

    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    uint32_t outId = 0;
    shared_ptr<UInt32List> outHandles = make_shared<UInt32List>(FuzzVectorUInt32(data + offset, size));
    ptpMediaLib_->GetIdByPath(FuzzString(data, size), outId);
    context->parent = outId;
    context->storageID = outId;
    ptpMediaLib_->GetHandles(context, outHandles);
}

static void PtpGetObjectInfoTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(FuzzObjectInfo(data, size));
    ptpMediaLib_->GetObjectInfo(context, objectInfo);

    context->handle = COMMON_PHOTOS_OFFSET;
    ptpMediaLib_->GetObjectInfo(context, objectInfo);
}

static void PtpGetFdTest(const uint8_t* data, size_t size)
{
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
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>(FuzzVectorUInt8(data, size));
    ptpMediaLib_->GetThumb(context, outThumb);
}

static void PtpSendObjectInfoTest(const uint8_t* data, size_t size)
{
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

    ptpMediaLib_->SendObjectInfo(nullptr, outStorageID, outParent, outHandle);
}

static void PtpMoveObjectTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    ptpMediaLib_->MoveObject(context);
}

static void PtpCopyObjectTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    uint32_t outObjectHandle = FuzzUInt32(data, size);
    context->handle = EDITED_PHOTOS_OFFSET;
    ptpMediaLib_->CopyObject(context, outObjectHandle);
    ptpMediaLib_->DeleteObject(context);
}

static void PtpSetObjectPropValueTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    ptpMediaLib_->SetObjectPropValue(context);
}

static void PtpCloseFdTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    uint32_t handle = 0;
    ptpMediaLib_->GetIdByPath(FuzzString(data, size), handle);
    context->handle = handle;
    int32_t outFd = FuzzInt32(data, size);
    string mode = FuzzString(data, size);
    ptpMediaLib_->GetFd(context, outFd, mode);
    ptpMediaLib_->CloseFd(context, outFd);
}

static void PtpGetObjectPropListTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();

    ptpMediaLib_->GetObjectPropList(context, outProps);

    context->parent = FuzzUInt32(data, size);
    ptpMediaLib_->GetObjectPropList(context, outProps);
}

static void PtpGetObjectPropValueTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    uint64_t outIntVal = 0;
    uint128_t outLongVal = { 0 };
    string outStrVal = "";
    ptpMediaLib_->GetObjectPropValue(context, outIntVal, outLongVal, outStrVal);
}

static void PtpGetPictureThumbTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    ptpMediaLib_->GetPictureThumb(context, outThumb);
}

static void PtpGetVideoThumbTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<UInt8List> outThumb = make_shared<UInt8List>();
    ptpMediaLib_->GetVideoThumb(context, outThumb);
}

static void PtpGetFdByOpenFileTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    int32_t outFd = FuzzInt32(data, size);
    ptpMediaLib_->GetFdByOpenFile(context, outFd);
}

static void PtpSetObjectInfoTest(const uint8_t* data, size_t size)
{
    const unique_ptr<FileAsset> fileAsset = make_unique<FileAsset>();
    fileAsset->SetMediaType(MediaType::MEDIA_TYPE_ALBUM);
    shared_ptr<ObjectInfo> outObjectInfo = make_shared<ObjectInfo>(FuzzObjectInfo(data, size));
    ptpMediaLib_->SetObjectInfo(fileAsset, outObjectInfo);

    fileAsset->SetMediaType(MediaType::MEDIA_TYPE_IMAGE);
    ptpMediaLib_->SetObjectInfo(fileAsset, outObjectInfo);

    fileAsset->SetMediaType(MediaType::MEDIA_TYPE_VIDEO);
    ptpMediaLib_->SetObjectInfo(fileAsset, outObjectInfo);
}

static void PtpSetObjectTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    shared_ptr<ObjectInfo> outObjectInfo = nullptr;
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    ptpMediaLib_->SetObject(resultSet, context, outObjectInfo);
}

static void PtpCompressImageTest(const uint8_t* data, size_t size)
{
    unique_ptr<PixelMap> pixelMap = nullptr;
    vector<uint8_t> imageDdata  = FuzzVectorUInt8(data, size);
    ptpMediaLib_->CompressImage(pixelMap, imageDdata);
}

static void PtpGetAlbumInfoTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    bool isHandle = FuzzBool(data, size);
    ptpMediaLib_->GetAlbumInfo(context, isHandle);
}

static void PtpGetPhotosInfoTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    bool isHandle = FuzzBool(data, size);
    ptpMediaLib_->GetPhotosInfo(context, isHandle);
}

static void PtpGetAlbumCloudTest(const uint8_t* data, size_t size)
{
    ptpMediaLib_->GetAlbumCloud();
    vector<string> ownerAlbumIds = FuzzVectorString(data, size);
    ptpMediaLib_->GetAlbumCloudDisplay(ownerAlbumIds);
}

static void PtpHaveMovingPhotesHandleTest(const uint8_t* data, size_t size)
{
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
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
}

static void PtpGetThumbUriTest(const uint8_t* data, size_t size)
{
    const int32_t handle = FuzzInt32(data, size);
    const string thumbSizeValue = FuzzString(data, size);
    const string dataPath = FILE_PATH + "/" + FuzzString(data, size);
    ptpMediaLib_->GetThumbUri(handle, thumbSizeValue, dataPath);
}

static void DeleteCanceledObjectTest(const uint8_t* data, size_t size)
{
    uint32_t id = FuzzUInt32(data, size);
    ptpMediaLib_->DeleteCanceledObject(id);
    ptpMediaLib_->Clear();
}

static void MtpMedialibraryManagerTest(const uint8_t* data, size_t size)
{
    PtpGetHandlesTest(data, size);
    PtpGetObjectInfoTest(data, size);
    PtpGetFdTest(data, size);
    PtpGetThumbTest(data, size);
    PtpSendObjectInfoTest(data, size);
    PtpMoveObjectTest(data, size);
    PtpCopyObjectTest(data, size);
    PtpSetObjectPropValueTest(data, size);
    PtpCloseFdTest(data, size);
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
    PtpGetThumbUriTest(data, size);
    DeleteCanceledObjectTest(data, size);
}

static void MtpMonitorTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpMonitor> mtpMonitor = make_shared<MtpMonitor>();
    mtpMonitor->Start();
    mtpMonitor->Stop();
}

static void MtpOperationTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperation> mtpOperation = make_shared<MtpOperation>();
    mtpOperation->mtpContextPtr_->operationCode = FuzzInt32(data, size);
    mtpOperation->Execute();
    mtpOperation->Stop();
    for (uint16_t code = MTP_OPERATION_GET_DEVICE_INFO_CODE; code < MTP_OPERATION_SKIP_CODE; code++) {
        mtpOperation->mtpContextPtr_->operationCode = code;
        mtpOperation->Execute();
        mtpOperation->Stop();
    }
}

// MtpOperationUtilsTest start
static void MtpOperationUtilsContainerTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    if (data == nullptr || size < sizeof(uint16_t) + sizeof(int32_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t containerType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    int errorCode = FuzzInt32(data + offset, size);
    mtpOperUtils_->GetDeviceInfo(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectInfo(payData, containerType, errorCode);
    mtpOperUtils_->GetNumObjects(payData);
    mtpOperUtils_->DoSetObjectPropValue(errorCode);
    mtpOperUtils_->GetObjectHandles(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectPropDesc(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectPropValue(payData, containerType, errorCode);
    mtpOperUtils_->GetObjectPropList(payData, containerType, errorCode);
    mtpOperUtils_->SendObjectInfo(payData, errorCode);
    mtpOperUtils_->GetPartialObject(payData);
    mtpOperUtils_->GetObjectPropsSupported(payData);
    mtpOperUtils_->GetOpenSession(payData, errorCode);
    mtpOperUtils_->GetCloseSession(payData);
    mtpOperUtils_->DeleteObject(payData, errorCode);
    mtpOperUtils_->MoveObject(payData, errorCode);
    mtpOperUtils_->CopyObject(payData, errorCode);
    mtpOperUtils_->GetStorageIDs(payData, containerType, errorCode);
    mtpOperUtils_->GetStorageInfo(payData, containerType, errorCode);
}

static void MtpOperationUtilsGetPathByHandleTest(const uint8_t* data, size_t size)
{
    if (mtpOperUtils_ == nullptr) {
        shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
            FuzzMtpOperationContext(data, size));
        if (context == nullptr) {
            MEDIA_ERR_LOG("context is nullptr");
            return;
        }
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    string path = FILE_PATH + "/" + FuzzString(data, size);
    string realPath = FILE_PATH + "/" + FuzzString(data, size);
    uint32_t handle = FuzzUInt32(data, size);
    mtpOperUtils_->GetPathByHandle(handle, path, realPath);
    mtpOperUtils_->GetHandleByPaths(path, handle);
}

static void MtpOperationUtilsHandleTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    if (mtpOperUtils_ == nullptr) {
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    shared_ptr<PayloadData> payData = make_shared<CloseSessionData>(context);
    mtpOperUtils_->SetDevicePropValueResp(payData);
    mtpOperUtils_->ResetDevicePropResp(payData);

    const int32_t int32Count = 3;
    const int32_t uInt16Count = 5;
    if (data == nullptr || size < sizeof(int32_t) * int32Count +
        sizeof(uint16_t) * uInt16Count + sizeof(uint32_t)) {
        return;
    }
    int32_t offset = 0;
    int32_t payload = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    mtpOperUtils_->ObjectEvent(payData, payload);

    int errorCode = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    mtpOperUtils_->CheckErrorCode(errorCode);
    uint32_t objectHandle = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint16_t eventCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    mtpOperUtils_->SendEventPacket(objectHandle, eventCode);

    errorCode = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    mtpOperUtils_->GetRespCommonData(payData, errorCode);

    uint16_t containerType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    mtpOperUtils_->GetObjectReferences(payData, containerType, errorCode);

    mtpOperUtils_->SetObjectReferences(payData);
    mtpOperUtils_->GetObjectDataDeal();
    mtpOperUtils_->GetObject(payData, errorCode);

    containerType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    mtpOperUtils_->GetThumb(payData, containerType, errorCode);
    containerType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    mtpOperUtils_->GetPropDesc(payData, containerType, errorCode);
    containerType = FuzzUInt16(data + offset, size);
    mtpOperUtils_->GetPropValue(payData, containerType, errorCode);
    mtpOperUtils_->HasStorage(errorCode);
}

static void MtpOperationUtilsStorageIdTest(const uint8_t* data, size_t size)
{
    if (mtpOperUtils_ == nullptr) {
        shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
            FuzzMtpOperationContext(data, size));
        if (context == nullptr) {
            MEDIA_ERR_LOG("context is nullptr");
            return;
        }
        mtpOperUtils_ = make_shared<MtpOperationUtils>(context);
    }

    string fsUuid = FuzzString(data, size);
    uint32_t storageId = FuzzUInt32(data, size);
    mtpOperUtils_->TryAddExternalStorage(fsUuid, storageId);
    mtpOperUtils_->TryRemoveExternalStorage(fsUuid, storageId);
    mtpOperUtils_->GetBatteryLevel();
}

static void MtpOperationUtilsTest(const uint8_t* data, size_t size)
{
    MtpOperationUtilsContainerTest(data, size);
    MtpOperationUtilsGetPathByHandleTest(data, size);
    MtpOperationUtilsHandleTest(data, size);
    MtpOperationUtilsStorageIdTest(data, size);
}

// MtpPacketToolTest start
static void MtpPacketToolPutTest(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    const int32_t uInt32Count = 3;
    const int32_t uInt64Count = 2;
    const int32_t int32Count = 3;
    const int32_t int64Count = 2;
    if (data == nullptr || size < (sizeof(uint16_t) * uInt16Count +
        sizeof(uint32_t) * uInt32Count + sizeof(uint64_t) * uInt64Count +
        sizeof(int8_t) + sizeof(int16_t) + sizeof(int32_t) * int32Count +
        sizeof(int64_t) * int64Count)) {
        return;
    }
    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    int32_t offset = 0;
    MtpPacketTool::PutUInt8(outBuffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    MtpPacketTool::PutUInt16(outBuffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    MtpPacketTool::PutUInt32(outBuffer, FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    MtpPacketTool::PutUInt64(outBuffer, FuzzUInt64(data + offset, size));
    offset += sizeof(uint64_t);
    MtpPacketTool::PutUInt128(outBuffer, FuzzUInt64(data + offset, size));
    offset += sizeof(uint64_t);
    uint32_t valueUInt32First = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Second = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::PutUInt128(outBuffer, valueUInt128);

    MtpPacketTool::PutInt8(outBuffer, FuzzInt8(data + offset, size));
    offset += sizeof(int8_t);
    MtpPacketTool::PutInt16(outBuffer, FuzzInt16(data + offset, size));
    offset += sizeof(int16_t);
    MtpPacketTool::PutInt32(outBuffer, FuzzInt32(data + offset, size));
    offset += sizeof(int32_t);
    MtpPacketTool::PutInt64(outBuffer, FuzzInt64(data + offset, size));
    offset += sizeof(int64_t);
    MtpPacketTool::PutInt128(outBuffer, FuzzInt64(data + offset, size));
    offset += sizeof(int64_t);
    int32_t valueInt32First = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t valueInt32Second = FuzzInt32(data + offset, size);
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    MtpPacketTool::PutInt128(outBuffer, valueInt128);
    MtpPacketTool::PutString(outBuffer, FuzzString(data, size));
}

static void MtpPacketToolGetTest(const uint8_t* data, size_t size)
{
    const int32_t uInt8Count = 6;
    if (data == nullptr || size < sizeof(uint8_t) * uInt8Count) {
        return;
    }
    int32_t offset = 0;
    uint8_t numFirst = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    uint8_t numSecond = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    MtpPacketTool::GetUInt16(numFirst, numSecond);
    numFirst = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    numSecond = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    uint8_t numThird = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    uint8_t numFourth = FuzzUInt8(data + offset, size);
    MtpPacketTool::GetUInt32(numFirst, numSecond, numThird, numFourth);
}

static void MtpPacketToolGetUInt8Test(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count + sizeof(uint8_t)) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt8(buffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    MtpPacketTool::GetUInt8(buffer, offsetTest);
    MtpPacketTool::PutUInt8(buffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    uint8_t valueUInt8 = FuzzUInt8(data + offset, size);
    MtpPacketTool::GetUInt8(buffer, offsetTest, valueUInt8);
}

static void MtpPacketToolGetUInt16Test(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 3;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt16(buffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    MtpPacketTool::GetUInt16(buffer, offsetTest);
    MtpPacketTool::PutUInt16(buffer, FuzzUInt16(data + offset, size));
    offset += sizeof(uint16_t);
    uint16_t valueUInt16 = FuzzUInt16(data + offset, size);
    MtpPacketTool::GetUInt16(buffer, offsetTest, valueUInt16);
}

static void MtpPacketToolGetUInt32Test(const uint8_t* data, size_t size)
{
    const int32_t uInt32Count = 3;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt32(buffer, FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    MtpPacketTool::GetUInt32(buffer, offsetTest);
    MtpPacketTool::PutUInt32(buffer, FuzzUInt32(data + offset, size));
    offset += sizeof(uint32_t);
    uint32_t valueUInt32 = FuzzUInt32(data + offset, size);
    MtpPacketTool::GetUInt32(buffer, offsetTest, valueUInt32);
}

static void MtpPacketToolGetUInt64Test(const uint8_t* data, size_t size)
{
    const int32_t uInt64Count = 2;
    if (data == nullptr || size < sizeof(uint64_t) * uInt64Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutUInt64(buffer, FuzzUInt64(data + offset, size));
    offset += sizeof(uint64_t);
    uint64_t valueUInt64 = FuzzUInt64(data + offset, size);
    MtpPacketTool::GetUInt64(buffer, offsetTest, valueUInt64);
}

static void MtpPacketToolGetUInt128Test(const uint8_t* data, size_t size)
{
    const int32_t uInt32Count = 2;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    uint32_t valueUInt32First = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Second = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::PutUInt128(buffer, valueUInt128);
    uint128_t outUInt128 = {0, 1};
    MtpPacketTool::GetUInt128(buffer, offsetTest, outUInt128);
}

static void MtpPacketToolGetInt8Test(const uint8_t* data, size_t size)
{
    const int32_t int8Count = 2;
    if (data == nullptr || size < sizeof(int8_t) * int8Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt8(buffer, FuzzInt8(data + offset, size));
    offset += sizeof(int8_t);
    size_t offsetTest = 0;
    int8_t valueInt8 = FuzzInt8(data + offset, size);
    MtpPacketTool::GetInt8(buffer, offsetTest, valueInt8);
}

static void MtpPacketToolGetInt16Test(const uint8_t* data, size_t size)
{
    const int32_t int16Count = 2;
    if (data == nullptr || size < sizeof(int16_t) * int16Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    size_t offsetTest = 0;
    MtpPacketTool::PutInt16(buffer, FuzzInt16(data + offset, size));
    offset += sizeof(int16_t);
    int16_t valueInt16 = FuzzInt16(data + offset, size);
    MtpPacketTool::GetInt16(buffer, offsetTest, valueInt16);
}

static void MtpPacketToolGetInt32Test(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    MtpPacketTool::PutUInt32(buffer, FuzzInt32(data + offset, size));
    offset += sizeof(int32_t);
    int32_t valueInt32 = FuzzInt32(data + offset, size);
    size_t offsetTest = 0;
    MtpPacketTool::GetInt32(buffer, offsetTest, valueInt32);
}

static void MtpPacketToolGetInt64Test(const uint8_t* data, size_t size)
{
    const int32_t int64Count = 2;
    if (data == nullptr || size < sizeof(int64_t) * int64Count) {
        return;
    }
    int32_t offset = 0;
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt64(buffer, FuzzInt64(data + offset, size));
    offset += sizeof(int64_t);
    size_t offsetTest = 0;
    int64_t valueInt64 = FuzzInt64(data + offset, size);
    MtpPacketTool::GetInt64(buffer, offsetTest, valueInt64);
}

static void MtpPacketToolGetInt128Test(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t valueInt32First = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t valueInt32Second = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    vector<uint8_t> buffer;
    MtpPacketTool::PutInt128(buffer, valueInt128);
    size_t offsetTest = 0;
    int128_t outInt128 = {0, 1};
    MtpPacketTool::GetInt128(buffer, offsetTest, outInt128);
}

static void MtpPacketToolGetStringTest(const uint8_t* data, size_t size)
{
    vector<uint8_t> buffer;
    MtpPacketTool::PutString(buffer, FuzzString(data, size));
    size_t offsetTest = 0;
    string str = "";
    MtpPacketTool::GetString(buffer, offsetTest);
    MtpPacketTool::PutString(buffer, FuzzString(data, size));
    MtpPacketTool::GetString(buffer, offsetTest, str);
    string valueString = FuzzString(data, size);
    MtpPacketTool::StrToString(valueString);
}

static void MtpPacketToolToStringTest(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 3;
    const int32_t uInt32Count = 3;
    if (data == nullptr || size < sizeof(int8_t) + sizeof(uint8_t) +
        sizeof(int16_t) + sizeof(uint16_t) + sizeof(int32_t) * int32Count +
        sizeof(uint32_t) * uInt32Count + sizeof(int64_t) +
        sizeof(uint64_t)) {
        return;
    }
    int32_t offset = 0;
    string outStr = "";
    int8_t valueInt8 = FuzzInt8(data + offset, size);
    offset += sizeof(int8_t);
    MtpPacketTool::Int8ToString(valueInt8, outStr);
    uint8_t valueUInt8 = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    MtpPacketTool::UInt8ToString(valueUInt8, outStr);
    int16_t valueInt16 = FuzzInt16(data + offset, size);
    offset += sizeof(int16_t);
    MtpPacketTool::Int16ToString(valueInt16, outStr);
    uint16_t valueUInt16 = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::UInt16ToString(valueUInt16, outStr);
    int32_t valueInt32 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MtpPacketTool::Int32ToString(valueInt32, outStr);
    uint32_t valueUInt32 = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    MtpPacketTool::UInt32ToString(valueUInt32, outStr);
    int64_t valueInt64 = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    MtpPacketTool::Int64ToString(valueInt64, outStr);
    uint64_t valueUInt64 = FuzzUInt64(data + offset, size);
    offset += sizeof(uint64_t);
    MtpPacketTool::UInt64ToString(valueUInt64, outStr);
    int32_t valueInt32First = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t valueInt32Second = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int128_t valueInt128 = {valueInt32First, valueInt32Second};
    MtpPacketTool::Int128ToString(valueInt128, outStr);
    uint32_t valueUInt32First = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Second = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint128_t valueUInt128 = {valueUInt32First, valueUInt32Second};
    MtpPacketTool::UInt128ToString(valueUInt128, outStr);
}

static void MtpPacketToolGetNameTest(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    const int32_t uInt16Count = 6;
    if (data == nullptr || size < sizeof(int32_t) * int32Count +
        sizeof(uint16_t) * uInt16Count) {
        return;
    }
    int32_t offset = 0;
    uint16_t code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetOperationName(code);
    code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetEventName(code);
    code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetFormatName(code);
    code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetObjectPropName(code);
    code = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    MtpPacketTool::GetEventName(code);

    time_t sec = 0;
    MtpPacketTool::FormatDateTime(sec);
    int type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MtpPacketTool::GetDataTypeName(type);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MtpPacketTool::GetAssociationName(type);

    uint16_t propCode = FuzzUInt16(data + offset, size);
    MtpPacketTool::GetObjectPropTypeByPropCode(propCode);
}

static void MtpPacketToolOtherTest(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(uint8_t)) {
        return;
    }
    MtpPacketTool::GetIndentBlank();
    size_t indent = size;
    MtpPacketTool::GetIndentBlank(indent);
    vector<uint8_t> dumpData = FuzzVectorUInt8(data, size);
    MtpPacketTool::Dump(dumpData);
    unique_ptr<char[]> hexBuf;
    int32_t offset = 0;
    int hexBufSize = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    unique_ptr<char[]> txtBuf;
    int txtBufSize = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);

    uint8_t u8 = FuzzUInt8(data + offset, size);
    MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);

    string str = FuzzString(data, size);
    hexBuf = make_unique<char[]>('a');
    txtBuf = make_unique<char[]>('a');
    MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);

    MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);

    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
    hexBuf[OFFSET_0] = '\0';
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
}

static void MtpPacketToolTest(const uint8_t* data, size_t size)
{
    MtpPacketToolPutTest(data, size);
    MtpPacketToolGetTest(data, size);
    MtpPacketToolGetUInt8Test(data, size);
    MtpPacketToolGetUInt16Test(data, size);
    MtpPacketToolGetUInt32Test(data, size);
    MtpPacketToolGetUInt64Test(data, size);
    MtpPacketToolGetUInt128Test(data, size);
    MtpPacketToolGetInt8Test(data, size);
    MtpPacketToolGetInt16Test(data, size);
    MtpPacketToolGetInt32Test(data, size);
    MtpPacketToolGetInt64Test(data, size);
    MtpPacketToolGetInt128Test(data, size);
    MtpPacketToolGetStringTest(data, size);
    MtpPacketToolToStringTest(data, size);
    MtpPacketToolGetNameTest(data, size);
    MtpPacketToolOtherTest(data, size);
}

static void MtpPacketTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
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

    uint16_t operationCode = FuzzUInt16(data, size);
    mtpPacket->IsNeedDataPhase(operationCode);
    mtpPacket->IsI2R(operationCode);
    mtpPacket->Reset();
}

static void MtpServiceTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpService> mtpService = make_shared<MtpService>();
    mtpService->StartService();
    mtpService->StopService();
}

static void MtpStoreObserverTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
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

static void PacketPayloadFactoryTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<PacketPayloadFactory> packetPayloadFactory = make_shared<PacketPayloadFactory>();
    uint16_t stage = FuzzUInt16(data, size);
    for (uint16_t code = MTP_OPERATION_GET_DEVICE_INFO_CODE; code < MTP_OPERATION_SKIP_CODE; code++) {
        packetPayloadFactory->CreatePayload(context, code, stage);
    }
}

// PropertyTest start
static void PropertySetFormEnumTest(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count + sizeof(int32_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t propCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    uint16_t propType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    bool propWriteable = FuzzBool(data, size);
    int value = FuzzInt32(data + offset, size);
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
    if (data == nullptr || size < sizeof(uint16_t) + sizeof(uint8_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t propCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    Property property(propCode, MTP_TYPE_UINT8_CODE);
    vector<uint8_t> buffer = FuzzVectorUInt8(data + offset, size);
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
    const int32_t uInt8Count = 4;
    const int32_t uInt32Count = 2;
    if (data == nullptr || size < sizeof(uint16_t) + sizeof(uint32_t) * uInt32Count +
        sizeof(uint8_t) * uInt8Count) {
        return;
    }
    int32_t offset = 0;
    uint16_t propCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    Property property(propCode, MTP_TYPE_AINT8_CODE);
    uint8_t indent = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    shared_ptr<vector<Property::Value>> values;
    string name = FuzzString(data, size);
    property.DumpValues(indent, values, name);
    values = make_shared<vector<Property::Value>>();
    indent = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    property.DumpValues(indent, values, name);
    indent = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    property.DumpForm(indent);
    property.SetFormRange(0, 0, 0);
    indent = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    property.DumpForm(indent);

    shared_ptr<Property::Value> value = make_shared<Property::Value>();
    uint32_t valueType = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    value->Dump(valueType);
    valueType = FuzzUInt32(data + offset, size);
    string outStr = value->ToString(valueType);
    value->BinToString(valueType, outStr);
}

static void PropertyReadValueTest(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count + sizeof(int32_t) +
        sizeof(uint8_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t propCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    uint16_t propType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    bool propWriteable = FuzzBool(data, size);
    int values = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    Property property(propCode, propType, propWriteable, values);

    vector<uint8_t> buffer = FuzzVectorUInt8(data + offset, size);
    size_t offsetTest = 0;
    Property::Value value;
    property.ReadValue(buffer, offsetTest, value);
    property.WriteValue(buffer, value);
    property.ReadValue(buffer, offsetTest, value);

    property.ReadValueEx(buffer, offsetTest, value);
    property.WriteValue(buffer, value);
    property.WriteValueEx(buffer, value);
    property.ReadValueEx(buffer, offsetTest, value);
}

static void PropertyReadArrayValuesTest(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count +
        sizeof(int32_t) * int32Count + sizeof(uint8_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t propCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    uint16_t propType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    bool propWriteable = FuzzBool(data, size);
    int value = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    Property property(propCode, propType, propWriteable, value);
    shared_ptr<vector<Property::Value>> values;

    vector<uint8_t> buffer = FuzzVectorUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    value = FuzzInt32(data + offset, size);
    MtpPacketTool::PutInt32(buffer, value);
    property.WriteValueData(buffer);
    size_t offsetTest = 0;
    property.ReadArrayValues(buffer, offsetTest, values);

    Property propertyOne(propCode, propType);
    propertyOne.WriteValueData(buffer);
    propertyOne.Write(buffer);
    property.ReadArrayValues(buffer, offsetTest, values);
}

static void PropertyDumpValueTest(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    const int32_t uInt8Count = 2;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count + sizeof(int32_t) +
        sizeof(uint8_t) * uInt8Count + sizeof(uint32_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t propCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    uint16_t propType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    bool propWriteable = FuzzBool(data, size);
    int value = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    Property property(propCode, propType, propWriteable, value);

    uint8_t indent = FuzzUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    string name = FuzzString(data, size);
    shared_ptr<Property::Value> valueTest;
    property.DumpValue(indent, valueTest, name);
    valueTest = make_shared<Property::Value>();
    uint32_t valueType = FuzzUInt32(data + offset, size);
    string outStr = FuzzString(data, size);
    valueTest->StrToString(valueType, outStr);

    valueTest->str_ = make_shared<string>(FuzzString(data, size));
    valueTest->StrToString(valueType, outStr);
    indent = FuzzUInt8(data + offset, size);
    property.DumpValue(indent, valueTest, name);
}

static void PropertyWriteFormDataTest(const uint8_t* data, size_t size)
{
    const int32_t uInt16Count = 2;
    if (data == nullptr || size < sizeof(uint16_t) * uInt16Count + sizeof(int32_t) +
        sizeof(uint8_t) + sizeof(int32_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t propCode = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    uint16_t propType = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    bool propWriteable = FuzzBool(data, size);
    int value = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    Property property(propCode, propType, propWriteable, value);

    property.SetFormRange(0, 0, 0);
    vector<uint8_t> buffer = FuzzVectorUInt8(data + offset, size);
    offset += sizeof(uint8_t);
    size_t offsetTest = 0;
    property.ReadFormData(buffer, offsetTest);

    property.WriteFormData(buffer);

    MtpPacketTool::PutInt8(buffer, offsetTest);
    property.ReadFormData(buffer, offsetTest);

    vector<int> values = FuzzVectorInt32(data + offset, size);
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

static void PtpAlbumHandlesTest(const uint8_t* data, size_t size)
{
    shared_ptr<PtpAlbumHandles> ptpAlbumHandles = PtpAlbumHandles::GetInstance();
    int32_t value = FuzzInt32(data, size);
    ptpAlbumHandles->AddHandle(value);
    ptpAlbumHandles->RemoveHandle(value);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    ptpAlbumHandles->AddAlbumHandles(resultSet);
    ptpAlbumHandles->FindHandle(value);
    std::set<int32_t> albumIds;
    albumIds.insert(0);
    ptpAlbumHandles->dataHandles_.push_back(FuzzInt32(data, size));
    std::vector<int32_t> removeIds;
    ptpAlbumHandles->UpdateHandle(albumIds, removeIds);
}

// PayloadDataTest start
static void CloseSessionDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    CloseSessionData closeSessionData(context);
    closeSessionData.CalculateSize();

    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    closeSessionData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    closeSessionData.Maker(outBuffer);
}

static void CopyObjectDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    CopyObjectData copyObjectData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    copyObjectData.Parser(buffer, readSize);
    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    copyObjectData.Maker(outBuffer);
    copyObjectData.CalculateSize();

    uint32_t objectHandle = FuzzUInt32(data, size);
    copyObjectData.SetObjectHandle(objectHandle);

    copyObjectData.Parser(buffer, readSize);
    copyObjectData.Maker(outBuffer);
    copyObjectData.CalculateSize();
    copyObjectData.SetObjectHandle(objectHandle);
}

static void DeleteObjectDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    DeleteObjectData deleteObjectData(context);
    deleteObjectData.CalculateSize();

    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    deleteObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    deleteObjectData.Maker(outBuffer);
}

static void GetDeviceInfoDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetDeviceInfoData getDeviceInfoData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getDeviceInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getDeviceInfoData.Maker(outBuffer);
    getDeviceInfoData.CalculateSize();

    string manufacturer = FuzzString(data, size);
    getDeviceInfoData.SetManufacturer(manufacturer);
    getDeviceInfoData.SetModel(manufacturer);
    getDeviceInfoData.SetVersion(manufacturer);
    getDeviceInfoData.SetSerialNum(manufacturer);
}

static void GetDevicePropDescDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetDevicePropDescData getDevicePropDescData(context);
    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getDevicePropDescData.Maker(outBuffer);
    getDevicePropDescData.CalculateSize();

    shared_ptr<Property> property = make_shared<Property>();
    getDevicePropDescData.SetProperty(property);

    getDevicePropDescData.Maker(outBuffer);
    getDevicePropDescData.CalculateSize();
}

static void GetDevicePropValueDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetDevicePropValueData getDevicePropValueData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getDevicePropValueData.Maker(outBuffer);
    getDevicePropValueData.CalculateSize();

    uint16_t type = FuzzUInt16(data, size);
    shared_ptr<Property::Value> value = make_shared<Property::Value>();
    getDevicePropValueData.SetValue(type, value);

    Property::Value writeValue;
    getDevicePropValueData.WriteValue(buffer, type, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_INT8_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_UINT8_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_INT16_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_UINT16_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_INT32_CODE, writeValue);
    getDevicePropValueData.WriteValue(buffer, MTP_TYPE_UINT32_CODE, writeValue);

    getDevicePropValueData.Maker(outBuffer);
    getDevicePropValueData.CalculateSize();

    int32_t readSize = buffer.size();
    getDevicePropValueData.Parser(buffer, readSize);
    getDevicePropValueData.context_ = context;
    getDevicePropValueData.Parser(buffer, readSize);
}

static void GetNumObjectsDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetNumObjectsData getNumObjectsData(context);
    getNumObjectsData.GetNum();
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getNumObjectsData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getNumObjectsData.Maker(outBuffer);
    getNumObjectsData.CalculateSize();

    int num = FuzzInt32(data, size);
    getNumObjectsData.SetNum(num);

    getNumObjectsData.GetNum();
    getNumObjectsData.Maker(outBuffer);
    getNumObjectsData.CalculateSize();
}

static void GetObjectDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectData getObjectData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectData.Maker(outBuffer);
    getObjectData.CalculateSize();

    uint32_t result = FuzzUInt32(data, size);
    getObjectData.SetResult(result);
    getObjectData.Parser(buffer, readSize);
    getObjectData.Maker(outBuffer);
    getObjectData.CalculateSize();
}

static void GetObjectHandlesDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectHandlesData getObjectHandlesData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectHandlesData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectHandlesData.Maker(outBuffer);
    getObjectHandlesData.CalculateSize();
    getObjectHandlesData.GetObjectHandles();

    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>(FuzzVectorUInt32(data, size));
    getObjectHandlesData.SetObjectHandles(objectHandles);
    getObjectHandlesData.Parser(buffer, readSize);
    getObjectHandlesData.Maker(outBuffer);
    getObjectHandlesData.CalculateSize();
    getObjectHandlesData.GetObjectHandles();
}

static void GetObjectInfoDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectInfoData getObjectInfoData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectInfoData.Maker(outBuffer);
    getObjectInfoData.CalculateSize();
    getObjectInfoData.GetObjectInfo();

    shared_ptr<ObjectInfo> objectInfo = make_shared<ObjectInfo>(
        FuzzObjectInfo(data, size));
    getObjectInfoData.SetObjectInfo(objectInfo);
    getObjectInfoData.Parser(buffer, readSize);
    getObjectInfoData.Maker(outBuffer);
    getObjectInfoData.CalculateSize();
    getObjectInfoData.GetObjectInfo();
}

static void GetObjectPropDescDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropDescData getObjectPropDescData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectPropDescData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectPropDescData.Maker(outBuffer);
    getObjectPropDescData.CalculateSize();
    getObjectPropDescData.GetProp();
    getObjectPropDescData.GetPropInt();
    getObjectPropDescData.GetPropStr();
    getObjectPropDescData.GetPropForm();
}

static void GetObjectPropListDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropListData getObjectPropListData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectPropListData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectPropListData.Maker(outBuffer);
    getObjectPropListData.CalculateSize();

    shared_ptr<vector<Property>> props = make_shared<vector<Property>>();
    getObjectPropListData.SetProps(props);

    getObjectPropListData.Parser(buffer, readSize);
    getObjectPropListData.Maker(outBuffer);
    getObjectPropListData.CalculateSize();

    Property prop;
    prop.type_ = FuzzUInt16(data, size);
    getObjectPropListData.WriteProperty(outBuffer, prop);
    getObjectPropListData.WritePropertyStrValue(outBuffer, prop);
    getObjectPropListData.WritePropertyIntValue(outBuffer, prop);
}

static void GetObjectPropValueDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropValueData getObjectPropValueData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectPropValueData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectPropValueData.Maker(outBuffer);
    getObjectPropValueData.CalculateSize();

    const int32_t uInt32Count = 4;
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t) * uInt32Count +
        sizeof(uint64_t)) {
        return;
    }
    int32_t offset = 0;
    int type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    uint64_t int64Value = FuzzUInt64(data + offset, size);
    offset += sizeof(int64_t);
    uint32_t valueUInt32First = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Second = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Third = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t valueUInt32Fourth = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint128_t int128Value = {valueUInt32First, valueUInt32Second,
        valueUInt32Third, valueUInt32Fourth};
    string strValue = FuzzString(data, size);
    getObjectPropValueData.SetPropValue(type, int64Value, int128Value, strValue);

    getObjectPropValueData.Parser(buffer, readSize);
    getObjectPropValueData.Maker(outBuffer);
    getObjectPropValueData.CalculateSize();
}

static void GetObjectPropsSupportedDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectPropsSupportedData getObjectPropsSupportedData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectPropsSupportedData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectPropsSupportedData.Maker(outBuffer);
    getObjectPropsSupportedData.CalculateSize();

    UInt16List properties = FuzzVectorUInt16(data, size);
    getObjectPropsSupportedData.GetObjectProps(properties);

    getObjectPropsSupportedData.Parser(buffer, readSize);
    getObjectPropsSupportedData.Maker(outBuffer);
    getObjectPropsSupportedData.CalculateSize();
}

static void GetObjectReferencesDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetObjectReferencesData getObjectReferencesData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getObjectReferencesData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getObjectReferencesData.Maker(outBuffer);
    getObjectReferencesData.CalculateSize();

    getObjectReferencesData.GetObjectHandles();

    shared_ptr<UInt32List> objectHandles = make_shared<UInt32List>(FuzzVectorUInt32(data, size));
    getObjectReferencesData.SetObjectHandles(objectHandles);

    getObjectReferencesData.GetObjectHandles();
    getObjectReferencesData.Parser(buffer, readSize);
    getObjectReferencesData.Maker(outBuffer);
    getObjectReferencesData.CalculateSize();
}

static void GetPartialObjectDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetPartialObjectData getPartialObjectData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getPartialObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getPartialObjectData.Maker(outBuffer);
    getPartialObjectData.CalculateSize();

    uint32_t length = FuzzUInt32(data, size);
    getPartialObjectData.SetLength(length);

    getPartialObjectData.Parser(buffer, readSize);
    getPartialObjectData.Maker(outBuffer);
    getPartialObjectData.CalculateSize();
}

static void GetStorageIdsDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetStorageIdsData getStorageIdsData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getStorageIdsData.Parser(buffer, readSize);

    vector<shared_ptr<Storage>> storages;
    getStorageIdsData.SetStorages(storages);
    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getStorageIdsData.Maker(outBuffer);
    getStorageIdsData.CalculateSize();
}

static void GetStorageInfoDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetStorageInfoData getStorageInfoData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getStorageInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getStorageInfoData.Maker(outBuffer);
    getStorageInfoData.CalculateSize();

    shared_ptr<Storage> storage = make_shared<Storage>();
    getStorageInfoData.SetStorage(storage);

    getStorageInfoData.Parser(buffer, readSize);
    getStorageInfoData.Maker(outBuffer);
    getStorageInfoData.CalculateSize();
}

static void GetThumbDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    GetThumbData getThumbData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    getThumbData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    getThumbData.Maker(outBuffer);
    getThumbData.CalculateSize();

    shared_ptr<UInt8List> thumb = make_shared<UInt8List>(FuzzVectorUInt8(data, size));
    getThumbData.SetThumb(thumb);

    getThumbData.Parser(buffer, readSize);
    getThumbData.Maker(outBuffer);
    getThumbData.CalculateSize();
}

static void MoveObjectDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    MoveObjectData moveObjectData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    moveObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    moveObjectData.Maker(outBuffer);
    moveObjectData.CalculateSize();
}

static void ObjectEventDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    ObjectEventData objectEventData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    objectEventData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    objectEventData.Maker(outBuffer);
    objectEventData.CalculateSize();

    const int32_t payload = FuzzInt32(data, size);
    objectEventData.SetPayload(payload);

    objectEventData.Parser(buffer, readSize);
    objectEventData.Maker(outBuffer);
    objectEventData.CalculateSize();
}

static void OpenSessionDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    OpenSessionData OpenSessionData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    OpenSessionData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    OpenSessionData.Maker(outBuffer);
    OpenSessionData.CalculateSize();

    uint32_t sessionID = FuzzUInt32(data, size);
    OpenSessionData.SetSessionId(sessionID);

    OpenSessionData.Parser(buffer, readSize);
    OpenSessionData.Maker(outBuffer);
    OpenSessionData.CalculateSize();
}

static void RespCommonDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    RespCommonData respCommonData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    respCommonData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    respCommonData.Maker(outBuffer);
    respCommonData.CalculateSize();

    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }
    int32_t offset = 0;
    int paramIndex = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    uint32_t value = FuzzUInt32(data + offset, size);
    respCommonData.SetParam(paramIndex, value);

    respCommonData.Parser(buffer, readSize);
    respCommonData.Maker(outBuffer);
    respCommonData.CalculateSize();
}

static void SendObjectDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SendObjectData sendObjectData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    sendObjectData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    sendObjectData.Maker(outBuffer);
    sendObjectData.CalculateSize();
}

static void SendObjectInfoDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SendObjectInfoData sendObjectInfoData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    sendObjectInfoData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    sendObjectInfoData.Maker(outBuffer);
    sendObjectInfoData.CalculateSize();

    const int32_t uInt32Count = 3;
    if (data == nullptr || size < sizeof(uint32_t) * uInt32Count + sizeof(uint8_t)) {
        return;
    }
    int32_t offset = 0;
    uint32_t storageID = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t parent = FuzzUInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t handle = FuzzUInt32(data + offset, size);
    sendObjectInfoData.SetSetParam(storageID, parent, handle);

    sendObjectInfoData.Parser(buffer, readSize);
    sendObjectInfoData.Maker(outBuffer);
    sendObjectInfoData.CalculateSize();

    size_t offsetTest = 1;
    offset += sizeof(uint32_t);
    buffer.push_back(FuzzUInt8(data + offset, size));
    sendObjectInfoData.ParserData(buffer, offsetTest);
    sendObjectInfoData.ParserDataForImageInfo(buffer, offsetTest);
    sendObjectInfoData.ParserDataForFileInfo(buffer, offsetTest);
}

static void SetDevicePropValueDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SetDevicePropValueData setDevicePropValueData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    setDevicePropValueData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    setDevicePropValueData.Maker(outBuffer);
    setDevicePropValueData.CalculateSize();
}

static void SetObjectPropValueDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    SetObjectPropValueData setObjectPropValueData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    setObjectPropValueData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    setObjectPropValueData.Maker(outBuffer);
    setObjectPropValueData.CalculateSize();

    const int32_t int32Count = 5;
    const int32_t int64Count = 5;
    if (data == nullptr || size < sizeof(int32_t) * int32Count +
        sizeof(int64_t) * int64Count + sizeof(uint16_t)) {
        return;
    }
    int32_t offset = 0;
    uint16_t result = FuzzUInt16(data + offset, size);
    offset += sizeof(uint16_t);
    setObjectPropValueData.SetResult(result);

    setObjectPropValueData.Parser(buffer, readSize);
    setObjectPropValueData.Maker(outBuffer);
    setObjectPropValueData.CalculateSize();

    size_t offsetTest = 0;
    int type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64_t int64Value = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    setObjectPropValueData.ReadIntValue(buffer, offsetTest, type, int64Value);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64Value = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    setObjectPropValueData.ReadInt8Value(buffer, offsetTest, type, int64Value);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64Value = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    setObjectPropValueData.ReadInt16Value(buffer, offsetTest, type, int64Value);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64Value = FuzzInt64(data + offset, size);
    offset += sizeof(int64_t);
    setObjectPropValueData.ReadInt32Value(buffer, offsetTest, type, int64Value);
    type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int64Value = FuzzInt64(data + offset, size);
    setObjectPropValueData.ReadInt64Value(buffer, offsetTest, type, int64Value);
}

static void SetObjectReferencesDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }

    SetObjectReferencesData setObjectReferencesData(context);
    vector<uint8_t> buffer = FuzzVectorUInt8(data, size);
    int32_t readSize = buffer.size();
    setObjectReferencesData.Parser(buffer, readSize);

    vector<uint8_t> outBuffer = FuzzVectorUInt8(data, size);
    setObjectReferencesData.Maker(outBuffer);
    setObjectReferencesData.CalculateSize();

    uint16_t result = FuzzUInt16(data, size);
    setObjectReferencesData.SetResult(result);

    setObjectReferencesData.Parser(buffer, readSize);
    setObjectReferencesData.Maker(outBuffer);
    setObjectReferencesData.CalculateSize();
}

static void PayloadDataTest(const uint8_t* data, size_t size)
{
    CloseSessionDataTest(data, size);
    CopyObjectDataTest(data, size);
    DeleteObjectDataTest(data, size);
    GetDeviceInfoDataTest(data, size);
    GetDevicePropDescDataTest(data, size);
    GetDevicePropValueDataTest(data, size);
    GetNumObjectsDataTest(data, size);
    GetObjectDataTest(data, size);
    GetObjectHandlesDataTest(data, size);
    GetObjectInfoDataTest(data, size);
    GetObjectPropDescDataTest(data, size);
    GetObjectPropListDataTest(data, size);
    GetObjectPropValueDataTest(data, size);
    GetObjectPropsSupportedDataTest(data, size);
    GetObjectReferencesDataTest(data, size);
    GetPartialObjectDataTest(data, size);
    GetStorageIdsDataTest(data, size);
    GetStorageInfoDataTest(data, size);
    GetThumbDataTest(data, size);
    MoveObjectDataTest(data, size);
    ObjectEventDataTest(data, size);
    OpenSessionDataTest(data, size);
    RespCommonDataTest(data, size);
    SendObjectDataTest(data, size);
    SendObjectInfoDataTest(data, size);
    SetDevicePropValueDataTest(data, size);
    SetObjectPropValueDataTest(data, size);
    SetObjectReferencesDataTest(data, size);
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
    OHOS::MtpFileObserverTest(data, size);
    OHOS::MtpManagerTest(data, size);
    OHOS::MtpMediaLibraryTest(data, size);
    OHOS::MtpMedialibraryManagerTest(data, size);
    OHOS::MtpMonitorTest(data, size);
    OHOS::MtpOperationTest(data, size);
    OHOS::MtpOperationUtilsTest(data, size);
    OHOS::MtpPacketToolTest(data, size);
    OHOS::MtpPacketTest(data, size);
    OHOS::MtpServiceTest(data, size);
    OHOS::MtpStoreObserverTest(data, size);
    OHOS::PacketPayloadFactoryTest(data, size);
    OHOS::PropertyTest(data, size);
    OHOS::PtpAlbumHandlesTest(data, size);
    OHOS::PayloadDataTest(data, size);
    return 0;
}
