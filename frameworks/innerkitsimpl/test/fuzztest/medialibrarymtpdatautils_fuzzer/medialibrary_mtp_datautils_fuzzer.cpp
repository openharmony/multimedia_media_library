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
#include "medialibrary_mtp_datautils_fuzzer.h"

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
#include "mtp_data_utils.h"
#include "property.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
const int32_t EVEN = 2;
static const string MEDIA_DATA_DB_COMPOSER = "composer";
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

static inline vector<uint16_t> FuzzVectorUInt16(const uint8_t *data, size_t size)
{
    return {FuzzUInt16(data, size)};
}

static inline vector<uint32_t> FuzzVectorUInt32(const uint8_t *data, size_t size)
{
    return {FuzzUInt32(data, size)};
}

static inline int32_t FuzzPhotoSubType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::PhotoSubType::DEFAULT) &&
        value <= static_cast<int32_t>(Media::PhotoSubType::SUBTYPE_END)) {
        return value;
    }
    return static_cast<int32_t>(Media::PhotoSubType::MOVING_PHOTO);
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

static void SolveHandlesFormatDataTest(const uint8_t* data, size_t size)
{
    uint16_t format = FuzzUInt16(data, size);
    MediaType outMediaType = MEDIA_TYPE_FILE;
    string outExtension = FuzzString(data, size);
    MtpDataUtils::SolveHandlesFormatData(format, outExtension, outMediaType);

    format = FuzzBool(data, size) ? MTP_FORMAT_UNDEFINED_CODE : FuzzUInt16(data, size);
    MtpDataUtils::SolveHandlesFormatData(format, outExtension, outMediaType);
}

static void SolveSetObjectPropValueDataTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    context->property = FuzzBool(data, size) ? MTP_PROPERTY_OBJECT_FILE_NAME_CODE : FuzzUInt32(data, size);
    string outColName = FuzzString(data, size);
    variant<int64_t, string> outColVal;
    MtpDataUtils::SolveSetObjectPropValueData(context, outColName, outColVal);
}

static void GetPropListBySetTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
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
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    MtpDataUtils::GetPropValueBySet(property, resultSet, outPropValue, false);
}

static void GetMovingOrEnditOneRowPropListTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<vector<uint16_t>> properties = make_shared<vector<uint16_t>>(FuzzVectorUInt16(data, size));
    properties->push_back(MTP_PROPERTY_STORAGE_ID_CODE);
    properties->push_back(MTP_PROPERTY_OBJECT_FORMAT_CODE);
    string path = FuzzString(data, size);
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MovingType movingType;
    MtpDataUtils::GetMovingOrEnditOneRowPropList(properties, path, context, outProps, movingType);
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
    shared_ptr<vector<uint16_t>> properties = make_shared<vector<uint16_t>>(FuzzVectorUInt16(data, size));
    properties->push_back(MTP_PROPERTY_STORAGE_ID_CODE);
    properties->push_back(MTP_PROPERTY_OBJECT_FORMAT_CODE);
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
    column = FuzzBool(data, size) ? MEDIA_DATA_DB_DATE_MODIFIED : FuzzString(data, size);
    MtpDataUtils::SetProperty(column, resultSet, typeThree, prop);
    ResultSetDataType typeFour = TYPE_DOUBLE;
    MtpDataUtils::SetProperty(column, resultSet, typeFour, prop);
    uint16_t outFormat = 0;
    MtpDataUtils::GetFormatByPath("", outFormat);
    string path = FuzzString(data, size);
    MtpDataUtils::GetFormatByPath(path, outFormat);
}

static void GetMtpPropListTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    context->property = MTP_PROPERTY_ALL_CODE;
    shared_ptr<unordered_map<uint32_t, string>> handles = make_shared<unordered_map<uint32_t, string>>();
    unordered_map<std::string, uint32_t> pathHandles;
    shared_ptr<vector<Property>> outPropValue = make_shared<vector<Property>>();
    MtpDataUtils::GetMtpPropList(handles, pathHandles, context, outPropValue);
}

static void GetMtpOneRowPropTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(int32_t)) {
        return;
    }
    int32_t offset = 0;
    shared_ptr<vector<uint16_t>> properties = make_shared<vector<uint16_t>>(FuzzVectorUInt16(data, size));
    uint32_t parentId = FuzzUInt32(data + offset, size);
    unordered_map<uint32_t, std::string>::iterator it;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    offset += sizeof(int32_t);
    int32_t storageId = FuzzInt32(data + offset, size);
    MtpDataUtils::GetMtpOneRowProp(properties, parentId, it, outProps, storageId);
}

static void SetMtpPropertyTest(const uint8_t* data, size_t size)
{
    string column = MEDIA_DATA_DB_NAME;
    string path = FuzzString(data, size);
    ResultSetDataType type;
    Property prop;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);

    column = MEDIA_DATA_DB_SIZE;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);

    column = MEDIA_DATA_DB_DATE_MODIFIED;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);

    column = MEDIA_DATA_DB_DATE_ADDED;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);

    column = MEDIA_DATA_DB_DESCRIPTION;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);

    column = MEDIA_DATA_DB_DURATION;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);

    column = MEDIA_DATA_DB_ARTIST;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);

    column = MEDIA_DATA_DB_ALBUM_NAME;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);

    column = MEDIA_DATA_DB_COMPOSER;
    MtpDataUtils::SetMtpProperty(column, path, type, prop);
}

static void SetPtpPropertyTest(const uint8_t* data, size_t size)
{
    string column = MEDIA_DATA_DB_NAME;
    string path = FuzzString(data, size);
    MovingType movingType;
    movingType.displayName = FuzzString(data, size);
    Property prop;
    prop.currentValue = make_shared<Property::Value>();
    MtpDataUtils::SetPtpProperty(column, path, movingType, prop);

    column = MEDIA_DATA_DB_PARENT_ID;
    MtpDataUtils::SetPtpProperty(column, path, movingType, prop);

    column = MEDIA_DATA_DB_SIZE;
    MtpDataUtils::SetPtpProperty(column, path, movingType, prop);

    column = MEDIA_DATA_DB_DATE_MODIFIED;
    MtpDataUtils::SetPtpProperty(column, path, movingType, prop);

    column = MEDIA_DATA_DB_DATE_ADDED;
    MtpDataUtils::SetPtpProperty(column, path, movingType, prop);
}

static void GetMovingOrEnditSourcePathTest(const uint8_t* data, size_t size)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>(
        FuzzMtpOperationContext(data, size));
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    string path = FuzzString(data, size);
    int32_t subtype = FuzzPhotoSubType(data, size);
    MtpDataUtils::GetMovingOrEnditSourcePath(path, subtype, context);

    context->handle = EDITED_PHOTOS_OFFSET;
    MtpDataUtils::GetMovingOrEnditSourcePath(path, subtype, context);

    context->handle = COMMON_MOVING_OFFSET;
    MtpDataUtils::GetMovingOrEnditSourcePath(path, subtype, context);

    context->handle = EDITED_MOVING_OFFSET;
    MtpDataUtils::GetMovingOrEnditSourcePath(path, subtype, context);
}

static void GetMtpPropValueTest(const uint8_t* data, size_t size)
{
    string path = FuzzString(data, size);
    uint32_t property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    uint16_t format = FuzzUInt16(data, size);
    PropertyValue outPropValue;
    MtpDataUtils::GetMtpPropValue(path, property, format, outPropValue);

    property = MTP_PROPERTY_OBJECT_SIZE_CODE;
    MtpDataUtils::GetMtpPropValue(path, property, format, outPropValue);

    property = MTP_PROPERTY_DATE_MODIFIED_CODE;
    MtpDataUtils::GetMtpPropValue(path, property, format, outPropValue);

    property = MTP_PROPERTY_DATE_ADDED_CODE;
    MtpDataUtils::GetMtpPropValue(path, property, format, outPropValue);
}

static void SetMtpOneDefaultlPropListTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(int32_t)) {
        return;
    }
    int32_t offset = 0;
    uint32_t handle = FuzzUInt32(data + offset, size);
    uint16_t property = MTP_PROPERTY_PROTECTION_STATUS_CODE;
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    offset += sizeof(int32_t);
    int32_t storageId = FuzzInt32(data + offset, size);
    MtpDataUtils::SetMtpOneDefaultlPropList(handle, property, outProps, storageId);

    property = MTP_PROPERTY_PERSISTENT_UID_CODE;
    MtpDataUtils::SetMtpOneDefaultlPropList(handle, property, outProps, storageId);

    property = MTP_PROPERTY_ALBUM_NAME_CODE;
    MtpDataUtils::SetMtpOneDefaultlPropList(handle, property, outProps, storageId);

    property = MTP_PROPERTY_STORAGE_ID_CODE;
    MtpDataUtils::SetMtpOneDefaultlPropList(handle, property, outProps, storageId);
}

static void MtpDataUtilsTest(const uint8_t* data, size_t size)
{
    SolveHandlesFormatDataTest(data, size);
    SolveSetObjectPropValueDataTest(data, size);
    GetPropListBySetTest(data, size);
    GetPropValueBySetTest(data, size);
    GetMovingOrEnditOneRowPropListTest(data, size);
    GetFormatTest(data, size);
    SetOneDefaultlPropListTest(data, size);
    GetMtpPropListTest(data, size);
    GetMtpOneRowPropTest(data, size);
    SetMtpPropertyTest(data, size);
    SetPtpPropertyTest(data, size);
    GetMovingOrEnditSourcePathTest(data, size);
    GetMtpPropValueTest(data, size);
    SetMtpOneDefaultlPropListTest(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MtpDataUtilsTest(data, size);
    return 0;
}