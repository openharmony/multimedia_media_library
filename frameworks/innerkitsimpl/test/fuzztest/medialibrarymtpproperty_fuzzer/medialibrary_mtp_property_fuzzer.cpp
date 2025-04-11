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
#include "medialibrary_mtp_property_fuzzer.h"

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
#include "mtp_packet_tools.h"
#include "property.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
const int32_t EVEN = 2;
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
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::PropertyTest(data, size);
    return 0;
}