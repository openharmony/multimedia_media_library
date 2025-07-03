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
#include <fuzzer/FuzzedDataProvider.h>

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
static const int32_t NUM_BYTES = 1;
FuzzedDataProvider *provider = nullptr;

static inline vector<int32_t> FuzzVectorInt32()
{
    return {provider->ConsumeIntegral<int32_t>()};
}

// PropertyTest start
static void PropertySetFormEnumTest()
{
    uint16_t propCode = provider->ConsumeIntegral<uint16_t>();
    uint16_t propType = provider->ConsumeIntegral<uint16_t>();
    bool propWriteable = provider->ConsumeBool();
    int value = provider->ConsumeIntegral<int32_t>();
    Property property(propCode, propType, propWriteable, value);

    property.SetFormRange(0, 0, 0);
    vector<int> values = FuzzVectorInt32();
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

static void PropertyWriteTest()
{
    uint16_t propCode = provider->ConsumeIntegral<uint16_t>();
    Property property(propCode, MTP_TYPE_UINT8_CODE);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    property.Write(buffer);
    size_t offsetTest = 0;
    property.Read(buffer, offsetTest);
    shared_ptr<string> str = make_shared<string>(provider->ConsumeBytesAsString(NUM_BYTES));
    property.SetDefaultValue(str);
    property.SetCurrentValue(str);
    property.GetCurrentValue();
    property.IsArrayType();
}

static void PropertyStringTest()
{
    uint16_t propCode = provider->ConsumeIntegral<uint16_t>();
    Property property(propCode, MTP_TYPE_AINT8_CODE);
    uint8_t indent = provider->ConsumeIntegral<uint8_t>();
    shared_ptr<vector<Property::Value>> values;
    string name = provider->ConsumeBytesAsString(NUM_BYTES);
    property.DumpValues(indent, values, name);
    values = make_shared<vector<Property::Value>>();
    indent = provider->ConsumeIntegral<uint8_t>();
    property.DumpValues(indent, values, name);
    indent = provider->ConsumeIntegral<uint8_t>();
    property.DumpForm(indent);
    property.SetFormRange(0, 0, 0);
    indent = provider->ConsumeIntegral<uint8_t>();
    property.DumpForm(indent);

    shared_ptr<Property::Value> value = make_shared<Property::Value>();
    uint32_t valueType = provider->ConsumeIntegral<uint32_t>();
    value->Dump(valueType);
    valueType = provider->ConsumeIntegral<uint32_t>();
    string outStr = value->ToString(valueType);
    value->BinToString(valueType, outStr);
}

static void PropertyReadValueTest()
{
    uint16_t propCode = provider->ConsumeIntegral<uint16_t>();
    uint16_t propType = provider->ConsumeIntegral<uint16_t>();
    bool propWriteable = provider->ConsumeBool();
    int values = provider->ConsumeIntegral<int32_t>();

    Property property(propCode, propType, propWriteable, values);

    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
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

static void PropertyReadArrayValuesTest()
{
    uint16_t propCode = provider->ConsumeIntegral<uint16_t>();
    uint16_t propType = provider->ConsumeIntegral<uint16_t>();
    bool propWriteable = provider->ConsumeBool();
    int value = provider->ConsumeIntegral<int32_t>();
    Property property(propCode, propType, propWriteable, value);
    shared_ptr<vector<Property::Value>> values;

    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    value = provider->ConsumeIntegral<uint32_t>();
    MtpPacketTool::PutUInt32(buffer, value);
    property.WriteValueData(buffer);
    size_t offsetTest = 0;
    property.ReadArrayValues(buffer, offsetTest, values);
}

static void PropertyDumpValueTest()
{
    uint16_t propCode = provider->ConsumeIntegral<uint16_t>();
    uint16_t propType = provider->ConsumeIntegral<uint16_t>();
    bool propWriteable = provider->ConsumeBool();
    int value = provider->ConsumeIntegral<int32_t>();
    Property property(propCode, propType, propWriteable, value);

    uint8_t indent = provider->ConsumeIntegral<uint8_t>();
    string name = provider->ConsumeBytesAsString(NUM_BYTES);
    shared_ptr<Property::Value> valueTest;
    property.DumpValue(indent, valueTest, name);
    valueTest = make_shared<Property::Value>();
    uint32_t valueType = provider->ConsumeIntegral<uint32_t>();
    string outStr = provider->ConsumeBytesAsString(NUM_BYTES);
    valueTest->StrToString(valueType, outStr);

    valueTest->str_ = make_shared<string>(provider->ConsumeBytesAsString(NUM_BYTES));
    valueTest->StrToString(valueType, outStr);
    indent = provider->ConsumeIntegral<uint8_t>();
    property.DumpValue(indent, valueTest, name);
}

static void PropertyWriteFormDataTest()
{
    uint16_t propCode = provider->ConsumeIntegral<uint16_t>();
    uint16_t propType = provider->ConsumeIntegral<uint16_t>();
    bool propWriteable = provider->ConsumeBool();
    int value = provider->ConsumeIntegral<int32_t>();
    Property property(propCode, propType, propWriteable, value);

    property.SetFormRange(0, 0, 0);
    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    size_t offsetTest = 0;
    property.ReadFormData(buffer, offsetTest);

    property.WriteFormData(buffer);

    MtpPacketTool::PutInt8(buffer, offsetTest);
    property.ReadFormData(buffer, offsetTest);

    vector<int> values = FuzzVectorInt32();
    property.SetFormEnum(values);
    property.ReadFormData(buffer, offsetTest);
    property.WriteFormData(buffer);
}

static void PropertyTest()
{
    PropertySetFormEnumTest();
    PropertyWriteTest();
    PropertyStringTest();
    PropertyReadValueTest();
    PropertyReadArrayValuesTest();
    PropertyDumpValueTest();
    PropertyWriteFormDataTest();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::PropertyTest();
    return 0;
}