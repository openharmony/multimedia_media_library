/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <thread>
#include "mtp_property_test.h"
#include "property.h"
#include "mtp_packet_tools.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_001, testing::ext::TestSize.Level1)
{
    Property propertyOne(0, MTP_TYPE_INT8_CODE, true, 1);
    propertyOne.SetFormRange(0, 0, 0);
    vector<int> values = {0, 1};
    propertyOne.SetFormEnum(values);
    Property propertyTwo(0, MTP_TYPE_UINT8_CODE, true, 1);
    propertyTwo.SetFormRange(0, 0, 0);
    propertyTwo.SetFormEnum(values);
    propertyTwo.Dump();
    Property propertyThree(0, MTP_TYPE_INT16_CODE, true, 1);
    propertyThree.SetFormRange(0, 0, 0);
    propertyThree.SetFormEnum(values);
    Property propertyFour(0, MTP_TYPE_UINT16_CODE, true, 1);
    propertyFour.SetFormRange(0, 0, 0);
    propertyFour.SetFormEnum(values);
    Property propertyFive(0, MTP_TYPE_INT32_CODE, true, 1);
    propertyFive.SetFormRange(0, 0, 0);
    propertyFive.SetFormEnum(values);
    Property propertySix(0, MTP_TYPE_UINT32_CODE, true, 1);
    propertySix.SetFormRange(0, 0, 0);
    propertySix.SetFormEnum(values);
    Property propertySeven(0, MTP_TYPE_INT64_CODE, true, 1);
    propertySeven.SetFormRange(0, 0, 0);
    propertySeven.SetFormEnum(values);
    Property propertyEight(0, MTP_TYPE_UINT64_CODE, true, 1);
    propertyEight.SetFormRange(0, 0, 0);
    propertyEight.SetFormEnum(values);
    Property property(0, MTP_TYPE_INT128_CODE, true, 1);
    property.SetFormRange(0, 0, 0);
    property.SetFormEnum(values);
    property.Dump();
    uint16_t ret = property.GetPropertyCode();
    EXPECT_EQ(ret, 0);
    ret = property.GetDataType();
    EXPECT_EQ(ret, MTP_TYPE_INT128_CODE);
    Property  propertyTest;
    ret = propertyTest.GetDataType();
    EXPECT_EQ(ret, 0);
    property.SetFormDateTime();
    property.IsDeviceProperty();
    property.IsArrayType();
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_002, TestSize.Level1)
{
    uint16_t propCode = 0;
    Property property(propCode, MTP_TYPE_INT128_CODE);
    vector<uint8_t> buffer;
    size_t offset = 0;
    bool ret = property.Read(buffer, offset);
    EXPECT_EQ(ret, false);
    MtpPacketTool::PutUInt16(buffer, propCode);
    ret = property.Read(buffer, offset);
    EXPECT_EQ(ret, false);
    MtpPacketTool::PutUInt8(buffer, propCode);
    ret = property.Read(buffer, offset);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_003, TestSize.Level1)
{
    uint16_t propCode = 0;
    Property property(propCode, MTP_TYPE_UINT8_CODE);
    vector<uint8_t> buffer;
    property.Write(buffer);
    size_t offsetTest = 50;
    buffer.insert(buffer.end(), 100, 0);
    property.Read(buffer, offsetTest);
    shared_ptr<string> str = make_shared<string>();
    property.SetDefaultValue(str);
    property.SetCurrentValue(str);
    property.GetCurrentValue();
    bool ret = property.IsArrayType();
    EXPECT_NE(ret, true);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_004, TestSize.Level1)
{
    uint16_t propCode = 0;
    Property property(propCode, MTP_TYPE_AINT8_CODE);
    uint8_t indent = 0;
    shared_ptr<vector<Property::Value>> values;
    string name = "Property";
    property.DumpValues(indent, values, name);
    values = make_shared<vector<Property::Value>>();
    property.DumpValues(indent, values, name);
    property.DumpForm(indent);
    property.SetFormRange(0, 0, 0);
    property.DumpForm(indent);
    vector<int> valuesTest;
    property.SetFormEnum(valuesTest);
    property.DumpForm(indent);
    property.SetFormDateTime();
    property.DumpForm(indent);
    shared_ptr<Property::Value> value = make_shared<Property::Value>();
    value->Dump(MTP_TYPE_AINT8_CODE);
    string outStr = value->ToString(MTP_TYPE_INT8_CODE);
    EXPECT_NE(outStr, "");
    outStr = value->ToString(MTP_TYPE_STRING_CODE);
    EXPECT_NE(outStr, "");
    outStr = value->ToString(MTP_TYPE_UNDEFINED_CODE);
    EXPECT_NE(outStr, "");
    bool ret = value->BinToString(MTP_TYPE_INT8_CODE, outStr);
    EXPECT_EQ(ret, true);
    value->BinToString(MTP_TYPE_INT8_CODE, outStr);
    value->BinToString(MTP_TYPE_UINT8_CODE, outStr);
    value->BinToString(MTP_TYPE_INT16_CODE, outStr);
    value->BinToString(MTP_TYPE_UINT16_CODE, outStr);
    value->BinToString(MTP_TYPE_INT32_CODE, outStr);
    value->BinToString(MTP_TYPE_UINT32_CODE, outStr);
    value->BinToString(MTP_TYPE_INT64_CODE, outStr);
    value->BinToString(MTP_TYPE_UINT64_CODE, outStr);
    value->BinToString(MTP_TYPE_INT128_CODE, outStr);
    value->BinToString(MTP_TYPE_UINT128_CODE, outStr);
    value->BinToString(MTP_TYPE_STRING_CODE, outStr);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_005, TestSize.Level1)
{
    uint16_t propCode = 0;
    Property property(propCode, MTP_TYPE_AINT8_CODE);
    vector<uint8_t> buffer;
    size_t offset = 0;
    Property::Value value;
    bool ret = property.ReadValue(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyOne(propCode, MTP_TYPE_UINT8_CODE);
    ret = propertyOne.ReadValue(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyTwo(propCode, MTP_TYPE_INT16_CODE);
    ret = propertyTwo.ReadValue(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyThree(propCode, MTP_TYPE_UINT16_CODE);
    ret = propertyThree.ReadValue(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyFour(propCode, MTP_TYPE_INT32_CODE);
    ret = propertyFour.ReadValue(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyFive(propCode, MTP_TYPE_UINT32_CODE);
    ret = propertyFive.ReadValue(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertySix(propCode, MTP_TYPE_INT128_CODE);
    ret = propertySix.ReadValue(buffer, offset, value);
    EXPECT_EQ(ret, false);
    size_t offsetTest = 50;
    buffer.insert(buffer.end(), 100, 0);
    property.WriteValue(buffer, value);
    ret = property.ReadValue(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyOne.WriteValue(buffer, value);
    ret = propertyOne.ReadValue(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyTwo.WriteValue(buffer, value);
    ret = propertyTwo.ReadValue(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyThree.WriteValue(buffer, value);
    ret = propertyThree.ReadValue(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyFour.WriteValue(buffer, value);
    ret = propertyFour.ReadValue(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyFive.WriteValue(buffer, value);
    ret = propertyFive.ReadValue(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertySix.WriteValue(buffer, value);
    ret = propertySix.ReadValue(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_006, TestSize.Level1)
{
    uint16_t propCode = 0;
    Property property(propCode, MTP_TYPE_INT64_CODE);
    vector<uint8_t> buffer;
    size_t offset = 0;
    Property::Value value;
    bool ret = property.ReadValueEx(buffer, offset, value);
    EXPECT_EQ(ret, false);
    ret = property.ReadValue(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyOne(propCode, MTP_TYPE_UINT64_CODE);
    ret = propertyOne.ReadValueEx(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyTwo(propCode, MTP_TYPE_INT128_CODE);
    ret = propertyTwo.ReadValueEx(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyThree(propCode, MTP_TYPE_UINT128_CODE);
    ret = propertyThree.ReadValueEx(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyFour(propCode, MTP_TYPE_STRING_CODE);
    ret = propertyFour.ReadValueEx(buffer, offset, value);
    EXPECT_EQ(ret, false);
    Property propertyFive(propCode, MTP_TYPE_UNDEFINED_CODE);
    ret = propertyFive.ReadValueEx(buffer, offset, value);
    EXPECT_EQ(ret, false);
    size_t offsetTest = 50;
    buffer.insert(buffer.end(), 100, 0);
    property.WriteValue(buffer, value);
    property.WriteValueEx(buffer, value);
    ret = property.ReadValueEx(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyOne.WriteValueEx(buffer, value);
    ret = propertyOne.ReadValueEx(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyTwo.WriteValueEx(buffer, value);
    ret = propertyTwo.ReadValueEx(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyThree.WriteValueEx(buffer, value);
    ret = propertyThree.ReadValueEx(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyFour.WriteValueEx(buffer, value);
    ret = propertyFour.ReadValueEx(buffer, offsetTest, value);
    EXPECT_EQ(ret, true);
    propertyFive.WriteValueEx(buffer, value);
    ret = propertyFive.ReadValueEx(buffer, offsetTest, value);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_007, TestSize.Level1)
{
    uint16_t propCode = 0;
    Property  property(propCode, MTP_TYPE_INT32_CODE);
    shared_ptr<vector<Property::Value>> values;
    vector<uint8_t> buffer;
    buffer.push_back(0);
    int8_t value = 0;
    MtpPacketTool::PutInt32(buffer, value);
    property.WriteValueData(buffer);
    size_t offset = 0;
    bool ret = property.ReadArrayValues(buffer, offset, values);
    EXPECT_EQ(ret, false);
    Property propertyOne(propCode, MTP_TYPE_UNDEFINED_CODE);
    propertyOne.WriteValueData(buffer);
    size_t offsetTest = 50;
    buffer.insert(buffer.end(), 100, 0);
    propertyOne.Write(buffer);
    ret = property.ReadArrayValues(buffer, offsetTest, values);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_008, TestSize.Level1)
{
    uint16_t propCode = 0;
    Property propertyOne(propCode, MTP_TYPE_UNDEFINED_CODE);
    uint8_t indent = 0;
    string name = "Property";
    shared_ptr<Property::Value> valueTest;
    propertyOne.DumpValue(indent, valueTest, name);
    valueTest = make_shared<Property::Value>();
    uint32_t valueType = MTP_TYPE_AINT32_CODE;
    string outStr = "Property";
    bool ret = valueTest->StrToString(valueType, outStr);
    EXPECT_EQ(ret, false);
    valueType = MTP_TYPE_STRING_CODE;
    ret = valueTest->StrToString(valueType, outStr);
    EXPECT_EQ(ret, true);
    valueTest->str_ = make_shared<string>();
    ret = valueTest->StrToString(valueType, outStr);
    EXPECT_EQ(ret, true);
    propertyOne.DumpValue(indent, valueTest, name);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_009, TestSize.Level1)
{
    uint16_t propCode = 0;
    Property property(propCode, MTP_TYPE_UINT8_CODE);
    property.SetFormRange(0, 0, 0);
    vector<uint8_t> buffer;
    size_t offset = 0;
    bool ret = property.ReadFormData(buffer, offset);
    EXPECT_EQ(ret, false);
    property.WriteFormData(buffer);
    size_t offsetTest = 50;
    buffer.insert(buffer.end(), 100, 0);
    MtpPacketTool::PutInt8(buffer, offsetTest);
    ret = property.ReadFormData(buffer, offsetTest);
    EXPECT_EQ(ret, true);
    vector<int> values;
    property.SetFormEnum(values);
    ret = property.ReadFormData(buffer, offsetTest);
    EXPECT_EQ(ret, true);
    property.WriteFormData(buffer);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_010, TestSize.Level1)
{
    std::shared_ptr<Property> property = std::make_shared<Property>();
    ASSERT_NE(property, nullptr);

    std::vector<uint8_t> buffer = {
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 0
    };
    size_t offset = 0;
    property->code_ = 0xD000;
    property->type_ = MTP_TYPE_AUINT8_CODE;
    bool res = property->ReadValueData(buffer, offset);
    EXPECT_TRUE(res);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_011, TestSize.Level1)
{
    std::shared_ptr<Property> property = std::make_shared<Property>();
    ASSERT_NE(property, nullptr);

    std::vector<uint8_t> buffer = {
        1, 0, 0, 0,
        1, 0, 0, 0,
        1, 0, 0, 0
    };
    size_t offset = 0;
    property->code_ = 0;
    property->type_ = MTP_TYPE_AUINT8_CODE;
    bool res = property->ReadValueData(buffer, offset);
    EXPECT_TRUE(res);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_012, TestSize.Level1)
{
    std::shared_ptr<Property> property = std::make_shared<Property>();
    ASSERT_NE(property, nullptr);

    std::vector<uint8_t> buffer = {
        0, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0
    };
    size_t offset = 0;
    property->code_ = 0xD000;
    property->type_ = MTP_TYPE_STRING_CODE;
    bool res = property->ReadValueData(buffer, offset);
    EXPECT_TRUE(res);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_013, TestSize.Level1)
{
    std::shared_ptr<Property> property = std::make_shared<Property>();
    ASSERT_NE(property, nullptr);

    std::vector<uint8_t> buffer = {
        0, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 0
    };
    size_t offset = 0;
    property->code_ = 0;
    property->type_ = MTP_TYPE_STRING_CODE;
    bool res = property->ReadValueData(buffer, offset);
    EXPECT_TRUE(res);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_014, TestSize.Level1)
{
    std::shared_ptr<Property> property = std::make_shared<Property>();
    ASSERT_NE(property, nullptr);

    std::vector<uint8_t> buffer = {
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 0
    };
    size_t offset = 0;
    property->type_ = MTP_TYPE_STRING_CODE;
    bool res = property->ReadFormData(buffer, offset);
    EXPECT_TRUE(res);
}

HWTEST_F(MtpPropetryTest, mtp_SetProperty_test_015, TestSize.Level1)
{
    std::shared_ptr<Property> property = std::make_shared<Property>();
    ASSERT_NE(property, nullptr);

    std::vector<uint8_t> buffer = {
        2, 1, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 0
    };
    size_t offset = 0;
    property->type_ = MTP_TYPE_STRING_CODE;
    bool res = property->ReadFormData(buffer, offset);
    EXPECT_TRUE(res);
}
} // namespace Media
} // namespace OHOS