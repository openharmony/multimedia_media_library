/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "mtp_native_test.h"
#include "mtp_file_observer.h"
#include "mtp_monitor.h"
#include "mtp_operation.h"
#include "mtp_packet.h"
#include "mtp_packet_tools.h"
#include "property.h"

using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace Media {
HWTEST_F(MtpNativeTest, mtp_packet_tools_test_001, TestSize.Level1)
{
    MtpPacketTool::GetUInt16(0, 0);
    uint8_t numFirst = 0;
    uint8_t numSecond = 0;
    MtpPacketTool::GetUInt32(numFirst, numSecond, 0, 0);
    vector<uint8_t> outBuffer;
    size_t offset = 0;
    MtpPacketTool::PutUInt16(outBuffer, 0);
    MtpPacketTool::PutUInt32(outBuffer, 0);
    MtpPacketTool::PutUInt64(outBuffer, 0);
    uint64_t numSecondTest = 0;
    MtpPacketTool::PutUInt128(outBuffer, numSecondTest);
    uint128_t valueTeat = {0, 1};
    MtpPacketTool::PutUInt128(outBuffer, valueTeat);
    MtpPacketTool::PutUInt8(outBuffer, 0);
    MtpPacketTool::GetUInt8(outBuffer, offset);
    size_t offsetTest = 50;
    vector<uint8_t> buffer(100);
    bool ret = MtpPacketTool::GetUInt8(buffer, offsetTest, numFirst);
    EXPECT_EQ(ret, true);
    outBuffer.clear();
    ret = MtpPacketTool::GetUInt8(outBuffer, offset, numFirst);
    EXPECT_EQ(ret, false);
    MtpPacketTool::GetUInt16(outBuffer, offset);
    uint16_t numFirstTest = 0;
    ret = MtpPacketTool::GetUInt16(outBuffer, offsetTest, numFirstTest);
    EXPECT_EQ(ret, false);
    ret = MtpPacketTool::GetUInt16(buffer, offsetTest, numFirstTest);
    EXPECT_EQ(ret, true);
    MtpPacketTool::GetUInt32(outBuffer, offset);
    uint32_t valueOne = 0;
    ret = MtpPacketTool::GetUInt32(buffer, offsetTest, valueOne);
    EXPECT_EQ(ret, true);
    ret = MtpPacketTool::GetUInt32(outBuffer, offsetTest, valueOne);
    EXPECT_EQ(ret, false);
    uint64_t valueTwo = 0;
    ret = MtpPacketTool::GetUInt64(buffer, offsetTest, valueTwo);
    EXPECT_EQ(ret, true);
    ret = MtpPacketTool::GetUInt64(outBuffer, offsetTest, valueTwo);
    EXPECT_EQ(ret, false);
    ret = MtpPacketTool::GetUInt128(buffer, offsetTest, valueTeat);
    EXPECT_EQ(ret, true);
    ret = MtpPacketTool::GetUInt128(outBuffer, offsetTest, valueTeat);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MtpNativeTest, mtp_packet_tools_test_002, TestSize.Level1)
{
    vector<uint8_t> outBuffer;
    int8_t value = 0;
    MtpPacketTool::PutInt8(outBuffer, value);
    MtpPacketTool::PutInt16(outBuffer, (int16_t)value);
    MtpPacketTool::PutInt32(outBuffer, (int32_t)value);
    MtpPacketTool::PutInt64(outBuffer, (int64_t)value);
    MtpPacketTool::PutInt128(outBuffer, (int64_t)value);
    int128_t buff{1, 2};
    MtpPacketTool::PutInt128(outBuffer, buff);
    string buffTest;
    MtpPacketTool::PutString(outBuffer, buffTest);
    vector<uint8_t> buffer;
    size_t offset = 0;
    bool ret = MtpPacketTool::GetInt8(buffer, offset, value);
    EXPECT_EQ(ret, false);
    int16_t valueOne = 0;
    ret = MtpPacketTool::GetInt16(buffer, offset, valueOne);
    EXPECT_EQ(ret, false);
    int32_t valueTwo = 0;
    ret = MtpPacketTool::GetInt32(buffer, offset, valueTwo);
    EXPECT_EQ(ret, false);
    int64_t valueThree = 0;
    ret = MtpPacketTool::GetInt64(buffer, offset, valueThree);
    EXPECT_EQ(ret, false);
    int128_t valueFour = {0, 1};
    ret = MtpPacketTool::GetInt128(buffer, offset, valueFour);
    EXPECT_EQ(ret, false);
    MtpPacketTool::PutUInt8(buffer, value);
    offset = 50;
    buffer.insert(buffer.end(), 100, 0);
    ret = MtpPacketTool::GetInt8(buffer, offset, value);
    EXPECT_EQ(ret, true);
    MtpPacketTool::PutUInt16(buffer, value);
    ret = MtpPacketTool::GetInt16(buffer, offset, valueOne);
    EXPECT_EQ(ret, true);
    MtpPacketTool::PutUInt32(buffer, value);
    ret = MtpPacketTool::GetInt32(buffer, offset, valueTwo);
    EXPECT_EQ(ret, true);
    MtpPacketTool::PutUInt64(buffer, value);
    ret = MtpPacketTool::GetInt64(buffer, offset, valueThree);
    EXPECT_EQ(ret, true);
    MtpPacketTool::PutUInt128(buffer, value);
    ret = MtpPacketTool::GetInt128(buffer, offset, valueFour);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MtpNativeTest, mtp_packet_tools_test_003, TestSize.Level1)
{
    vector<uint8_t> buffer;
    buffer.push_back(0);
    MtpPacketTool::PutUInt8(buffer, 0);
    MtpPacketTool::PutUInt16(buffer, 0);
    size_t offset = 0;
    string ret = MtpPacketTool::GetString(buffer, offset);
    EXPECT_EQ(ret, "");
    string str;
    MtpPacketTool::GetString(buffer, offset, str);
    size_t offsetTest = 50;
    buffer.insert(buffer.end(), 100, 0);
    MtpPacketTool::GetString(buffer, offsetTest, str);
    MtpPacketTool::GetString(buffer, offsetTest);
}

HWTEST_F(MtpNativeTest, mtp_packet_tools_test_004, TestSize.Level1)
{
    string value = "tools";
    auto ret = MtpPacketTool::StrToString(value);
    EXPECT_NE(ret, "");
    ret = MtpPacketTool::GetIndentBlank();
    EXPECT_NE(ret, "");
    size_t indent = 0;
    ret = MtpPacketTool::GetIndentBlank(indent);
    EXPECT_EQ(ret, "");
    vector<uint8_t> data;
    MtpPacketTool::Dump(data);
    unique_ptr<char[]> hexBuf;
    int hexBufSize = 0;
    unique_ptr<char[]> txtBuf;
    int txtBufSize = 0;
    bool retTest = MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);
    EXPECT_EQ(retTest, false);
    uint8_t u8 = 0;
    retTest = MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);
    EXPECT_EQ(retTest, false);
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
    hexBuf = make_unique<char[]>('a');
    txtBuf = make_unique<char[]>('a');
    retTest = MtpPacketTool::DumpClear(indent, hexBuf, hexBufSize, txtBuf, txtBufSize);
    EXPECT_EQ(retTest, false);
    retTest = MtpPacketTool::DumpChar(u8, hexBuf, hexBufSize, txtBuf, txtBufSize);
    EXPECT_EQ(retTest, false);
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
    hexBuf[OFFSET_0] = '\0';
    MtpPacketTool::DumpShow(hexBuf, hexBufSize, txtBuf, txtBufSize);
    time_t sec = 0;
    MtpPacketTool::FormatDateTime(sec);
    MtpPacketTool::GetOperationName(0);
    MtpPacketTool::GetEventName(0);
    MtpPacketTool::GetFormatName(0);
    MtpPacketTool::GetObjectPropName(0);
    MtpPacketTool::GetEventName(0);
    MtpPacketTool::GetDataTypeName(0);
    MtpPacketTool::GetAssociationName(0);
    uint16_t propCode = MTP_PROPERTY_STORAGE_ID_CODE;
    MtpPacketTool::GetObjectPropTypeByPropCode(propCode);
}

HWTEST_F(MtpNativeTest, mtp_Property_test_001, TestSize.Level1)
{
    Property propertyOne(0, MTP_TYPE_INT8_CODE, true, 0);
    propertyOne.SetFormRange(0, 0, 0);
    vector<int> values = {0, 1};
    propertyOne.SetFormEnum(values);
    Property propertyTwo(0, MTP_TYPE_UINT8_CODE, true, 0);
    propertyTwo.SetFormRange(0, 0, 0);
    propertyTwo.SetFormEnum(values);
    propertyTwo.Dump();
    Property propertyThree(0, MTP_TYPE_INT16_CODE, true, 0);
    propertyThree.SetFormRange(0, 0, 0);
    propertyThree.SetFormEnum(values);
    Property propertyFour(0, MTP_TYPE_UINT16_CODE, true, 0);
    propertyFour.SetFormRange(0, 0, 0);
    propertyFour.SetFormEnum(values);
    Property propertyFive(0, MTP_TYPE_INT32_CODE, true, 0);
    propertyFive.SetFormRange(0, 0, 0);
    propertyFive.SetFormEnum(values);
    Property propertySix(0, MTP_TYPE_UINT32_CODE, true, 0);
    propertySix.SetFormRange(0, 0, 0);
    propertySix.SetFormEnum(values);
    Property propertySeven(0, MTP_TYPE_INT64_CODE, true, 0);
    propertySeven.SetFormRange(0, 0, 0);
    propertySeven.SetFormEnum(values);
    Property propertyEight(0, MTP_TYPE_UINT64_CODE, true, 0);
    propertyEight.SetFormRange(0, 0, 0);
    propertyEight.SetFormEnum(values);
    Property property(0, MTP_TYPE_INT128_CODE, true, 0);
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

HWTEST_F(MtpNativeTest, mtp_Property_test_002, TestSize.Level1)
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

HWTEST_F(MtpNativeTest, mtp_Property_test_003, TestSize.Level1)
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

HWTEST_F(MtpNativeTest, mtp_Property_test_004, TestSize.Level1)
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

HWTEST_F(MtpNativeTest, mtp_Property_test_005, TestSize.Level1)
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

HWTEST_F(MtpNativeTest, mtp_Property_test_006, TestSize.Level1)
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

HWTEST_F(MtpNativeTest, mtp_Property_test_007, TestSize.Level1)
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

HWTEST_F(MtpNativeTest, mtp_Property_test_008, TestSize.Level1)
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

HWTEST_F(MtpNativeTest, mtp_Property_test_009, TestSize.Level1)
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

HWTEST_F(MtpNativeTest, mtp_operation_test_001, TestSize.Level1)
{
    MtpOperation mtpOperation;
    mtpOperation.Init();
    mtpOperation.ResetOperation();
    mtpOperation.Execute();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    shared_ptr<PayloadData> data = make_shared<CloseSessionData>(context);
    uint16_t containerType = MTP_INVALID_PARAMETER_CODE;
    int errorCode = 0;
    uint16_t ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_GET_DEVICE_INFO_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_OPEN_SESSION_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_RESET_DEVICE_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    context->operationCode = MTP_OPERATION_CLOSE_SESSION_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    context->operationCode = MTP_OPERATION_GET_STORAGE_IDS_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    context->operationCode = MTP_OPERATION_GET_STORAGE_INFO_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    context->operationCode = MTP_OPERATION_GET_OBJECT_PROPS_SUPPORTED_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_GET_OBJECT_HANDLES_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_GET_NUM_OBJECTS_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_INVALID_STORAGEID_CODE);
    context->operationCode = MTP_OPERATION_GET_OBJECT_INFO_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_GET_OBJECT_PROP_DESC_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_GET_OBJECT_PROP_VALUE_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_SET_OBJECT_PROP_VALUE_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_GET_OBJECT_PROP_LIST_CODE;
    ret = mtpOperation.GetPayloadData(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
}

HWTEST_F(MtpNativeTest, mtp_operation_test_002, TestSize.Level1)
{
    MtpOperation mtpOperation;
    mtpOperation.Init();
    mtpOperation.ResetOperation();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    shared_ptr<PayloadData> data = make_shared<CloseSessionData>(context);
    uint16_t containerType = MTP_INVALID_PARAMETER_CODE;
    int errorCode = 0;
    uint16_t ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_GET_OBJECT_REFERENCES_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_SET_OBJECT_REFERENCES_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_DELETE_OBJECT_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTHANDLE_CODE);
    context->operationCode = MTP_OPERATION_MOVE_OBJECT_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTHANDLE_CODE);
    context->operationCode = MTP_OPERATION_COPY_OBJECT_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTHANDLE_CODE);
    context->operationCode = MTP_OPERATION_GET_DEVICE_PROP_DESC_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_NE(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_GET_DEVICE_PROP_VALUE_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_NE(ret, MTP_OK_CODE);
    context->operationCode = MTP_OPERATION_SET_DEVICE_PROP_VALUE_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_NE(ret, MTP_INVALID_PARENTOBJECT_CODE);
    context->operationCode = MTP_OPERATION_RESET_DEVICE_PROP_VALUE_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_NE(ret, MTP_INVALID_OBJECTHANDLE_CODE);
    context->operationCode = MTP_OPERATION_GET_OBJECT_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTHANDLE_CODE);
    context->operationCode = MTP_OPERATION_GET_THUMB_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTHANDLE_CODE);
    context->operationCode = MTP_OPERATION_SEND_OBJECT_INFO_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_INVALID_PARENTOBJECT_CODE);
    context->operationCode = MTP_OPERATION_GET_PARTIAL_OBJECT_CODE;
    ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MtpNativeTest, mtp_operation_test_003, TestSize.Level1)
{
    MtpOperation mtpOperation;
    mtpOperation.Init();
    mtpOperation.ResetOperation();
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    shared_ptr<PayloadData> data = make_shared<CloseSessionData>(context);
    uint16_t containerType = MTP_INVALID_PARAMETER_CODE;
    int errorCode = 0;
    uint16_t ret = mtpOperation.GetPayloadDataMore(context, data, containerType, errorCode);
    EXPECT_EQ(ret, MTP_OK_CODE);
    mtpOperation.ReceiveRequestPacket(errorCode);
    mtpOperation.SendObjectData(errorCode);
    mtpOperation.RecevieObjectData(errorCode);
    mtpOperation.SendMakeResponsePacket(errorCode);
    mtpOperation.ReceiveI2Rdata(errorCode);
    mtpOperation.SendR2Idata(errorCode);
    shared_ptr<Storage> storage = make_shared<Storage>();
    mtpOperation.AddStorage(storage);
    mtpOperation.RemoveStorage(storage);
    uint16_t operationCode = MTP_OPERATION_OPEN_SESSION_CODE;
    mtpOperation.DealRequest(operationCode, errorCode);
    operationCode = MTP_INVALID_PARAMETER_CODE;
    mtpOperation.DealRequest(operationCode, errorCode);
}

HWTEST_F(MtpNativeTest, mtp_packet_002, TestSize.Level1)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    int TEST_UID = 5003;
    auto remoteObj = saManager->GetSystemAbility(TEST_UID);
    MtpMedialibraryManager::GetInstance()->Init(remoteObj);
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    shared_ptr<MtpPacket> mtpPacket = make_shared<MtpPacket>(context);
    uint16_t ret = mtpPacket->Parser();
    EXPECT_TRUE(ret != MTP_SUCCESS);
    MtpErrorUtils::SolveGetHandlesError(E_SUCCESS);
    MtpErrorUtils::SolveGetObjectInfoError(E_SUCCESS);
    MtpErrorUtils::SolveSendObjectInfoError(E_SUCCESS);
    MtpErrorUtils::SolveMoveObjectError(E_SUCCESS);
    MtpErrorUtils::SolveCopyObjectError(E_SUCCESS);
    MtpErrorUtils::SolveDeleteObjectError(E_SUCCESS);
    MtpErrorUtils::SolveObjectPropValueError(E_SUCCESS);
    MtpErrorUtils::SolveCloseFdError(E_SUCCESS);
}

HWTEST_F(MtpNativeTest, mtp_packet_003, TestSize.Level1)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    shared_ptr<MtpPacket> mtpPacket = make_shared<MtpPacket>(context);
    int ret = mtpPacket->ParserHead();
    EXPECT_EQ(ret, MTP_ERROR_PACKET_INCORRECT);
    ret = mtpPacket->ParserPayload();
    EXPECT_EQ(ret, MTP_ERROR_PACKET_INCORRECT);
    ret = mtpPacket->MakeHead();
    EXPECT_EQ(ret, MTP_SUCCESS);
    ret = mtpPacket->MakerPayload();
    EXPECT_EQ(ret, MTP_SUCCESS);
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(context);
    shared_ptr<PayloadData> payloadData = make_shared<CloseSessionData>(context);
    mtpPacket->Init(headerData, payloadData);
    ret = mtpPacket->MakeHead();
    EXPECT_EQ(ret, MTP_SUCCESS);
    ret = mtpPacket->MakerPayload();
    EXPECT_NE(ret, MTP_SUCCESS);
    mtpPacket->Reset();
    ret = mtpPacket->ParserHead();
    EXPECT_EQ(ret, MTP_ERROR_PACKET_INCORRECT);
    ret = mtpPacket->ParserPayload();
    EXPECT_EQ(ret, MTP_ERROR_PACKET_INCORRECT);
}
} // namespace Media
} // ohos