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
#include "mtp_data_utils.h"

using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace Media {
HWTEST_F(MtpNativeTest, mtp_SolveHandlesFormatData_test_001, TestSize.Level0)
{
    uint16_t format = 12287U;
    MediaType outMediaType = MEDIA_TYPE_FILE;
    string outExtension = "SolveHandlesFormatData";
    int32_t ret = MtpDataUtils::SolveHandlesFormatData(format, outExtension, outMediaType);
    EXPECT_EQ(ret, MTP_ERROR_INVALID_OBJECTHANDLE);
    uint16_t formatTest = MTP_FORMAT_UNDEFINED_CODE;
    ret = MtpDataUtils::SolveHandlesFormatData(formatTest, outExtension, outMediaType);
    EXPECT_EQ(ret, MTP_SUCCESS);
    uint16_t test = MTP_FORMAT_MICROSOFT_POWERPOINT_PRESENTATION_CODE;
    ret = MtpDataUtils::SolveHandlesFormatData(test, outExtension, outMediaType);
    EXPECT_EQ(ret, MTP_SUCCESS);
}

HWTEST_F(MtpNativeTest, mtp_SolveSendObjectFormatData_test_001, TestSize.Level0)
{
    uint16_t format = 12287U;
    MediaType outMediaType = MEDIA_TYPE_FILE;
    int32_t ret = MtpDataUtils::SolveSendObjectFormatData(format, outMediaType);
    EXPECT_EQ(ret, MTP_SUCCESS);
    uint16_t formatTest = MTP_FORMAT_UNDEFINED_CODE;
    ret = MtpDataUtils::SolveSendObjectFormatData(formatTest, outMediaType);
    EXPECT_EQ(ret, MTP_SUCCESS);
}

HWTEST_F(MtpNativeTest, mtp_SolveSetObjectPropValueData_test_001, TestSize.Level0)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->property = 56326U;
    string outColName = "SolveSetObjectPropValueData";
    variant<int64_t, string> outColVal;
    int32_t ret = MtpDataUtils::SolveSetObjectPropValueData(context, outColName, outColVal);
    EXPECT_EQ(ret, MTP_ERROR_INVALID_OBJECTPROP_VALUE);
}

HWTEST_F(MtpNativeTest, mtp_SolveSetObjectPropValueData_test_002, TestSize.Level0)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    context->properType = MTP_TYPE_STRING_CODE;
    variant<int64_t, string> outColVal;
    string outColName = "SolveSetObjectPropValueData";
    int32_t ret = MtpDataUtils::SolveSetObjectPropValueData(context, outColName, outColVal);
    EXPECT_EQ(ret, MTP_SUCCESS);
}

HWTEST_F(MtpNativeTest, mtp_SolveSetObjectPropValueData_test_003, TestSize.Level0)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    context->properType = MTP_TYPE_AUINT128_CODE;
    string outColName = "SolveSetObjectPropValueData";
    variant<int64_t, string> outColVal;
    int32_t ret = MtpDataUtils::SolveSetObjectPropValueData(context, outColName, outColVal);
    EXPECT_EQ(ret, MTP_SUCCESS);
}

HWTEST_F(MtpNativeTest, mtp_GetMediaTypeByformat_test_001, TestSize.Level0)
{
    uint16_t format = 12287U;
    MediaType outMediaType = MEDIA_TYPE_FILE;
    MtpDataUtils::GetMediaTypeByformat(format, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_DEFAULT);
    uint16_t formatTest = MTP_FORMAT_UNDEFINED_CODE;
    MtpDataUtils::GetMediaTypeByformat(formatTest, outMediaType);
    uint32_t property = MTP_PROPERTY_ALL_CODE;
    uint16_t formatOne = 0;
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    int32_t ret = MtpDataUtils::GetPropListBySet(property, formatOne, resultSet, outProps);
    EXPECT_EQ(ret, MTP_SUCCESS);
    uint32_t propertyTest = MTP_PROPERTY_ALL_CODE;
    ret = MtpDataUtils::GetPropListBySet(propertyTest, formatOne, resultSet, outProps);
    EXPECT_EQ(ret, MTP_SUCCESS);
}

HWTEST_F(MtpNativeTest, mtp_GetPropValueBySet_test_001, TestSize.Level0)
{
    uint32_t property = MTP_PROPERTY_ALL_CODE;
    PropertyValue outPropValue;
    const shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    int32_t ret = MtpDataUtils::GetPropValueBySet(property, resultSet, outPropValue, false);
    EXPECT_EQ(ret, MTP_ERROR_INVALID_OBJECTHANDLE);
}

HWTEST_F(MtpNativeTest, mtp_GetMediaTypeByName_test_001, TestSize.Level0)
{
    string displayName = "GetMediaTypeByName";
    MediaType outMediaType = MEDIA_TYPE_FILE;
    int32_t ret = MtpDataUtils::GetMediaTypeByName(displayName, outMediaType);
    EXPECT_EQ(ret, E_SUCCESS);
    displayName = "GetMediaTypeByName.test";
    ret = MtpDataUtils::GetMediaTypeByName(displayName, outMediaType);
    EXPECT_EQ(ret, E_SUCCESS);
    displayName = MTP_FORMAT_UNDEFINED;
    ret = MtpDataUtils::GetMediaTypeByName(displayName, outMediaType);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MtpNativeTest, mtp_GetPropList_test_001, TestSize.Level0)
{
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    shared_ptr<UInt16List> properties = make_shared<UInt16List>();
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    int32_t ret = MtpDataUtils::GetPropList(resultSet, properties, outProps);
    EXPECT_EQ(ret, MTP_INVALID_OBJECTPROPCODE_CODE);
}

HWTEST_F(MtpNativeTest, mtp_GetFormat_test_001, TestSize.Level0)
{
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShareResultSet>();
    uint16_t outFormat = 0;
    int32_t ret = MtpDataUtils::GetFormat(resultSet, outFormat);
    EXPECT_EQ(ret, E_FAIL);
    uint32_t handle = 0;
    shared_ptr<UInt16List> properties =  make_shared<UInt16List>();
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    properties->push_back(0);
    properties->push_back(MTP_PROPERTY_OBJECT_SIZE_CODE);
    properties->push_back(MTP_PROPERTY_STORAGE_ID_CODE);
    MtpDataUtils::GetOneRowPropList(handle, resultSet, properties, outProps);
}

HWTEST_F(MtpNativeTest, mtp_SetOneDefaultlPropList_test_001, TestSize.Level0)
{
    shared_ptr<vector<Property>> outProps = make_shared<vector<Property>>();
    MtpDataUtils::SetOneDefaultlPropList(0, MTP_PROPERTY_PROTECTION_STATUS_CODE, outProps);
    MtpDataUtils::SetOneDefaultlPropList(0, MTP_PROPERTY_PERSISTENT_UID_CODE, outProps);
    MtpDataUtils::SetOneDefaultlPropList(0, MTP_PROPERTY_ALBUM_NAME_CODE, outProps);
    MtpDataUtils::SetOneDefaultlPropList(0, MTP_PROPERTY_STORAGE_ID_CODE, outProps);
    string column = "SetPropert";
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
    string path = "/data";
    MtpDataUtils::GetFormatByPath(path, outFormat);
    EXPECT_EQ(outFormat, MTP_FORMAT_ASSOCIATION_CODE);
}
} // namespace Media
} // ohos