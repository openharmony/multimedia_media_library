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
#define MLOG_TAG "MediaCloudSync"
#include "mdk_record_field_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#include "media_log.h"
#include "mdk_record_field.h"
#include "mdk_asset.h"
#include "mdk_reference.h"
#include "mdk_error.h"
#include "json/json.h"

using namespace testing::ext;

namespace OHOS::Media::CloudSync {

void MdkRecordFieldTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void MdkRecordFieldTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void MdkRecordFieldTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void MdkRecordFieldTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(MdkRecordFieldTest, Constructor_Default, TestSize.Level1)
{
    MDKRecordField field;
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_NULL);
}

HWTEST_F(MdkRecordFieldTest, Constructor_Copy, TestSize.Level1)
{
    MDKRecordField field1;
    field1 = MDKRecordField(123);
    MDKRecordField field2(field1);
    EXPECT_EQ(field2.GetType(), MDKRecordFieldType::FIELD_TYPE_INT);
    EXPECT_EQ(static_cast<int>(field2), 123);
}

HWTEST_F(MdkRecordFieldTest, AssignmentOperator, TestSize.Level1)
{
    MDKRecordField field1(123);
    MDKRecordField field2;
    field2 = field1;
    EXPECT_EQ(field2.GetType(), MDKRecordFieldType::FIELD_TYPE_INT);
    EXPECT_EQ(static_cast<int>(field2), 123);
}

HWTEST_F(MdkRecordFieldTest, Constructor_Int, TestSize.Level1)
{
    MDKRecordField field(123);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_INT);
    EXPECT_EQ(static_cast<int>(field), 123);
}

HWTEST_F(MdkRecordFieldTest, Constructor_Int64, TestSize.Level1)
{
    MDKRecordField field(static_cast<int64_t>(1234567890));
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_INT);
    EXPECT_EQ(static_cast<int64_t>(field), 1234567890);
}

HWTEST_F(MdkRecordFieldTest, Constructor_Double, TestSize.Level1)
{
    MDKRecordField field(3.14);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_DOUBLE);
    EXPECT_DOUBLE_EQ(static_cast<double>(field), 3.14);
}

HWTEST_F(MdkRecordFieldTest, Constructor_Bool, TestSize.Level1)
{
    MDKRecordField field(true);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_BOOL);
    EXPECT_TRUE(static_cast<bool>(field));
}

HWTEST_F(MdkRecordFieldTest, Constructor_Bool_False, TestSize.Level1)
{
    MDKRecordField field(false);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_BOOL);
    EXPECT_FALSE(static_cast<bool>(field));
}

HWTEST_F(MdkRecordFieldTest, Constructor_CharPtr, TestSize.Level1)
{
    MDKRecordField field("test");
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_STRING);
    EXPECT_EQ(static_cast<std::string>(field), "test");
}

HWTEST_F(MdkRecordFieldTest, Constructor_String, TestSize.Level1)
{
    std::string str = "hello";
    MDKRecordField field(str);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_STRING);
    EXPECT_EQ(static_cast<std::string>(field), "hello");
}

HWTEST_F(MdkRecordFieldTest, Constructor_EmptyString, TestSize.Level1)
{
    std::string str = "";
    MDKRecordField field(str);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_STRING);
    EXPECT_EQ(static_cast<std::string>(field), "");
}

HWTEST_F(MdkRecordFieldTest, Constructor_LongString, TestSize.Level1)
{
    std::string str(1000, 'A');
    MDKRecordField field(str);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_STRING);
    EXPECT_EQ(static_cast<std::string>(field).length(), 1000);
}

HWTEST_F(MdkRecordFieldTest, Constructor_StringWithSpaces, TestSize.Level1)
{
    std::string str = "hello world";
    MDKRecordField field(str);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_STRING);
    EXPECT_EQ(static_cast<std::string>(field), "hello world");
}

HWTEST_F(MdkRecordFieldTest, Constructor_Bytes, TestSize.Level1)
{
    std::vector<uint8_t> bytes = {1, 2, 3, 4, 5};
    MDKRecordField field(bytes);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_BYTES);
    auto result = static_cast<std::vector<uint8_t>>(field);
    EXPECT_EQ(result.size(), 5);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[4], 5);
}

HWTEST_F(MdkRecordFieldTest, Constructor_EmptyBytes, TestSize.Level1)
{
    std::vector<uint8_t> bytes;
    MDKRecordField field(bytes);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_BYTES);
    auto result = static_cast<std::vector<uint8_t>>(field);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(MdkRecordFieldTest, Constructor_LargeBytes, TestSize.Level1)
{
    std::vector<uint8_t> bytes(1000, 255);
    MDKRecordField field(bytes);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_BYTES);
    auto result = static_cast<std::vector<uint8_t>>(field);
    EXPECT_EQ(result.size(), 1000);
}

HWTEST_F(MdkRecordFieldTest, Constructor_Map, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> map;
    map["key1"] = MDKRecordField("value1");
    map["key2"] = MDKRecordField(123);
    MDKRecordField field(map);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_MAP);
}

HWTEST_F(MdkRecordFieldTest, Constructor_EmptyMap, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> map;
    MDKRecordField field(map);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_MAP);
}

HWTEST_F(MdkRecordFieldTest, Constructor_List, TestSize.Level1)
{
    std::vector<MDKRecordField> list;
    list.push_back(MDKRecordField("item1"));
    list.push_back(MDKRecordField(456));
    MDKRecordField field(list);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_LIST);
}

HWTEST_F(MdkRecordFieldTest, Constructor_EmptyList, TestSize.Level1)
{
    std::vector<MDKRecordField> list;
    MDKRecordField field(list);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_LIST);
}

HWTEST_F(MdkRecordFieldTest, Constructor_LargeList, TestSize.Level1)
{
    std::vector<MDKRecordField> list;
    for (int i = 0; i < 100; i++) {
        list.push_back(MDKRecordField(i));
    }
    MDKRecordField field(list);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_LIST);
}

HWTEST_F(MdkRecordFieldTest, Constructor_Asset, TestSize.Level1)
{
    MDKAsset asset;
    asset.uri = "file://test.uri";
    asset.assetName = "test_asset";
    asset.operationType = MDKAssetOperType::DK_ASSET_ADD;
    asset.hash = "abc123";
    asset.version = 1;
    asset.assetId = "asset123";
    asset.subPath = "/sub/path";
    asset.exCheckInfo = "ex_check";
    asset.size = 1024;
    MDKRecordField field(asset);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_ASSET);
}

HWTEST_F(MdkRecordFieldTest, Constructor_Reference, TestSize.Level1)
{
    MDKReference ref;
    ref.recordId = "record123";
    ref.recordType = "Photo";
    MDKRecordField field(ref);
    EXPECT_EQ(field.GetType(), MDKRecordFieldType::FIELD_TYPE_REFERENCE);
}

HWTEST_F(MdkRecordFieldTest, GetInt_Success, TestSize.Level1)
{
    MDKRecordField field(123);
    int val;
    auto ret = field.GetInt(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val, 123);
}

HWTEST_F(MdkRecordFieldTest, GetInt_FromInt64, TestSize.Level1)
{
    MDKRecordField field(static_cast<int64_t>(1234567890));
    int val;
    auto ret = field.GetInt(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val, 1234567890);
}

HWTEST_F(MdkRecordFieldTest, GetInt_FromDouble, TestSize.Level1)
{
    MDKRecordField field(3.14);
    int val;
    auto ret = field.GetInt(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetInt_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    int val;
    auto ret = field.GetInt(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetInt_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    int val;
    auto ret = field.GetInt(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetInt_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    int val;
    auto ret = field.GetInt(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetLong_Success, TestSize.Level1)
{
    MDKRecordField field(static_cast<int64_t>(1234567890));
    int64_t val;
    auto ret = field.GetLong(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val, 1234567890);
}

HWTEST_F(MdkRecordFieldTest, GetLong_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    int64_t val;
    auto ret = field.GetLong(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val, 123);
}

HWTEST_F(MdkRecordFieldTest, GetLong_FromDouble, TestSize.Level1)
{
    MDKRecordField field(3.14);
    int64_t val;
    auto ret = field.GetLong(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetLong_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    int64_t val;
    auto ret = field.GetLong(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetLong_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    int64_t val;
    auto ret = field.GetLong(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetLong_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    int64_t val;
    auto ret = field.GetLong(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetDouble_Success, TestSize.Level1)
{
    MDKRecordField field(3.14159);
    double val;
    auto ret = field.GetDouble(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_DOUBLE_EQ(val, 3.14159);
}

HWTEST_F(MdkRecordFieldTest, GetDouble_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    double val;
    auto ret = field.GetDouble(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetDouble_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    double val;
    auto ret = field.GetDouble(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetDouble_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    double val;
    auto ret = field.GetDouble(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetDouble_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    double val;
    auto ret = field.GetDouble(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetBool_Success, TestSize.Level1)
{
    MDKRecordField field(true);
    bool val;
    auto ret = field.GetBool(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_TRUE(val);
}

HWTEST_F(MdkRecordFieldTest, GetBool_False, TestSize.Level1)
{
    MDKRecordField field(false);
    bool val;
    auto ret = field.GetBool(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_FALSE(val);
}

HWTEST_F(MdkRecordFieldTest, GetBool_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    bool val;
    auto ret = field.GetBool(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetBool_FromDouble, TestSize.Level1)
{
    MDKRecordField field(3.14);
    bool val;
    auto ret = field.GetBool(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetBool_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    bool val;
    auto ret = field.GetBool(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetBool_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    bool val;
    auto ret = field.GetBool(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetString_Success, TestSize.Level1)
{
    MDKRecordField field("hello");
    std::string val;
    auto ret = field.GetString(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val, "hello");
}

HWTEST_F(MdkRecordFieldTest, GetString_Empty, TestSize.Level1)
{
    MDKRecordField field("");
    std::string val;
    auto ret = field.GetString(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val, "");
}

HWTEST_F(MdkRecordFieldTest, GetString_LongString, TestSize.Level1)
{
    std::string str(500, 'X');
    MDKRecordField field(str);
    std::string val;
    auto ret = field.GetString(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.length(), 500);
}

HWTEST_F(MdkRecordFieldTest, GetString_WithSpecialChars, TestSize.Level1)
{
    MDKRecordField field("test<name>with\"quotes\"");
    std::string val;
    auto ret = field.GetString(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val, "test<name>with\"quotes\"");
}

HWTEST_F(MdkRecordFieldTest, GetString_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    std::string val;
    auto ret = field.GetString(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetString_FromDouble, TestSize.Level1)
{
    MDKRecordField field(3.14);
    std::string val;
    auto ret = field.GetString(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetString_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    std::string val;
    auto ret = field.GetString(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetString_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    std::string val;
    auto ret = field.GetString(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetBytes_Success, TestSize.Level1)
{
    std::vector<uint8_t> bytes = {1, 2, 3, 4, 5};
    MDKRecordField field(bytes);
    std::vector<uint8_t> val;
    auto ret = field.GetBytes(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 5);
    EXPECT_EQ(val[0], 1);
    EXPECT_EQ(val[4], 5);
}

HWTEST_F(MdkRecordFieldTest, GetBytes_Empty, TestSize.Level1)
{
    std::vector<uint8_t> bytes;
    MDKRecordField field(bytes);
    std::vector<uint8_t> val;
    auto ret = field.GetBytes(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 0);
}

HWTEST_F(MdkRecordFieldTest, GetBytes_Large, TestSize.Level1)
{
    std::vector<uint8_t> bytes(500, 128);
    MDKRecordField field(bytes);
    std::vector<uint8_t> val;
    auto ret = field.GetBytes(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 500);
}

HWTEST_F(MdkRecordFieldTest, GetBytes_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    std::vector<uint8_t> val;
    auto ret = field.GetBytes(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetBytes_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    std::vector<uint8_t> val;
    auto ret = field.GetBytes(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetBytes_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    std::vector<uint8_t> val;
    auto ret = field.GetBytes(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetBytes_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    std::vector<uint8_t> val;
    auto ret = field.GetBytes(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetRecordList_Success, TestSize.Level1)
{
    std::vector<MDKRecordField> list;
    list.push_back(MDKRecordField("item1"));
    list.push_back(MDKRecordField(456));
    list.push_back(MDKRecordField(789));
    MDKRecordField field(list);
    std::vector<MDKRecordField> val;
    auto ret = field.GetRecordList(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 3);
}

HWTEST_F(MdkRecordFieldTest, GetRecordList_Empty, TestSize.Level1)
{
    std::vector<MDKRecordField> list;
    MDKRecordField field(list);
    std::vector<MDKRecordField> val;
    auto ret = field.GetRecordList(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 0);
}

HWTEST_F(MdkRecordFieldTest, GetRecordList_Large, TestSize.Level1)
{
    std::vector<MDKRecordField> list;
    for (int i = 0; i < 50; i++) {
        list.push_back(MDKRecordField(i));
    }
    MDKRecordField field(list);
    std::vector<MDKRecordField> val;
    auto ret = field.GetRecordList(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 50);
}

HWTEST_F(MdkRecordFieldTest, GetRecordList_Nested, TestSize.Level1)
{
    std::vector<MDKRecordField> innerList;
    innerList.push_back(MDKRecordField("inner1"));
    innerList.push_back(MDKRecordField(222));
    
    std::vector<MDKRecordField> outerList;
    outerList.push_back(MDKRecordField(innerList));
    outerList.push_back(MDKRecordField("outer2"));
    
    MDKRecordField field(outerList);
    std::vector<MDKRecordField> val;
    auto ret = field.GetRecordList(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 2);
}

HWTEST_F(MdkRecordFieldTest, GetRecordList_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    std::vector<MDKRecordField> val;
    auto ret = field.GetRecordList(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetRecordList_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    std::vector<MDKRecordField> val;
    auto ret = field.GetRecordList(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetRecordList_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    std::vector<MDKRecordField> val;
    auto ret = field.GetRecordList(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetRecordList_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    std::vector<MDKRecordField> val;
    auto ret = field.GetRecordList(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetRecordMap_Success, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> map;
    map["key1"] = MDKRecordField("value1");
    map["key2"] = MDKRecordField(456);
    map["key3"] = MDKRecordField(7.89);
    MDKRecordField field(map);
    std::map<std::string, MDKRecordField> val;
    auto ret = field.GetRecordMap(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 3);
    EXPECT_EQ(val["key1"].GetType(), MDKRecordFieldType::FIELD_TYPE_STRING);
    EXPECT_EQ(val["key2"].GetType(), MDKRecordFieldType::FIELD_TYPE_INT);
}

HWTEST_F(MdkRecordFieldTest, GetRecordMap_Empty, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> map;
    MDKRecordField field(map);
    std::map<std::string, MDKRecordField> val;
    auto ret = field.GetRecordMap(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 0);
}

HWTEST_F(MdkRecordFieldTest, GetRecordMap_Large, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> map;
    for (int i = 0; i < 50; i++) {
        map["key" + std::to_string(i)] = MDKRecordField(i);
    }
    MDKRecordField field(map);
    std::map<std::string, MDKRecordField> val;
    auto ret = field.GetRecordMap(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 50);
}

HWTEST_F(MdkRecordFieldTest, GetRecordMap_Nested, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> innerMap;
    innerMap["inner1"] = MDKRecordField("innerValue1");
    innerMap["inner2"] = MDKRecordField(222);
    
    std::map<std::string, MDKRecordField> outerMap;
    outerMap["outer1"] = MDKRecordField(innerMap);
    outerMap["outer2"] = MDKRecordField("outerValue2");
    
    MDKRecordField field(outerMap);
    std::map<std::string, MDKRecordField> val;
    auto ret = field.GetRecordMap(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.size(), 2);
}

HWTEST_F(MdkRecordFieldTest, GetRecordMap_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    std::map<std::string, MDKRecordField> val;
    auto ret = field.GetRecordMap(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetRecordMap_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    std::map<std::string, MDKRecordField> val;
    auto ret = field.GetRecordMap(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetRecordMap_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    std::map<std::string, MDKRecordField> val;
    auto ret = field.GetRecordMap(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetRecordMap_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    std::map<std::string, MDKRecordField> val;
    auto ret = field.GetRecordMap(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetAsset_Success, TestSize.Level1)
{
    MDKAsset asset;
    asset.uri = "file://test.uri";
    asset.assetName = "test_asset";
    asset.operationType = MDKAssetOperType::DK_ASSET_ADD;
    asset.hash = "abc123";
    asset.version = 1;
    asset.assetId = "asset123";
    asset.subPath = "/sub/path";
    asset.exCheckInfo = "ex_check";
    asset.size = 1024;
    
    MDKRecordField field(asset);
    MDKAsset val;
    auto ret = field.GetAsset(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.uri, "file://test.uri");
    EXPECT_EQ(val.assetName, "test_asset");
    EXPECT_EQ(val.operationType, MDKAssetOperType::DK_ASSET_ADD);
    EXPECT_EQ(val.hash, "abc123");
    EXPECT_EQ(val.version, 1);
    EXPECT_EQ(val.assetId, "asset123");
    EXPECT_EQ(val.subPath, "/sub/path");
    EXPECT_EQ(val.exCheckInfo, "ex_check");
    EXPECT_EQ(val.size, 1024);
}

HWTEST_F(MdkRecordFieldTest, GetAsset_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    MDKAsset val;
    auto ret = field.GetAsset(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetAsset_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    MDKAsset val;
    auto ret = field.GetAsset(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetAsset_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    MDKAsset val;
    auto ret = field.GetAsset(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetAsset_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    MDKAsset val;
    auto ret = field.GetAsset(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetReference_Success, TestSize.Level1)
{
    MDKReference ref;
    ref.recordId = "record123";
    ref.recordType = "Photo";
    
    MDKRecordField field(ref);
    MDKReference val;
    auto ret = field.GetReference(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::NO_ERROR);
    EXPECT_EQ(val.recordId, "record123");
    EXPECT_EQ(val.recordType, "Photo");
}

HWTEST_F(MdkRecordFieldTest, GetReference_FromInt, TestSize.Level1)
{
    MDKRecordField field(123);
    MDKReference val;
    auto ret = field.GetReference(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetReference_FromString, TestSize.Level1)
{
    MDKRecordField field("test");
    MDKReference val;
    auto ret = field.GetReference(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetReference_FromBool, TestSize.Level1)
{
    MDKRecordField field(true);
    MDKReference val;
    auto ret = field.GetReference(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, GetReference_FromNull, TestSize.Level1)
{
    MDKRecordField field;
    MDKReference val;
    auto ret = field.GetReference(val);
    EXPECT_EQ(ret, MDKLocalErrorCode::DATA_TYPE_ERROR);
}

HWTEST_F(MdkRecordFieldTest, OperatorInt_Conversion, TestSize.Level1)
{
    MDKRecordField field(123);
    EXPECT_EQ(static_cast<int>(field), 123);
}

HWTEST_F(MdkRecordFieldTest, OperatorInt64_Conversion, TestSize.Level1)
{
    MDKRecordField field(static_cast<int64_t>(1234567890));
    EXPECT_EQ(static_cast<int64_t>(field), 1234567890);
}

HWTEST_F(MdkRecordFieldTest, OperatorDouble_Conversion, TestSize.Level1)
{
    MDKRecordField field(3.14);
    EXPECT_DOUBLE_EQ(static_cast<double>(field), 3.14);
}

HWTEST_F(MdkRecordFieldTest, OperatorBool_Conversion, TestSize.Level1)
{
    MDKRecordField field(true);
    EXPECT_TRUE(static_cast<bool>(field));
}

HWTEST_F(MdkRecordFieldTest, OperatorString_Conversion, TestSize.Level1)
{
    MDKRecordField field("hello");
    EXPECT_EQ(static_cast<std::string>(field), "hello");
}

HWTEST_F(MdkRecordFieldTest, OperatorBytes_Conversion, TestSize.Level1)
{
    std::vector<uint8_t> bytes = {1, 2, 3, 4, 5};
    MDKRecordField field(bytes);
    auto result = static_cast<std::vector<uint8_t>>(field);
    EXPECT_EQ(result.size(), 5);
}

HWTEST_F(MdkRecordFieldTest, OperatorList_Conversion, TestSize.Level1)
{
    std::vector<MDKRecordField> list;
    list.push_back(MDKRecordField("item1"));
    list.push_back(MDKRecordField(456));
    MDKRecordField field(list);
    auto result = static_cast<std::vector<MDKRecordField>>(field);
    EXPECT_EQ(result.size(), 2);
}

HWTEST_F(MdkRecordFieldTest, OperatorMap_Conversion, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> map;
    map["key1"] = MDKRecordField("value1");
    MDKRecordField field(map);
    auto result = static_cast<std::map<std::string, MDKRecordField>>(field);
    EXPECT_EQ(result.size(), 1);
}

HWTEST_F(MdkRecordFieldTest, OperatorAsset_Conversion, TestSize.Level1)
{
    MDKAsset asset;
    asset.uri = "file://test.uri";
    MDKRecordField field(asset);
    auto result = static_cast<MDKAsset>(field);
    EXPECT_EQ(result.uri, "file://test.uri");
}

HWTEST_F(MdkRecordFieldTest, OperatorReference_Conversion, TestSize.Level1)
{
    MDKReference ref;
    ref.recordId = "record123";
    MDKRecordField field(ref);
    auto result = static_cast<MDKReference>(field);
    EXPECT_EQ(result.recordId, "record123");
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Null, TestSize.Level1)
{
    MDKRecordField field;
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isNull());
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Int, TestSize.Level1)
{
    MDKRecordField field(123);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isInt64());
    EXPECT_EQ(json.asInt64(), 123);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Int64_Large, TestSize.Level1)
{
    MDKRecordField field(static_cast<int64_t>(9223372036854775807));
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isInt64());
    EXPECT_EQ(json.asInt64(), 9223372036854775807);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_NegativeInt, TestSize.Level1)
{
    MDKRecordField field(-123);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isInt64());
    EXPECT_EQ(json.asInt64(), -123);
}

HWTEST_F(MdkRecordFieldTest, To_Zero, TestSize.Level1)
{
    MDKRecordField field(0);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isInt64());
    EXPECT_EQ(json.asInt64(), 0);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Double, TestSize.Level1)
{
    MDKRecordField field(3.14159);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isDouble());
    EXPECT_DOUBLE_EQ(json.asDouble(), 3.14159);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Double_Large, TestSize.Level1)
{
    MDKRecordField field(123456789.123456);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isDouble());
    EXPECT_DOUBLE_EQ(json.asDouble(), 123456789.123456);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_NegativeDouble, TestSize.Level1)
{
    MDKRecordField field(-3.14);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isDouble());
    EXPECT_DOUBLE_EQ(json.asDouble(), -3.14);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Bool_True, TestSize.Level1)
{
    MDKRecordField field(true);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isBool());
    EXPECT_TRUE(json.asBool());
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Bool_False, TestSize.Level1)
{
    MDKRecordField field(false);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isBool());
    EXPECT_FALSE(json.asBool());
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_String, TestSize.Level1)
{
    MDKRecordField field("hello world");
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isString());
    EXPECT_EQ(json.asString(), "hello world");
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_EmptyString, TestSize.Level1)
{
    MDKRecordField field("");
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isString());
    EXPECT_EQ(json.asString(), "");
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_LongString, TestSize.Level1)
{
    std::string str(500, 'A');
    MDKRecordField field(str);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isString());
    EXPECT_EQ(json.asString().length(), 500);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_StringWithSpecialChars, TestSize.Level1)
{
    MDKRecordField field("test<name>with\"quotes\"");
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isString());
    EXPECT_EQ(json.asString(), "test<name>with\"quotes\"");
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Bytes, TestSize.Level1)
{
    std::vector<uint8_t> bytes = {1, 2, 3, 4, 5};
    MDKRecordField field(bytes);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isNull());
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_List, TestSize.Level1)
{
    std::vector<MDKRecordField> list;
    list.push_back(MDKRecordField("item1"));
    list.push_back(MDKRecordField(456));
    MDKRecordField field(list);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isArray());
    EXPECT_EQ(json.size(), 2);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_List_Nested, TestSize.Level1)
{
    std::vector<MDKRecordField> innerList;
    innerList.push_back(MDKRecordField("inner1"));
    innerList.push_back(MDKRecordField(222));
    
    std::vector<MDKRecordField> outerList;
    outerList.push_back(MDKRecordField(innerList));
    outerList.push_back(MDKRecordField("outer2"));
    
    MDKRecordField field(outerList);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isArray());
    EXPECT_EQ(json.size(), 2);
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Map, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> map;
    map["key1"] = MDKRecordField("value1");
    map["key2"] = MDKRecordField(456);
    MDKRecordField field(map);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isObject());
    EXPECT_TRUE(json.isMember("key1"));
    EXPECT_TRUE(json.isMember("key2"));
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Map_Nested, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> innerMap;
    innerMap["inner1"] = MDKRecordField("innerValue1");
    innerMap["inner2"] = MDKRecordField(222);
    
    std::map<std::string, MDKRecordField> outerMap;
    outerMap["outer1"] = MDKRecordField(innerMap);
    outerMap["outer2"] = MDKRecordField("outerValue2");
    
    MDKRecordField field(outerMap);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isObject());
    EXPECT_TRUE(json.isMember("outer1"));
    EXPECT_TRUE(json.isMember("outer2"));
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Asset, TestSize.Level1)
{
    MDKAsset asset;
    asset.uri = "file://test.uri";
    asset.assetName = "test_asset";
    asset.operationType = MDKAssetOperType::DK_ASSET_ADD;
    asset.hash = "abc123";
    asset.version = 1;
    asset.assetId = "asset123";
    asset.subPath = "/sub/path";
    asset.exCheckInfo = "ex_check";
    asset.size = 1024;
    
    MDKRecordField field(asset);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isObject());
    EXPECT_TRUE(json.isMember("uri"));
    EXPECT_TRUE(json.isMember("assetName"));
    EXPECT_TRUE(json.isMember("assetOperType"));
    EXPECT_TRUE(json.isMember("sha256"));
    EXPECT_TRUE(json.isMember("version"));
    EXPECT_TRUE(json.isMember("assetId"));
    EXPECT_TRUE(json.isMember("subPath"));
    EXPECT_TRUE(json.isMember("exCheckInfo"));
    EXPECT_TRUE(json.isMember("size"));
}

HWTEST_F(MdkRecordFieldTest, ToJsonValue_Reference, TestSize.Level1)
{
    MDKReference ref;
    ref.recordId = "record123";
    ref.recordType = "Photo";
    
    MDKRecordField field(ref);
    Json::Value json = field.ToJsonValue();
    EXPECT_TRUE(json.isObject());
    EXPECT_TRUE(json.isMember("recordId"));
    EXPECT_TRUE(json.isMember("recordType"));
}

HWTEST_F(MdkRecordFieldTest, ParseIntFromJson_Double, TestSize.Level1)
{
    Json::Value json = 3.14;
    MDKRecordField field;
    bool ret = field.ParseIntFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseIntFromJson_String, TestSize.Level1)
{
    Json::Value json = "not a number";
    MDKRecordField field;
    bool ret = field.ParseIntFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseIntFromJson_Bool, TestSize.Level1)
{
    Json::Value json = true;
    MDKRecordField field;
    bool ret = field.ParseIntFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseIntFromJson_Null, TestSize.Level1)
{
    Json::Value json;
    MDKRecordField field;
    bool ret = field.ParseIntFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseIntFromJson_NegativeNumber, TestSize.Level1)
{
    Json::Value json = -123;
    MDKRecordField field;
    bool ret = field.ParseIntFromJson(json);
    EXPECT_TRUE(ret);
    EXPECT_EQ(static_cast<int>(field), -123);
}

HWTEST_F(MdkRecordFieldTest, ParseIntFromJson_Zero, TestSize.Level1)
{
    Json::Value json = 0;
    MDKRecordField field;
    bool ret = field.ParseIntFromJson(json);
    EXPECT_TRUE(ret);
    EXPECT_EQ(static_cast<int>(field), 0);
}

HWTEST_F(MdkRecordFieldTest, ParseDoubleFromJson_String, TestSize.Level1)
{
    Json::Value json = "not a number";
    MDKRecordField field;
    bool ret = field.ParseDoubleFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseDoubleFromJson_Bool, TestSize.Level1)
{
    Json::Value json = true;
    MDKRecordField field;
    bool ret = field.ParseDoubleFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseDoubleFromJson_Null, TestSize.Level1)
{
    Json::Value json;
    MDKRecordField field;
    bool ret = field.ParseDoubleFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseDoubleFromJson_LargeNumber, TestSize.Level1)
{
    Json::Value json = 123456789.123456;
    MDKRecordField field;
    bool ret = field.ParseDoubleFromJson(json);
    EXPECT_TRUE(ret);
    EXPECT_DOUBLE_EQ(static_cast<double>(field), 123456789.123456);
}

HWTEST_F(MdkRecordFieldTest, ParseDoubleFromJson_NegativeNumber, TestSize.Level1)
{
    Json::Value json = -3.14;
    MDKRecordField field;
    bool ret = field.ParseDoubleFromJson(json);
    EXPECT_TRUE(ret);
    EXPECT_DOUBLE_EQ(static_cast<double>(field), -3.14);
}

HWTEST_F(MdkRecordFieldTest, ParseDoubleFromJson_Zero, TestSize.Level1)
{
    Json::Value json = 0.0;
    MDKRecordField field;
    bool ret = field.ParseDoubleFromJson(json);
    EXPECT_TRUE(ret);
    EXPECT_DOUBLE_EQ(static_cast<double>(field), 0.0);
}

HWTEST_F(MdkRecordFieldTest, ParseStringFromJson_Long, TestSize.Level1)
{
    std::string str(500, 'X');
    Json::Value json = str;
    MDKRecordField field;
    bool ret = field.ParseStringFromJson(json);
    EXPECT_TRUE(ret);
    EXPECT_EQ(static_cast<std::string>(field).length(), 500);
}

HWTEST_F(MdkRecordFieldTest, ParseStringFromJson_SpecialChars, TestSize.Level1)
{
    Json::Value json = "test<name>with\"quotes\"";
    MDKRecordField field;
    bool ret = field.ParseStringFromJson(json);
    EXPECT_TRUE(ret);
    EXPECT_EQ(static_cast<std::string>(field), "test<name>with\"quotes\"");
}

HWTEST_F(MdkRecordFieldTest, ParseStringFromJson_Int, TestSize.Level1)
{
    Json::Value json = 123;
    MDKRecordField field;
    bool ret = field.ParseStringFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseStringFromJson_Double, TestSize.Level1)
{
    Json::Value json = 3.14;
    MDKRecordField field;
    bool ret = field.ParseStringFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseStringFromJson_Bool, TestSize.Level1)
{
    Json::Value json = true;
    MDKRecordField field;
    bool ret = field.ParseStringFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseStringFromJson_Null, TestSize.Level1)
{
    Json::Value json;
    MDKRecordField field;
    bool ret = field.ParseStringFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseBoolFromJson_Int, TestSize.Level1)
{
    Json::Value json = 123;
    MDKRecordField field;
    bool ret = field.ParseBoolFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseBoolFromJson_Double, TestSize.Level1)
{
    Json::Value json = 3.14;
    MDKRecordField field;
    bool ret = field.ParseBoolFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseBoolFromJson_String, TestSize.Level1)
{
    Json::Value json = "test";
    MDKRecordField field;
    bool ret = field.ParseBoolFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseBoolFromJson_Null, TestSize.Level1)
{
    Json::Value json;
    MDKRecordField field;
    bool ret = field.ParseBoolFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseBytesFromJson_AlwaysFalse, TestSize.Level1)
{
    Json::Value json = "not bytes";
    MDKRecordField field;
    bool ret = field.ParseBytesFromJson(json);
    EXPECT_FALSE(ret);
}

HWTEST_F(MdkRecordFieldTest, ParseListFromJson_NotArray, TestSize.Level1)
{
    Json::Value json = "not an array";
    MDKRecordField field;
    bool ret = field.ParseListFromJson(MDKRecordFieldType::FIELD_TYPE_LIST, json);
    EXPECT_FALSE(ret);
}
} // namespace OHOS::Media::CloudSync