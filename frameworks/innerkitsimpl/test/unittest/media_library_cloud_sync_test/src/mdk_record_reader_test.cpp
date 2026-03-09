/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MDKRecordReaderTest"

#include "mdk_record_reader_test.h"

#include <string>
#include <map>

#include "media_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace CloudSync {

std::map<std::string, MDKRecordField> MDKRecordReaderTest::CreateTestFields()
{
    std::map<std::string, MDKRecordField> fields;
    fields["string_key"] = MDKRecordField("test_string_value");
    int int64Key = 1234567890;
    fields["int64_key"] = MDKRecordField(int64_t(int64Key));
    int int32Key = 12345;
    fields["int32_key"] = MDKRecordField(int32_t(int32Key));
    fields["bool_key"] = MDKRecordField(true);
    return fields;
}

MDKAsset MDKRecordReaderTest::CreateTestMDKAsset()
{
    MDKAsset asset;
    return asset;
}

void MDKRecordReaderTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "MDKRecordReaderTest SetUpTestCase";
}

void MDKRecordReaderTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "MDKRecordReaderTest TearDownTestCase";
}

void MDKRecordReaderTest::SetUp()
{
    GTEST_LOG_(INFO) << "MDKRecordReaderTest SetUp";
}

void MDKRecordReaderTest::TearDown()
{
    GTEST_LOG_(INFO) << "MDKRecordReaderTest TearDown";
}

HWTEST_F(MDKRecordReaderTest, GetAssetValue_KeyNotFound_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields = CreateTestFields();
    auto recordReader = MDKRecordReader();

    auto result = recordReader.GetAssetValue(fields, "non_existent_key");
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(MDKRecordReaderTest, GetAssetValue_InvalidAsset_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    MDKRecordField invalidField = MDKRecordField("not_an_asset");
    fields["invalid_key"] = invalidField;
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetAssetValue(fields, "invalid_key");
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(MDKRecordReaderTest, GetStringValue_KeyFound_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["string_key"] = MDKRecordField("test_string_value");
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetStringValue(fields, "string_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ("test_string_value", result.value());
}

HWTEST_F(MDKRecordReaderTest, GetStringValue_KeyNotFound_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields = CreateTestFields();
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetStringValue(fields, "non_existent_key");
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(MDKRecordReaderTest, GetStringValue_EmptyString_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["empty_key"] = MDKRecordField("");
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetStringValue(fields, "empty_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ("", result.value());
}

HWTEST_F(MDKRecordReaderTest, GetStringValue_LongNumberAsInt_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["number_key"] = MDKRecordField("1234567890");
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetStringValue(fields, "number_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ("1234567890", result.value());
}

HWTEST_F(MDKRecordReaderTest, GetLongValue_KeyFound_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["int64_key"] = MDKRecordField(int64_t(12345678901234));
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetLongValue(fields, "int64_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(12345678901234, result.value());
}

HWTEST_F(MDKRecordReaderTest, GetLongValue_KeyNotFound_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields = CreateTestFields();
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetLongValue(fields, "non_existent_key");
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(MDKRecordReaderTest, GetLongValue_ZeroValue_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["zero_key"] = MDKRecordField(int64_t(0));
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetLongValue(fields, "zero_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(0, result.value());
}

HWTEST_F(MDKRecordReaderTest, GetLongValue_NegativeValue_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["negative_key"] = MDKRecordField(int64_t(-1234567890));
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetLongValue(fields, "negative_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(-1234567890, result.value());
}

HWTEST_F(MDKRecordReaderTest, GetLongValue_MaxValue_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["max_key"] = MDKRecordField(std::numeric_limits<int64_t>::max());
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetLongValue(fields, "max_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(std::numeric_limits<int64_t>::max(), result.value());
}

HWTEST_F(MDKRecordReaderTest, GetLongValue_MinValue_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["min_key"] = MDKRecordField(std::numeric_limits<int64_t>::min());
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetLongValue(fields, "min_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(std::numeric_limits<int64_t>::min(), result.value());
}

HWTEST_F(MDKRecordReaderTest, GetIntValue_KeyFound_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["int32_key"] = MDKRecordField(int32_t(12345));
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetIntValue(fields, "int32_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(12345, result.value());
}

HWTEST_F(MDKRecordReaderTest, GetIntValue_KeyNotFound_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields = CreateTestFields();
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetIntValue(fields, "non_existent_key");
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(MDKRecordReaderTest, GetIntValue_ZeroValue_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["zero_key"] = MDKRecordField(int32_t(0));
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetIntValue(fields, "zero_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(0, result.value());
}

HWTEST_F(MDKRecordReaderTest, GetIntValue_NegativeValue_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["negative_key"] = MDKRecordField(int32_t(-12345));
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetIntValue(fields, "negative_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(-12345, result.value());
}

HWTEST_F(MDKRecordReaderTest, GetIntValue_MaxValue_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["max_key"] = MDKRecordField(std::numeric_limits<int32_t>::max());
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetIntValue(fields, "max_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(std::numeric_limits<int32_t>::max(), result.value());
}

HWTEST_F(MDKRecordReaderTest, GetIntValue_MinValue_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["min_key"] = MDKRecordField(std::numeric_limits<int32_t>::min());
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetIntValue(fields, "min_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(std::numeric_limits<int32_t>::min(), result.value());
}

HWTEST_F(MDKRecordReaderTest, GetIntValue_LargeInt64Value_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    int64_t largeValue = 99999999;
    fields["large_key"] = MDKRecordField(largeValue);
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetIntValue(fields, "large_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(99999999, result.value());
}

HWTEST_F(MDKRecordReaderTest, GetBoolValue_True_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["bool_key"] = MDKRecordField(true);
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetBoolValue(fields, "bool_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
}

HWTEST_F(MDKRecordReaderTest, GetBoolValue_False_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["bool_key"] = MDKRecordField(false);
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetBoolValue(fields, "bool_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(result.value());
}

HWTEST_F(MDKRecordReaderTest, GetBoolValue_KeyNotFound_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields = CreateTestFields();
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetBoolValue(fields, "non_existent_key");
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(MDKRecordReaderTest, GetBoolValue_StringAsBool_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["string_key"] = MDKRecordField("1");
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetBoolValue(fields, "string_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
}

HWTEST_F(MDKRecordReaderTest, GetBoolValue_StringFalseAsBool_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["string_key"] = MDKRecordField("0");
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetBoolValue(fields, "string_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(result.value());
}

HWTEST_F(MDKRecordReaderTest, MultipleKeys_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    fields["string_key"] = MDKRecordField("test_value");
    fields["int64_key"] = MDKRecordField(int64_t(1234567890));
    fields["int32_key"] = MDKRecordField(int32_t(12345));
    fields["bool_key"] = MDKRecordField(true);
    MDKAsset asset = CreateTestMDKAsset();
    fields["asset_key"] = MDKRecordField(asset);
    auto recordReader = MDKRecordReader();
    auto stringResult = recordReader.GetStringValue(fields, "string_key");
    auto int64Result = recordReader.GetLongValue(fields, "int64_key");
    auto int32Result = recordReader.GetIntValue(fields, "int32_key");
    auto boolResult = recordReader.GetBoolValue(fields, "bool_key");
    auto assetResult = recordReader.GetAssetValue(fields, "asset_key");

    EXPECT_TRUE(stringResult.has_value());
    EXPECT_TRUE(int64Result.has_value());
    EXPECT_TRUE(int32Result.has_value());
    EXPECT_TRUE(boolResult.has_value());
    EXPECT_TRUE(assetResult.has_value());

    EXPECT_EQ("test_value", stringResult.value());
    EXPECT_EQ(1234567890, int64Result.value());
    EXPECT_EQ(12345, int32Result.value());
    EXPECT_TRUE(boolResult.value());
}

HWTEST_F(MDKRecordReaderTest, EmptyFieldsMap_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    auto recordReader = MDKRecordReader();
    auto stringResult = recordReader.GetStringValue(fields, "any_key");
    auto int64Result = recordReader.GetLongValue(fields, "any_key");
    auto int32Result = recordReader.GetIntValue(fields, "any_key");
    auto boolResult = recordReader.GetBoolValue(fields, "any_key");
    auto assetResult = recordReader.GetAssetValue(fields, "any_key");

    EXPECT_FALSE(stringResult.has_value());
    EXPECT_FALSE(int64Result.has_value());
    EXPECT_FALSE(int32Result.has_value());
    EXPECT_FALSE(boolResult.has_value());
    EXPECT_FALSE(assetResult.has_value());
}

HWTEST_F(MDKRecordReaderTest, SpecialStringValues_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;

    fields["json_string"] = MDKRecordField("{\"key\":\"value\"}");
    fields["url_string"] = MDKRecordField("https://example.com/path/to/file.jpg");
    fields["path_string"] = MDKRecordField("/storage/emulated/0/DCIM/Camera/test.jpg");
    fields["uuid_string"] = MDKRecordField("550e8400-e29b-41d4-a716-446655440");
    auto recordReader = MDKRecordReader();
    auto jsonResult = recordReader.GetStringValue(fields, "json_string");
    auto urlResult = recordReader.GetStringValue(fields, "url_string");
    auto pathResult = recordReader.GetStringValue(fields, "path_string");
    auto uuidResult = recordReader.GetStringValue(fields, "uuid_string");

    EXPECT_TRUE(jsonResult.has_value());
    EXPECT_TRUE(urlResult.has_value());
    EXPECT_TRUE(pathResult.has_value());
    EXPECT_TRUE(uuidResult.has_value());

    EXPECT_EQ("{\"key\":\"value\"}", jsonResult.value());
    EXPECT_EQ("https://example.com/path/to/file.jpg", urlResult.value());
    EXPECT_EQ("/storage/emulated/0/DCIM/Camera/test.jpg", pathResult.value());
    EXPECT_EQ("550e8400-e29b-41d4-a716-446655440", uuidResult.value());
}

HWTEST_F(MDKRecordReaderTest, EdgeCaseIntValues_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;

    fields["one"] = MDKRecordField(int32_t(1));
    fields["minus_one"] = MDKRecordField(int32_t(-1));
    fields["large_positive"] = MDKRecordField(int32_t(2147483647));
    fields["large_negative"] = MDKRecordField(int32_t(-2147483648));
    auto recordReader = MDKRecordReader();
    auto oneResult = recordReader.GetIntValue(fields, "one");
    auto minusOneResult = recordReader.GetIntValue(fields, "minus_one");
    auto largePosResult = recordReader.GetIntValue(fields, "large_positive");
    auto largeNegResult = recordReader.GetIntValue(fields, "large_negative");

    EXPECT_EQ(1, oneResult.value());
    EXPECT_EQ(-1, minusOneResult.value());
    EXPECT_EQ(2147483647, largePosResult.value());
    EXPECT_EQ(-2147483648, largeNegResult.value());
}

HWTEST_F(MDKRecordReaderTest, EdgeCaseInt64Values_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;

    fields["one"] = MDKRecordField(int64_t(1));
    fields["minus_one"] = MDKRecordField(int64_t(-1));
    fields["large"] = MDKRecordField(int64_t(9223372036854775807));

    auto recordReader = MDKRecordReader();
    auto oneResult = recordReader.GetLongValue(fields, "one");
    auto minusOneResult = recordReader.GetLongValue(fields, "minus_one");
    auto largePosResult = recordReader.GetLongValue(fields, "large");

    EXPECT_EQ(1, oneResult.value());
    EXPECT_EQ(-1, minusOneResult.value());
    EXPECT_EQ(9223372036854775807, largePosResult.value());
}

HWTEST_F(MDKRecordReaderTest, LongToIntegerConversion_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;

    fields["int32_max"] = MDKRecordField(int64_t(std::numeric_limits<int32_t>::max()));
    fields["int32_min"] = MDKRecordField(int64_t(std::numeric_limits<int32_t>::min()));
    auto recordReader = MDKRecordReader();
    auto maxResult = recordReader.GetIntValue(fields, "int32_max");
    auto minResult = recordReader.GetIntValue(fields, "int32_min");

    EXPECT_EQ(std::numeric_limits<int32_t>::max(), maxResult.value());
    EXPECT_EQ(std::numeric_limits<int32_t>::min(), minResult.value());
}

HWTEST_F(MDKRecordReaderTest, UnicodeStringValues_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;

    fields["chinese"] = MDKRecordField("中文测试");
    fields["emoji"] = MDKRecordField("📸测试");
    fields["russian"] = MDKRecordField("Тест");
    fields["arabic"] = MDKRecordField("اختبار");
    auto recordReader = MDKRecordReader();
    auto chineseResult = recordReader.GetStringValue(fields, "chinese");
    auto emojiResult = recordReader.GetStringValue(fields, "emoji");
    auto russianResult = recordReader.GetStringValue(fields, "russian");
    auto arabicResult = recordReader.GetStringValue(fields, "arabic");

    EXPECT_TRUE(chineseResult.has_value());
    EXPECT_TRUE(emojiResult.has_value());
    EXPECT_TRUE(russianResult.has_value());
    EXPECT_TRUE(arabicResult.has_value());

    EXPECT_EQ("中文测试", chineseResult.value());
    EXPECT_EQ("📸测试", emojiResult.value());
    EXPECT_EQ("Тест", russianResult.value());
    EXPECT_EQ("اختبار", arabicResult.value());
}

HWTEST_F(MDKRecordReaderTest, VeryLongString_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    std::string longString(1000, 'A');
    fields["long_key"] = MDKRecordField(longString);
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetStringValue(fields, "long_key");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(1000, result.value().length());
}

HWTEST_F(MDKRecordReaderTest, AssetWithEmptyValues_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    MDKAsset asset;
    fields["empty_asset"] = MDKRecordField(asset);
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetAssetValue(fields, "empty_asset");
    EXPECT_TRUE(result.has_value());
}

HWTEST_F(MDKRecordReaderTest, AssetWithLargeValues_Test, TestSize.Level1)
{
    std::map<std::string, MDKRecordField> fields;
    MDKAsset asset;
    fields["large_asset"] = MDKRecordField(asset);
    auto recordReader = MDKRecordReader();
    auto result = recordReader.GetAssetValue(fields, "large_asset");
    EXPECT_TRUE(result.has_value());
}

}  // namespace CloudSync
}  // namespace Media
}  // namespace OHOS
