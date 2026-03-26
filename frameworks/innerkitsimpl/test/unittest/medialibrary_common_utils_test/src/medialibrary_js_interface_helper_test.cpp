/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "medialibrary_common_utils_test.h"

#include "js_interface_helper.h"
#include "media_column.h"
#include "photo_album_column.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    string photoName = "mypic.jpg";
    string pathName = "/data/mypath/mypic.jpg";
    predicates->EqualTo(MediaColumn::MEDIA_NAME, photoName);
    predicates->In(MediaColumn::MEDIA_FILE_PATH, vector<string>({pathName}));
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), photoName.size() + pathName.size());
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_test, TestSize.Level1)
{
    string photoUri = "file://media/Photo/4/IMG_1770017466_000/IMG_20260202_152926.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(photoUri);
    string emptyUri = JsInterfaceHelper::GetSafeUri("");
    EXPECT_EQ(safeUri.find(photoUri) == std::string::npos, true);
    EXPECT_EQ(emptyUri.empty(), true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_test, TestSize.Level1)
{
    string privateString = "private info";
    string safePrivateString = JsInterfaceHelper::MaskString(privateString);
    EXPECT_EQ(safePrivateString.find(privateString) == std::string::npos, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_empty_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, false);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_orderbyasc_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->OrderByAsc(MediaColumn::MEDIA_DATE_MODIFIED);
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_orderbydesc_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->OrderByDesc(MediaColumn::MEDIA_DATE_MODIFIED);
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_multiple_operations_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "test.jpg");
    predicates->OrderByAsc(MediaColumn::MEDIA_DATE_MODIFIED);
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_only_equalto_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "test.jpg");
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, false);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_multiple_order_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->OrderByAsc(MediaColumn::MEDIA_DATE_MODIFIED);
    predicates->OrderByDesc(MediaColumn::MEDIA_SIZE);
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_with_other_ops_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "test.jpg");
    predicates->OrderByAsc(MediaColumn::MEDIA_DATE_MODIFIED);
    predicates->And();
    predicates->EqualTo(MediaColumn::MEDIA_TYPE, "image");
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_order_at_end_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "test.jpg");
    predicates->And();
    predicates->EqualTo(MediaColumn::MEDIA_TYPE, "image");
    predicates->OrderByAsc(MediaColumn::MEDIA_DATE_MODIFIED);
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_order_at_start_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->OrderByAsc(MediaColumn::MEDIA_DATE_MODIFIED);
    predicates->And();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "test.jpg");
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_no_order_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "test.jpg");
    predicates->And();
    predicates->EqualTo(MediaColumn::MEDIA_TYPE, "image");
    predicates->Or();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "test2.jpg");
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, false);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_unicode_test, TestSize.Level1)
{
    string unicode = "héllo wörld";
    string maskedString = JsInterfaceHelper::MaskString(unicode);
    EXPECT_GT(maskedString.size(), 0);
    EXPECT_NE(maskedString, unicode);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_mixed_chars_test, TestSize.Level1)
{
    string mixed = "a1b2c3";
    string maskedString = JsInterfaceHelper::MaskString(mixed);
    EXPECT_GT(maskedString.size(), 0);
    EXPECT_NE(maskedString, mixed);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_windows_path_test, TestSize.Level1)
{
    string windowsPath = "C:\\Users\\file.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(windowsPath);
    EXPECT_EQ(safeUri, windowsPath);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_network_path_test, TestSize.Level1)
{
    string networkPath = "//server/share/file.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(networkPath);
    EXPECT_NE(safeUri, networkPath);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_complex_condition_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "test.jpg");
    predicates->And();
    predicates->EqualTo(MediaColumn::MEDIA_TYPE, "image");
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_empty_string_value_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_NAME, "");
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_boundary_3_test, TestSize.Level1)
{
    string exactly3 = "abc";
    string maskedString = JsInterfaceHelper::MaskString(exactly3);
    EXPECT_EQ(maskedString.size(), 3);
    EXPECT_EQ(maskedString[0], '*');
    EXPECT_EQ(maskedString[1], '*');
    EXPECT_EQ(maskedString[2], 'c');
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_boundary_4_test, TestSize.Level1)
{
    string exactly4 = "abcd";
    string maskedString = JsInterfaceHelper::MaskString(exactly4);
    EXPECT_EQ(maskedString.size(), 3);
    EXPECT_EQ(maskedString[0], '*');
    EXPECT_EQ(maskedString[1], 'c');
    EXPECT_EQ(maskedString[2], 'd');
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_space_test, TestSize.Level1)
{
    string space = " ";
    string maskedString = JsInterfaceHelper::MaskString(space);
    EXPECT_EQ(maskedString, "*");
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_space_test, TestSize.Level1)
{
    string space = "/ .jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(space);
    EXPECT_NE(safeUri, space);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_newline_test, TestSize.Level1)
{
    string newline = "\n";
    string maskedString = JsInterfaceHelper::MaskString(newline);
    EXPECT_EQ(maskedString, "*");
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_newline_test, TestSize.Level1)
{
    string newline = "/\n.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(newline);
    EXPECT_NE(safeUri, newline);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_tab_test, TestSize.Level1)
{
    string tab = "\t";
    string maskedString = JsInterfaceHelper::MaskString(tab);
    EXPECT_EQ(maskedString, "*");
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_tab_test, TestSize.Level1)
{
    string tab = "/\t.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(tab);
    EXPECT_NE(safeUri, tab);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_false_bool_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_IS_FAV, false);
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
    EXPECT_NE(printStr.find("bool::false"), std::string::npos);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_true_bool_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_IS_FAV, true);
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
    EXPECT_NE(printStr.find("bool::true"), std::string::npos);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_double_slash_test, TestSize.Level1)
{
    string doubleSlash = "//file.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(doubleSlash);
    EXPECT_NE(safeUri, doubleSlash);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_null_char_test, TestSize.Level1)
{
    string nullChar = "\0";
    string maskedString = JsInterfaceHelper::MaskString(nullChar);
    EXPECT_EQ(maskedString, "");
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_null_char_test, TestSize.Level1)
{
    string nullChar = "/\0.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(nullChar);
    EXPECT_EQ(safeUri, nullChar);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_very_long_test, TestSize.Level1)
{
    string veryLong(1000, 'a');
    string maskedString = JsInterfaceHelper::MaskString(veryLong);
    EXPECT_EQ(maskedString.size(), 3);
    EXPECT_EQ(maskedString[0], '*');
    EXPECT_EQ(maskedString[1], 'a');
    EXPECT_EQ(maskedString[2], 'a');
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_very_long_path_test, TestSize.Level1)
{
    string veryLongPath = "/";
    for (int i = 0; i < 100; i++) {
        veryLongPath += "dir" + std::to_string(i) + "/";
    }
    veryLongPath += "file.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(veryLongPath);
    EXPECT_NE(safeUri, veryLongPath);
    EXPECT_GT(safeUri.size(), 0);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_max_values_test, TestSize.Level1)
{
    vector<string> values;
    for (int i = 0; i < 1000; i++) {
        values.push_back("file" + std::to_string(i) + ".jpg");
    }
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->In(MediaColumn::MEDIA_NAME, values);
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicatesHasOrderClause_max_operations_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    for (int i = 0; i < 100; i++) {
        predicates->EqualTo(MediaColumn::MEDIA_NAME, "test" + std::to_string(i) + ".jpg");
        predicates->Or();
    }
    predicates->OrderByAsc(MediaColumn::MEDIA_DATE_MODIFIED);
    bool hasOrder = JsInterfaceHelper::PredicatesHasOrderClause(*predicates);
    EXPECT_EQ(hasOrder, true);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_zero_test, TestSize.Level1)
{
    string zero = "0";
    string maskedString = JsInterfaceHelper::MaskString(zero);
    EXPECT_EQ(maskedString, "*");
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_zero_test, TestSize.Level1)
{
    string zero = "/0.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(zero);
    EXPECT_NE(safeUri, zero);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_zero_value_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_SIZE, 0);
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_negative_test, TestSize.Level1)
{
    string negative = "-1";
    string maskedString = JsInterfaceHelper::MaskString(negative);
    EXPECT_GT(maskedString.size(), 0);
    EXPECT_NE(maskedString, negative);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_negative_test, TestSize.Level1)
{
    string negative = "/-1.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(negative);
    EXPECT_NE(safeUri, negative);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_negative_value_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_SIZE, -1);
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_float_test, TestSize.Level1)
{
    string floatStr = "3.14";
    string maskedString = JsInterfaceHelper::MaskString(floatStr);
    EXPECT_GT(maskedString.size(), 0);
    EXPECT_NE(maskedString, floatStr);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_float_test, TestSize.Level1)
{
    string floatStr = "/3.14.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(floatStr);
    EXPECT_NE(safeUri, floatStr);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_float_value_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_SIZE, 3.14);
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_hex_test, TestSize.Level1)
{
    string hex = "0x1234";
    string maskedString = JsInterfaceHelper::MaskString(hex);
    EXPECT_GT(maskedString.size(), 0);
    EXPECT_NE(maskedString, hex);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_GetSafeUri_hex_test, TestSize.Level1)
{
    string hex = "/0x1234.jpg";
    string safeUri = JsInterfaceHelper::GetSafeUri(hex);
    EXPECT_NE(safeUri, hex);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_PredicateToStringSafe_hex_value_test, TestSize.Level1)
{
    auto predicates = make_shared<DataShare::DataSharePredicates>();
    predicates->EqualTo(MediaColumn::MEDIA_SIZE, 0x1234);
    string printStr = JsInterfaceHelper::PredicateToStringSafe(predicates);
    EXPECT_GT(printStr.size(), 0);
}

HWTEST_F(MediaLibraryCommonUtilsTest, medialib_MaskString_binary_test, TestSize.Level1)
{
    string binary = "0b1010";
    string maskedString = JsInterfaceHelper::MaskString(binary);
    EXPECT_GT(maskedString.size(), 0);
    EXPECT_NE(maskedString, binary);
}
} // namespace Media
} // namespace OHOS