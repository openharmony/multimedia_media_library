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

#include "photo_query_filter_test.h"
#include "photo_query_filter.h"
#include "media_column.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void PhotoQueryFilterTest::SetUpTestCase(void) {}
void PhotoQueryFilterTest::TearDownTestCase(void) {}
void PhotoQueryFilterTest::SetUp(void) {}
void PhotoQueryFilterTest::TearDown(void) {}

/*
 * Feature : PhotoQueryFilterTest
 * Function : GetSqlWhereClause
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(PhotoQueryFilterTest, PhotoQueryFilter_Test_001, TestSize.Level0)
{
    PhotoQueryFilter::Option option = PhotoQueryFilter::Option::FILTER_HIDDEN;
    PhotoQueryFilter::GetSqlWhereClause(option);

    option = PhotoQueryFilter::Option::FILTER_TRASHED;
    PhotoQueryFilter::GetSqlWhereClause(option);

    option = PhotoQueryFilter::Option::CUSTOM_FILTER;
    string res = PhotoQueryFilter::GetSqlWhereClause(option);
    EXPECT_EQ(res, "");
}

/*
 * Feature : PhotoQueryFilterTest
 * Function : GetSqlWhereClause
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(PhotoQueryFilterTest, PhotoQueryFilter_Test_002, TestSize.Level0)
{
    PhotoQueryFilter::Config config;
    config.syncStatusConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.cleanFlagConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.pendingConfig = PhotoQueryFilter::ConfigType::INCLUDE;
    config.tempConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.hiddenConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.trashedConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.burstCoverOnly = PhotoQueryFilter::ConfigType::IGNORE;
    string res = PhotoQueryFilter::GetSqlWhereClause(config);
    EXPECT_NE(res, "");
}

/*
 * Feature : PhotoQueryFilterTest
 * Function : GetSqlWhereClause
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(PhotoQueryFilterTest, PhotoQueryFilter_Test_003, TestSize.Level0)
{
    PhotoQueryFilter::Config config;
    config.syncStatusConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.cleanFlagConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.pendingConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.tempConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.hiddenConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.trashedConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.burstCoverOnly = PhotoQueryFilter::ConfigType::IGNORE;
    string res = PhotoQueryFilter::GetSqlWhereClause(config);
    EXPECT_EQ(res, "");
}

/*
 * Feature : PhotoQueryFilterTest
 * Function : ModifyPredicate
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(PhotoQueryFilterTest, PhotoQueryFilter_Test_004, TestSize.Level0)
{
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    PhotoQueryFilter::ModifyPredicate(PhotoQueryFilter::Option::FILTER_HIDDEN, predicates);
    PhotoQueryFilter::ModifyPredicate(PhotoQueryFilter::Option::FILTER_TRASHED, predicates);
    PhotoQueryFilter::ModifyPredicate(PhotoQueryFilter::Option::CUSTOM_FILTER, predicates);

    PhotoQueryFilter::Config config;
    config.syncStatusConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.cleanFlagConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.pendingConfig = PhotoQueryFilter::ConfigType::INCLUDE;
    config.tempConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.hiddenConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.trashedConfig = PhotoQueryFilter::ConfigType::IGNORE;
    config.burstCoverOnly = PhotoQueryFilter::ConfigType::IGNORE;
    PhotoQueryFilter::ModifyPredicate(config, predicates);

    config.pendingConfig = PhotoQueryFilter::ConfigType::IGNORE;
    PhotoQueryFilter::ModifyPredicate(config, predicates);

    PhotoQueryFilter::Option option = PhotoQueryFilter::Option::CUSTOM_FILTER;
    string res = PhotoQueryFilter::GetSqlWhereClause(option);
    EXPECT_EQ(res, "");
}
} // namespace Media
} // namespace OHOS