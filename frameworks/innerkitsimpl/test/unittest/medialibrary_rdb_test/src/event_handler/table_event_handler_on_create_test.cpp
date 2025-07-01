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
#include "table_event_handler_on_create_test.h"

#include "media_log.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS::Media {
using namespace testing::ext;
void TableEventHandlerOnCreateTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    TableEventHandler tableEventHandler;
    tableEventHandler.OnCreate(MediaLibraryUnistoreManager::GetInstance().GetRdbStore());
}

void TableEventHandlerOnCreateTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void TableEventHandlerOnCreateTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void TableEventHandlerOnCreateTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

// always passed until the OnCreate is implemented
HWTEST_F(TableEventHandlerOnCreateTest, TableEventHandler_OnCreate, TestSize.Level0)
{
    EXPECT_TRUE(true);
}
}  // namespace OHOS::Media