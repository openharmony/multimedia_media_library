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

#ifndef MEDIA_LIBRARY_TEST_TABLE_EVENT_HANDLER_ON_UPGRADE_TEST_H
#define MEDIA_LIBRARY_TEST_TABLE_EVENT_HANDLER_ON_UPGRADE_TEST_H

#include "table_event_handler.h"

#include <gtest/gtest.h>

namespace OHOS::Media {
class TableEventHandlerOnUpgradeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    static int32_t MockDatabase();
};
}  // namespace OHOS::Media
#endif  // MEDIA_LIBRARY_TEST_TABLE_EVENT_HANDLER_ON_UPGRADE_TEST_H