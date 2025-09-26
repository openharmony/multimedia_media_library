/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_BACKUP_CLONE_MAPCODE_TEST_H
#define MEDIALIBRARY_BACKUP_CLONE_MAPCODE_TEST_H

#define private public
#define protected public
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include "rdb_helper.h"
#include "result_set_utils.h"
#include "backup_const.h"
#include "medialibrary_subscriber.h"
#undef protected
#undef private

namespace OHOS {
namespace Media {
class MediaLibraryBackupCloneMapCodeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class MockMedialibrarySubscriber : public Media::MedialibrarySubscriber {
public:
    MockMedialibrarySubscriber() = default;
    ~MockMedialibrarySubscriber() = default;

    MOCK_METHOD0(IsCurrentStatusOn, bool());
};
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_BACKUP_CLONE_MAPCODE_TEST_H
