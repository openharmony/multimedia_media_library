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

#ifndef MEDIA_PERMISSION_CHECK_TEST_H
#define MEDIA_PERMISSION_CHECK_TEST_H

#include "gtest/gtest.h"
#include "media_permission_check.h"
// #include "media_file_utils.h"
// #include "media_dbperm_parser_req.h"
namespace OHOS {
namespace Media {
class MediaPermissionCheckTest : public ::testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::unordered_map<uint32_t, std::vector<std::vector<PermissionType>>> originalBusinessCodeToPermissions;
};

} // namespace Media
} // namespace OHOS
#endif // MEDIA_PERMISSION_CHECK_TEST_H
