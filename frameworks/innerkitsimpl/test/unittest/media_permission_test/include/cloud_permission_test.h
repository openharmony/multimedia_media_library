/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef CLOUD_PERMISSION_TEST_H
#define CLOUD_PERMISSION_TEST_H

#include <cstdint>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
class CloudPermissionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static int64_t InsertAssetWithPosition(PhotoPositionType position);
    static void SetPermissionWithReadImageVideo();
    static void SetPermissionWithReadCloudImageVideo();
    static void SetPermissionWithBoth();
    static void SetPermissionWithoutAny();
    static void MockPermission(const std::vector<std::string> &perms);
};
}  // namespace Media
}  // namespace OHOS
#endif  // CLOUD_PERMISSION_TEST_H