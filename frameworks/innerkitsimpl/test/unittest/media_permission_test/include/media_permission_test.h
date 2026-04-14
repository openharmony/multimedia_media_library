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

#ifndef MEDIA_PERMISSION_TEST_H
#define MEDIA_PERMISSION_TEST_H

#include "gtest/gtest.h"
#include "abs_permission_handler.h"

namespace OHOS {
namespace Media {
class MediaPermissionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<Media::AbsPermissionHandler> permissionHandler_ = nullptr;
};

class CloudPermissionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void SetPermissionWithReadImageVideo(uint64_t &tokenId);
    static void SetPermissionWithReadCloudImageVideo(uint64_t &tokenId);
    static void SetPermissionWithBoth(uint64_t &tokenId);
    static void SetPermissionWithoutAny(uint64_t &tokenId);
    static void ResetPermission(uint64_t tokenId);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_PERMISSION_TEST_H
