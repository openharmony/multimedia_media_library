/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * * distributed under License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CLOUD_INT64_FIELDS_HASH_MAP_TEST_H
#define CLOUD_INT64_FIELDS_HASH_MAP_TEST_H

#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

namespace OHOS::Media::CloudSync {
class CloudInt64FieldsHashMapTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
}  // namespace OHOS::Media::CloudSync

#endif  // CLOUD_INT64_FIELDS_HASH_MAP_TEST_H
