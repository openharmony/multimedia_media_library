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

#ifndef MDK_RECORD_READER_TEST_H
#define MDK_RECORD_READER_TEST_H

#include <gtest/gtest.h>

#include <string>
#include <map>
#include <optional>

#include "mdk_record_reader.h"
#include "mdk_record_field.h"
#include "mdk_asset.h"

namespace OHOS {
namespace Media {
namespace CloudSync {
class MDKRecordReaderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    std::map<std::string, MDKRecordField> CreateTestFields();
    MDKAsset CreateTestMDKAsset();
};
} // namespace CloudSync
} // namespace Media
} // namespace OHOS
#endif // MDK_RECORD_READER_TEST_H
