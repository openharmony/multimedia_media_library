/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hi_audit_test.h"

#include <iostream>
#include "media_log.h"
#include <fstream>

#define private public
#include "hi_audit.h"
#include "zip_util.h"
#undef private

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void HiAuditTest::SetUpTestCase(void) {}

void HiAuditTest::TearDownTestCase(void) {}

void HiAuditTest::SetUp(void) {}

void HiAuditTest::TearDown(void) {}

HWTEST_F(HiAuditTest, HiAuditTest_Write_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("HiAuditTest_Write_test_001 begin");
    std::string filePath = "/data/app/el2/100/log/com.ohos.medialibrary.medialibrarydata/audit/media_library.csv";
    int oriLineCount = 0;
    if (std::filesystem::exists(filePath)) {
        std::string line;
        std::ifstream file(filePath);
        ASSERT_EQ(file.is_open(), true);
        while (std::getline(file, line)) {
            ++oriLineCount;
        }
    }
    AuditLog auditLog = { true, "USER BEHAVIOR", "ADD", "io", 1, "running", "ok" };
    OHOS::Media::HiAudit::GetInstance().Write(auditLog);
    int finalLineCount = 0;
    if (std::filesystem::exists(filePath)) {
        std::string line;
        std::ifstream file(filePath);
        ASSERT_EQ(file.is_open(), true);
        while (std::getline(file, line)) {
            ++finalLineCount;
        }
    }
    ASSERT_EQ(finalLineCount, oriLineCount);
    MEDIA_INFO_LOG("HiAuditTest_Write_test_001 end");
}
} // namespace OHOS
} // namespace OHOS