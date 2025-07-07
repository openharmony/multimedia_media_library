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

#ifndef MEDIALIBRARY_TRIGGER_TEST
#define MEDIALIBRARY_TRIGGER_TEST

#include <gtest/gtest.h>
#include "medialibrary_trigger.h"

namespace OHOS {
namespace Media {

class MediaLibraryTriggerTest  : public ::testing::Test {
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

class MockTrigger : public MediaLibraryTriggerBase {
public:
    void SetIsTriggerFireForRowReturn(bool ret) {isTriggerFireForRowReturn_ = ret;}
    void SetProcessReturn(int32_t ret) {processReturn_ = ret;}

    int32_t Process(std::shared_ptr<TransactionOperations> trans,
        const std::vector<AccurateRefresh::PhotoAssetChangeData>& changeDataVec) override {
        return processReturn_;
    }

    bool IsTriggerFireForRow(std::shared_ptr<TransactionOperations> trans,
        const AccurateRefresh::PhotoAssetChangeData& changeData) override {
        return isTriggerFireForRowReturn_;
    }
private:
    bool isTriggerFireForRowReturn_ = false;
    int32_t processReturn_ = NativeRdb::E_ERROR;
};
} // namespace Media
} // namespace OHOS

#endif // MEDIALIBRARY_TRIGGER_TEST