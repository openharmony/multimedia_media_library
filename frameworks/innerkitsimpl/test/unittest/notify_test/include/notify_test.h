/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FILEMANAGEMENT_USERFILEMGR_PHOTOALBUM_UNITTEST_H
#define OHOS_FILEMANAGEMENT_USERFILEMGR_PHOTOALBUM_UNITTEST_H

#include <gtest/gtest.h>
#include <condition_variable>
#include "datashare_helper.h"

namespace OHOS::Media {
class TestObserver : public DataShare::DataShareObserver  {
public:
    TestObserver() {}

    ~TestObserver() = default;

    void OnChange(const ChangeInfo &changeInfo) override
    {
        changeInfo_ = changeInfo;
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.notify_one();
    }

    ChangeInfo changeInfo_;
    std::mutex mutex_;
    std::condition_variable condition_;
};
class NotifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};
} // namespace OHOS::Media
#endif // OHOS_FILEMANAGEMENT_USERFILEMGR_PHOTOALBUM_UNITTEST_H
