/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MEDIASCANNER_UNIT_TEST_H
#define MEDIASCANNER_UNIT_TEST_H

#include <condition_variable>
#include <chrono>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <thread>

#include "gtest/gtest.h"
#include "imedia_scanner_callback.h"

namespace OHOS {
namespace Media {
class MediaScannerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void WaitForCallback();
};

class ApplicationCallback : public IMediaScannerCallback {
public:
    explicit ApplicationCallback(const std::string &testCaseName);
    ~ApplicationCallback() = default;

    int32_t OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) override;

private:
    std::string testCaseName_;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIASCANNER_UNIT_TEST_H
