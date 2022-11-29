/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "mtp_test.h"
#include "media_log.h"

using namespace std;
namespace OHOS {
namespace Media {
std::shared_ptr<MtpTest> MtpTest::mtpTestInstance_{nullptr};
std::mutex MtpTest::instanceLock_;
MtpTest::MtpTest(void) {}

shared_ptr<MtpTest> MtpTest::GetInstance()
{
    if (mtpTestInstance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(instanceLock_);
        mtpTestInstance_ = make_shared<MtpTest>();
    }

    return mtpTestInstance_;
}

void MtpTest::setOutBuffer(std::vector<uint8_t> testData)
{
    MEDIA_INFO_LOG("MtpTest::setOutBuffer IN");
    std::vector<uint8_t>().swap(testData_);
    testData_.insert(testData_.end(), testData.begin(), testData.end());
    MEDIA_INFO_LOG("MtpTest::setOutBuffer OUT");
}

void MtpTest::getOutBuffer(std::vector<uint8_t> &outBuffer)
{
    MEDIA_INFO_LOG("MtpTest::getOutBuffer IN");
    outBuffer.insert(outBuffer.end(), testData_.begin(), testData_.end());
    MEDIA_INFO_LOG("MtpTest::getOutBuffer OUT");
}
} // namespace Media
} // namespace OHOS