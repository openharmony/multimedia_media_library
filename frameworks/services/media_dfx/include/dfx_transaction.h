/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_DFX_TRANSACTION_H
#define OHOS_MEDIA_DFX_TRANSACTION_H

#include <string>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class DfxTransaction {
public:
    enum EXPORT AbnormalType : uint8_t {
        CREATE_ERROR,
        COMMIT_ERROR,
        ROLLBACK_ERROR,
        EXECUTE_ERROR,
        NULLPTR_ERROR,
        TIMEOUT_WARN,
    };
    EXPORT DfxTransaction(std::string funcName);
    EXPORT ~DfxTransaction();
    EXPORT void Restart();
    EXPORT void ReportIfTimeout();
    EXPORT void ReportError(uint8_t abnormalType, int32_t errCode);

private:
    void Report(uint8_t abnormalType, int32_t errCode = 0);
    std::string funcName_;
    int64_t startTime_{ 0 };
    int64_t timeCost_{ 0 };
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIA_DFX_TRANSACTION_H
