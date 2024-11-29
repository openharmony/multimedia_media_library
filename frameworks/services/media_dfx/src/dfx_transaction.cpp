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

#define MLOG_TAG "DfxTransaction"

#include "dfx_transaction.h"

#include "hisysevent.h"
#include "media_file_utils.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";
constexpr int64_t TIME_COST_THRESHOLD = 2000; // 2s
DfxTransaction::DfxTransaction(std::string funcName) : funcName_(funcName)
{
    startTime_ = MediaFileUtils::UTCTimeMilliSeconds();
}

DfxTransaction::~DfxTransaction() {}

void DfxTransaction::Restart()
{
    timeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - startTime_;
}

void DfxTransaction::ReportIfTimeout()
{
    timeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - startTime_;
    if (timeCost_ < TIME_COST_THRESHOLD) {
        return;
    }
    Report(AbnormalType::TIMEOUT_WARN);
}

void DfxTransaction::ReportError(uint8_t abnormalType, int32_t errCode)
{
    timeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - startTime_;
    Report(abnormalType, errCode);
}

void DfxTransaction::Report(uint8_t abnormalType, int32_t errCode)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_TRANSACTION_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "FUNC_NAME", funcName_,
        "START_TIME", startTime_,
        "TIME_COST", timeCost_,
        "ABNORMAL_TYPE", abnormalType,
        "ERROR_CODE", errCode);
    if (ret != 0) {
        MEDIA_ERR_LOG("Dfx Transaction Report error: %{public}d", ret);
    }
}
} // namespace Media
} // namespace OHOS