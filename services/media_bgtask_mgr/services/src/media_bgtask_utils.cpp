/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaBgTaskUtils"

#include "media_bgtask_utils.h"

#include <cstdlib>

#include <string>

#include "parameters.h"
#include "string_ex.h"

#include "media_bgtask_mgr_log.h"

namespace OHOS {
namespace MediaBgtaskSchedule {

bool MediaBgTaskUtils::IsStrTrueOrLtZero(std::string value)
{
    bool result = false;
    if (value == "true") {
        result = true;
    } else {
        int intv;
        bool isInt = StrToInt(value, intv);
        if (isInt && intv > 0) {
            result = true;
        }
    }
    return result;
}

bool MediaBgTaskUtils::IsParamTrueOrLtZero(std::string key)
{
    std::string value = system::GetParameter(key, "");
    bool result = IsStrTrueOrLtZero(value);
    MEDIA_INFO_LOG("check param %{public}s get [%{public}s], return %{public}s",
        key.c_str(),
        value.c_str(),
        result ? "true" : "false");
    return result;
}

std::string MediaBgTaskUtils::TaskOpsToString(TaskOps ops)
{
    switch (ops) {
        case START:
            return "start";
        case STOP:
            return "stop";
        default:
            return "None";
    }
}

TaskOps MediaBgTaskUtils::StringToTaskOps(const std::string &str)
{
    if (str == "start")
        return START;
    if (str == "stop")
        return STOP;
    return NONE;
}

std::string MediaBgTaskUtils::DesensitizeUri(const std::string &fileUri)
{
    std::string result = fileUri;
    size_t slashIndex = result.rfind('/');
    CHECK_AND_RETURN_RET(slashIndex != std::string::npos, result);
    return result.replace(slashIndex + 1, result.length() - slashIndex - 1, "*");
}

time_t MediaBgTaskUtils::GetNowTime()
{
    return time(0);
}

bool MediaBgTaskUtils::IsNumber(const std::string& str)
{
    CHECK_AND_RETURN_RET_LOG(!str.empty(), false, "IsNumber input is empty");
    for (char const& c : str) {
        CHECK_AND_RETURN_RET(isdigit(c) != 0, false);
    }
    return true;
}

}  // namespace MediaBgtaskSchedule
}  // namespace OHOS

