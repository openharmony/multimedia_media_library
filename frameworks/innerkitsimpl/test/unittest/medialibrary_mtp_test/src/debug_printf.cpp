/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstdarg>
#include <string>

using namespace std;

namespace OHOS {
namespace Media {

const std::string NEW_STR = "%";
const std::string OLD_STR = "%{public}";
const std::size_t OLD_STR_LEN = OLD_STR.length();

extern "C" void DebugPrintf(const char* fmt, ...)
{
    std::string fmtstr = fmt;
    while (true) {
        std::string::size_type pos(0);
        if ((pos = fmtstr.find(OLD_STR)) != std::string::npos) {
            fmtstr.replace(pos, OLD_STR_LEN, NEW_STR);
        } else {
            break;
        }
    }

    va_list ap;
    va_start(ap, fmt);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    vprintf(fmtstr.c_str(), ap);
#pragma clang diagnostic pop
    va_end(ap);
}
} // namespace Media
} // namespace OHOS