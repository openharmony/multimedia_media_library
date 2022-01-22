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
#include "inner/utils/receiver_utils.h"
#include <set>
#include "string_ex.h"
namespace OHOS {
namespace Media {
void ReceiverUtils::RemoveEmptyString(std::vector<std::string> &strList)
{
    std::vector<std::string> tmpVtr;
    for (auto &it : strList) {
        std::string trimedStr = TrimStr(it);
        if (trimedStr.empty()) {
            continue;
        }
        tmpVtr.push_back(trimedStr);
    }
    strList = tmpVtr;
}

void ReceiverUtils::RemoveDuplicateString(std::vector<std::string> &strList)
{
    std::vector<std::string> tmpVtr;
    std::set<std::string> tmpSet;
    for (auto &it : strList) {
        auto ret = tmpSet.insert(it);
        if (ret.second) {
            tmpVtr.push_back(it);
        }
    }
    strList = tmpVtr;
}
} // namespace Media
} // namespace OHOS
