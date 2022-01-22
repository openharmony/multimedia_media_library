/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef RECEIVER_UTILS_H
#define RECEIVER_UTILS_H
#include <string>
#include <vector>
namespace OHOS {
namespace Media {
class ReceiverUtils {
public:
    static void RemoveEmptyString(std::vector<std::string> &strList);
    static void RemoveDuplicateString(std::vector<std::string> &strList);
};
} // namespace Media
} // namespace OHOS
#endif // RECEIVER_UTILS_H
