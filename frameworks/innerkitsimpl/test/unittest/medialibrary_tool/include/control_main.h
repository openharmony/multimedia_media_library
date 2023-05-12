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
#ifndef FRAMEWORKS_MEDIATOOLS_CONTROL_MAIN_H_
#define FRAMEWORKS_MEDIATOOLS_CONTROL_MAIN_H_
#include <string>
#include <vector>

namespace OHOS {
namespace Media {
namespace MediaTool {
class ControlMain {
public:
    static int32_t Main(const std::vector<std::string> &args);
};
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_MEDIATOOLS_CONTROL_MAIN_H_
