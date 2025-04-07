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
#ifndef FRAMEWORKS_MEDIATOOLS_UTILS_CONSTANT_UTILS_H_
#define FRAMEWORKS_MEDIATOOLS_UTILS_CONSTANT_UTILS_H_
#include <string>

#include "fetch_result.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
struct DumpOpt {
    bool isPrintFormTitle {true};
    int32_t start {0};
    int32_t count {INT32_MAX};
    std::string split {","};
    std::string delimiter {"\""};
    std::vector<std::string> columns;
};

struct ColumnInfo {
    std::string name;
    int32_t index {-1};
    ResultSetDataType type {ResultSetDataType::TYPE_NULL};
};
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_MEDIATOOLS_UTILS_CONSTANT_UTILS_H_
