/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_MEDIATOOLS_COMMAND_QUERY_COMMAND_V10_H
#define FRAMEWORKS_MEDIATOOLS_COMMAND_QUERY_COMMAND_V10_H
#include "command/command.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
class QueryCommandV10 : public Command {
public:
    QueryCommandV10() = default;
    ~QueryCommandV10() override = default;
    QueryCommandV10(const QueryCommandV10 &queryCommand) = delete;
    QueryCommandV10(QueryCommandV10 &&queryCommand) = delete;
    QueryCommandV10 &operator=(const QueryCommandV10 &queryCommand) = delete;
    QueryCommandV10 &operator=(QueryCommandV10 &&queryCommand) = delete;
    int32_t Start(const ExecEnv &env) override;
};
}
}
}
#endif
