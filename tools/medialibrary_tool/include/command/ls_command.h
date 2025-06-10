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
#ifndef FRAMEWORKS_MEDIATOOLS_COMMAND_LS_COMMAND_H_
#define FRAMEWORKS_MEDIATOOLS_COMMAND_LS_COMMAND_H_

#include "command/command.h"

#include <nlohmann/json.hpp>

namespace OHOS {
namespace Media {
namespace MediaTool {
class LSCommand : public Command {
public:
    LSCommand() = default;
    ~LSCommand() override = default;
    LSCommand(const LSCommand &lsCommand) = delete;
    LSCommand(LSCommand &&lsCommand) = delete;
    LSCommand &operator=(const LSCommand &lsCommand) = delete;
    LSCommand &operator=(LSCommand &&lsCommand) = delete;
    int32_t Start(const ExecEnv &env) override;

    bool ParseArgs(const std::vector<std::string>& args);
    bool ParsePositionalArgs(const std::vector<std::string>& positionalArgs);
    bool ParseFlagsArgs(const std::vector<std::string>& flags);
    bool CheckArgs();
    string ToString();
    string ErrorCodeToMsg(int32_t errorCode);
    int32_t PrintFileInfo(const std::string& fileInfoJSONString);
    int32_t Execute();

private:
    bool longFormat_ = false;
    string inputPath_;
    string lsPath_;

    static const int LS_POS_ARG_MIN;
    static const int LS_POS_ARG_MAX;
};
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_MEDIATOOLS_COMMAND_LIST_COMMAND_V10_H_
