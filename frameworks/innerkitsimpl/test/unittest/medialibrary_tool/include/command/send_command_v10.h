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
#ifndef FRAMEWORKS_MEDIATOOLS_COMMAND_SEND_COMMAND_V10_H_
#define FRAMEWORKS_MEDIATOOLS_COMMAND_SEND_COMMAND_V10_H_
#include "command/command.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
class SendCommandV10 : public Command {
public:
    SendCommandV10() = default;
    ~SendCommandV10() override = default;
    SendCommandV10(const SendCommandV10 &sendCommand) = delete;
    SendCommandV10(SendCommandV10 &&sendCommand) = delete;
    SendCommandV10 &operator=(const SendCommandV10 &sendCommand) = delete;
    SendCommandV10 &operator=(SendCommandV10 &&sendCommand) = delete;
    int32_t Start(const ExecEnv &env) override;
};
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_MEDIATOOLS_COMMAND_SEND_COMMAND_V10_H_
