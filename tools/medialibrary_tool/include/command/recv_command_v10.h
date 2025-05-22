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
#ifndef FRAMEWORKS_MEDIATOOLS_COMMAND_RECV_COMMAND_V10_H_
#define FRAMEWORKS_MEDIATOOLS_COMMAND_RECV_COMMAND_V10_H_
#include "command/command.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
class RecvCommandV10 : public Command {
public:
    RecvCommandV10() = default;
    ~RecvCommandV10() override = default;
    RecvCommandV10(const RecvCommandV10 &recvCommand) = delete;
    RecvCommandV10(RecvCommandV10 &&recvCommand) = delete;
    RecvCommandV10 &operator=(const RecvCommandV10 &recvCommand) = delete;
    RecvCommandV10 &operator=(RecvCommandV10 &&recvCommand) = delete;
    int32_t Start(const ExecEnv &env) override;
    int32_t RecvAssets(const ExecEnv& env, const std::string& tableName);
    int32_t QueryAssets(std::shared_ptr<DataShare::DataShareResultSet>& resultSet, const std::string& tableName);
    bool CheckArgs(const ExecEnv& env);
    bool QueryMovingPhotoAsset(const string& movingPhotoImagePath, unique_ptr<FileAsset>& movingPhotoAsset);
    bool IsMovingPhotoVideoPath(unique_ptr<FileAsset>& movingPhotoAsset);

private:
    string srcPath_;
    string inputPath_;
    string uri_;
    string tableName_;

    bool isRecvAll_ = false;
};
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_MEDIATOOLS_COMMAND_RECV_COMMAND_V10_H_
