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
#include "command_line.h"

#include "constant.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "media_file_utils.h"
#include "medialibrary_errno.h"
#include "userfile_client_ex.h"
#include "utils/file_utils.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
constexpr char CHAR_PATH_DELIMITER = '/';
constexpr int MEDIATOOL_ARG_MIN = 3;
constexpr int MEDIATOOL_ARG_CMD = 1;
constexpr int MEDIATOOL_ARG_FIRST = 2;
constexpr int MEDIATOOL_ARG_SECOND = 3;
const std::string OPT_STR_SEND = "send";
const std::string OPT_STR_RECV = "recv";
const std::string OPT_STR_LIST = "list";
const std::string OPT_STR_ALL = "all";

void ShowUsage()
{
    std::string str;
    str.append("usage:\n");
    str.append("  send pathname               |send file\n");
    str.append("  recv uri|all pathname       |recv uri\n");
    str.append("  list uri|all                |list uri\n");
    printf("%s", str.c_str());
}

bool CheckRecvPath(ExecEnv &env)
{
    std::string path = (env.isFile) ? ExtractFilePath(env.recvPath) : env.recvPath;
    if (!MediaFileUtils::IsDirectory(path)) {
        ForceCreateDirectory(path);
    }
    if (!MediaFileUtils::IsDirectory(path)) {
        printf("%s path issue. path:%s\n", STR_FAIL.c_str(), path.c_str());
        return false;
    }
    if (env.isFile) {
        if (FileExists(env.recvPath)) {
            printf("%s file has exist. file:%s\n", STR_FAIL.c_str(), env.recvPath.c_str());
            return false;
        }
    } else {
        if (!IsEmptyFolder(env.recvPath)) {
            printf("%s path is not empty. path:%s\n", STR_FAIL.c_str(), env.recvPath.c_str());
            return false;
        }
        env.recvPath = IncludeTrailingPathDelimiter(env.recvPath);
    }
    return true;
}

bool CheckList(ExecEnv &env)
{
    if (env.optArgs.uri == OPT_STR_ALL) {
        env.uri.clear();
    } else if (!env.optArgs.uri.empty()) {
        std::string tableName = UserFileClientEx::GetTableNameByUri(env.optArgs.uri);
        if (tableName.empty()) {
            printf("%s uri issue. uri:%s\n", STR_FAIL.c_str(), env.optArgs.uri.c_str());
            return false;
        }
        env.uri = env.optArgs.uri;
    } else {
        env.uri.clear();
    }
    return true;
}

bool CheckRecv(ExecEnv &env)
{
    if (env.optArgs.uri == OPT_STR_ALL) {
        env.uri.clear();
        env.isFile = false;
    } else if (!env.optArgs.uri.empty()) {
        std::string tableName = UserFileClientEx::GetTableNameByUri(env.optArgs.uri);
        if (tableName.empty()) {
            printf("%s uri issue. uri:%s\n", STR_FAIL.c_str(), env.optArgs.uri.c_str());
            return false;
        }
        env.uri = env.optArgs.uri;
        env.isFile = true;
    } else {
        env.uri.clear();
        env.isFile = false;
    }
    if (env.optArgs.recvPath.empty()) {
        printf("%s recv path empty.\n", STR_FAIL.c_str());
        return false;
    }
    if (env.optArgs.recvPath.find(CHAR_PATH_DELIMITER) == 0) {
        env.recvPath = env.optArgs.recvPath;
    } else {
        env.recvPath = env.workPath + env.optArgs.recvPath;
    }
    if (!CheckRecvPath(env)) {
        return false;
    }
    return true;
}

bool CheckSend(ExecEnv &env)
{
    if (env.optArgs.path.empty()) {
        printf("%s path empty.\n", STR_FAIL.c_str());
        return false;
    }
    if (!PathToRealPath(env.optArgs.path, env.path)) {
        printf("%s path issue. errno:%d, path:%s.\n", STR_FAIL.c_str(), errno, env.optArgs.path.c_str());
        return false;
    }
    if (FileUtils::IsFile(env.path)) {
        env.isFile = true;
    } else if (MediaFileUtils::IsDirectory(env.path)) {
        env.path = IncludeTrailingPathDelimiter(env.path);
        env.isFile = false;
    } else {
        printf("%s path issue. not file and not directory. path:%s.\n", STR_FAIL.c_str(), env.path.c_str());
        return false;
    }
    return true;
}

bool Check(ExecEnv &env)
{
    if (env.optArgs.cmdType == OptCmdType::TYPE_SEND) {
        return CheckSend(env);
    }
    if (env.optArgs.cmdType == OptCmdType::TYPE_RECV) {
        return CheckRecv(env);
    }
    if (env.optArgs.cmdType == OptCmdType::TYPE_LIST) {
        return CheckList(env);
    }
    return false;
}

int32_t CommandLine::Parser(ExecEnv &env)
{
    if (env.args.size() < MEDIATOOL_ARG_MIN) {
        ShowUsage();
        return Media::E_ERR;
    }
    std::string cmd = env.args[MEDIATOOL_ARG_CMD];
    std::string optFirst = env.args[MEDIATOOL_ARG_FIRST];
    std::string optSecond = (env.args.size() > MEDIATOOL_ARG_SECOND) ? env.args[MEDIATOOL_ARG_SECOND] : "";
    if (cmd == OPT_STR_SEND) {
        env.optArgs.cmdType = OptCmdType::TYPE_SEND;
        env.optArgs.path = optFirst;
    } else if (cmd == OPT_STR_RECV) {
        env.optArgs.cmdType = OptCmdType::TYPE_RECV;
        env.optArgs.uri = optFirst;
        env.optArgs.recvPath = optSecond;
    } else if (cmd == OPT_STR_LIST) {
        env.optArgs.cmdType = OptCmdType::TYPE_LIST;
        env.optArgs.uri = optFirst;
    } else {
        ShowUsage();
        return Media::E_ERR;
    }
    if (!Check(env)) {
        return Media::E_ERR;
    }
    return Media::E_OK;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
