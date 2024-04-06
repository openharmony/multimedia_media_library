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
#define MLOG_TAG "ControlMain"
#include "control_main.h"

#include <array>
#include <unistd.h>

#include "command/command.h"
#include "command_line.h"
#include "constant.h"
#include "directory_ex.h"
#include "exec_env.h"
#include "get_self_permissions.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "mimetype_utils.h"
#include "system_ability_definition.h"
#include "userfile_client_ex.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
static int32_t InitPermission()
{
    std::vector<std::string> perms;
    perms.emplace_back("ohos.permission.READ_AUDIO");
    perms.emplace_back("ohos.permission.WRITE_AUDIO");
    perms.emplace_back("ohos.permission.READ_IMAGEVIDEO");
    perms.emplace_back("ohos.permission.WRITE_IMAGEVIDEO");
    perms.emplace_back("ohos.permission.MEDIA_LOCATION");
    perms.emplace_back("ohos.permission.FILE_ACCESS_MANAGER");
    perms.emplace_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaTool", perms, tokenId);
    if (tokenId == 0) {
        printf("%s set access token permisson failed.\n", STR_FAIL.c_str());
        return Media::E_ERR;
    }
    return Media::E_OK;
}

static void Finish()
{
    UserFileClientEx::Clear();
}

static int32_t Init(ExecEnv &env, const std::vector<std::string> &args)
{
    env.args.assign(args.begin(), args.end());
    std::array<char, PATH_MAX> buffer {0};
    getcwd(buffer.data(), PATH_MAX);
    env.workPath.append(buffer.data());
    env.workPath = IncludeTrailingPathDelimiter(env.workPath);
    return InitPermission();
}

int32_t ControlMain::Main(const std::vector<std::string> &args)
{
    ExecEnv env;
    int32_t res = Init(env, args);
    if (res != Media::E_OK) {
        return res;
    }
    res = CommandLine::Parser(env);
    if (res != Media::E_OK) {
        return res;
    }
    do {
        res = UserFileClientEx::Init();
        if (res != Media::E_OK) {
            break;
        }
        MimeTypeUtils::InitMimeTypeMap();
        std::unique_ptr<Command> cmd = Command::Create(env);
        if (cmd == nullptr) {
            res = Media::E_ERR;
            break;
        }
        MEDIA_INFO_LOG("Main, env:{%{private}s}", env.ToStr().c_str());
        res = cmd->Start(env);
        if (res != Media::E_OK) {
            MEDIA_ERR_LOG("Main, start, res:%{public}d", res);
            break;
        }
    } while (0);
    Finish();
    return res;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
