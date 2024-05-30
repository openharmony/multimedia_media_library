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
#ifndef FRAMEWORKS_MEDIATOOLS_OPTION_ARGS_H_
#define FRAMEWORKS_MEDIATOOLS_OPTION_ARGS_H_
#include <string>

#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
enum class OptCmdType : uint32_t {
    TYPE_INIT = 0,
    TYPE_SEND = 1,
    TYPE_RECV = 2,
    TYPE_LIST = 3,
    TYPE_DELETE = 4,
    TYPE_QUERY = 5,
    TYPE_LAST = 6
};

struct OptionArgs {
    OptCmdType cmdType {OptCmdType::TYPE_INIT};
    Media::MediaType mediaType {Media::MediaType::MEDIA_TYPE_DEFAULT};
    std::string path; // dir or file
    std::string uri; // such as "datashare:///media/Photo/54"
    std::string recvPath; // dir or file
    std::string displayName;
    std::vector<std::string> extraArgs;
};
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_MEDIATOOLS_OPTION_ARGS_H_
