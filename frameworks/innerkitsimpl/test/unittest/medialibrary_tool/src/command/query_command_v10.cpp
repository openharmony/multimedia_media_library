
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
#include <string>
#include <vector>
#include "media_log.h"
#include "command/query_command_v10.h"
#include "userfile_client_ex.h"
#include "media_file_utils.h"
#include "utils/database_utils.h"
#include "medialibrary_errno.h"
#include "datashare_predicates.h"
#include "userfile_client.h"
#include "constant.h"
#include "result_set_utils.h"
#include "parameter.h"
#include "parameters.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
const string PATH_HEAD = "/storage/cloud/";
static std::vector<std::string> QueryMediaFiles(const std::string &displayName)
{
    std::vector<std::string> queryfilePaths;
    std::string fileTableName = MediaFileUtils::GetTableNameByDisplayName(displayName);
    if (fileTableName == AudioColumn::AUDIOS_TABLE || fileTableName == PhotoColumn::PHOTOS_TABLE) {
        auto resultSet = UserFileClientEx::GetResultsetByDisplayName(fileTableName, displayName);
        if (resultSet == nullptr || resultSet->GoToFirstRow() != 0) {
            printf("The displayName you want to query do not exist!\n");
            printf("find 0 result\n");
            return queryfilePaths;
        }
        do {
            auto path = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
            auto pos = path.find("/storage/cloud/file", 0);
            if (pos != string::npos) {
                path.insert(pos + PATH_HEAD.length(), "100/");
            }
            queryfilePaths.push_back(path);
        } while (!resultSet->GoToNextRow());
    } else {
        printf("The displayName format is not correct!\n");
    }
    return queryfilePaths;
}

int32_t QueryCommandV10::Start(const ExecEnv &env)
{
    std::vector<std::string> filePaths;
    filePaths = QueryMediaFiles(env.queryParam.displayName);
    int count = filePaths.size();
    if (filePaths.empty()) {
        return Media::E_OK;
    }
    printf("find %d result: \n", count);
    for (auto path:filePaths) {
        printf("%s\n", path.c_str());
    }
    return Media::E_OK;
}
}
}
}
