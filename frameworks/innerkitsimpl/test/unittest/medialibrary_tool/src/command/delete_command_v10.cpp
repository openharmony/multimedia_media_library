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

#include "command/delete_command_v10.h"
#include "constant.h"
#include "medialibrary_errno.h"
#include "userfile_client_ex.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
int32_t DeleteCommandV10::DeleteOne(const std::string &uri)
{
    int32_t ret = UserFileClientEx::Trash(uri);
    if (ret < 0) {
        printf("%s trash failed. err:%d\n", STR_FAIL.c_str(), ret);
        return Media::E_ERR;
    }
    ret = UserFileClientEx::Delete(uri);
    if (ret < 0) {
        printf("%s delete failed. err:%d\n", STR_FAIL.c_str(), ret);
        return Media::E_ERR;
    }
    printf("%s delete success.\n", STR_SUCCESS.c_str());
    return Media::E_OK;
}

int32_t DeleteCommandV10::DeleteAll(bool isOnlyDeleteDb)
{
    return UserFileClientEx::Delete(isOnlyDeleteDb);
}

int32_t DeleteCommandV10::Start(const ExecEnv &env)
{
    int32_t ret = 0;
    if (env.deleteParam.isDeleteAll) {
        ret = DeleteAll(env.deleteParam.isOnlyDeleteDb);
    } else {
        ret = DeleteOne(env.deleteParam.deleteUri);
    }
    if (ret != Media::E_OK) {
        printf("%s delete failed. err:%d\n", STR_FAIL.c_str(), ret);
        return Media::E_ERR;
    }
    return Media::E_OK;
}
} // MediaTool
} // Media
} // OHOS