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

#define MLOG_TAG "MediaToolPermissionHandler"

#include "media_tool_permission_handler.h"

namespace OHOS::Media {

static bool IsMediaToolOperation(MediaLibraryCommand &cmd, PermParam &permParam)
{
    if (permParam.isOpenFile) {
        return cmd.GetQuerySetParam(IS_TOOL_OPEN) == TOOL_OPEN_TRUE;
    }
    return IsMediatoolOperation(cmd);
}

int32_t MediaToolPermissionHandler::ExecuteCheckPermission(MediaLibraryCommand &cmd, PermParam &permParam)
{
    MEDIA_DEBUG_LOG("MediaToolPermissionHandler enter");
    return ConvertPermResult(IsMediaToolOperation(cmd, permParam) && IsDeveloperMediaTool(cmd));
}

} // namespace name