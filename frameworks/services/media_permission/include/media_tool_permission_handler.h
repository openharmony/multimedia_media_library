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

#ifndef MEDIA_TOOL_PERMISSION_HANDLER_H
#define MEDIA_TOOL_PERMISSION_HANDLER_H

#include "abs_permission_handler.h"

namespace OHOS::Media {
/**
 * MedialTool鉴权处理器：校验是否MedialTool调用
 */
class MediaToolPermissionHandler : public AbsPermissionHandler {
public:
    MediaToolPermissionHandler() {};
    ~MediaToolPermissionHandler() {};
private:
    int32_t ExecuteCheckPermission(MediaLibraryCommand &cmd, PermParam &permParam) override; // 鉴权逻辑
};

} // namespace OHOS::Media
#endif