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

#ifndef SYSTEM_API_CHECK_HANDLER_H
#define SYSTEM_API_CHECK_HANDLER_H

#include "abs_permission_handler.h"

namespace OHOS::Media {
/**
 * 系统API权限鉴权处理器
 */
class SystemApiCheckHandler : public AbsPermissionHandler {
public:
    SystemApiCheckHandler()
    {
        checkStopOnFail_ = true;
    };
private:
    int32_t ExecuteCheckPermission(MediaLibraryCommand &cmd, PermParam &permParam) override; // 鉴权逻辑
};

} // namespace OHOS::Media
#endif