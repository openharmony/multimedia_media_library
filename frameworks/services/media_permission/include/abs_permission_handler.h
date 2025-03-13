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

#ifndef ABS_PERMISSION_HANDLER_H
#define ABS_PERMISSION_HANDLER_H

#include "permission_common.h"

namespace OHOS::Media {
/**
 * 鉴权处理器基类
 */
class AbsPermissionHandler {
public:
    AbsPermissionHandler(){};
    virtual ~AbsPermissionHandler(){};
    int32_t CheckPermission(MediaLibraryCommand &cmd, PermParam &permParam);
    void SetNextHandler(std::shared_ptr<AbsPermissionHandler> nextHandler)
    {
        nextHandler_ = nextHandler;
    }
protected:
    bool checkStopOnFail_ = false; // 失败时不进行后面的校验
    std::shared_ptr<AbsPermissionHandler> nextHandler_ = nullptr;
    bool isDoDfx_ = false; // 是否进行dfx打点
    int32_t ExecuteCheckPermissionWithDfx(MediaLibraryCommand &cmd, PermParam &permParam); // 鉴权+打点逻辑
    virtual int32_t ExecuteCheckPermission(MediaLibraryCommand &cmd, PermParam &permParam) = 0; // 鉴权逻辑
};

} // namespace OHOS::Media
#endif