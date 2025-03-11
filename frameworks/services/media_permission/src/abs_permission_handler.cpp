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

#define MLOG_TAG "AbsPermissionHandler"

#include "abs_permission_handler.h"

#include <cstdlib>

#include "medialibrary_bundle_manager.h"
#include "medialibrary_uripermission_operations.h"
#include "permission_utils.h"
#include "system_ability_definition.h"
#include "medialibrary_operation.h"
#include "parameters.h"
#ifdef MEDIALIBRARY_SECURITY_OPEN
#include "sec_comp_kit.h"
#endif

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS::Media {

int32_t AbsPermissionHandler::CheckPermission(MediaLibraryCommand &cmd, PermParam &permParam)
{
    MEDIA_DEBUG_LOG("CheckPermission:isDoDfx_=%{public}d", isDoDfx_);
    int32_t err = ExecuteCheckPermissionWithDfx(cmd, permParam);
    if (checkStopOnFail_) {
        if (err != E_SUCCESS || nextHandler_ == nullptr) {
            MEDIA_DEBUG_LOG("permission chain is end");
            return err;
        }
        return nextHandler_->CheckPermission(cmd, permParam);
    }
    if (err == E_SUCCESS || nextHandler_ == nullptr) {
        MEDIA_DEBUG_LOG("permission chain is end");
        return err;
    }
    return nextHandler_->CheckPermission(cmd, permParam); // 下一鉴权处理器鉴权
}

static bool IsFitCollectInfo(MediaLibraryCommand &cmd)
{
    return (cmd.GetOprnObject() == OperationObject::FILESYSTEM_PHOTO) ||
        (cmd.GetOprnObject() == OperationObject::THUMBNAIL) ||
        (cmd.GetOprnObject() == OperationObject::THUMBNAIL_ASTC);
}

int32_t AbsPermissionHandler::ExecuteCheckPermissionWithDfx(MediaLibraryCommand &cmd, PermParam &permParam)
{
    MEDIA_DEBUG_LOG("ExecuteCheckPermissionWithDfx begin, isOpenFile: %{public}d", permParam.isOpenFile);
    int32_t err = ExecuteCheckPermission(cmd, permParam);
    if (isDoDfx_ && IsFitCollectInfo(cmd) && permParam.isOpenFile) {
        MEDIA_DEBUG_LOG("dfx begin");
        bool permGranted = err == E_SUCCESS;
        PermissionUsedType type = PermissionUsedTypeValue::SECURITY_COMPONENT_TYPE;
        if (permParam.isWrite) {
            PermissionUtils::CollectPermissionInfo(PERM_WRITE_IMAGEVIDEO, permGranted, type);
        } else {
            PermissionUtils::CollectPermissionInfo(PERM_READ_IMAGEVIDEO, permGranted, type);
        }
        MEDIA_DEBUG_LOG("dfx end");
    }
    MEDIA_DEBUG_LOG("ExecuteCheckPermissionWithDfx end:err=%{public}d", err);
    return err;
}

} // namespace name