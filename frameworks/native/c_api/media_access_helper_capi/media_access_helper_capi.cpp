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

#include "media_access_helper_capi.h"

#include "media_log.h"
#include "oh_media_asset_change_request.h"

MediaLibrary_ErrorCode OH_MediaAccessHelper_ApplyChanges(OH_MediaAssetChangeRequest* changeRequest)
{
    CHECK_AND_RETURN_RET_LOG(changeRequest != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "changeRequest is nullptr!");
    CHECK_AND_RETURN_RET_LOG(changeRequest->request_ != nullptr, MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED,
        "request_ is nullptr!");

    return changeRequest->request_->ApplyChanges();
}