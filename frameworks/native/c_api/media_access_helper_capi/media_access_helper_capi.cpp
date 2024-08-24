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
#include "media_asset_change_request_impl.h"

MediaLibrary_ErrorCode OH_MediaAccessHelper_ApplyChanges(OH_MediaAssetChangeRequest* changeRequest)
{
    CHECK_AND_RETURN_RET_LOG(changeRequest != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "changeRequest is nullptr!");

    return changeRequest->ApplyChanges();
}