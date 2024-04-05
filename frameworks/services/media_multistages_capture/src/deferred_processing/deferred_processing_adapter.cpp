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

#define MLOG_TAG "DeferredProcessingAdapter"

#include "deferred_processing_adapter.h"

#ifdef ABILITY_CAMERA_SUPPORT
#include "camera_manager.h"
#endif
#include "ipc_skeleton.h"
#include "media_log.h"
#ifdef ABILITY_CAMERA_SUPPORT
#include "multistages_capture_deferred_proc_session_callback.h"
#endif
using namespace std;
#ifdef ABILITY_CAMERA_SUPPORT
using namespace OHOS::CameraStandard;
#endif

namespace OHOS {
namespace Media {

DeferredProcessingAdapter::DeferredProcessingAdapter()
{
    #ifdef ABILITY_CAMERA_SUPPORT
    const static int32_t INVALID_UID = -1;
    const static int32_t BASE_USER_RANGE = 200000;

    int uid = IPCSkeleton::GetCallingUid();
    if (uid <= INVALID_UID) {
        MEDIA_ERR_LOG("DeferredProcessingAdapter invalid uid: %{public}d", uid);
        return;
    }
    int32_t userId = uid / BASE_USER_RANGE;
    deferredProcSession_ = CameraManager::CreateDeferredPhotoProcessingSession(userId,
        make_shared<MultiStagesCaptureDeferredProcSessionCallback>());
    if (deferredProcSession_ == nullptr) {
        MEDIA_ERR_LOG("CreateDeferredPhotoProcessingSession err");
    }
    #endif
    MEDIA_INFO_LOG("DeferredProcessingAdapter init succ");
}

DeferredProcessingAdapter::~DeferredProcessingAdapter() {}

void DeferredProcessingAdapter::BeginSynchronize()
{
    MEDIA_INFO_LOG("DeferredProcessingAdapter::BeginSynchronize");
    #ifdef ABILITY_CAMERA_SUPPORT
    if (deferredProcSession_ == nullptr) {
        MEDIA_ERR_LOG("BeginSynchronize deferredProcSession_ is nullptr");
        return;
    }
    deferredProcSession_->BeginSynchronize();
    #endif
}

void DeferredProcessingAdapter::EndSynchronize()
{
    MEDIA_INFO_LOG("DeferredProcessingAdapter::EndSynchronize");
    #ifdef ABILITY_CAMERA_SUPPORT
    if (deferredProcSession_ == nullptr) {
        MEDIA_ERR_LOG("EndSynchronize deferredProcSession_ is nullptr");
        return;
    }
    deferredProcSession_->EndSynchronize();
    #endif
}

#ifdef ABILITY_CAMERA_SUPPORT
void DeferredProcessingAdapter::AddImage(const std::string &imageId, DpsMetadata &metadata, const bool isTrashed)
{
    MEDIA_INFO_LOG("enter photoid: %{public}s, isTrashed: %{public}d", imageId.c_str(), isTrashed);
    if (deferredProcSession_ == nullptr) {
        MEDIA_ERR_LOG("AddImage deferredProcSession_ is nullptr");
        return;
    }
    deferredProcSession_->AddImage(imageId, metadata, isTrashed);
}
#endif

void DeferredProcessingAdapter::RemoveImage(const std::string &imageId, bool isRestorable)
{
    MEDIA_INFO_LOG("enter photoid: %{public}s, isRestorable: %{public}d", imageId.c_str(), isRestorable);
    #ifdef ABILITY_CAMERA_SUPPORT
    if (deferredProcSession_ == nullptr) {
        MEDIA_ERR_LOG("RemoveImage deferredProcSession_ is nullptr");
        return;
    }
    deferredProcSession_->RemoveImage(imageId, isRestorable);
    #endif
}

void DeferredProcessingAdapter::RestoreImage(const std::string &imageId)
{
    MEDIA_INFO_LOG("enter photoid: %{public}s", imageId.c_str());
    #ifdef ABILITY_CAMERA_SUPPORT
    if (deferredProcSession_ == nullptr) {
        MEDIA_ERR_LOG("RestoreImage deferredProcSession_ is nullptr");
        return;
    }
    deferredProcSession_->RestoreImage(imageId);
    #endif
}

void DeferredProcessingAdapter::ProcessImage(const std::string &appName, const std::string &imageId)
{
    MEDIA_INFO_LOG("enter appName: %{public}s, photoid: %{public}s", appName.c_str(), imageId.c_str());
    #ifdef ABILITY_CAMERA_SUPPORT
    if (deferredProcSession_ == nullptr) {
        MEDIA_ERR_LOG("ProcessImage deferredProcSession_ is nullptr");
        return;
    }
    deferredProcSession_->ProcessImage(appName, imageId);
    #endif
}

bool DeferredProcessingAdapter::CancelProcessImage(const std::string &imageId)
{
    MEDIA_INFO_LOG("DeferredProcessingAdapter::CancelProcessImage photoid: %{public}s", imageId.c_str());
    #ifdef ABILITY_CAMERA_SUPPORT
    if (deferredProcSession_ == nullptr) {
        MEDIA_ERR_LOG("CancelProcessImage deferredProcSession_ is nullptr");
        return false;
    }
    return deferredProcSession_->CancelProcessImage(imageId);
    #else
    return false;
    #endif
}

} // namespace Media
} // namespace OHOS