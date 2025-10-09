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

#ifndef MULTISTAGES_CAPTURE_DEFERRED_PHOTO_PROC_SESSION_CALLBACK_H
#define MULTISTAGES_CAPTURE_DEFERRED_PHOTO_PROC_SESSION_CALLBACK_H

#ifdef ABILITY_CAMERA_SUPPORT
#include <memory>
#include <string>

#include "deferred_photo_proc_session.h"
#include "result_set_utils.h"
#include "medialibrary_command.h"

namespace OHOS {
namespace Media {
class Picture;
#define EXPORT __attribute__ ((visibility ("default")))
using ProcessDoneHandler = std::function<void(bool, const std::string &)>;
class MultiStagesCaptureDeferredPhotoProcSessionCallback : public CameraStandard::IDeferredPhotoProcSessionCallback {
public:
    EXPORT MultiStagesCaptureDeferredPhotoProcSessionCallback();
    EXPORT ~MultiStagesCaptureDeferredPhotoProcSessionCallback();

    void OnProcessImageDone(const std::string &imageId, const uint8_t *addr, const long bytes,
        uint32_t cloudImageEnhanceFlag) override;
    void OnProcessImageDone(const std::string &imageId, std::shared_ptr<CameraStandard::PictureIntf> picture,
        uint32_t cloudImageEnhanceFlag) override;
    void OnDeliveryLowQualityImage(const std::string &imageId,
        std::shared_ptr<CameraStandard::PictureIntf> picture) override;
    EXPORT void OnError(const std::string &imageId, const CameraStandard::DpsErrorCode error) override;
    void OnStateChanged(const CameraStandard::DpsStatusCode state) override;

    void SetProcessImageDoneCallback(const ProcessDoneHandler &func);

private:
    EXPORT int32_t UpdatePhotoQuality(const std::string &photoId);
    EXPORT void UpdatePhotoQuality(const int32_t &fileId, NativeRdb::ValuesBucket &updateValues);
    EXPORT void UpdateCEAvailable(const int32_t &fileId, uint32_t cloudImageEnhanceFlag,
        NativeRdb::ValuesBucket &updateValues, int32_t modifyType = 0);
    EXPORT void GetCommandByImageId(const std::string &imageId, MediaLibraryCommand &cmd);
    EXPORT void UpdateHighQualityPictureInfo(const int32_t &fileId, uint32_t cloudImageEnhanceFlag,
         int32_t modifyType = 0);
    EXPORT void NotifyIfTempFile(std::shared_ptr<NativeRdb::ResultSet> resultSet, bool isError = false);
    EXPORT void ProcessAndSaveHighQualityImage(const std::string& imageId, std::shared_ptr<Media::Picture> picture,
        std::shared_ptr<NativeRdb::ResultSet> resultSet, uint32_t cloudImageEnhanceFlag, int32_t modifyType = 0);
    void CallProcessImageDone(bool success, const std::string &photoId);

private:
    ProcessDoneHandler processDoneCallback_;
};
} // namespace Media
} // namespace OHOS
#endif
#endif  // MULTISTAGES_CAPTURE_DEFERRED_PHOTO_PROC_SESSION_CALLBACK_H