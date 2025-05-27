/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#ifndef OHOS_MEDIA_ASSETS_CONTROLLER_SERVICE_H
#define OHOS_MEDIA_ASSETS_CONTROLLER_SERVICE_H

#include "message_parcel.h"
#include "medialibrary_business_code.h"
#include "i_media_controller_service.h"
#include "user_define_ipc.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MediaAssetsControllerService : public IPC::IMediaControllerService {
public:
    EXPORT void RemoveFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void RemoveGalleryFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void SaveFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void SaveGalleryFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void CommitEditedAssetOpen(MessageParcel &data, MessageParcel &reply);
    EXPORT void CommitEditedAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void SysTrashPhotos(MessageParcel &data, MessageParcel &reply);
    EXPORT void TrashPhotos(MessageParcel &data, MessageParcel &reply);
    EXPORT void DeletePhotosCompleted(MessageParcel &data, MessageParcel &reply);
    EXPORT void PublicCreateAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void SystemCreateAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void PublicCreateAssetForApp(MessageParcel &data, MessageParcel &reply);
    EXPORT void SystemCreateAssetForApp(MessageParcel &data, MessageParcel &reply);
    EXPORT void CreateAssetForAppWithAlbum(MessageParcel &data, MessageParcel &reply);
    EXPORT void CloneAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void RevertToOriginal(MessageParcel &data, MessageParcel &reply);
public:
    virtual ~MediaAssetsControllerService() = default;
    bool Accept(uint32_t code) override;
    void OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
};
} // namespace OHOS::Media
#endif  // OHOS_MEDIA_ASSETS_CONTROLLER_SERVICE_H