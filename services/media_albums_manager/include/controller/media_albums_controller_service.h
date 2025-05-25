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

#ifndef OHOS_MEDIA_ALBUMS_CONTROLLER_SERVICE_H
#define OHOS_MEDIA_ALBUMS_CONTROLLER_SERVICE_H

#include "message_parcel.h"
#include "medialibrary_business_code.h"
#include "i_media_controller_service.h"
#include "user_define_ipc.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MediaAlbumsControllerService : public IPC::IMediaControllerService {
public:
    EXPORT void DeleteHighlightAlbums(MessageParcel &data, MessageParcel &reply);
    EXPORT void DeletePhotoAlbums(MessageParcel &data, MessageParcel &reply);
    EXPORT void CreatePhotoAlbum(MessageParcel &data, MessageParcel &reply);
public:
    virtual ~MediaAlbumsControllerService() = default;
    bool Accept(uint32_t code) override;
    void OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
};
} // namespace OHOS::Media
#endif  // OHOS_MEDIA_ALBUMS_CONTROLLER_SERVICE_H