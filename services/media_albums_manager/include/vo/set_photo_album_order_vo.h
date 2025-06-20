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

#ifndef OHOS_MEDIA_ALBUMS_MANAGER_SET_PHOTO_ALBUM_ORDER_VO_H
#define OHOS_MEDIA_ALBUMS_MANAGER_SET_PHOTO_ALBUM_ORDER_VO_H

#include <string>
#include <sstream>
#include <vector>

#include "album_order.h"
#include "i_media_parcelable.h"

namespace OHOS::Media {
class SetPhotoAlbumOrderReqBody : public IPC::IMediaParcelable {
public:
    std::string albumOrderColumn;
    std::string orderSectionColumn;
    std::string orderTypeColumn;
    std::string orderStatusColumn;

    std::vector<int32_t> albumIds;
    std::vector<int32_t> albumOrders;
    std::vector<int32_t> orderSection;
    std::vector<int32_t> orderType;
    std::vector<int32_t> orderStatus;

public:  // functions of Parcelable.
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;
};
} // namespace OHOS::Media
#endif // OHOS_MEDIA_ALBUMS_MANAGER_SET_PHOTO_ALBUM_ORDER_VO_H