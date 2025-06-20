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

#ifndef OHOS_MEDIA_ASSETS_MANAGER_SET_PHOTO_ALBUM_ORDER_DTO_H
#define OHOS_MEDIA_ASSETS_MANAGER_SET_PHOTO_ALBUM_ORDER_DTO_H

#include <string>
#include <sstream>

namespace OHOS::Media {
class SetPhotoAlbumOrderDto {
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
public:
    bool CheckArray() const;
    std::string ToString() const;
};
}  // namespace OHOS::Media
#endif // OHOS_MEDIA_ASSETS_MANAGER_SET_PHOTO_ALBUM_ORDER_DTO_H