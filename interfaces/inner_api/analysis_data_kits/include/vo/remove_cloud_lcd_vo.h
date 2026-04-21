/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ALBUMS_MANAGER_REMOVE_CLOUD_LCD_VO_H
#define OHOS_MEDIA_ALBUMS_MANAGER_REMOVE_CLOUD_LCD_VO_H

#include <string>
#include <vector>
#include <sstream>
#include <unordered_map>

#include "media_itypes_utils.h"
#include "i_media_parcelable.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT RemoveCloudLcdReqBody : public IPC::IMediaParcelable {
public:
    std::vector<int64_t> fileIds;

public:
    virtual ~RemoveCloudLcdReqBody() = default;
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;

public:
    std::string ToString() const;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_ALBUMS_MANAGER_REMOVE_CLOUD_LCD_VO_H