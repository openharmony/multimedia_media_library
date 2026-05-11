/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
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

#ifndef MEDIA_ALBUMS_MANAGER_INCLUDE_VO_ALBUM_CHANGE_SET_HIDDEN_ATTRIBUTE_VO_H_
#define MEDIA_ALBUMS_MANAGER_INCLUDE_VO_ALBUM_CHANGE_SET_HIDDEN_ATTRIBUTE_VO_H_

#include <string>
#include "message_parcel.h"

namespace OHOS::Media {

struct AlbumChangeSetHiddenAttributeReqBody {
    int32_t albumId = 0;
    bool fileHidden = false;
    bool inherited = false;
    int32_t albumType {-1};
    int32_t albumSubType {-1};

    bool Marshalling(MessageParcel &parcel) const;
    bool Unmarshalling(MessageParcel &parcel);
};

} // namespace OHOS::Media

#endif // MEDIA_ALBUMS_MANAGER_INCLUDE_VO_ALBUM_CHANGE_SET_HIDDEN_ATTRIBUTE_VO_H_