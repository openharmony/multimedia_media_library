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

#include "album_change_set_album_name_by_file_vo.h"
#include <sstream>
#include "media_log.h"

namespace OHOS::Media {

bool AlbumChangeSetAlbumNameByFileReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(albumId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(albumName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(albumType);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(albumSubType);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool AlbumChangeSetAlbumNameByFileReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(albumId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(albumName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(albumType);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(albumSubType);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
} // namespace OHOS::Media