/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_CLOUD_SYNC_GET_CHECK_RECORDS_ALBUM_VO_H
#define OHOS_MEDIA_CLOUD_SYNC_GET_CHECK_RECORDS_ALBUM_VO_H

#include <string>
#include <vector>
#include <sstream>

#include "i_media_parcelable.h"
#include "media_itypes_utils.h"
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
class EXPORT GetCheckRecordAlbumData : public IPC::IMediaParcelable {
public:
    std::string recordId;
    bool isDelete;

public:  // functions of Parcelable.
    virtual ~GetCheckRecordAlbumData() = default;
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;

public:  // basic functions
    std::string ToString() const;
};
class EXPORT GetCheckRecordsAlbumReqBody : public IPC::IMediaParcelable {
public:
    std::vector<std::string> cloudIds;

public:
    bool AddCheckAlbumsRecords(std::string &cloudId);

public:  // functions of Parcelable.
    virtual ~GetCheckRecordsAlbumReqBody() = default;
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;

public:  // basic functions
    std::string ToString() const;
};

class EXPORT CheckDataAlbum : public IPC::IMediaParcelable {
public:
    std::string cloudId;
    int64_t size;             // 原文件大小
    std::string data;         // 原文件路径
    std::string displayName;  // 原文件名称
    int32_t mediaType;        // 原文件类型（图片/视频）, 1:图片, 2:视频
    int32_t cloudVersion;     // 本地记录云端版本
    int32_t position;         // 本地数据库记录文件位置
    int64_t dateModified;
    int32_t dirty;

public:  // functions of Parcelable.
    virtual ~CheckDataAlbum() = default;
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;

public:  // basic functions
    std::string ToString() const;
};

class EXPORT GetCheckRecordsAlbumRespBody : public IPC::IMediaParcelable {
public:
    std::unordered_map<std::string, CheckDataAlbum> checkDataAlbumList;

public:  // functions of Parcelable.
    virtual ~GetCheckRecordsAlbumRespBody() = default;
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;

public:  // basic functions
    std::string ToString() const;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_GET_CHECK_RECORDS_ALBUM_VO_H