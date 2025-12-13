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

#ifndef OHOS_MEDIA_ASSETS_GET_FUSSION_ASSETS_VO_H
#define OHOS_MEDIA_ASSETS_GET_FUSSION_ASSETS_VO_H

#include <string>
#include <vector>

#include "i_media_parcelable.h"

namespace OHOS::Media {
class FussionAssetsResult : public IPC::IMediaParcelable {
public:
    int32_t assetsType;
    int32_t assetsCount;
    std::string assetsPath;

    FussionAssetsResult() : assetsType(0), assetsCount(0), assetsPath("") {}
    explicit FussionAssetsResult(int32_t type, int32_t count, const std::string &path)
        : assetsType(type), assetsCount(count), assetsPath(path) {}
public:  // functions of Parcelable.
    virtual ~FussionAssetsResult() = default;
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;
};

class GetFussionAssetsReqBody : public IPC::IMediaParcelable {
public:
    int32_t albumId;
    int32_t albumType {-1};
public:  // functions of Parcelable.
    virtual ~GetFussionAssetsReqBody() = default;
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;

public:  // basic functions
    std::string ToString() const;
};

class GetFussionAssetsRespBody : public IPC::IMediaParcelable {
public:
    std::vector<FussionAssetsResult> queryResult;
public:  // functions of Parcelable.
    virtual ~GetFussionAssetsRespBody() = default;
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;
};
} // namespace OHOS::Media
#endif // OHOS_MEDIA_ASSETS_GET_FUSSION_ASSETS_VO_H