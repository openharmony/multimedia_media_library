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

#ifndef OHOS_MEDIA_ASSETS_MANAGER_GET_URIS_BY_OLD_URIS_INNER_VO_H
#define OHOS_MEDIA_ASSETS_MANAGER_GET_URIS_BY_OLD_URIS_INNER_VO_H

#include <string>
#include "i_media_parcelable.h"
#include "get_uris_by_old_uris_inner_dto.h"

namespace OHOS::Media {
class GetUrisByOldUrisInnerReqBody : public IPC::IMediaParcelable {
public:
    std::vector<std::string> uris{};
    std::vector<std::string> columns{};
public:  // functions of Parcelable.
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;
public:
    void Convert2Dto(GetUrisByOldUrisInnerDto &dto);
};

class GetUrisByOldUrisInnerRspBody : public IPC::IMediaParcelable {
public:
    std::vector<int32_t> fileIds{};
    std::vector<std::string> datas{};
    std::vector<std::string> displayNames{};
    std::vector<int32_t> oldFileIds{};
    std::vector<std::string> oldDatas{};
public:  // functions of Parcelable.
    bool Unmarshalling(MessageParcel &parcel) override;
    bool Marshalling(MessageParcel &parcel) const override;
public:
    void InitByDto(const GetUrisByOldUrisInnerDto &dto);
};
} // namespace OHOS::Media
#endif // OHOS_MEDIA_ASSETS_MANAGER_GET_URIS_BY_OLD_URIS_INNER_VO_H