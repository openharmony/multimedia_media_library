/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_ALBUM_ORDER_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_ALBUM_ORDER_H_

#include <memory>
#include <string>
#include <vector>
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
using namespace std;

enum AlbumOrderParam: int32_t {
    ALBUM_ORDER,
    ORDER_SECTION,
    ORDER_TYPE,
    ORDER_STATUS
};

class AlbumOrder {
public:
    EXPORT AlbumOrder();
    EXPORT virtual ~AlbumOrder();

    EXPORT void SetAlbumId(const int32_t albumId);
    EXPORT int32_t GetAlbumId() const;

    EXPORT void SetAlbumOrder(const int32_t albumOrder);
    EXPORT int32_t GetAlbumOrder() const;
    
    EXPORT void SetOrderSection(const int32_t orderSection);
    EXPORT int32_t GetOrderSection() const;
    
    EXPORT void SetOrderType(const int32_t orderType);
    EXPORT int32_t GetOrderType() const;

    EXPORT void SetOrderStatus(const int32_t orderStatus);
    EXPORT int32_t GetOrderStatus() const;

    EXPORT void SetResultNapiType(const ResultNapiType resultNapiType);
    EXPORT ResultNapiType GetResultNapiType() const;

    EXPORT static bool IsAlbumOrderColumn(OrderStyleType orderStyle, const string &columnName);

private:
    int32_t albumId_;
    int32_t albumOrder_;
    int32_t orderSection_;
    int32_t orderType_;
    int32_t orderStatus_;

    ResultNapiType resultNapiType_ = ResultNapiType::TYPE_MEDIALIBRARY;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_PHOTO_ALBUM_ASSET_H_
