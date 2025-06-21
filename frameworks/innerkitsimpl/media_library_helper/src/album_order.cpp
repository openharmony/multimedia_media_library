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
#define MLOG_TAG "AlbumOrder"

#include "album_order.h"
#include "photo_album_column.h"

#include "medialibrary_type_const.h"

using namespace std;

namespace OHOS {
namespace Media {
AlbumOrder::AlbumOrder()
{
    albumId_ = DEFAULT_ALBUM_ID;
    albumOrder_ = DEFAULT_ALBUMS_ORDER;
    orderSection_ = DEFAULT_ORDER_SECTION;
    orderType_ = DEFAULT_ORDER_TYPE;
    orderStatus_ = DEFAULT_ORDER_STATUS;
}

AlbumOrder::~AlbumOrder() = default;

void AlbumOrder::SetAlbumId(const int32_t albumId)
{
    albumId_ = albumId;
}

int32_t AlbumOrder::GetAlbumId() const
{
    return albumId_;
}

void AlbumOrder::SetAlbumOrder(const int32_t albumOrder)
{
    albumOrder_ = albumOrder;
}

int32_t AlbumOrder::GetAlbumOrder() const
{
    return albumOrder_;
}

void AlbumOrder::SetOrderSection(const int32_t orderSection)
{
    orderSection_ = orderSection;
}

int32_t AlbumOrder::GetOrderSection() const
{
    return orderSection_;
}

void AlbumOrder::SetOrderType(const int32_t orderType)
{
    orderType_ = orderType;
}

int32_t AlbumOrder::GetOrderType() const
{
    return orderType_;
}

void AlbumOrder::SetOrderStatus(const int32_t orderStatus)
{
    orderStatus_ = orderStatus;
}

int32_t AlbumOrder::GetOrderStatus() const
{
    return orderStatus_;
}

void AlbumOrder::SetResultNapiType(const ResultNapiType resultNapiType)
{
    resultNapiType_ = resultNapiType;
}

ResultNapiType AlbumOrder::GetResultNapiType() const
{
    return resultNapiType_;
}

bool AlbumOrder::IsAlbumOrderColumn(OrderStyleType orderStyle, const string &columnName)
{
    if (orderStyle == OrderStyleType::MIX) {
        return PhotoAlbumColumns::DEFAULT_FETCH_ORDER_COLUMNS_STYLE1.find(columnName) !=
            PhotoAlbumColumns::DEFAULT_FETCH_ORDER_COLUMNS_STYLE1.end();
    }
    return PhotoAlbumColumns::DEFAULT_FETCH_ORDER_COLUMNS_STYLE2.find(columnName) !=
        PhotoAlbumColumns::DEFAULT_FETCH_ORDER_COLUMNS_STYLE2.end();
}
}  // namespace Media
}  // namespace OHOS