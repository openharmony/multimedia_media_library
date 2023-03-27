/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "photo_map_column.h"

using namespace std;

namespace OHOS::Media {
const string &PhotoMap::GetTable()
{
    static const string TABLE = "PhotoMap";
    return TABLE;
}

const string &PhotoMap::GetAlbumId()
{
    static const string ALBUM_ID = "map_album";
    return ALBUM_ID;
}

const string &PhotoMap::GetAssetId()
{
    static const string ASSET_ID = "map_asset";
    return ASSET_ID;
}

const string PhotoMap::CREATE_TABLE = CreateTable() + GetTable() +
    " (" +
    GetAlbumId() + " INT, " +
    GetAssetId() + " INT, " +
    "PRIMARY KEY (" + GetAlbumId() + "," + GetAssetId() + ")" +
    ")";
} // namespace OHOS::Media
