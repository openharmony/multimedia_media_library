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
#define MLOG_TAG "PhotoMapCodeColumn"

#include "base_column.h"
#include "media_column.h"
#include "photo_map_code_column.h"
#include <cerrno>
#include <fstream>
#include <iostream>
#include <bitset>
#include <string>
#include <cmath>

namespace OHOS {
namespace Media {
const std::string PhotoMapCodeColumn::MAPCODE_LEVEL_SCALE_NUMBER = "4294967296";
const std::string PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE = "tab_map_photo_map";

const std::string PhotoMapCodeColumn::MAPCODE_FILE_ID = "file_id";

const std::string PhotoMapCodeColumn::MAPCODE_LEVEL_20 = "cell_20int";

const std::string PhotoMapCodeColumn::MAPCODE_LEVEL_4_INDEX = "map_cell_4_index";
const std::string PhotoMapCodeColumn::MAPCODE_LEVEL_20_INDEX = "map_cell_20_index";

const std::string PhotoMapCodeColumn::CREATE_MAP_CODE_TABLE = "CREATE TABLE IF NOT EXISTS " +
  PhotoMapCodeColumn::PHOTOS_MAP_CODE_TABLE + " (" +
  PhotoMapCodeColumn::MAPCODE_FILE_ID + " INTEGER PRIMARY KEY, " +
  PhotoMapCodeColumn::MAPCODE_LEVEL_20 + " BIGINT DEFAULT 0 " +
  ") ";

const std::string PhotoMapCodeColumn::CREATE_MAPCODE_LEVEL_4_INDEX = BaseColumn::CreateIndex() +
    MAPCODE_LEVEL_4_INDEX + " ON " + PHOTOS_MAP_CODE_TABLE + " (" + MAPCODE_LEVEL_20 + "/" +
    MAPCODE_LEVEL_SCALE_NUMBER + " DESC)";
const std::string PhotoMapCodeColumn::CREATE_MAPCODE_LEVEL_20_INDEX = BaseColumn::CreateIndex() +
    MAPCODE_LEVEL_20_INDEX + " ON " + PHOTOS_MAP_CODE_TABLE + " (" + MAPCODE_LEVEL_20 + " DESC)";

const std::string PhotoMapCodeColumn::DROP_MAPCODE_LEVEL_4_INDEX = BaseColumn::DropIndex() + MAPCODE_LEVEL_4_INDEX;
const std::string PhotoMapCodeColumn::DROP_MAPCODE_LEVEL_20_INDEX = BaseColumn::DropIndex() + MAPCODE_LEVEL_20_INDEX;
const std::string PhotoMapCodeColumn::DROP_LONGITUDE_INDEX = BaseColumn::DropIndex() + PhotoColumn::LONGITUDE_INDEX;
const std::string PhotoMapCodeColumn::DROP_LATITUDE_INDEX = BaseColumn::DropIndex() + PhotoColumn::LATITUDE_INDEX;
} // namespace Media
} // namespace OHOS
