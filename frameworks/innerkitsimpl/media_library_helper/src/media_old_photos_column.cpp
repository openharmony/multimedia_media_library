/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_old_photos_column.h"

namespace OHOS {
namespace Media {

const std::string TabOldPhotosColumn::OLD_PHOTOS_TABLE = "tab_old_photos";

const std::string TabOldPhotosColumn::MEDIA_ID = "file_id";
const std::string TabOldPhotosColumn::MEDIA_FILE_PATH = "data";
const std::string TabOldPhotosColumn::MEDIA_OLD_ID = "old_file_id";
const std::string TabOldPhotosColumn::MEDIA_OLD_FILE_PATH = "old_data";
const std::string TabOldPhotosColumn::MEDIA_CLONE_SEQUENCE = "clone_sequence";

const std::set<std::string> TabOldPhotosColumn::DEFAULT_TAB_OLD_PHOTOS_COLUMNS = {
    MEDIA_ID, MEDIA_FILE_PATH, MEDIA_OLD_ID, MEDIA_OLD_FILE_PATH, MEDIA_CLONE_SEQUENCE
};

} // namespace Media
} // namespace OHOS