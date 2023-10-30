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

#ifndef OHOS_MEDIA_BACKUP_DEFINES_H
#define OHOS_MEDIA_BACKUP_DEFINES_H

#include <string>
#include <vector>

namespace OHOS {
namespace Media {
constexpr int32_t QUERY_COUNT = 500;
constexpr int32_t CONNECT_SIZE = 10;
constexpr int32_t MILLISECONDS = 1000;
constexpr int32_t GALLERY_HIDDEN_ID = -4;

const std::string ORIGIN_PATH = "/data/storage/el2/backup/restore";
const std::string DOCUMENT_PATH = "/storage/media/local/files/Documents";
const std::string RESTORE_CLOUD_DIR = "/storage/cloud/files/Photo";
const std::string RESTORE_LOCAL_DIR = "/storage/media/local/files/Photo";
const std::string UPDATE_FILE_DIR = "/storage/media/local/files/data";

// DB field for update scene
const std::string GALLERY_LOCAL_MEDIA_ID = "local_media_id";
const std::string GALLERY_FILE_DATA = "_data";
const std::string GALLERY_TITLE = "title";
const std::string GALLERY_DISPLAY_NAME = "_display_name";
const std::string GALLERY_DESCRIPTION = "description";
const std::string GALLERY_IS_FAVORITE = "is_hw_favorite";
const std::string GALLERY_RECYCLED_TIME = "recycledTime";
const std::string GALLERY_FILE_SIZE = "_size";
const std::string GALLERY_DURATION = "duration";
const std::string GALLERY_MEDIA_TYPE = "media_type";
const std::string GALLERY_SHOW_DATE_TOKEN = "showDateToken";
const std::string GALLERY_HEIGHT = "height";
const std::string GALLERY_WIDTH = "width";
const std::string GALLERY_ORIENTATION = "orientation";

struct FileInfo {
    std::string filePath;
    std::string displayName;
    std::string title;
    std::string userComment;
    std::string relativePath;
    int64_t fileSize {0};
    int64_t duration {0};
    int64_t recycledTime {0};
    int32_t hidden {0};
    int32_t isFavorite {0};
    int32_t fileType {0};
    int64_t showDateToken {0};
    int32_t height {0};
    int32_t width {0};
    int64_t dateAdded {0};
    int32_t orientation {0};
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_BACKUP_DEFINES_H
