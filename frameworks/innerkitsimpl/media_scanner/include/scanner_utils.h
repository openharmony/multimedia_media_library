/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef SCANNER_UTILS_H
#define SCANNER_UTILS_H

#include <string>
#include <unordered_set>
#include <vector>
#include <sys/stat.h>

#include "media_lib_service_const.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
enum ErrorCodes {
    ERR_FAIL = -1,
    ERR_SUCCESS,
    ERR_EMPTY_ARGS,
    ERR_NOT_ACCESSIBLE,
    ERR_INCORRECT_PATH,
    ERR_MEM_ALLOC_FAIL,
    ERR_MIMETYPE_NOTSUPPORT,
    ERR_SCAN_NOT_INIT
};

const std::string ROOT_PATH = "";
const int32_t MAX_PATH_LENGTH = 200;
const int32_t MAX_BATCH_SIZE = 5;

// Const for File Metadata defaults
const std::string FILE_PATH_DEFAULT = "";
const std::string FILE_NAME_DEFAULT = "Unknown";
const int64_t FILE_SIZE_DEFAULT = 0;
const std::string URI_DEFAULT = "";
const int64_t FILE_DATE_ADDED_DEFAULT = 0;
const int64_t FILE_DATE_MODIFIED_DEFAULT = 0;
const MediaType FILE_MEDIA_TYPE_DEFAULT = MEDIA_TYPE_FILE;
const int32_t FILE_ID_DEFAULT = -1;
const std::string FILE_EXTENSION_DEFAULT = "";

const int32_t FILE_DURATION_DEFAULT = 0;
const std::string FILE_TITLE_DEFAULT = "Unknown";
const std::string FILE_ARTIST_DEFAULT = "Unknown";
const int32_t FILE_HEIGHT_DEFAULT = 0;
const int32_t FILE_WIDTH_DEFAULT = 0;
const int32_t FILE_ALBUM_ID_DEFAULT = 0;
const std::string FILE_ALBUM_NAME_DEFAULT = "Unknown";
const int32_t FILE_ORIENTATION_DEFAULT = 0;
const std::string FILE_RELATIVE_PATH_DEFAULT = "Unknown";

const std::string DEFAULT_AUDIO_MIME_TYPE = "audio/*";
const std::string DEFAULT_VIDEO_MIME_TYPE = "video/*";
const std::string DEFAULT_IMAGE_MIME_TYPE = "image/*";
const std::string DEFAULT_FILE_MIME_TYPE = "file/*";

class ScannerUtils {
public:
    ScannerUtils();
    ~ScannerUtils();

    static bool IsExists(const std::string &path);
    static std::string GetFileNameFromUri(const std::string &path);
    static std::string GetFileExtensionFromFileUri(const std::string &path);
    static std::string GetMimeTypeFromExtension(const std::string &extension);
    static int32_t GetAbsolutePath(std::string &path);
    static std::string GetParentPath(const std::string &path);
    static bool IsFileHidden(const std::string &path);
    static bool IsDirectory(const std::string &path);
    static MediaType GetMediatypeFromMimetype(const std::string &mimetype);
};
} // namespace Media
} // namespace OHOS

#endif // SCANNER_UTILS_H
