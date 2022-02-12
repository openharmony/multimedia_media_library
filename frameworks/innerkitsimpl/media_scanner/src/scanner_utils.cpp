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

#include "scanner_utils.h"
#include <cerrno>

namespace OHOS {
namespace Media {
using namespace std;
// Check if file exists or not
bool ScannerUtils::IsExists(const string &path)
{
    struct stat statInfo {};

    if (path.empty()) {
        return false;
    }

    return ((stat(path.c_str(), &statInfo)) == ERR_SUCCESS);
}

// Get the file name from file URI
string ScannerUtils::GetFileNameFromUri(const string &path)
{
    if (!path.empty()) {
        size_t lastSlashPosition = path.rfind("/");
        if (lastSlashPosition != string::npos) {
            if (path.size() > lastSlashPosition) {
                return path.substr(lastSlashPosition + 1);
            }
        }
    }

    return "";
}

// Get file extension from the given filepath uri
string ScannerUtils::GetFileExtensionFromFileUri(const string &path)
{
    if (!path.empty()) {
        size_t dotIndex = path.rfind(".");
        if (dotIndex != string::npos) {
            return path.substr(dotIndex + 1);
        }
    }

    return "";
}

MediaType ScannerUtils::GetMediatypeFromMimetype(const string &mimetype)
{
    MediaType mediaType = MEDIA_TYPE_FILE;

    if (!mimetype.empty()) {
        if (mimetype == DEFAULT_AUDIO_MIME_TYPE) {
            mediaType = MEDIA_TYPE_AUDIO;
        } else if (mimetype == DEFAULT_VIDEO_MIME_TYPE) {
            mediaType = MEDIA_TYPE_VIDEO;
        } else if (mimetype == DEFAULT_IMAGE_MIME_TYPE) {
            mediaType = MEDIA_TYPE_IMAGE;
        }
    }

    return mediaType;
}

// Obtain Mime type from the file extension
string ScannerUtils::GetMimeTypeFromExtension(const string &extension)
{
    string mimeType = DEFAULT_FILE_MIME_TYPE;
    string extn = extension;

    if (extn.empty()) {
        return mimeType;
    }

    transform(extn.begin(), extn.end(), extn.begin(), ::tolower);
    if (SUPPORTED_AUDIO_FORMATS_SET.find(extn) != SUPPORTED_AUDIO_FORMATS_SET.end()) {
        mimeType = DEFAULT_AUDIO_MIME_TYPE;
    } else if (SUPPORTED_VIDEO_FORMATS_SET.find(extn) != SUPPORTED_VIDEO_FORMATS_SET.end()) {
        mimeType = DEFAULT_VIDEO_MIME_TYPE;
    } else if (SUPPORTED_IMAGE_FORMATS_SET.find(extn) != SUPPORTED_IMAGE_FORMATS_SET.end()) {
        mimeType = DEFAULT_IMAGE_MIME_TYPE;
    }

    return mimeType;
}

// Check if the given path is a directory path
bool ScannerUtils::IsDirectory(const string &path)
{
    struct stat s;

    if (!path.empty()) {
        if (stat(path.c_str(), &s) == 0) {
            if (s.st_mode & S_IFDIR) {
                return true;
            }
        }
    }

    return false;
}

// Check if the given file starts with '.' , i.e. if it is hidden
bool ScannerUtils::IsFileHidden(const string &path)
{
    if (!path.empty()) {
        string fileName = GetFileNameFromUri(path);
        if (fileName.at(0) == '.') {
            return true;
        }
    }

    return false;
}

// Get the parent path
string ScannerUtils::GetParentPath(const string &path)
{
    if (!path.empty()) {
        size_t lastSlashPosition = path.rfind("/");
        if (lastSlashPosition != string::npos && path.size() > lastSlashPosition) {
            return path.substr(0, lastSlashPosition);
        }
    }

    return "";
}

// Get the absolute path from the given path
int32_t ScannerUtils::GetAbsolutePath(string &path)
{
    int32_t errCode = ERR_EMPTY_ARGS;

    if (path.empty() || path.length() > PATH_MAX) {
        MEDIA_ERR_LOG("Src path is too long or empty");
        return ERR_INCORRECT_PATH;
    }

    char actualPath[PATH_MAX] = { 0x00 };
    auto ptr = realpath(path.c_str(), actualPath);
    if (ptr != nullptr) {
        path = ptr;
        errCode = ERR_SUCCESS;
    } else {
        MEDIA_ERR_LOG("Failed to obtain the canonical path for source path %{public}s %{public}d",
                      path.c_str(), errno);
        errCode = ERR_INCORRECT_PATH;
    }

    return errCode;
}

int32_t ScannerUtils::GetRootMediaDir(string &dir, int32_t &len)
{
    dir = ROOT_MEDIA_DIR;
    len = dir.length();

    return ERR_SUCCESS;
}

string ScannerUtils::GetFileTitle(const string& displayName)
{
    string title = "";
    if (!displayName.empty()) {
        string::size_type pos = displayName.find_first_of('.');
        if (pos == displayName.length()) {
            return displayName;
        }
        title = displayName.substr(0, pos);
    }
    return title;
}
} // namespace Media
} // namespace OHOS
