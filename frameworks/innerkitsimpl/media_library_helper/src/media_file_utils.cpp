/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "FileUtils"

#include "media_file_utils.h"

#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <ftw.h>
#include <regex>
#include <sstream>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

#include "directory_ex.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"

using namespace std;

namespace OHOS {
namespace Media {
static const mode_t CHOWN_RWX_USR_GRP = 02770;
static const mode_t CHOWN_RW_USR_GRP = 0660;
static const size_t DISPLAYNAME_MAX = 255;
const int32_t OPEN_FDS = 64;
constexpr size_t EMPTY_DIR_ENTRY_COUNT = 2;  // Empty dir has 2 entry: . and ..

int32_t UnlinkCb(const char *fpath, const struct stat *sb, int32_t typeflag, struct FTW *ftwbuf)
{
    CHECK_AND_RETURN_RET_LOG(fpath != nullptr, E_FAIL, "fpath == nullptr");
    int32_t errRet = remove(fpath);
    if (errRet) {
        MEDIA_ERR_LOG("Failed to remove path: %{private}s, errno: %{public}d", fpath, errno);
    }

    return errRet;
}

int32_t MediaFileUtils::RemoveDirectory(const string &path)
{
    int32_t errCode;
    char *dirPath = const_cast<char*>(path.c_str());

    errCode = nftw(dirPath, UnlinkCb, OPEN_FDS, FTW_DEPTH | FTW_PHYS);
    return errCode;
}

bool MediaFileUtils::CreateDirectory(const string &dirPath)
{
    string subStr;
    string segment;

    /*  Create directory and its sub directories if does not exist
     *  take each string after '/' create directory if does not exist.
     *  Created directory will be the base path for the next sub directory.
     */

    stringstream folderStream(dirPath.c_str());
    while (std::getline(folderStream, segment, '/')) {
        if (segment == "")    // skip the first "/" in case of "/storage/media/local/files"
            continue;

        subStr = subStr + SLASH_CHAR + segment;
        if (!IsDirectory(subStr)) {
            string folderPath = subStr;
            mode_t mask = umask(0);
            if (mkdir(folderPath.c_str(), CHOWN_RWX_USR_GRP) == -1) {
                MEDIA_ERR_LOG("Failed to create directory %{public}d", errno);
                umask(mask);
                return false;
            }
            umask(mask);
        }
    }

    return true;
}

bool MediaFileUtils::IsFileExists(const string &fileName)
{
    struct stat statInfo {};

    return ((stat(fileName.c_str(), &statInfo)) == SUCCESS);
}

bool MediaFileUtils::IsDirEmpty(const string &path)
{
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        MEDIA_ERR_LOG("Failed to open dir:%{private}s, errno: %{public}d. Just return dir NOT empty.",
            path.c_str(), errno);
        return false;
    }
    struct dirent *ent = nullptr;
    size_t entCount = 0;
    while ((ent = readdir(dir)) != nullptr) {
        if (++entCount > EMPTY_DIR_ENTRY_COUNT) {
            break;
        }
    }
    if (closedir(dir) < 0) {
        MEDIA_ERR_LOG("Fail to closedir: %{private}s, errno: %{public}d.", path.c_str(), errno);
    }
    return (entCount > EMPTY_DIR_ENTRY_COUNT) ? false : true;
}

string MediaFileUtils::GetFilename(const string &filePath)
{
    string fileName = "";

    if (!(filePath.empty())) {
        size_t lastSlash = filePath.rfind("/");
        if (lastSlash != string::npos) {
            if (filePath.size() > (lastSlash + 1)) {
                fileName = filePath.substr(lastSlash + 1, filePath.length() - lastSlash);
            }
        }
    }

    return fileName;
}

bool MediaFileUtils::IsDirectory(const string &dirName)
{
    struct stat statInfo {};
    if (stat(dirName.c_str(), &statInfo) == SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return true;
        }
    }

    return false;
}

bool MediaFileUtils::CreateFile(const string &filePath)
{
    bool errCode = false;

    if (filePath.empty() || IsFileExists(filePath)) {
        return errCode;
    }

    ofstream file(filePath);
    if (!file) {
        MEDIA_ERR_LOG("Output file path could not be created");
        return errCode;
    }

    if (chmod(filePath.c_str(), CHOWN_RW_USR_GRP) == SUCCESS) {
        errCode = true;
    }

    file.close();

    return errCode;
}

bool MediaFileUtils::DeleteFile(const string &fileName)
{
    return (remove(fileName.c_str()) == SUCCESS);
}

bool MediaFileUtils::DeleteDir(const std::string &dirName)
{
    bool errRet = false;

    if (IsDirectory(dirName)) {
        errRet = (RemoveDirectory(dirName) == SUCCESS);
    }

    return errRet;
}

bool MediaFileUtils::MoveFile(const string &oldPath, const string &newPath)
{
    bool errRet = false;

    if (IsFileExists(oldPath) && !IsFileExists(newPath)) {
        errRet = (rename(oldPath.c_str(), newPath.c_str()) == SUCCESS);
    }

    return errRet;
}

bool CopyFileUtil(const string &filePath, const string &newPath)
{
    struct stat fst;
    bool errCode = false;
    if (filePath.size() >= PATH_MAX) {
        MEDIA_ERR_LOG("File path too long %{public}d", static_cast<int>(filePath.size()));
        return errCode;
    }
    MEDIA_INFO_LOG("File path is %{private}s", filePath.c_str());
    std::string absFilePath = "";
    if (!PathToRealPath(filePath, absFilePath)) {
        MEDIA_ERR_LOG("file is not real path, file path: %{private}s", filePath.c_str());
        return errCode;
    }
    if (absFilePath.empty()) {
        MEDIA_ERR_LOG("Failed to obtain the canonical path for source path%{private}s %{public}d",
                      filePath.c_str(), errno);
        return errCode;
    }

    int32_t source = open(absFilePath.c_str(), O_RDONLY);
    if (source == -1) {
        MEDIA_ERR_LOG("Open failed for source file");
        return errCode;
    }

    int32_t dest = open(newPath.c_str(), O_WRONLY | O_CREAT, CHOWN_RWX_USR_GRP);
    if (dest == -1) {
        MEDIA_ERR_LOG("Open failed for destination file %{public}d", errno);
        close(source);
        return errCode;
    }

    if (fstat(source, &fst) == SUCCESS) {
        // Copy file content
        if (sendfile(dest, source, 0, fst.st_size) != E_ERR) {
            // Copy ownership and mode of source file
            if (fchown(dest, fst.st_uid, fst.st_gid) == SUCCESS &&
                fchmod(dest, fst.st_mode) == SUCCESS) {
                errCode = true;
            }
        }
    }

    close(source);
    close(dest);

    return errCode;
}

bool MediaFileUtils::CopyFile(const string &filePath, const string &newPath)
{
    string newPathCorrected;
    bool errCode = false;

    if (!(newPath.empty()) && !(filePath.empty())) {
        newPathCorrected = newPath + "/" + GetFilename(filePath);
    } else {
        MEDIA_ERR_LOG("Src filepath or dest filePath value cannot be empty");
        return false;
    }

    if (IsFileExists(filePath) && !IsFileExists(newPathCorrected)) {
        errCode = true; // set to create file if directory exists
        if (!(IsDirectory(newPath))) {
            errCode = CreateDirectory(newPath);
        }
        if (errCode) {
            string canonicalDirPath = "";
            if (!PathToRealPath(newPath, canonicalDirPath)) {
                MEDIA_ERR_LOG("Failed to obtain the canonical path for newpath %{private}s %{public}d",
                              filePath.c_str(), errno);
                return false;
            }
            newPathCorrected = canonicalDirPath + "/" + GetFilename(filePath);
            errCode = CopyFileUtil(filePath, newPathCorrected);
        }
    }

    return errCode;
}

bool MediaFileUtils::RenameDir(const string &oldPath, const string &newPath)
{
    bool errRet = false;

    if (IsDirectory(oldPath)) {
        errRet = (rename(oldPath.c_str(), newPath.c_str()) == SUCCESS);
        if (!errRet) {
            MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        }
    }

    return errRet;
}

bool MediaFileUtils::CheckDisplayName(const std::string &displayName)
{
    size_t size = displayName.length();
    if (size == 0 || size > DISPLAYNAME_MAX) {
        MEDIA_ERR_LOG("display name size err, size = %{public}zu", size);
        return false;
    }
    std::regex express("[\\\\/:*?\"\'`<>|{}\\[\\]]");
    bool bValid = std::regex_search(displayName, express);
    if ((displayName.at(0) == '.') || bValid) {
        MEDIA_ERR_LOG("CheckDisplayName fail %{private}s", displayName.c_str());
        return false;
    }
    return true;
}

bool MediaFileUtils::CheckTitle(const std::string &title)
{
    size_t size = title.length();
    if (size == 0 || size > DISPLAYNAME_MAX) {
        MEDIA_ERR_LOG("title size err, size = %{public}zu", size);
        return false;
    }
    std::regex express("[\\.\\\\/:*?\"\'`<>|{}\\[\\]]");
    bool bValid = std::regex_search(title, express);
    if (bValid) {
        MEDIA_ERR_LOG("CheckTitle title fail %{private}s", title.c_str());
    }
    return !bValid;
}

int64_t MediaFileUtils::GetAlbumDateModified(const string &albumPath)
{
    struct stat statInfo {};
    if (!albumPath.empty() && stat(albumPath.c_str(), &statInfo) == 0) {
        return (statInfo.st_mtime);
    }
    return 0;
}

int64_t MediaFileUtils::UTCTimeSeconds()
{
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)(t.tv_sec);
}
string MediaFileUtils::GetNetworkIdFromUri(const string &uri)
{
    string networkId;
    if (uri.empty()) {
        return networkId;
    }
    size_t pos = uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX);
    if (pos == string::npos) {
        return networkId;
    }
    string tempUri = uri.substr(MEDIALIBRARY_DATA_ABILITY_PREFIX.length());
    if (tempUri.empty()) {
        return networkId;
    }
    pos = tempUri.find_first_of('/');
    if (pos == 0 || pos == string::npos) {
        return networkId;
    }
    networkId = tempUri.substr(0, pos);
    return networkId;
}

string MediaFileUtils::UpdatePath(const string &path, const string &uri)
{
    string retStr = path;
    MEDIA_INFO_LOG("MediaFileUtils::UpdatePath path = %{private}s, uri = %{private}s", path.c_str(), uri.c_str());
    if (path.empty() || uri.empty()) {
        return retStr;
    }

    string networkId = GetNetworkIdFromUri(uri);
    if (networkId.empty()) {
        MEDIA_INFO_LOG("MediaFileUtils::UpdatePath retStr = %{private}s", retStr.c_str());
        return retStr;
    }

    size_t pos = path.find(MEDIA_DATA_DEVICE_PATH);
    if (pos == string::npos) {
        return retStr;
    }

    string beginStr = path.substr(0, pos);
    if (beginStr.empty()) {
        return retStr;
    }

    string endStr = path.substr(pos + MEDIA_DATA_DEVICE_PATH.length());
    if (endStr.empty()) {
        return retStr;
    }

    retStr = beginStr + networkId + endStr;
    MEDIA_INFO_LOG("MediaFileUtils::UpdatePath retStr = %{private}s", retStr.c_str());
    return retStr;
}

string MediaFileUtils::GetFileMediaTypeUri(int32_t mediaType, const string &networkId)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return uri + MEDIALIBRARY_TYPE_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return uri + MEDIALIBRARY_TYPE_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return uri + MEDIALIBRARY_TYPE_IMAGE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return uri + MEDIALIBRARY_TYPE_FILE_URI;
    }
}

string MediaFileUtils::GetUriByNameAndId(const string &displayName, const string &networkId, int32_t id)
{
    MediaType mediaType = GetMediaType(displayName);
    return MediaFileUtils::GetFileMediaTypeUri(mediaType, networkId) + SLASH_CHAR + to_string(id);
}

MediaType MediaFileUtils::GetMediaType(const std::string &filePath)
{
    MediaType mediaType = MEDIA_TYPE_FILE;

    if (filePath.size() == 0) {
        return MEDIA_TYPE_ALL;
    }

    size_t dotIndex = filePath.rfind('.');
    if (dotIndex != string::npos) {
        string extension = filePath.substr(dotIndex + 1, filePath.length() - dotIndex);
        transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        if (SUPPORTED_AUDIO_FORMATS_SET.find(extension) != SUPPORTED_AUDIO_FORMATS_SET.end()) {
            mediaType = MEDIA_TYPE_AUDIO;
        } else if (SUPPORTED_VIDEO_FORMATS_SET.find(extension) != SUPPORTED_VIDEO_FORMATS_SET.end()) {
            mediaType = MEDIA_TYPE_VIDEO;
        } else if (SUPPORTED_IMAGE_FORMATS_SET.find(extension) != SUPPORTED_IMAGE_FORMATS_SET.end()) {
            mediaType = MEDIA_TYPE_IMAGE;
        } else {
            mediaType = MEDIA_TYPE_FILE;
        }
    }

    return mediaType;
}

string MediaFileUtils::SplitByChar(const string &str, const char split)
{
    size_t splitIndex = str.find_last_of(split);
    return (splitIndex == string::npos) ? ("") : (str.substr(splitIndex + 1));
}

string MediaFileUtils::GetExtensionFromPath(const string &path)
{
    string extension = SplitByChar(path, '.');
    if (!extension.empty()) {
        transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    }
    return extension;
}

int32_t MediaFileUtils::OpenFile(const string &filePath, const string &mode)
{
    int32_t errCode = E_ERR;

    if (filePath.empty() || mode.empty()) {
        MEDIA_ERR_LOG("Invalid open argument! mode: %{public}s, path: %{private}s", mode.c_str(), filePath.c_str());
        return errCode;
    }

    static const unordered_map<string, int32_t> MEDIA_OPEN_MODE_MAP = {
        { MEDIA_FILEMODE_READONLY, O_RDONLY },
        { MEDIA_FILEMODE_WRITEONLY, O_WRONLY },
        { MEDIA_FILEMODE_READWRITE, O_RDWR },
        { MEDIA_FILEMODE_WRITETRUNCATE, O_WRONLY | O_TRUNC },
        { MEDIA_FILEMODE_WRITEAPPEND, O_WRONLY | O_APPEND },
        { MEDIA_FILEMODE_READWRITETRUNCATE, O_RDWR | O_TRUNC },
        { MEDIA_FILEMODE_READWRITEAPPEND, O_RDWR | O_APPEND },
    };
    if (MEDIA_OPEN_MODE_MAP.find(mode) == MEDIA_OPEN_MODE_MAP.end()) {
        return E_ERR;
    }

    if (filePath.size() >= PATH_MAX) {
        MEDIA_ERR_LOG("File path too long %{public}d", (int)filePath.size());
        return errCode;
    }
    string absFilePath;
    if (!PathToRealPath(filePath, absFilePath)) {
        MEDIA_ERR_LOG("file is not real path, file path: %{private}s", filePath.c_str());
        return errCode;
    }
    if (absFilePath.empty()) {
        MEDIA_ERR_LOG("Failed to obtain the canonical path for source path %{public}d %{private}s",
                      errno, filePath.c_str());
        return errCode;
    }
    MEDIA_INFO_LOG("File absFilePath is %{private}s", absFilePath.c_str());
    return open(absFilePath.c_str(), MEDIA_OPEN_MODE_MAP.at(mode));
}
} // namespace Media
} // namespace OHOS
