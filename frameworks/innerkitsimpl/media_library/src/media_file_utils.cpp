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

#include "media_file_utils.h"

#include <regex>

#include "media_lib_service_const.h"
#include "media_log.h"

using namespace std;

namespace OHOS {
namespace Media {
int32_t UnlinkCb(const char *fpath, const struct stat *sb, int32_t typeflag, struct FTW *ftwbuf)
{
    int32_t errRet = remove(fpath);
    if (errRet) {
        perror(fpath);
    }

    return errRet;
}

int32_t RemoveDirectory(const string &path)
{
    int32_t errCode;
    char *dirPath = const_cast<char*>(path.c_str());

    errCode = nftw(dirPath, UnlinkCb, OPEN_FDS, FTW_DEPTH | FTW_PHYS);
    return errCode;
}

void ChangeOwnerToMedia(const string &path)
{
    uid_t usrId;
    gid_t grpId;
    struct passwd *pw = nullptr;
    struct group *grp = nullptr;

    pw = getpwnam(CHOWN_OWNER_NAME.c_str());
    if (pw == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain the user account information");
        return;
    }
    usrId = pw->pw_uid;

    grp = getgrnam(CHOWN_GROUP_NAME.c_str());
    if (grp == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain the group information");
        memset_s(pw, sizeof(struct passwd), 0, sizeof(struct passwd));
        return;
    }
    grpId = grp->gr_gid;

    if (chown(path.c_str(), usrId, grpId) == -1) {
        MEDIA_ERR_LOG("chown failed for the given path");
    }

    memset_s(pw, sizeof(struct passwd), 0, sizeof(struct passwd));
    memset_s(pw, sizeof(struct group), 0, sizeof(struct group));
}

bool MediaFileUtils::CreateDirectory(const string& dirPath)
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
            if (mkdir(folderPath.c_str(), CHOWN_RWX_USR_GRP) == -1) {
                MEDIA_ERR_LOG("Failed to create directory");
                return false;
            }

            ChangeOwnerToMedia(folderPath);
            if (chmod(folderPath.c_str(), CHOWN_RWX_USR_GRP) == -1) {
                MEDIA_ERR_LOG("chmod failed for the newly created directory");
            }
        }
    }

    return true;
}

bool MediaFileUtils::IsFileExists(const string& fileName)
{
    struct stat statInfo {};

    return ((stat(fileName.c_str(), &statInfo)) == SUCCESS);
}

string MediaFileUtils::GetFilename(const string& filePath)
{
    string fileName = "";

    if (!(filePath.empty())) {
        size_t lastSlash = filePath.rfind("/");
        if (lastSlash != string::npos) {
            if (filePath.size() > lastSlash) {
                fileName = filePath.substr(lastSlash + 1, filePath.length() - lastSlash);
            }
        }
    }

    return fileName;
}

bool MediaFileUtils::IsDirectory(const string& dirName)
{
    struct stat statInfo {};
    if (stat(dirName.c_str(), &statInfo) == SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return true;
        }
    }

    return false;
}

bool MediaFileUtils::CreateFile(const string& filePath)
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

    // Change ownership to Media and mode to Read-write user and group
    ChangeOwnerToMedia(filePath);
    if (chmod(filePath.c_str(), CHOWN_RW_USR_GRP) == SUCCESS) {
        errCode = true;
    }

    file.close();

    return errCode;
}

bool MediaFileUtils::DeleteFile(const string& fileName)
{
    return (remove(fileName.c_str()) == SUCCESS);
}

bool MediaFileUtils::DeleteDir(const std::string& dirName)
{
    bool errRet = false;

    if (IsDirectory(dirName)) {
        errRet = (RemoveDirectory(dirName) == SUCCESS);
    }

    return errRet;
}

bool MediaFileUtils::MoveFile(const string& oldPath, const string& newPath)
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
    char actualPath[PATH_MAX];

    auto absFilePath = realpath(filePath.c_str(), actualPath);
    if (absFilePath == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain the canonical path for source path%{public}s %{public}d",
                      filePath.c_str(), errno);
        return errCode;
    }

    int32_t source = open(absFilePath, O_RDONLY);
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
        if (sendfile(dest, source, 0, fst.st_size) != FAIL) {
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

    if (IsFileExists(filePath) == true && !IsFileExists(newPathCorrected)) {
        errCode = true; // set to create file if directory exists
        if (!(IsDirectory(newPath))) {
            errCode = CreateDirectory(newPath);
        }
        if (errCode == true) {
            char actualPath[PATH_MAX];
            char* canonicalDirPath = realpath(newPath.c_str(), actualPath);
            if (canonicalDirPath == nullptr) {
                MEDIA_ERR_LOG("Failed to obtain the canonical path for newpath %{public}s %{public}d",
                              filePath.c_str(), errno);
                return false;
            }
            newPathCorrected = std::string(canonicalDirPath) + "/" + GetFilename(filePath);
            errCode = CopyFileUtil(filePath, newPathCorrected);
        }
    }

    return errCode;
}

bool MediaFileUtils::RenameDir(const string& oldPath, const string& newPath)
{
    bool errRet = false;

    if (IsDirectory(oldPath)) {
        errRet = (rename(oldPath.c_str(), newPath.c_str()) == SUCCESS);
    }

    return errRet;
}
bool MediaFileUtils::CheckDisplayName(std::string displayName)
{
    bool isDisplayName = true;
    int size = displayName.length();
    if (size <= 0 || size > DISPLAYNAME_MAX) {
        return false;
    }
    std::regex express("[\\/:*?\"<>|]");
    bool bValid = !std::regex_search(displayName, express);
    for (int i = 0; i < size; i++) {
        if (displayName.at(0) == '.' || !bValid) {
            MEDIA_ERR_LOG("CheckDisplayName displayName fail");
            isDisplayName = false;
            break;
        }
    }
    return isDisplayName;
}
bool MediaFileUtils::CheckTitle(std::string title)
{
    bool isTitle = true;
    int size = title.length();
    if (size <= 0 || size > DISPLAYNAME_MAX) {
        return false;
    }
    std::regex express("[\\/:*?\"<>|]");
    bool bValid = !std::regex_search(title, express);
    for (int i = 0; i < size; i++) {
        if (title[i] == '.' || !bValid) {
            MEDIA_ERR_LOG("CheckDisplayName title fail");
            isTitle = false;
            break;
        }
    }
    return isTitle;
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
} // namespace Media
} // namespace OHOS
