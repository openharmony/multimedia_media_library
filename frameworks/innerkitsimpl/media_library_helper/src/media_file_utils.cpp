/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <ftw.h>
#include <regex>
#include <securec.h>
#include <sstream>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

#include "avmetadatahelper.h"
#include "directory_ex.h"
#include "hmdfs.h"
#include "ipc_skeleton.h"
#include "media_column.h"
#include "media_file_uri.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "mimetype_utils.h"
#include "medialibrary_tracer.h"
#include "string_ex.h"

using namespace std;

namespace OHOS::Media {
static const mode_t CHOWN_RWX_USR_GRP = 02771;
static const mode_t CHOWN_RW_USR_GRP = 0660;
constexpr size_t DISPLAYNAME_MAX = 255;
const int32_t OPEN_FDS = 64;
const std::string PATH_PARA = "path=";
constexpr size_t EMPTY_DIR_ENTRY_COUNT = 2;  // Empty dir has 2 entry: . and ..
constexpr size_t DEFAULT_TIME_SIZE = 32;

static const std::unordered_map<std::string, std::vector<std::string>> MEDIA_MIME_TYPE_MAP = {
    { "application/epub+zip", { "epub" } },
    { "application/lrc", { "lrc"} },
    { "application/pkix-cert", { "cer" } },
    { "application/rss+xml", { "rss" } },
    { "application/sdp", { "sdp" } },
    { "application/smil+xml", { "smil" } },
    { "application/ttml+xml", { "ttml", "dfxp" } },
    { "application/vnd.ms-pki.stl", { "stl" } },
    { "application/vnd.ms-powerpoint", { "pot", "ppt" } },
    { "application/vnd.ms-wpl", { "wpl" } },
    { "application/vnd.stardivision.writer", { "vor" } },
    { "application/vnd.youtube.yt", { "yt" } },
    { "application/x-font", { "pcf" } },
    { "application/x-mobipocket-ebook", { "prc", "mobi" } },
    { "application/x-pem-file", { "pem" } },
    { "application/x-pkcs12", { "p12", "pfx" } },
    { "application/x-subrip", { "srt" } },
    { "application/x-webarchive", { "webarchive" } },
    { "application/x-webarchive-xml", { "webarchivexml" } },
    { "application/pgp-signature", { "pgp" } },
    { "application/x-x509-ca-cert", { "crt", "der" } },
    { "application/json", { "json" } },
    { "application/javascript", { "js" } },
    { "application/zip", { "zip" } },
    { "application/rar", { "rar" } },
    { "application/pdf", { "pdf" } },
    { "application/msword", { "doc" } },
    { "application/ms-excel", { "xls" } },
    { "application/vnd.openxmlformats-officedocument.wordprocessingml.document", { "docx" } },
    { "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", { "xlsx" } },
    { "application/vnd.openxmlformats-officedocument.presentationml.presentation", { "pptx" } },
    { "audio/3gpp", { "3ga" } },
    { "audio/ac3", { "ac3", "a52"} },
    { "audio/amr", { "amr" } },
    { "audio/imelody", { "imy" } },
    { "audio/midi", { "rtttl", "xmf", "rtx" } },
    { "audio/mobile-xmf", { "mxmf"} },
    { "audio/mp4", { "m4a", "m4b", "m4p", "f4a", "f4b", "f4p" } },
    { "audio/mpegurl", { "m3u" } },
    { "audio/sp-midi", { "smf" } },
    { "audio/x-matroska", { "mka" } },
    { "audio/x-pn-realaudio", { "ra" } },
    { "audio/x-mpeg", { "mp3" } },
    { "audio/aac", { "aac", "adts", "adt" } },
    { "audio/basic", { "snd" } },
    { "audio/flac", { "flac" } },
    { "audio/mpeg", { "mp3", "mp2", "mp1", "mpa", "m4r" } },
    { "audio/wav", { "wav" } },
    { "audio/ogg", { "ogg" } },
    { "image/gif", { "gif"} },
    { "image/heic", { "heic" } },
    { "image/heic-sequence", { "heics", "heifs" } },
    { "image/bmp", { "bmp", "bm" } },
    { "image/heif", { "heif", "hif" } },
    { "image/avif", { "avif" } },
    { "image/ico", { "cur" } },
    { "image/webp", { "webp"} },
    { "image/x-adobe-dng", { "dng" } },
    { "image/x-fuji-raf", { "raf" } },
    { "image/x-icon", { "ico" } },
    { "image/x-nikon-nrw", { "nrw" } },
    { "image/x-panasonic-rw2", { "rw2" } },
    { "image/x-pentax-pef", { "pef" } },
    { "image/x-samsung-srw", { "srw" } },
    { "image/x-sony-arw", { "arw" } },
    { "image/jpeg", { "jpg", "jpeg", "jpe" } },
    { "image/png", { "png" } },
    { "image/svg+xml", { "svg" } },
    { "image/x-dcraw", { "raw" } },
    { "video/3gpp2", { "3gpp2", "3gp2", "3g2" } },
    { "video/3gpp", { "3gpp", "3gp" } },
    { "video/mp4", { "m4v", "f4v", "mp4v", "mpeg4", "mp4" }},
    { "video/mp2t", { "m2ts", "mts"} },
    { "video/mp2ts", { "ts" } },
    { "video/vnd.youtube.yt", { "yt" } },
    { "video/x-webex", { "wrf" } },
    { "video/mpeg", { "mpeg", "mpeg2", "mpv2", "mp2v", "m2v", "m2t", "mpeg1", "mpv1", "mp1v", "m1v", "mpg" } },
    { "video/quicktime", { "mov" } },
    { "video/x-matroska", { "mkv" } },
    { "video/webm", { "webm" } },
    { "video/H264", { "h264" } },
    { "text/comma-separated-values", { "csv" } },
    { "text/plain", { "diff", "po", "txt" } },
    { "text/rtf", { "rtf" } },
    { "text/text", { "phps", "m3u", "m3u8" } },
    { "text/xml", { "xml" } },
    { "text/x-vcard", { "vcf" } },
    { "text/x-c++hdr", { "hpp", "h++", "hxx", "hh" } },
    { "text/x-c++src", { "cpp", "c++", "cxx", "cc" } },
    { "text/css", { "css" } },
    { "text/html", { "html", "htm", "shtml"} },
    { "text/markdown", { "md", "markdown" } },
    { "text/x-java", { "java" } },
    { "text/x-python", { "py" } }
};

int32_t UnlinkCb(const char *fpath, const struct stat *sb, int32_t typeflag, struct FTW *ftwbuf)
{
    CHECK_AND_RETURN_RET_LOG(fpath != nullptr, E_FAIL, "fpath == nullptr");
    int32_t errRet = remove(fpath);
    if (errRet) {
        MEDIA_ERR_LOG("Failed to remove errno: %{public}d, path: %{private}s", errno, fpath);
    }

    return errRet;
}

int32_t MediaFileUtils::RemoveDirectory(const string &path)
{
    return nftw(path.c_str(), UnlinkCb, OPEN_FDS, FTW_DEPTH | FTW_PHYS);
}

bool MediaFileUtils::Mkdir(const string &subStr, shared_ptr<int> errCodePtr)
{
    mode_t mask = umask(0);
    if (mkdir(subStr.c_str(), CHOWN_RWX_USR_GRP) == -1) {
        if (errCodePtr != nullptr) {
            *errCodePtr = errno;
        }
        MEDIA_ERR_LOG("Failed to create directory %{public}d", errno);
        umask(mask);
        return (errno == EEXIST) ? true : false;
    }
    umask(mask);
    return true;
}

bool MediaFileUtils::CreateDirectory(const string &dirPath, shared_ptr<int> errCodePtr)
{
    string subStr;
    string segment;

    /*  Create directory and its sub directories if does not exist
     *  take each string after '/' create directory if does not exist.
     *  Created directory will be the base path for the next sub directory.
     */

    stringstream folderStream(dirPath);
    while (getline(folderStream, segment, '/')) {
        if (segment.empty()) {    // skip the first "/" in case of "/storage/cloud/files"
            continue;
        }

        subStr.append(SLASH_CHAR + segment);
        if (!IsDirectory(subStr, errCodePtr)) {
            if (!Mkdir(subStr, errCodePtr)) {
                return false;
            }
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
    size_t entCount = 0;
    while (readdir(dir) != nullptr) {
        if (++entCount > EMPTY_DIR_ENTRY_COUNT) {
            break;
        }
    }
    if (closedir(dir) < 0) {
        MEDIA_ERR_LOG("Fail to closedir: %{private}s, errno: %{public}d.", path.c_str(), errno);
    }
    return entCount <= EMPTY_DIR_ENTRY_COUNT;
}

string MediaFileUtils::GetFileName(const string &filePath)
{
    string fileName;

    if (!(filePath.empty())) {
        size_t lastSlash = filePath.rfind('/');
        if (lastSlash != string::npos) {
            if (filePath.size() > (lastSlash + 1)) {
                fileName = filePath.substr(lastSlash + 1);
            }
        }
    }

    return fileName;
}

bool MediaFileUtils::IsDirectory(const string &dirName, shared_ptr<int> errCodePtr)
{
    struct stat statInfo {};

    if (stat(dirName.c_str(), &statInfo) == SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return true;
        }
    } else if (errCodePtr != nullptr) {
        *errCodePtr = errno;
        return false;
    }

    return false;
}

bool MediaFileUtils::CreateFile(const string &filePath)
{
    bool state = false;

    if (filePath.empty()) {
        MEDIA_ERR_LOG("Invalid file path");
        return state;
    }
    if (IsFileExists(filePath)) {
        MEDIA_ERR_LOG("file already exists");
        return state;
    }

    ofstream file(filePath);
    if (!file) {
        MEDIA_ERR_LOG("Output file path could not be created");
        return state;
    }

    if (chmod(filePath.c_str(), CHOWN_RW_USR_GRP) == SUCCESS) {
        state = true;
    } else {
        MEDIA_ERR_LOG("Failed to change permissions, error: %{public}d", errno);
    }

    file.close();

    return state;
}

bool MediaFileUtils::DeleteFile(const string &fileName)
{
    return (remove(fileName.c_str()) == SUCCESS);
}

bool MediaFileUtils::DeleteDir(const string &dirName)
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

bool MediaFileUtils::CopyFileUtil(const string &filePath, const string &newPath)
{
    struct stat fst{};
    bool errCode = false;
    if (filePath.size() >= PATH_MAX) {
        MEDIA_ERR_LOG("File path too long %{public}d", static_cast<int>(filePath.size()));
        return errCode;
    }
    MEDIA_INFO_LOG("File path is %{private}s", filePath.c_str());
    string absFilePath;
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
        if (sendfile(dest, source, nullptr, fst.st_size) != E_ERR) {
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

bool MediaFileUtils::WriteStrToFile(const string &filePath, const string &str)
{
    if (filePath.empty()) {
        MEDIA_ERR_LOG("FilePath is empty");
        return false;
    }
    if (str.empty()) {
        MEDIA_ERR_LOG("Write str is empty");
        return false;
    }

    if (!IsFileExists(filePath)) {
        MEDIA_ERR_LOG("Can not get FilePath %{private}s", filePath.c_str());
        return false;
    }

    ofstream file(filePath);
    if (!file.is_open()) {
        MEDIA_ERR_LOG("Can not open FilePath %{private}s", filePath.c_str());
        return false;
    }

    file << str;
    file.close();
    if (!file.good()) {
        MEDIA_ERR_LOG("Can not write FilePath %{private}s", filePath.c_str());
        return false;
    }
    return true;
}

bool MediaFileUtils::CopyFile(int32_t rfd, int32_t wfd)
{
    static const off_t sendSize1G = 1LL * 1024 * 1024 * 1024;
    static const off_t maxSendSize2G = 2LL * 1024 * 1024 * 1024;
    struct stat fst = {0};
    if (fstat(rfd, &fst) != 0) {
        MEDIA_INFO_LOG("send failed, errno=%{public}d", errno);
        return false;
    }
    off_t fileSize = fst.st_size;

    if (fileSize >= maxSendSize2G) {
        off_t offset = 0;
        while (offset < fileSize) {
            off_t sendSize = fileSize - offset;
            if (sendSize > sendSize1G) {
                sendSize = sendSize1G;
            }
            if (sendfile(wfd, rfd, &offset, sendSize) != sendSize) {
                MEDIA_INFO_LOG("send failed, errno=%{public}d", errno);
                return false;
            }
        }
    } else {
        if (sendfile(wfd, rfd, nullptr, fst.st_size) != fileSize) {
            MEDIA_INFO_LOG("send failed, errno=%{public}d", errno);
            return false;
        }
    }
    return true;
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

int32_t MediaFileUtils::CheckStringSize(const string &str, const size_t max)
{
    size_t size = str.length();
    if (size == 0) {
        return -EINVAL;
    }
    if (size > max) {
        return -ENAMETOOLONG;
    }
    return E_OK;
}

static inline bool RegexCheck(const string &str, const string &regexStr)
{
    const regex express(regexStr);
    return regex_search(str, express);
}

static inline int32_t CheckTitle(const string &title)
{
    static const string TITLE_REGEX_CHECK = R"([\.\\/:*?"'`<>|{}\[\]])";
    if (RegexCheck(title, TITLE_REGEX_CHECK)) {
        MEDIA_ERR_LOG("Failed to check title regex: %{private}s", title.c_str());
        return -EINVAL;
    }
    return E_OK;
}

int32_t MediaFileUtils::CheckDisplayName(const string &displayName)
{
    int err = CheckStringSize(displayName, DISPLAYNAME_MAX);
    if (err < 0) {
        return err;
    }
    if (displayName.at(0) == '.') {
        return -EINVAL;
    }
    string title = GetTitleFromDisplayName(displayName);
    if (title.empty()) {
        return -EINVAL;
    }
    return CheckTitle(title);
}

int32_t MediaFileUtils::CheckFileDisplayName(const string &displayName)
{
    int err = CheckStringSize(displayName, DISPLAYNAME_MAX);
    if (err < 0) {
        return err;
    }
    if (displayName.at(0) == '.') {
        return -EINVAL;
    }
    static const string TITLE_REGEX_CHECK = R"([\\/:*?"'`<>|{}\[\]])";
    if (RegexCheck(displayName, TITLE_REGEX_CHECK)) {
        MEDIA_ERR_LOG("Failed to check displayName regex: %{private}s", displayName.c_str());
        return -EINVAL;
    }
    return E_OK;
}

int32_t MediaFileUtils::CheckRelativePath(const std::string &relativePath)
{
    if (relativePath.empty()) {
        return -EINVAL;
    }

    uint32_t firstPoint = (relativePath.front() == '/') ? 1 : 0;
    size_t lastPoint = 0;
    while (true) {
        lastPoint = relativePath.find_first_of('/', firstPoint);
        if (lastPoint == string::npos) {
            lastPoint = relativePath.length();
        }
        size_t len = lastPoint - firstPoint;
        if (len == 0) {
            MEDIA_ERR_LOG("relativePath %{private}s is invalid", relativePath.c_str());
            return -EINVAL;
        }
        string checkedDirName = relativePath.substr(firstPoint, len);
        if (CheckDentryName(checkedDirName) != E_OK) {
            MEDIA_ERR_LOG("Dir Name %{private}s is invalid in path %{private}s",
                checkedDirName.c_str(), relativePath.c_str());
            return -EINVAL;
        }
        if (lastPoint == relativePath.length()) {
            break;
        }
        firstPoint = lastPoint + 1;
        if (firstPoint == relativePath.length()) {
            break;
        }
    }
    return E_OK;
}

bool MediaFileUtils::CheckDisplayLevel(const int32_t &displayLevel)
{
    if (PORTRAIT_PAGE_MODE.find(displayLevel) == PORTRAIT_PAGE_MODE.end()) {
        MEDIA_ERR_LOG("display level %{private}d is invalid", displayLevel);
        return false;
    }
    return true;
}

string MediaFileUtils::GetHighlightPath(const string &uri)
{
    int prefixLen = 0;
    string uriPrefix = "datashare:///media";
    if (uri.find(uriPrefix) != string::npos) {
        prefixLen = static_cast<int>(uriPrefix.length());
    } else if (uri.find(ML_FILE_URI_PREFIX) != string::npos) {
        prefixLen = static_cast<int>(ML_FILE_URI_PREFIX.length());
    } else {
        return "";
    }

    string path = "/storage/cloud/files/.thumbs" + uri.substr(prefixLen);
    return path;
}

void MediaFileUtils::FormatRelativePath(string &relativePath)
{
    if (relativePath.empty()) {
        return;
    }
    string FormatRelativePath = relativePath;
    if (relativePath.back() != '/') {
        relativePath += '/';
    }
    if (relativePath.front() == '/') {
        relativePath = relativePath.substr(1);
    }
}

void MediaFileUtils::GetRootDirFromRelativePath(const string &relativePath, string &rootDir)
{
    rootDir = relativePath;
    if (relativePath.empty()) {
        return;
    }
    if (relativePath.back() != '/') {
        rootDir += '/';
    }
    if (rootDir[0] == '/') {
        size_t dirIndex = rootDir.find_first_of('/', 1);
        if (dirIndex == string::npos) {
            return;
        }
        rootDir = rootDir.substr(1, dirIndex);
    } else {
        size_t dirIndex = rootDir.find_first_of('/');
        if (dirIndex == string::npos) {
            return;
        }
        rootDir = rootDir.substr(0, dirIndex + 1);
    }
}

int32_t MediaFileUtils::CheckAlbumName(const string &albumName)
{
    int err = CheckStringSize(albumName, DISPLAYNAME_MAX);
    if (err < 0) {
        return err;
    }

    static const string ALBUM_NAME_REGEX = R"([\.\\/:*?"'`<>|{}\[\]])";
    if (RegexCheck(albumName, ALBUM_NAME_REGEX)) {
        MEDIA_ERR_LOG("Failed to check album name regex: %{private}s", albumName.c_str());
        return -EINVAL;
    }
    return E_OK;
}

int32_t MediaFileUtils::CheckDentryName(const string &dentryName)
{
    int err = CheckStringSize(dentryName, DISPLAYNAME_MAX);
    if (err < 0) {
        return err;
    }

    static const string DENTRY_REGEX_CHECK = R"([\\/:*?"'`<>|{}\[\]])";
    if (RegexCheck(dentryName, DENTRY_REGEX_CHECK)) {
        MEDIA_ERR_LOG("Failed to check dentry regex: %{private}s", dentryName.c_str());
        return -EINVAL;
    }
    return E_OK;
}

string MediaFileUtils::GetParentPath(const string &path)
{
    string name;
    size_t slashIndex = path.rfind("/");
    if (slashIndex != string::npos) {
        name = path.substr(0, slashIndex);
    }

    return name;
}

string MediaFileUtils::GetTitleFromDisplayName(const string &displayName)
{
    string title;
    if (!displayName.empty()) {
        string::size_type pos = displayName.find_last_of('.');
        if (pos == string::npos) {
            return "";
        }
        title = displayName.substr(0, pos);
    }
    return title;
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
    struct timespec t{};
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)(t.tv_sec);
}

int64_t MediaFileUtils::UTCTimeMilliSeconds()
{
    struct timespec t;
    constexpr int64_t SEC_TO_MSEC = 1e3;
    constexpr int64_t MSEC_TO_NSEC = 1e6;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * SEC_TO_MSEC + t.tv_nsec / MSEC_TO_NSEC;
}

int64_t MediaFileUtils::UTCTimeNanoSeconds()
{
    struct timespec t {};
    constexpr int64_t SEC_TO_NSEC = 1e9;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * SEC_TO_NSEC + t.tv_nsec;
}

string MediaFileUtils::StrCreateTime(const string &format, int64_t time)
{
    char strTime[DEFAULT_TIME_SIZE] = "";
    auto tm = localtime(&time);
    (void)strftime(strTime, sizeof(strTime), format.c_str(), tm);
    return strTime;
}

string MediaFileUtils::StrCreateTimeByMilliseconds(const string &format, int64_t time)
{
    char strTime[DEFAULT_TIME_SIZE] = "";
    int64_t times = time / MSEC_TO_SEC;
    auto tm = localtime(&times);
    (void)strftime(strTime, sizeof(strTime), format.c_str(), tm);
    return strTime;
}

string MediaFileUtils::GetIdFromUri(const string &uri)
{
    return MediaFileUri(uri).GetFileId();
}

string MediaFileUtils::GetNetworkIdFromUri(const string &uri)
{
    return MediaFileUri(uri).GetNetworkId();
}

string MediaFileUtils::UpdatePath(const string &path, const string &uri)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaFileUtils::UpdatePath");

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

MediaType MediaFileUtils::GetMediaType(const string &filePath)
{
    if (filePath.empty()) {
        return MEDIA_TYPE_ALL;
    }

    string extention = GetExtensionFromPath(filePath);
    string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extention, MEDIA_MIME_TYPE_MAP);
    return MimeTypeUtils::GetMediaTypeFromMimeType(mimeType);
}

string MediaFileUtils::SplitByChar(const string &str, const char split)
{
    size_t splitIndex = str.find_last_of(split);
    return (splitIndex == string::npos) ? ("") : (str.substr(splitIndex + 1));
}

string MediaFileUtils::GetExtensionFromPath(const string &path)
{
    string extention = SplitByChar(path, '.');
    if (!extention.empty()) {
        transform(extention.begin(), extention.end(), extention.begin(), ::tolower);
    }
    return extention;
}

static void SendHmdfsCallerInfoToIoctl(const int32_t fd, const string &clientbundleName)
{
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    hmdfs_caller_info caller_info;
    caller_info.tokenId = tokenId;

    if (strcpy_s(caller_info.bundle_name, sizeof(caller_info.bundle_name), clientbundleName.c_str()) != 0) {
        MEDIA_ERR_LOG("Failed to copy clientbundleName: %{public}s", clientbundleName.c_str());
    } else {
        MEDIA_DEBUG_LOG("tokenId = %{public}d, clientbundleName = %{public}s", tokenId, clientbundleName.c_str());
        int32_t ret = ioctl(fd, HMDFS_IOC_GET_CALLER_INFO, caller_info);
        if (ret < 0) {
            MEDIA_DEBUG_LOG("Failed to set caller_info to fd: %{public}d, error: %{public}d", fd, errno);
        }
    }
}

int32_t MediaFileUtils::OpenFile(const string &filePath, const string &mode, const string &clientbundleName)
{
    int32_t errCode = E_ERR;

    if (filePath.empty() || mode.empty()) {
        MEDIA_ERR_LOG("Invalid open argument! mode: %{private}s, path: %{private}s", mode.c_str(), filePath.c_str());
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
    int32_t fd = open(absFilePath.c_str(), MEDIA_OPEN_MODE_MAP.at(mode));
    if (clientbundleName.empty()) {
        MEDIA_DEBUG_LOG("ClientBundleName is empty,failed to to set caller_info to fd");
    } else {
        SendHmdfsCallerInfoToIoctl(fd, clientbundleName);
    }
    return fd;
}

int32_t MediaFileUtils::CreateAsset(const string &filePath)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaFileUtils::CreateAsset");

    int32_t errCode = E_ERR;

    if (filePath.empty()) {
        MEDIA_ERR_LOG("Filepath is empty");
        return E_VIOLATION_PARAMETERS;
    }

    if (IsFileExists(filePath)) {
        MEDIA_ERR_LOG("the file exists path: %{private}s", filePath.c_str());
        return E_FILE_EXIST;
    }

    size_t slashIndex = filePath.rfind('/');
    if (slashIndex != string::npos) {
        string fileName = filePath.substr(slashIndex + 1);
        if (!fileName.empty() && fileName.at(0) != '.') {
            size_t dotIndex = filePath.rfind('.');
            if ((dotIndex == string::npos) && (GetMediaType(filePath) != MEDIA_TYPE_FILE)) {
                return errCode;
            }
        }
    }

    ofstream file(filePath);
    if (!file) {
        MEDIA_ERR_LOG("Output file path could not be created errno %{public}d", errno);
        return errCode;
    }

    file.close();

    return E_SUCCESS;
}

int32_t MediaFileUtils::ModifyAsset(const string &oldPath, const string &newPath)
{
    int32_t err = E_MODIFY_DATA_FAIL;

    if (oldPath.empty() || newPath.empty()) {
        MEDIA_ERR_LOG("Failed to modify asset, oldPath: %{private}s or newPath: %{private}s is empty!",
            oldPath.c_str(), newPath.c_str());
        return err;
    }
    if (!IsFileExists(oldPath)) {
        MEDIA_ERR_LOG("Failed to modify asset, oldPath: %{private}s does not exist!", oldPath.c_str());
        return E_NO_SUCH_FILE;
    }
    if (IsFileExists(newPath)) {
        MEDIA_ERR_LOG("Failed to modify asset, newPath: %{private}s is already exist!", newPath.c_str());
        return E_FILE_EXIST;
    }
    err = rename(oldPath.c_str(), newPath.c_str());
    if (err < 0) {
        MEDIA_ERR_LOG("Failed rename, errno: %{public}d, old path: %{public}s exists: %{public}d, "
            "new path: %{public}s exists: %{public}d", errno, oldPath.c_str(), IsFileExists(
                oldPath), newPath.c_str(), IsFileExists(newPath));
        return E_FILE_OPER_FAIL;
    }

    return E_SUCCESS;
}

int32_t MediaFileUtils::OpenAsset(const string &filePath, const string &mode)
{
    if (filePath.empty()) {
        return E_INVALID_PATH;
    }
    if (mode.empty()) {
        return E_INVALID_MODE;
    }

    int32_t flags = O_RDWR;
    if (mode == MEDIA_FILEMODE_READONLY) {
        flags = O_RDONLY;
    } else if (mode == MEDIA_FILEMODE_WRITEONLY) {
        flags = O_WRONLY;
    } else if (mode == MEDIA_FILEMODE_WRITETRUNCATE) {
        flags = O_WRONLY | O_TRUNC;
    } else if (mode == MEDIA_FILEMODE_WRITEAPPEND) {
        flags = O_WRONLY | O_APPEND;
    } else if (mode == MEDIA_FILEMODE_READWRITETRUNCATE) {
        flags = O_RDWR | O_TRUNC;
    }

    if (filePath.size() >= PATH_MAX) {
        MEDIA_ERR_LOG("File path too long %{public}d", (int)filePath.size());
        return E_INVALID_PATH;
    }
    MEDIA_INFO_LOG("File path is %{private}s", filePath.c_str());
    std::string absFilePath;
    if (!PathToRealPath(filePath, absFilePath)) {
        MEDIA_ERR_LOG("file is not real path, file path: %{private}s", filePath.c_str());
        return E_INVALID_PATH;
    }
    if (absFilePath.empty()) {
        MEDIA_ERR_LOG("Failed to obtain the canonical path for source path %{private}s %{public}d",
                      filePath.c_str(), errno);
        return E_INVALID_PATH;
    }

    MEDIA_INFO_LOG("File absFilePath is %{private}s", absFilePath.c_str());
    return open(absFilePath.c_str(), flags);
}

int32_t MediaFileUtils::CloseAsset(int32_t fd)
{
    return close(fd);
}

std::string MediaFileUtils::GetMediaTypeUri(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return MEDIALIBRARY_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return MEDIALIBRARY_IMAGE_URI;
        case MEDIA_TYPE_SMARTALBUM:
            return MEDIALIBRARY_SMARTALBUM_CHANGE_URI;
        case MEDIA_TYPE_DEVICE:
            return MEDIALIBRARY_DEVICE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_FILE_URI;
    }
}

std::string MediaFileUtils::GetMediaTypeUriV10(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return AudioColumn::DEFAULT_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
        case MEDIA_TYPE_IMAGE:
            return PhotoColumn::DEFAULT_PHOTO_URI;
        case MEDIA_TYPE_SMARTALBUM:
            return MEDIALIBRARY_SMARTALBUM_CHANGE_URI;
        case MEDIA_TYPE_DEVICE:
            return MEDIALIBRARY_DEVICE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_FILE_URI;
    }
}

bool MediaFileUtils::CheckMode(const string &mode)
{
    if (mode.empty()) {
        return false;
    }
    if (MEDIA_OPEN_MODES.find(mode) != MEDIA_OPEN_MODES.end()) {
        return true;
    } else {
        MEDIA_ERR_LOG("Input Mode %{private}s is invalid", mode.c_str());
        return false;
    }
}

size_t MediaFileUtils::FindIgnoreCase(const std::string &str, const std::string &key)
{
    auto it = search(str.begin(), str.end(), key.begin(), key.end(), [](const char a, const char b) {
        return ::tolower(a) == ::tolower(b);
    });
    if (it == str.end()) {
        return string::npos;
    }
    size_t pos = static_cast<size_t>(it - str.begin());
    return (pos > 0) ? pos : 0;
}

int64_t MediaFileUtils::GetVirtualIdByType(int32_t id, MediaType type)
{
    switch (type) {
        case MediaType::MEDIA_TYPE_IMAGE:
        case MediaType::MEDIA_TYPE_VIDEO: {
            return (int64_t) id * VIRTUAL_ID_DIVIDER - PHOTO_VIRTUAL_IDENTIFIER;
        }
        case MediaType::MEDIA_TYPE_AUDIO: {
            return (int64_t) id * VIRTUAL_ID_DIVIDER - AUDIO_VIRTUAL_IDENTIFIER;
        }
        default: {
            return (int64_t)id * VIRTUAL_ID_DIVIDER - FILE_VIRTUAL_IDENTIFIER;
        }
    }
}

double MediaFileUtils::GetRealIdByTable(int32_t virtualId, const string &tableName)
{
    if (tableName == PhotoColumn::PHOTOS_TABLE) {
        return (double) (virtualId + PHOTO_VIRTUAL_IDENTIFIER) / VIRTUAL_ID_DIVIDER;
    } else if (tableName == AudioColumn::AUDIOS_TABLE) {
        return (double) (virtualId + AUDIO_VIRTUAL_IDENTIFIER) / VIRTUAL_ID_DIVIDER;
    } else {
        return (double) (virtualId + FILE_VIRTUAL_IDENTIFIER) / VIRTUAL_ID_DIVIDER;
    }
}

string MediaFileUtils::GetVirtualUriFromRealUri(const string &uri, const string &extrUri)
{
    if ((uri.find(PhotoColumn::PHOTO_TYPE_URI) != string::npos) ||
        (uri.find(AudioColumn::AUDIO_TYPE_URI) != string::npos) ||
        (uri.find(PhotoColumn::HIGHTLIGHT_COVER_URI) != string::npos)) {
        return uri;
    }

    string pureUri = uri;
    string suffixUri;
    size_t questionMaskPoint = uri.rfind('?');
    size_t hashKeyPoint = uri.rfind('#');
    if (questionMaskPoint != string::npos) {
        suffixUri = uri.substr(questionMaskPoint);
        pureUri = uri.substr(0, questionMaskPoint);
    } else if (hashKeyPoint != string::npos) {
        suffixUri = uri.substr(hashKeyPoint);
        pureUri = uri.substr(0, hashKeyPoint);
    }

    MediaFileUri fileUri(pureUri);
    string fileId = fileUri.GetFileId();
    if (!all_of(fileId.begin(), fileId.end(), ::isdigit)) {
        return uri;
    }
    int32_t id;
    if (!StrToInt(fileId, id)) {
        MEDIA_ERR_LOG("invalid fileuri %{private}s", uri.c_str());
        return uri;
    }
    int64_t virtualId;
    MediaType type;
    if ((pureUri.find(MEDIALIBRARY_TYPE_IMAGE_URI) != string::npos)) {
        type = MediaType::MEDIA_TYPE_IMAGE;
        virtualId = GetVirtualIdByType(id, MediaType::MEDIA_TYPE_IMAGE);
    } else if (pureUri.find(MEDIALIBRARY_TYPE_VIDEO_URI) != string::npos) {
        type = MediaType::MEDIA_TYPE_VIDEO;
        virtualId = GetVirtualIdByType(id, MediaType::MEDIA_TYPE_VIDEO);
    } else if ((pureUri.find(MEDIALIBRARY_TYPE_AUDIO_URI) != string::npos)) {
        type = MediaType::MEDIA_TYPE_AUDIO;
        virtualId = GetVirtualIdByType(id, MediaType::MEDIA_TYPE_AUDIO);
    } else {
        type = MediaType::MEDIA_TYPE_FILE;
        virtualId = GetVirtualIdByType(id, MediaType::MEDIA_TYPE_FILE);
    }
    MediaFileUri virtualUri(type, to_string(virtualId), fileUri.GetNetworkId(),
        (fileUri.IsApi10() ? MEDIA_API_VERSION_V10 : MEDIA_API_VERSION_V9),
        (fileUri.IsApi10() ? extrUri : ""));

    return suffixUri.empty() ? virtualUri.ToString() : virtualUri.ToString() + suffixUri;
}

void GetExtrParamFromUri(const std::string &uri, std::string &displayName)
{
    if (uri.find(PATH_PARA) != string::npos) {
        size_t lastSlashPosition = uri.rfind('/');
        if (lastSlashPosition != string::npos) {
            displayName = uri.substr(lastSlashPosition + 1);
        }
    }
}

void InitPureAndSuffixUri(string &pureUri, string &suffixUri, const string &uri)
{
    size_t questionMaskPoint = uri.rfind('?');
    size_t hashKeyPoint = uri.rfind('#');
    if (questionMaskPoint != string::npos) {
        suffixUri = uri.substr(questionMaskPoint);
        pureUri = uri.substr(0, questionMaskPoint);
    } else if (hashKeyPoint != string::npos) {
        suffixUri = uri.substr(hashKeyPoint);
        pureUri = uri.substr(0, hashKeyPoint);
    }
}

string MediaFileUtils::GetRealUriFromVirtualUri(const string &uri)
{
    if ((uri.find(PhotoColumn::PHOTO_TYPE_URI) != string::npos) ||
        (uri.find(AudioColumn::AUDIO_TYPE_URI) != string::npos) ||
        (uri.find(PhotoColumn::HIGHTLIGHT_COVER_URI) != string::npos)) {
        return uri;
    }

    string pureUri = uri;
    string suffixUri;
    InitPureAndSuffixUri(pureUri, suffixUri, uri);
    MediaFileUri fileUri(pureUri);
    string fileId = fileUri.GetFileId();
    if (!all_of(fileId.begin(), fileId.end(), ::isdigit)) {
        return uri;
    }
    int32_t id;
    if (!StrToInt(fileId, id)) {
        MEDIA_ERR_LOG("invalid fileuri %{private}s", uri.c_str());
        return uri;
    }
    int32_t realId = 0;
    MediaType type;
    if ((pureUri.find(MEDIALIBRARY_TYPE_IMAGE_URI) != string::npos)) {
        type = MediaType::MEDIA_TYPE_IMAGE;
        realId = static_cast<int32_t>(GetRealIdByTable(id, PhotoColumn::PHOTOS_TABLE));
    } else if (pureUri.find(MEDIALIBRARY_TYPE_VIDEO_URI) != string::npos) {
        type = MediaType::MEDIA_TYPE_VIDEO;
        realId = static_cast<int32_t>(GetRealIdByTable(id, PhotoColumn::PHOTOS_TABLE));
    } else if ((pureUri.find(MEDIALIBRARY_TYPE_AUDIO_URI) != string::npos)) {
        type = MediaType::MEDIA_TYPE_AUDIO;
        realId = static_cast<int32_t>(GetRealIdByTable(id, AudioColumn::AUDIOS_TABLE));
    } else {
        type = MediaType::MEDIA_TYPE_FILE;
        realId = static_cast<int32_t>(GetRealIdByTable(id, MEDIALIBRARY_TABLE));
    }
    string extrUri;
    if (fileUri.IsApi10()) {
        string displayName;
        GetExtrParamFromUri(pureUri, displayName);
        extrUri = GetExtraUri(displayName, fileUri.GetFilePath(), false);
    }

    MediaFileUri realUri(type, to_string(realId), fileUri.GetNetworkId(),
        (fileUri.IsApi10() ? MEDIA_API_VERSION_V10 : MEDIA_API_VERSION_V9), (fileUri.IsApi10() ? extrUri : ""));

    if (suffixUri.empty()) {
        return realUri.ToString();
    }
    return realUri.ToString() + suffixUri;
}

#ifdef MEDIALIBRARY_COMPATIBILITY
string MediaFileUtils::GetTableFromVirtualUri(const std::string &virtualUri)
{
    MediaFileUri uri(virtualUri);
    if (!uri.IsValid()) {
        MEDIA_ERR_LOG("virtual uri:%{private}s is invalid", virtualUri.c_str());
        return "";
    }
    string virtualId = uri.GetFileId();
    if (std::all_of(virtualId.begin(), virtualId.end(), ::isdigit)) {
        int64_t id = stol(virtualId);
        int64_t remainNumber = id % VIRTUAL_ID_DIVIDER;
        switch (remainNumber) {
            case VIRTUAL_ID_DIVIDER - PHOTO_VIRTUAL_IDENTIFIER:
                return PhotoColumn::PHOTOS_TABLE;
            case VIRTUAL_ID_DIVIDER - AUDIO_VIRTUAL_IDENTIFIER:
                return AudioColumn::AUDIOS_TABLE;
            case VIRTUAL_ID_DIVIDER - FILE_VIRTUAL_IDENTIFIER:
                return MEDIALIBRARY_TABLE;
            default:
                MEDIA_ERR_LOG("virtualId:%{public}ld is wrong", (long) id);
                return "";
        }
    } else {
        MEDIA_ERR_LOG("virtual uri:%{private}s is invalid, can not get id", virtualUri.c_str());
        return "";
    }
}
#endif

bool MediaFileUtils::IsUriV10(const string &mediaType)
{
    return mediaType == URI_TYPE_PHOTO ||
        mediaType == URI_TYPE_PHOTO_ALBUM ||
        mediaType == URI_TYPE_AUDIO_V10;
}

bool MediaFileUtils::IsFileTablePath(const string &path)
{
    if (path.empty() || path.size() <= ROOT_MEDIA_DIR.size()) {
        return false;
    }

    if (path.find(ROOT_MEDIA_DIR) == string::npos) {
        return false;
    }

    string relativePath = path.substr(ROOT_MEDIA_DIR.size());
    if ((relativePath.find(DOCS_PATH) == 0)) {
        return true;
    }
    return false;
}

bool MediaFileUtils::IsPhotoTablePath(const string &path)
{
    if (path.empty() || path.size() <= ROOT_MEDIA_DIR.size()) {
        return false;
    }

    if (path.find(ROOT_MEDIA_DIR) == string::npos) {
        return false;
    }

    string relativePath = path.substr(ROOT_MEDIA_DIR.size());

    const vector<string> photoPathVector = {
        PHOTO_BUCKET, PIC_DIR_VALUES, VIDEO_DIR_VALUES, CAMERA_DIR_VALUES
    };
    for (auto &photoPath : photoPathVector) {
        if (relativePath.find(photoPath) == 0) {
            return true;
        }
    }
    return false;
}

bool MediaFileUtils::StartsWith(const std::string &str, const std::string &prefix)
{
    return str.compare(0, prefix.size(), prefix) == 0;
}

void MediaFileUtils::UriAppendKeyValue(string &uri, const string &key, std::string value)
{
    string uriKey = key + '=';
    if (uri.find(uriKey) != string::npos) {
        return;
    }

    char queryMark = (uri.find('?') == string::npos) ? '?' : '&';
    string append = queryMark + key + '=' + value;

    size_t pos = uri.find('#');
    if (pos == string::npos) {
        uri += append;
    } else {
        uri.insert(pos, append);
    }
}

string MediaFileUtils::GetExtraUri(const string &displayName, const string &path, const bool isNeedEncode)
{
    string extraUri = "/" + GetTitleFromDisplayName(GetFileName(path)) + "/" + displayName;
    if (!isNeedEncode) {
        return extraUri;
    }
    return MediaFileUtils::Encode(extraUri);
}

string MediaFileUtils::GetUriByExtrConditions(const string &prefix, const string &fileId, const string &suffix)
{
    return prefix + fileId + suffix;
}

string MediaFileUtils::Encode(const string &uri)
{
    const unordered_set<char> uriCompentsSet = {
        ';', ',', '/', '?', ':', '@', '&',
        '=', '+', '$', '-', '_', '.', '!',
        '~', '*', '(', ')', '\''
    };
    const int32_t encodeLen = 2;
    ostringstream outPutStream;
    outPutStream.fill('0');
    outPutStream << std::hex;

    for (unsigned char tmpChar : uri) {
        if (std::isalnum(tmpChar) || uriCompentsSet.find(tmpChar) != uriCompentsSet.end()) {
            outPutStream << tmpChar;
        } else {
            outPutStream << std::uppercase;
            outPutStream << '%' << std::setw(encodeLen) << static_cast<unsigned int>(tmpChar);
            outPutStream << std::nouppercase;
        }
    }

    return outPutStream.str();
}

string MediaFileUtils::AddDocsToRelativePath(const string &relativePath)
{
    if (MediaFileUtils::StartsWith(relativePath, DOC_DIR_VALUES) ||
        MediaFileUtils::StartsWith(relativePath, DOWNLOAD_DIR_VALUES)) {
        return DOCS_PATH + relativePath;
    }
    return relativePath;
}

string MediaFileUtils::RemoveDocsFromRelativePath(const string &relativePath)
{
    if (MediaFileUtils::StartsWith(relativePath, DOCS_PATH)) {
        return relativePath.substr(DOCS_PATH.size());
    }
    return relativePath;
}

int64_t MediaFileUtils::Timespec2Millisecond(const struct timespec &time)
{
    return time.tv_sec * MSEC_TO_SEC + time.tv_nsec / MSEC_TO_NSEC;
}

string MediaFileUtils::GetMovingPhotoVideoPath(const string &imagePath)
{
    size_t splitIndex = imagePath.find_last_of('.');
    return (splitIndex == string::npos) ? "" : (imagePath.substr(0, splitIndex) + ".mp4");
}

bool MediaFileUtils::CheckMovingPhotoExtension(const string &extension)
{
    // image of moving photo must be image/jpeg or image/heif
    string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extension, MEDIA_MIME_TYPE_MAP);
    return mimeType == "image/jpeg" || mimeType == "image/heif";
}

bool MediaFileUtils::CheckMovingPhotoVideoExtension(const string &extension)
{
    // video of moving photo must be video/mp4
    return MimeTypeUtils::GetMimeTypeFromExtension(extension, MEDIA_MIME_TYPE_MAP) == "video/mp4";
}

bool MediaFileUtils::CheckMovingPhotoImage(const string &path)
{
    return CheckMovingPhotoExtension(GetExtensionFromPath(path));
}

bool MediaFileUtils::CheckMovingPhotoVideo(const string &path)
{
    string absFilePath;
    if (!PathToRealPath(path, absFilePath)) {
        MEDIA_ERR_LOG("Failed to get real path, path: %{private}s", path.c_str());
        return false;
    }
    if (absFilePath.empty()) {
        MEDIA_ERR_LOG("Failed to check path for %{private}s, errno: %{public}d", path.c_str(), errno);
        return false;
    }

    string extension = GetExtensionFromPath(absFilePath);
    if (!CheckMovingPhotoVideoExtension(extension)) {
        MEDIA_ERR_LOG("Failed to check extension (%{public}s) of moving photo video", extension.c_str());
        return false;
    }

    UniqueFd uniqueFd(open(absFilePath.c_str(), O_RDONLY));
    return CheckMovingPhotoVideo(uniqueFd);
}

bool MediaFileUtils::CheckMovingPhotoVideo(const UniqueFd &uniqueFd)
{
    if (uniqueFd.Get() <= 0) {
        MEDIA_ERR_LOG("Failed to open video of moving photo, errno = %{public}d", errno);
        return false;
    }
    struct stat64 st;
    if (fstat64(uniqueFd.Get(), &st) != 0) {
        MEDIA_ERR_LOG("Failed to get file state, errno = %{public}d", errno);
        return false;
    }

    shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (avMetadataHelper == nullptr) {
        MEDIA_WARN_LOG("Failed to create AVMetadataHelper, ignore checking duration");
        return true;
    }

    int32_t err = avMetadataHelper->SetSource(uniqueFd.Get(), 0,
        static_cast<int64_t>(st.st_size), AV_META_USAGE_META_ONLY);
    if (err != 0) {
        MEDIA_ERR_LOG("SetSource failed for the given file descriptor, err = %{public}d", err);
        return false;
    }

    unordered_map<int32_t, string> resultMap = avMetadataHelper->ResolveMetadata();
    if (resultMap.find(AV_KEY_DURATION) == resultMap.end()) {
        MEDIA_ERR_LOG("AV_KEY_DURATION does not exist");
        return false;
    }
    string durationStr = resultMap.at(AV_KEY_DURATION);
    int32_t duration = std::atoi(durationStr.c_str());
    if (!CheckMovingPhotoVideoDuration(duration)) {
        MEDIA_ERR_LOG("Failed to check duration of moving photo video: %{public}d ms", duration);
        return false;
    }
    return true;
}

bool MediaFileUtils::CheckMovingPhotoVideoDuration(int32_t duration)
{
    // duration of moving photo video must be 2~3 s
    constexpr int32_t MIN_DURATION_MS = 2000;
    constexpr int32_t MAX_DURATION_MS = 3000;
    return duration >= MIN_DURATION_MS && duration <= MAX_DURATION_MS;
}

bool MediaFileUtils::GetFileSize(const std::string& filePath, size_t& size)
{
    struct stat statbuf;
    if (lstat(filePath.c_str(), &statbuf) == -1) {
        MEDIA_WARN_LOG("Failed to get file size, errno: %{public}d, path: %{private}s", errno, filePath.c_str());
        size = 0;
        return false;
    }
    size = statbuf.st_size;
    return true;
}

bool MediaFileUtils::SplitMovingPhotoUri(const std::string& uri, std::vector<std::string>& ret)
{
    const std::string split(MOVING_PHOTO_URI_SPLIT);
    if (uri.empty() || IsMediaLibraryUri(uri)) {
        MEDIA_ERR_LOG("Failed to split moving photo uri, uri=%{public}s", uri.c_str());
        return false;
    }
    std::string temp = uri;
    size_t pos = temp.find(split);
    uint32_t step = split.size();
    ret.push_back(temp.substr(0, pos));
    ret.push_back(temp.substr(pos + step));
    return true;
}

bool MediaFileUtils::IsMediaLibraryUri(const std::string& uri)
{
    return !uri.empty() && uri.find(MOVING_PHOTO_URI_SPLIT) == uri.npos;
}
} // namespace OHOS::Media
