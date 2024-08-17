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

#include "backup_file_utils.h"

#include <utime.h>
#include <sys/types.h>

#include "scanner_utils.h"
#include "media_file_uri.h"
#include "metadata_extractor.h"
#include "mimetype_utils.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "medialibrary_asset_operations.h"
#include "moving_photo_file_utils.h"

namespace OHOS {
namespace Media {
const string DEFAULT_IMAGE_NAME = "IMG_";
const string DEFAULT_VIDEO_NAME = "VID_";
const string DEFAULT_AUDIO_NAME = "AUD_";

constexpr int ASSET_MAX_COMPLEMENT_ID = 999;

int32_t BackupFileUtils::FillMetadata(std::unique_ptr<Metadata> &data)
{
    int32_t err = GetFileMetadata(data);
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get file metadata");
        return err;
    }
    if (data->GetFileMediaType() == MEDIA_TYPE_IMAGE) {
        err = MetadataExtractor::ExtractImageMetadata(data);
    } else {
        err = MetadataExtractor::ExtractAVMetadata(data, Scene::AV_META_SCENE_CLONE);
        MEDIA_INFO_LOG("Extract av metadata end");
    }
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to extension data");
        return err;
    }
    return E_OK;
}

int32_t BackupFileUtils::GetFileMetadata(std::unique_ptr<Metadata> &data)
{
    std::string path = data->GetFilePath();
    struct stat statInfo {};
    if (stat(path.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("stat syscall err %{public}d", errno);
        return E_FAIL;
    }
    data->SetFileSize(statInfo.st_size);
    auto dateModified = static_cast<int64_t>(MediaFileUtils::Timespec2Millisecond(statInfo.st_mtim));
    if (dateModified == 0) {
        dateModified = MediaFileUtils::UTCTimeMilliSeconds();
        MEDIA_WARN_LOG("Invalid dateModified from st_mtim, use current time instead: %{public}lld",
            static_cast<long long>(dateModified));
    }
    if (dateModified != 0 && data->GetFileDateModified() == 0) {
        data->SetFileDateModified(dateModified);
    }
    string extension = ScannerUtils::GetFileExtension(path);
    string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extension);
    data->SetFileExtension(extension);
    data->SetFileMimeType(mimeType);
    return E_OK;
}

string BackupFileUtils::GarbleFilePath(const std::string &filePath, int32_t sceneCode, std::string cloneFilePath)
{
    if (filePath.empty()) {
        return filePath;
    }
    size_t displayNameIndex = filePath.rfind("/");
    if (displayNameIndex == string::npos || displayNameIndex + 1 >= filePath.size()) {
        return filePath;
    }
    std::string garbleDisplayName = GarbleFileName(filePath.substr(displayNameIndex + 1));
    std::string path;
    if (sceneCode == UPGRADE_RESTORE_ID) {
        path = filePath.substr(0, displayNameIndex).replace(0, UPGRADE_FILE_DIR.length(), GARBLE);
    } else if (sceneCode == DUAL_FRAME_CLONE_RESTORE_ID) {
        path = filePath.substr(0, displayNameIndex).replace(0, GARBLE_DUAL_FRAME_CLONE_DIR.length(), GARBLE);
    } else if (sceneCode == CLONE_RESTORE_ID) {
        path = filePath.substr(0, displayNameIndex).replace(0, cloneFilePath.length(), GARBLE);
    } else {
        path = filePath.substr(0, displayNameIndex);
    }
    path += "/" + garbleDisplayName;
    return path;
}

string BackupFileUtils::GarbleFileName(const std::string &fileName)
{
    if (fileName.empty()) {
        return fileName;
    }
    if (fileName.find("Screenshot_") == 0 || fileName.find("IMG_") == 0 || fileName.find("VID_") == 0 ||
        fileName.find("SVID_") == 0) {
        return fileName;
    }
    size_t titleIndex = fileName.rfind(".");
    if (titleIndex == string::npos) {
        titleIndex = fileName.size();
    }
    if (titleIndex <= GARBLE.size() * GARBLE_UNIT) {
        return fileName;
    }
    return GARBLE + fileName.substr(GARBLE.size());
}

int32_t BackupFileUtils::CreateAssetPathById(int32_t fileId, int32_t mediaType, const string &extension,
    string &filePath)
{
    int32_t bucketNum = 0;
    int32_t errCode = MediaFileUri::CreateAssetBucket(fileId, bucketNum);
    if (errCode != E_OK) {
        return errCode;
    }

    string realName;
    errCode = CreateAssetRealName(fileId, mediaType, extension, realName);
    if (errCode != E_OK) {
        return errCode;
    }

    string dirPath = (mediaType == MediaType::MEDIA_TYPE_AUDIO ? RESTORE_AUDIO_CLOUD_DIR : RESTORE_CLOUD_DIR) + "/" +
        to_string(bucketNum);
    string localDirPath = GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::LOCAL, dirPath);
    if (!MediaFileUtils::IsFileExists(localDirPath)) {
        bool ret = MediaFileUtils::CreateDirectory(localDirPath);
        errCode = ret? E_OK: E_CHECK_DIR_FAIL;
    }
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create Dir Failed! localDirPath=%{private}s", localDirPath.c_str());
        return errCode;
    }

    filePath = dirPath + "/" + realName;
    return E_OK;
}

int32_t BackupFileUtils::CreateAssetRealName(int32_t fileId, int32_t mediaType,
    const string &extension, string &name)
{
    string fileNumStr = to_string(fileId);
    if (fileId <= ASSET_MAX_COMPLEMENT_ID) {
        size_t fileIdLen = fileNumStr.length();
        fileNumStr = ("00" + fileNumStr).substr(fileIdLen - 1);
    }

    string mediaTypeStr;
    switch (mediaType) {
        case MediaType::MEDIA_TYPE_IMAGE:
            mediaTypeStr = DEFAULT_IMAGE_NAME;
            break;
        case MediaType::MEDIA_TYPE_VIDEO:
            mediaTypeStr = DEFAULT_VIDEO_NAME;
            break;
        case MediaType::MEDIA_TYPE_AUDIO:
            mediaTypeStr = DEFAULT_AUDIO_NAME;
            break;
        default:
            MEDIA_ERR_LOG("This mediatype %{public}d can not get real name", mediaType);
            return E_INVALID_VALUES;
    }
    name = mediaTypeStr + to_string(MediaFileUtils::UTCTimeSeconds()) + "_" + fileNumStr + "." + extension;
    return E_OK;
}

std::string BackupFileUtils::GetFullPathByPrefixType(PrefixType prefixType, const std::string &relativePath)
{
    std::string fullPath;
    auto it = PREFIX_MAP.find(prefixType);
    if (it == PREFIX_MAP.end()) {
        MEDIA_ERR_LOG("Get path prefix failed: %{public}d", prefixType);
        return fullPath;
    }
    fullPath = it->second + relativePath;
    return fullPath;
}

int32_t BackupFileUtils::CreatePath(int32_t mediaType, const std::string &displayName, std::string &path)
{
    int32_t uniqueId = MediaLibraryAssetOperations::CreateAssetUniqueId(mediaType);
    int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, mediaType,
        MediaFileUtils::GetExtensionFromPath(displayName), path);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create path failed, errCode: %{public}d", errCode);
        path.clear();
        return errCode;
    }
    return E_OK;
}

int32_t BackupFileUtils::PreparePath(const std::string &path)
{
    size_t index = path.rfind("/");
    if (index == std::string::npos || index == path.length() - 1) {
        MEDIA_ERR_LOG("Parse directory path failed: %{private}s", path.c_str());
        return E_CHECK_DIR_FAIL;
    }
    std::string dirPath = path.substr(0, index);
    if (!MediaFileUtils::IsFileExists(dirPath) && !MediaFileUtils::CreateDirectory(dirPath)) {
        MEDIA_ERR_LOG("Directory path doesn't exist and was created failed: %{public}s", dirPath.c_str());
        return E_CHECK_DIR_FAIL;
    }
    return E_OK;
}

int32_t BackupFileUtils::MoveFile(const string &oldPath, const string &newPath, int32_t sceneCode)
{
    bool errRet = false;
    if (!MediaFileUtils::IsFileExists(oldPath)) {
        MEDIA_ERR_LOG("old path: %{public}s is not exists.", GarbleFilePath(oldPath, sceneCode).c_str());
        return E_NO_SUCH_FILE;
    } else if (MediaFileUtils::IsFileExists(newPath)) {
        MEDIA_ERR_LOG("new path: %{public}s is exists.", GarbleFilePath(newPath, sceneCode).c_str());
        return E_FILE_EXIST;
    }
    return rename(oldPath.c_str(), newPath.c_str());
}

std::string BackupFileUtils::GetReplacedPathByPrefixType(PrefixType srcPrefixType, PrefixType dstPrefixType,
    const std::string &path)
{
    std::string replacedPath;
    if (PREFIX_MAP.count(srcPrefixType) == 0 || PREFIX_MAP.count(dstPrefixType) == 0) {
        MEDIA_ERR_LOG("Get source or destination prefix failed: %{public}d, %{public}d", srcPrefixType, dstPrefixType);
        return replacedPath;
    }
    std::string srcPrefix = PREFIX_MAP.at(srcPrefixType);
    std::string dstPrefix = PREFIX_MAP.at(dstPrefixType);
    replacedPath = path;
    replacedPath.replace(0, srcPrefix.length(), dstPrefix);
    return replacedPath;
}

void BackupFileUtils::ModifyFile(const std::string path, int64_t modifiedTime)
{
    if (modifiedTime <= 0) {
        MEDIA_ERR_LOG("ModifyTime error!");
        return;
    }
    struct utimbuf buf;
    buf.actime = modifiedTime; // second
    buf.modtime = modifiedTime; // second
    int ret = utime(path.c_str(), &buf);
    if (ret != 0) {
        MEDIA_ERR_LOG("Modify file failed: %{public}d", ret);
    }
}

string BackupFileUtils::GetFileNameFromPath(const string &path)
{
    if (!path.empty()) {
        size_t lastPosition = path.rfind("/");
        if (lastPosition != string::npos) {
            if (path.size() > lastPosition) {
                return path.substr(lastPosition + 1);
            }
        }
    }

    MEDIA_ERR_LOG("Failed to obtain file name because given pathname is empty");
    return "";
}

string BackupFileUtils::GetFileTitle(const string &displayName)
{
    string::size_type pos = displayName.find_last_of('.');
    return (pos == string::npos) ? displayName : displayName.substr(0, pos);
}

bool BackupFileUtils::IsFileValid(const std::string &filePath, int32_t sceneCode)
{
    std::string garbledFilePath = BackupFileUtils::GarbleFilePath(filePath, sceneCode);
    struct stat statInfo {};
    if (stat(filePath.c_str(), &statInfo) != E_SUCCESS) {
        MEDIA_ERR_LOG("Invalid file (%{public}s), get statInfo failed, err: %{public}d", garbledFilePath.c_str(),
            errno);
        return false;
    }
    if (statInfo.st_mode & S_IFDIR) {
        MEDIA_ERR_LOG("Invalid file (%{public}s), is a directory", garbledFilePath.c_str());
        return false;
    }
    if (statInfo.st_size <= 0) {
        MEDIA_ERR_LOG("Invalid file (%{public}s), get size (%{public}lld) <= 0", garbledFilePath.c_str(),
            (long long)statInfo.st_size);
        return false;
    }
    return true;
}

std::string BackupFileUtils::GetDetailsPath(const std::string &type,
    const std::unordered_map<std::string, int32_t> &failedFiles)
{
    std::string detailsPath = RESTORE_FAILED_FILES_PATH + "_" + type + ".txt";
    if (MediaFileUtils::IsFileExists(detailsPath) && !MediaFileUtils::DeleteFile(detailsPath)) {
        MEDIA_ERR_LOG("%{public}s exists and delete failed", detailsPath.c_str());
        return "";
    }
    if (failedFiles.empty()) {
        return "";
    }
    if (MediaFileUtils::CreateAsset(detailsPath) != E_SUCCESS) {
        MEDIA_ERR_LOG("Create %{public}s failed", detailsPath.c_str());
        return "";
    }
    std::string failedFilesStr = GetFailedFilesStr(failedFiles);
    if (!MediaFileUtils::WriteStrToFile(detailsPath, failedFilesStr)) {
        MEDIA_ERR_LOG("Write to %{public}s failed", detailsPath.c_str());
        return "";
    }
    return detailsPath;
}

std::string BackupFileUtils::GetFailedFilesStr(const std::unordered_map<std::string, int32_t> &failedFiles)
{
    std::stringstream failedFilesStream;
    failedFilesStream << "[";
    size_t index = 0;
    for (const auto &iter : failedFiles) {
        failedFilesStream << "\n\"" + iter.first;
        index + 1 < failedFiles.size() ? failedFilesStream << "\"," : failedFilesStream << "\"";
        index++;
    }
    failedFilesStream << "\n]";
    return failedFilesStream.str();
}

bool BackupFileUtils::GetPathPosByPrefixLevel(int32_t sceneCode, const std::string &path, int32_t prefixLevel,
    size_t &pos)
{
    int32_t count = 0;
    for (size_t index = 0; index < path.length(); index++) {
        if (path[index] != '/') {
            continue;
        }
        count++;
        if (count == prefixLevel) {
            pos = index;
            break;
        }
    }
    if (count < prefixLevel) {
        MEDIA_ERR_LOG("Get position failed for %{public}s, %{public}d < %{public}d",
            GarbleFilePath(path, sceneCode).c_str(), count, prefixLevel);
        return false;
    }
    return true;
}

bool BackupFileUtils::ShouldIncludeSD(const std::string &prefix)
{
    return MediaFileUtils::IsFileExists(prefix + "/" + PHOTO_SD_DB_NAME) ||
        MediaFileUtils::IsFileExists(prefix + "/" + VIDEO_SD_DB_NAME);
}

void BackupFileUtils::DeleteSDDatabase(const std::string &prefix)
{
    std::vector<std::string> sdDBs = { PHOTO_SD_DB_NAME, VIDEO_SD_DB_NAME };
    for (const auto &sdDB : sdDBs) {
        std::string sdDBPath = prefix + "/" + sdDB;
        if (!MediaFileUtils::IsFileExists(sdDBPath)) {
            continue;
        }
        if (!MediaFileUtils::DeleteFile(sdDBPath)) {
            MEDIA_ERR_LOG("Delete SD database %{public}s failed, errno: %{public}d", sdDB.c_str(), errno);
        }
    }
}

bool BackupFileUtils::IsLivePhoto(const FileInfo &fileInfo)
{
    return fileInfo.specialFileType == LIVE_PHOTO_TYPE;
}

static void addPathSuffix(const string &oldPath, const string &suffix, string &newPath)
{
    if (oldPath.empty() || suffix.empty()) {
        MEDIA_WARN_LOG("oldPath or suffix is empty");
        return;
    }

    newPath = oldPath + suffix;
    while (MediaFileUtils::IsFileExists(newPath)) {
        newPath += ".dup" + suffix;
    }
}

bool BackupFileUtils::ConvertToMovingPhoto(const string &livePhotoPath,
    string &movingPhotoVideoPath, string &extraDataPath)
{
    if (!MediaFileUtils::IsFileExists(livePhotoPath)) {
        MEDIA_ERR_LOG("Live photo does not exist, path:%{private}s, errno:%{public}d", livePhotoPath.c_str(), errno);
        return false;
    }

    addPathSuffix(livePhotoPath, ".mp4", movingPhotoVideoPath);
    addPathSuffix(livePhotoPath, ".extra", extraDataPath);
    int32_t ret = MovingPhotoFileUtils::ConvertToMovingPhoto(livePhotoPath,
        livePhotoPath, movingPhotoVideoPath, extraDataPath);
    return ret == E_OK;
}
} // namespace Media
} // namespace OHOS