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
#include "metadata_extractor.h"
#include "mimetype_utils.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "medialibrary_asset_operations.h"

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
        err = MetadataExtractor::ExtractAVMetadata(data);
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
    if (dateModified != 0 && data->GetFileDateModified() == 0) {
        data->SetFileDateModified(dateModified);
    }
    string extension = ScannerUtils::GetFileExtension(path);
    string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extension);
    data->SetFileExtension(extension);
    data->SetFileMimeType(mimeType);
    return E_OK;
}

string BackupFileUtils::GarbleFilePath(const std::string &filePath, int32_t sceneCode)
{
    if (filePath.empty()) {
        return filePath;
    }
    size_t displayNameIndex = filePath.rfind("/");
    if (displayNameIndex == string::npos) {
        return filePath;
    }
    std::string displayName = filePath.substr(displayNameIndex);
    std::string garbleDisplayName = GarbleFileName(displayName);
    std::string path;
    if (sceneCode == UPGRADE_RESTORE_ID) {
        path = filePath.substr(0, displayNameIndex).replace(0, UPGRADE_FILE_DIR.length(), GARBLE);
    } else if (sceneCode == DUAL_FRAME_CLONE_RESTORE_ID) {
        path = filePath.substr(0, displayNameIndex).replace(0, GARBLE_DUAL_FRAME_CLONE_DIR.length(), GARBLE);
    } else if (sceneCode == CLONE_RESTORE_ID) {
        path = filePath.substr(0, displayNameIndex).replace(0, GARBLE_CLONE_DIR.length(), GARBLE);
    } else {
        path = filePath.substr(0, displayNameIndex);
    }
    path += displayName;
    return path;
}

string BackupFileUtils::GarbleFileName(std::string &fileName)
{
    if (fileName.empty()) {
        return fileName;
    }
    if (fileName.find("Screenshot_") == 0 || fileName.find("IMG_") == 0 || fileName.find("VID_") == 0 ||
        fileName.find("SVID_") == 0) {
        return fileName;
    }
    if (fileName.length() > GARBLE_HIGH_LENGTH) {
        return fileName.replace(0, GARBLE_HIGH_LENGTH, GARBLE);
    } else if (fileName.length() > GARBLE_MID_LENGTH) {
        return fileName.replace(0, GARBLE_MID_LENGTH, GARBLE);
    } else if (fileName.length() > GARBLE_LOW_LENGTH) {
        return fileName.replace(0, GARBLE_LOW_LENGTH, GARBLE);
    } else {
        return fileName.replace(0, 1, GARBLE);
    }
}

int32_t BackupFileUtils::CreateAssetPathById(int32_t fileId, int32_t mediaType, const string &extension,
    string &filePath)
{
    int32_t bucketNum = 0;
    int32_t errCode = MediaLibraryAssetOperations::CreateAssetBucket(fileId, bucketNum);
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
    if (!MediaFileUtils::IsFileExists(dirPath)) {
        bool ret = MediaFileUtils::CreateDirectory(dirPath);
        errCode = ret? E_OK: E_CHECK_DIR_FAIL;
    }
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create Dir Failed! dirPath=%{private}s", dirPath.c_str());
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

bool BackupFileUtils::MoveFile(const string &oldPath, const string &newPath, int32_t sceneCode)
{
    bool errRet = false;
    if (!MediaFileUtils::IsFileExists(oldPath)) {
        MEDIA_ERR_LOG("old path: %{public}s is not exists.", GarbleFilePath(oldPath, sceneCode).c_str());
        return E_NO_SUCH_FILE;
    } else if (MediaFileUtils::IsFileExists(newPath)) {
        MEDIA_ERR_LOG("new path: %{public}s is exists.", GarbleFilePath(newPath, sceneCode).c_str());
        return E_FILE_EXIST;
    }
    return (rename(oldPath.c_str(), newPath.c_str()) == SUCCESS);
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
    if (stat(filePath.c_str(), &statInfo) != SUCCESS) {
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
} // namespace Media
} // namespace OHOS