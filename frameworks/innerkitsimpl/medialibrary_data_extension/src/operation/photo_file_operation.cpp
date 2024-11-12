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
#define MLOG_TAG "PhotoFileOperation"

#include "photo_file_operation.h"

#include <sstream>

#include "media_log.h"
#include "medialibrary_errno.h"
#include "userfile_manager_types.h"
#include "media_file_utils.h"
#include "media_column.h"
#include "result_set_utils.h"

namespace OHOS::Media {
std::string PhotoFileOperation::ToString(const PhotoAssetInfo &photoInfo)
{
    std::stringstream ss;
    ss << "PhotoAssetInfo[displayName: " << photoInfo.displayName << ", filePath: " << photoInfo.filePath
       << ", dateModified: " << photoInfo.dateModified << ", subtype: " << photoInfo.subtype
       << ", videoFilePath: " << photoInfo.videoFilePath << ", editDataFolder: " << photoInfo.editDataFolder << "]";
    return ss.str();
}

/**
 * @brief Copy Photo File, include photo file, video file and edit data folder.
 */
int32_t PhotoFileOperation::CopyPhoto(
    const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::string &targetPath)
{
    if (resultSet == nullptr || targetPath.empty()) {
        MEDIA_ERR_LOG("Media_Operation: CopyPhoto failed, resultSet is null or targetPath is empty");
        return E_FAIL;
    }
    // Build the Original Photo Asset Info
    PhotoFileOperation::PhotoAssetInfo sourcePhotoInfo;
    sourcePhotoInfo.displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultSet);
    sourcePhotoInfo.filePath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    sourcePhotoInfo.subtype = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
    sourcePhotoInfo.dateModified = GetInt64Val(MediaColumn::MEDIA_DATE_MODIFIED, resultSet);
    sourcePhotoInfo.videoFilePath = this->FindVideoFilePath(sourcePhotoInfo);
    sourcePhotoInfo.editDataFolder = this->FindEditDataFolder(sourcePhotoInfo);
    // Build the Target Photo Asset Info
    PhotoFileOperation::PhotoAssetInfo targetPhotoInfo;
    targetPhotoInfo.displayName = sourcePhotoInfo.displayName;
    targetPhotoInfo.filePath = targetPath;
    targetPhotoInfo.subtype = sourcePhotoInfo.subtype;
    targetPhotoInfo.dateModified = sourcePhotoInfo.dateModified;
    // No need to copy video file if the Original Photo is not a moving photo.
    if (!sourcePhotoInfo.videoFilePath.empty()) {
        targetPhotoInfo.videoFilePath = this->GetVideoFilePath(targetPhotoInfo);
    }
    // No need to copy edit data folder if the Original Photo is not edited.
    if (!sourcePhotoInfo.editDataFolder.empty()) {
        targetPhotoInfo.editDataFolder = this->BuildEditDataFolder(targetPhotoInfo);
    }
    MEDIA_INFO_LOG("Media_Operation: sourcePhotoInfo: %{public}s, targetPhotoInfo: %{public}s",
        this->ToString(sourcePhotoInfo).c_str(),
        this->ToString(targetPhotoInfo).c_str());
    return this->CopyPhoto(sourcePhotoInfo, targetPhotoInfo);
}

/**
 * @brief Copy Photo File, include photo file, video file and edit data folder.
 */
int32_t PhotoFileOperation::CopyPhoto(const PhotoFileOperation::PhotoAssetInfo &sourcePhotoInfo,
    const PhotoFileOperation::PhotoAssetInfo &targetPhotoInfo)
{
    int32_t opRet = this->CopyPhotoFile(sourcePhotoInfo, targetPhotoInfo);
    if (opRet != E_OK) {
        return opRet;
    }
    opRet = this->CopyPhotoRelatedVideoFile(sourcePhotoInfo, targetPhotoInfo);
    if (opRet != E_OK) {
        return opRet;
    }
    return this->CopyPhotoRelatedExtraData(sourcePhotoInfo, targetPhotoInfo);
}

/**
 * @brief Get the video file path of the photo, without any check.
 * @return the video file path of the photo. Only replace the suffix of file extension, such as .jpg to .mp4.
 * @example if filePath is /xxx/.../xxx/123456789.jpg, then return /xxx/.../xxx/123456789.mp4.
 */
std::string PhotoFileOperation::GetVideoFilePath(const PhotoFileOperation::PhotoAssetInfo &photoInfo)
{
    return MediaFileUtils::GetMovingPhotoVideoPath(photoInfo.filePath);
}

/**
 * @brief Get the video file path of the photo, without any check.
 * @return the video file path of the photo. Only replace the suffix of file extension, such as .jpg to .mp4.
 *         If the photo is not a moving photo, return an empty string.
 *         If the photo's file path is empty, return an empty string.
 *         If the photo is a moving photo, return the video file path of the photo.
 */
std::string PhotoFileOperation::FindVideoFilePath(const PhotoFileOperation::PhotoAssetInfo &photoInfo)
{
    if (photoInfo.subtype != static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        return "";
    }
    // If file path is empty, return empty string. Trace log will be printed in CopyPhotoFile.
    if (photoInfo.filePath.empty()) {
        return "";
    }
    std::string videoFilePath = this->GetVideoFilePath(photoInfo);
    if (!MediaFileUtils::IsFileExists(videoFilePath)) {
        MEDIA_WARN_LOG("Media_Operation: videoFilePath not exists, videoFilePath: %{public}s, Object: %{public}s.",
            videoFilePath.c_str(),
            this->ToString(photoInfo).c_str());
        return "";
    }
    return videoFilePath;
}

/**
 * @brief Find the Relative Path of filePath.
 * @return Relative Path.
 *         If prefix of filePath is "/storage/cloud/files", return the relative path of cloud prefix.
 *         If prefix of filePath is "/storage/media/local/files", return the relative path of local prefix.
 *         Otherwise, return empty string.
 */
std::string PhotoFileOperation::FindRelativePath(const std::string &filePath)
{
    std::string prefix = "/storage/cloud/files";
    size_t pos = filePath.find(prefix);
    if (pos != std::string::npos) {
        return filePath.substr(pos + prefix.size());
    }
    prefix = "/storage/media/local/files";
    pos = filePath.find(prefix);
    if (pos != std::string::npos) {
        return filePath.substr(pos + prefix.size());
    }
    MEDIA_ERR_LOG("Media_Operation: Find RelativePath failed, filePath: %{public}s", filePath.c_str());
    return "";
}

/**
 * @brief Find the prefix of Edit Data Folder.
 * @return Return the prefix of Edit Data Folder.
 *         There are two prefixes, one is local, the other is cloud.
 *         If the prefix of filePath is cloud, return "/storage/cloud/files/.editData".
 *         If the prefix of filePath is local, return "/storage/media/local/files/.editData";
 *         If the prefix of filePath is not found, return "".
 */
std::string PhotoFileOperation::FindPrefixOfEditDataFolder(const std::string &filePath)
{
    std::string prefix = "/storage/cloud/files";
    size_t pos = filePath.find(prefix);
    if (pos != std::string::npos) {
        return "/storage/cloud/files/.editData";
    }
    prefix = "/storage/media/local/files";
    pos = filePath.find(prefix);
    if (pos != std::string::npos) {
        return "/storage/media/local/files/.editData";
    }
    MEDIA_WARN_LOG("Media_Operation: Get Prefix failed, filePath: %{public}s", filePath.c_str());
    return "";
}

/**
 * @brief Build the Edit Data Folder for the Photo file, without any check.
 * @return Return the Edit Data Folder for the Photo file.
 *         If the filePath is cloud, return "/storage/cloud/files/.editData/" + the relativePath of Photo file.
 *         If the filePath is local, return "/storage/media/local/files/.editData/" + the relativePath of Photo file.
 *         If the filePath is not identified, return "".
 */
std::string PhotoFileOperation::BuildEditDataFolder(const PhotoFileOperation::PhotoAssetInfo &photoInfo)
{
    std::string prefix = this->FindPrefixOfEditDataFolder(photoInfo.filePath);
    std::string relativePath = this->FindRelativePath(photoInfo.filePath);
    if (prefix.empty() || relativePath.empty()) {
        return "";
    }
    return prefix + relativePath;
}

/**
 * @brief Find the Edit Data Folder for the Photo file.
 * @return Return the Edit Data Folder path. If the Edit Data Folder is invalid, return empty string.
 *         If the Edit Data Folder is not exist, has 3 scenario:
 *         1. The photo file is not edited. Normal scenario.
 *         2. The photo file is not MOVING_PHOTO. Noraml scenario.
 *         3. The photo file is edited or MOVING_PHOTO, but the Edit Data Folder is not exist. Exceptional scenario.
 */
std::string PhotoFileOperation::FindEditDataFolder(const PhotoFileOperation::PhotoAssetInfo &photoInfo)
{
    std::string editDataFolderPath = this->BuildEditDataFolder(photoInfo);
    if (!editDataFolderPath.empty() && !MediaFileUtils::IsFileExists(editDataFolderPath)) {
        MEDIA_INFO_LOG("Media_Operation: EditDataFolder not exists, It may not be edited photo or moving photo. "
                       "Object: %{public}s.",
            this->ToString(photoInfo).c_str());
        return "";
    }
    return editDataFolderPath;
}

/**
 * @brief Copy Photo File, only include the photo file defined in the Photos table.
 * @return E_OK if success,
 *         E_INVALID_PATH if the source file or target file is invalid,
 *         E_FILE_OPER_FAIL if the copy operation failed.
 */
int32_t PhotoFileOperation::CopyPhotoFile(const PhotoFileOperation::PhotoAssetInfo &sourcePhotoInfo,
    const PhotoFileOperation::PhotoAssetInfo &targetPhotoInfo)
{
    std::string srcPath = sourcePhotoInfo.filePath;
    std::string targetPath = targetPhotoInfo.filePath;
    int64_t dateModified = targetPhotoInfo.dateModified;
    // If File Path is empty, return E_INVALID_PATH.
    if (srcPath.empty() || targetPath.empty()) {
        MEDIA_ERR_LOG("Media_Operation: CopyPhotoFile failed, srcPath or targetPath is empty. "
                      "Source Object: %{public}s, Target Object: %{public}s",
            this->ToString(sourcePhotoInfo).c_str(),
            this->ToString(targetPhotoInfo).c_str());
        return E_INVALID_PATH;
    }
    int32_t opRet = this->CopyFile(srcPath, targetPath);
    if (opRet != E_OK) {
        MEDIA_ERR_LOG("Media_Operation: CopyPhoto failed, srcPath: %{public}s, targetPath: %{public}s",
            srcPath.c_str(),
            targetPath.c_str());
        return opRet;
    }
    MediaFileUtils::ModifyFile(targetPath, dateModified / MSEC_TO_SEC);
    MEDIA_INFO_LOG("Media_Operation: CopyPhotoFile success, srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(),
        targetPath.c_str());
    return E_OK;
}

/**
 * @brief Copy Photo File, only include the vide file related to the photo file defined in the Photos table.
 * @return E_OK if success or not MOVING_PHOTO or video file empty,
 *         E_INVALID_PATH if the source file or target file is invalid,
 *         E_FILE_OPER_FAIL if the copy operation failed.
 */
int32_t PhotoFileOperation::CopyPhotoRelatedVideoFile(const PhotoFileOperation::PhotoAssetInfo &sourcePhotoInfo,
    const PhotoFileOperation::PhotoAssetInfo &targetPhotoInfo)
{
    // If photoSubtype is MOVING_PHOTO, copy video file.
    if (sourcePhotoInfo.subtype != static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        return E_OK;
    }
    std::string srcVideoPath = sourcePhotoInfo.videoFilePath;
    std::string targetVideoPath = targetPhotoInfo.videoFilePath;
    int64_t dateModified = targetPhotoInfo.dateModified;
    // If video file is empty, return E_OK. Trace log will be printed in FindVideoFilePath.
    if (srcVideoPath.empty() || targetVideoPath.empty()) {
        return E_OK;
    }
    int32_t opRet = this->CopyFile(srcVideoPath, targetVideoPath);
    if (opRet != E_OK) {
        MEDIA_ERR_LOG("Media_Operation: CopyPhoto Video failed, srcPath: %{public}s, targetPath: %{public}s",
            srcVideoPath.c_str(),
            targetVideoPath.c_str());
        return opRet;
    }
    MediaFileUtils::ModifyFile(targetVideoPath, dateModified / MSEC_TO_SEC);
    MEDIA_INFO_LOG("Media_Operation: CopyPhotoRelatedVideoFile success, srcPath: %{public}s, targetPath: %{public}s",
        srcVideoPath.c_str(),
        targetVideoPath.c_str());
    return E_OK;
}

/**
 * @brief Copy the Edit Data.
 * @return E_OK if success or not edited photo.
 *         E_NO_SUCH_FILE if the source Edit Data Folder not exits.
 *         E_FAIL if the copy operation failed.
 */
int32_t PhotoFileOperation::CopyPhotoRelatedExtraData(const PhotoFileOperation::PhotoAssetInfo &sourcePhotoInfo,
    const PhotoFileOperation::PhotoAssetInfo &targetPhotoInfo)
{
    std::string srcEditDataFolder = sourcePhotoInfo.editDataFolder;
    std::string targetEditDataFolder = targetPhotoInfo.editDataFolder;
    // If Edit Data Folder is empty, return E_OK. Trace log will be printed in FindEditDataFolder.
    if (srcEditDataFolder.empty() || targetEditDataFolder.empty()) {
        return E_OK;
    }
    if (!MediaFileUtils::IsFileExists(srcEditDataFolder)) {
        MEDIA_ERR_LOG("Media_Operation: %{public}s doesn't exist. %{pubilc}s",
            srcEditDataFolder.c_str(),
            this->ToString(sourcePhotoInfo).c_str());
        return E_NO_SUCH_FILE;
    }
    int32_t opRet = MediaFileUtils::CreateDirectoryAndCopyFiles(srcEditDataFolder, targetEditDataFolder);
    if (opRet != E_OK) {
        MEDIA_ERR_LOG("Media_Operation: CopyPhoto extraData failed, srcPath: %{public}s, targetPath: %{public}s",
            srcEditDataFolder.c_str(),
            targetEditDataFolder.c_str());
        return opRet;
    }
    MEDIA_INFO_LOG("Media_Operation: CopyPhotoRelatedExtraData success, srcPath: %{public}s, targetPath: %{public}s",
        srcEditDataFolder.c_str(),
        targetEditDataFolder.c_str());
    return E_OK;
}

/**
 * @brief Copy File.
 * @return E_OK if success,
 *         E_INVALID_PATH if the source file or target file is invalid,
 *         E_FILE_OPER_FAIL if the copy operation failed.
 */
int32_t PhotoFileOperation::CopyFile(const std::string &srcPath, std::string &targetPath)
{
    if (srcPath.empty() || !MediaFileUtils::IsFileExists((srcPath)) || !MediaFileUtils::IsFileValid(srcPath)) {
        MEDIA_ERR_LOG("Media_Operation: source file invalid! srcPath: %{public}s", srcPath.c_str());
        return E_INVALID_PATH;
    }
    if (targetPath.empty()) {
        MEDIA_ERR_LOG("Media_Operation: target file invalid! targetPath: %{public}s", targetPath.c_str());
        return E_INVALID_PATH;
    }
    bool opRet = MediaFileUtils::CopyFileUtil(srcPath, targetPath);
    opRet = opRet && MediaFileUtils::IsFileExists(targetPath);
    if (!opRet) {
        MEDIA_ERR_LOG("Media_Operation: CopyFile failed, filePath: %{public}s, errmsg: %{public}s",
            srcPath.c_str(),
            strerror(errno));
        return E_FILE_OPER_FAIL;
    }
    return E_OK;
}
}  // namespace OHOS::Media