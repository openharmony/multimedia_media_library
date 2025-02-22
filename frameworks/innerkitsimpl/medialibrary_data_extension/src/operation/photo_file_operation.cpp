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
#include "medialibrary_kvstore_utils.h"
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
       << ", videoFilePath: " << photoInfo.videoFilePath << ", editDataFolder: " << photoInfo.editDataFolder
       << ", thumbnailFolder: " << photoInfo.thumbnailFolder << "]";
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
 * @brief Copy thumbnail, include folder and astc data.
 */
int32_t PhotoFileOperation::CopyThumbnail(
    const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const std::string &targetPath, int64_t &newAssetId)
{
    if (resultSet == nullptr || targetPath.empty()) {
        MEDIA_ERR_LOG("Media_Operation: CopyPhoto failed, resultSet is null or targetPath is empty");
        return E_FAIL;
    }

    // Build the Original Photo Asset Info
    PhotoFileOperation::PhotoAssetInfo sourcePhotoInfo;
    sourcePhotoInfo.filePath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    sourcePhotoInfo.thumbnailFolder = this->FindThumbnailFolder(sourcePhotoInfo);
    if (sourcePhotoInfo.thumbnailFolder.empty()) {
        MEDIA_INFO_LOG("Source thumbnail is empty, skip copy. thumbnailFolder:%{public}s",
            sourcePhotoInfo.thumbnailFolder.c_str());
        return E_FAIL;
    }

    // copy folder
    PhotoFileOperation::PhotoAssetInfo targetPhotoInfo;
    targetPhotoInfo.filePath = targetPath;
    targetPhotoInfo.thumbnailFolder = this->BuildThumbnailFolder(targetPhotoInfo);
    int32_t opRet = this->CopyPhotoRelatedThumbnail(sourcePhotoInfo, targetPhotoInfo);
    if (opRet != E_OK) {
        return opRet;
    }

    std::string dateTaken = to_string(GetInt64Val(MediaColumn::MEDIA_DATE_TAKEN, resultSet));
    std::string oldAssetId = to_string(GetInt64Val(MediaColumn::MEDIA_ID, resultSet));
    return HandleThumbnailAstcData(dateTaken, oldAssetId, to_string(newAssetId));
}

int32_t PhotoFileOperation::HandleThumbnailAstcData(const std::string &dateTaken, const std::string &oldAssetId,
    const std::string &newAssetId)
{
    // 取旧key拿value，然后在put新key和value（和旧的value一样）到kvstore中
    string oldKey;
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::GenerateKvStoreKey(oldAssetId, dateTaken, oldKey), E_ERR,
        "GenerateKvStoreKey failed");

    string newKey;
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::GenerateKvStoreKey(newAssetId, dateTaken, newKey), E_ERR,
        "GenerateKvStoreKey failed");

    int32_t err = MediaLibraryKvStoreUtils::CopyAstcDataToKvStoreByType(KvStoreValueType::MONTH_ASTC, oldKey, newKey);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "CopyAstcDataToKvStoreByType failed, err: %{public}d", err);

    err = MediaLibraryKvStoreUtils::CopyAstcDataToKvStoreByType(KvStoreValueType::YEAR_ASTC, oldKey, newKey);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "CopyAstcDataToKvStoreByType failed, err: %{public}d", err);
    MEDIA_INFO_LOG("Success to copy thumbnail. oldKey:%{public}s, newKey:%{public}s", oldKey.c_str(), newKey.c_str());
    return E_OK;
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
 * @brief Find the prefix of photo Data Folder.
 * @return Return the prefix of photo Data Folder.
 *         There are two prefixes, one is local, the other is cloud.
 *         If the prefix of filePath is cloud, return "/storage/cloud/files/" + dataName.
 *         If the prefix of filePath is local, return "/storage/media/local/files/" + dataName;
 *         If the prefix of filePath is not found, return "".
 */
std::string PhotoFileOperation::FindPrefixDataFolder(const std::string &filePath, const std::string &dataName)
{
    std::string prefix = "/storage/cloud/files";
    size_t pos = filePath.find(prefix);
    if (pos != std::string::npos) {
        return "/storage/cloud/files/" + dataName;
    }
    prefix = "/storage/media/local/files";
    pos = filePath.find(prefix);
    if (pos != std::string::npos) {
        return "/storage/media/local/files/" + dataName;
    }
    MEDIA_WARN_LOG("Media_Operation: Get Prefix failed, filePath: %{public}s", filePath.c_str());
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
    return FindPrefixDataFolder(filePath, ".editData");
}

/**
 * @brief Find the prefix of thumbs Data Folder.
 * @return Return the prefix of thumbs Data Folder.
 *         There are two prefixes, one is local, the other is cloud.
 *         If the prefix of filePath is cloud, return "/storage/cloud/files/.thumbs".
 *         If the prefix of filePath is local, return "/storage/media/local/files/.thumbs";
 *         If the prefix of filePath is not found, return "".
 */
std::string PhotoFileOperation::FindPrefixOfThumbnailFolder(const std::string &filePath)
{
    return FindPrefixDataFolder(filePath, ".thumbs");
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
 * @brief Build the thumbs Data Folder for the Photo file, without any check.
 * @return Return the thumbs Data Folder for the Photo file.
 *         If the filePath is cloud, return "/storage/cloud/files/.thumbs/" + the relativePath of Photo file.
 *         If the filePath is local, return "/storage/media/local/files/.thumbs/" + the relativePath of Photo file.
 *         If the filePath is not identified, return "".
 */
std::string PhotoFileOperation::BuildThumbnailFolder(const PhotoFileOperation::PhotoAssetInfo &photoInfo)
{
    std::string prefix = this->FindPrefixOfThumbnailFolder(photoInfo.filePath);
    std::string relativePath = this->FindRelativePath(photoInfo.filePath);
    if (prefix.empty() || relativePath.empty()) {
        return "";
    }
    return prefix + relativePath;
}

/**
 * @brief Find the thumbs Data Folder for the Photo file.
 * @return Return the thumbs Data Folder path. If the thumbs Data Folder is invalid, return empty string.
 *         If the thumbs Data Folder is not exist, has 3 scenario:
 *         1. The photo file is not thumbs. Normal scenario.
 *         2. The photo file is not MOVING_PHOTO. Noraml scenario.
 *         3. The photo file is thumbs or MOVING_PHOTO, but the thumbs Data Folder is not exist. Exceptional scenario.
 */
std::string PhotoFileOperation::FindThumbnailFolder(const PhotoFileOperation::PhotoAssetInfo &photoInfo)
{
    std::string thumbnailFolderPath = this->BuildThumbnailFolder(photoInfo);
    if (!thumbnailFolderPath.empty() && !MediaFileUtils::IsFileExists(thumbnailFolderPath)) {
        MEDIA_INFO_LOG("Media_Operation: thumbnailFolder not exists, Object: %{public}s.",
            this->ToString(photoInfo).c_str());
        return "";
    }
    return thumbnailFolderPath;
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
    CHECK_AND_RETURN_RET_LOG(opRet == E_OK, opRet,
        "Media_Operation: CopyPhoto Video failed, srcPath: %{public}s, targetPath: %{public}s", srcVideoPath.c_str(),
        targetVideoPath.c_str());
    MediaFileUtils::ModifyFile(targetVideoPath, dateModified / MSEC_TO_SEC);
    MEDIA_INFO_LOG("Media_Operation: CopyPhotoRelatedVideoFile success, srcPath: %{public}s, targetPath: %{public}s",
        srcVideoPath.c_str(),
        targetVideoPath.c_str());
    return E_OK;
}

int32_t PhotoFileOperation::CopyPhotoRelatedData(const PhotoFileOperation::PhotoAssetInfo &sourcePhotoInfo,
    const PhotoFileOperation::PhotoAssetInfo &targetPhotoInfo,
    const std::string& srcFolder, const std::string& targetFolder)
{
    if (srcFolder.empty() || targetFolder.empty()) {
        return E_OK;
    }
    if (!MediaFileUtils::IsFileExists(srcFolder)) {
        MEDIA_ERR_LOG("Media_Operation: %{public}s doesn't exist. %{public}s",
            srcFolder.c_str(), this->ToString(sourcePhotoInfo).c_str());
        return E_NO_SUCH_FILE;
    }
    int32_t opRet = MediaFileUtils::CopyDirectory(srcFolder, targetFolder);
    if (opRet != E_OK) {
        MEDIA_ERR_LOG("Media_Operation: CopyPhoto extraData failed, sourceInfo: %{public}s, targetInfo: %{public}s",
            this->ToString(sourcePhotoInfo).c_str(), this->ToString(targetPhotoInfo).c_str());
        return opRet;
    }
    MEDIA_INFO_LOG("Media_Operation: CopyPhotoRelatedExtraData success, sourceInfo:%{public}s, targetInfo:%{public}s",
        this->ToString(sourcePhotoInfo).c_str(), this->ToString(targetPhotoInfo).c_str());
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
    return CopyPhotoRelatedData(sourcePhotoInfo, targetPhotoInfo, srcEditDataFolder, targetEditDataFolder);
}

/**
 * @brief Copy the thumbnail Data.
 * @return E_OK if success or not thumbnail folder.
 *         E_NO_SUCH_FILE if the source Edit Data Folder not exits.
 *         E_FAIL if the copy operation failed.
 */
int32_t PhotoFileOperation::CopyPhotoRelatedThumbnail(const PhotoFileOperation::PhotoAssetInfo &sourcePhotoInfo,
    const PhotoFileOperation::PhotoAssetInfo &targetPhotoInfo)
{
    std::string srcThumbnailFolder = sourcePhotoInfo.thumbnailFolder;
    std::string targetThumbnailFolder = targetPhotoInfo.thumbnailFolder;
    int32_t opRet = CopyPhotoRelatedData(sourcePhotoInfo, targetPhotoInfo, srcThumbnailFolder, targetThumbnailFolder);
    CHECK_AND_RETURN_RET_LOG(opRet == E_OK, opRet,
        "Media_Operation: CopyPhoto thumbnail failed, srcPath: %{public}s, targetPath: %{public}s",
        srcThumbnailFolder.c_str(), targetThumbnailFolder.c_str());

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