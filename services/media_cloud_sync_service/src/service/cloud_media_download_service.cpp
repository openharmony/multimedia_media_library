/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Cloud_Service"

#include "cloud_media_download_service.h"

#include "cover_position_parser.h"
#include "directory_ex.h"
#include "parameters.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "moving_photo_file_utils.h"
#include "cloud_media_file_utils.h"
#include "cloud_media_attachment_utils.h"
#include "cloud_media_sync_utils.h"
#include "cloud_sync_notify_handler.h"
#include "thumbnail_const.h"
#include "thumbnail_service.h"
#include "cloud_media_asset_manager.h"
#include "cloud_media_asset_types.h"
#include "cloud_media_dfx_service.h"
#include "dfx_const.h"
#include "media_gallery_sync_notify.h"

namespace OHOS::Media::CloudSync {
using ChangeType = AAFwk::ChangeInfo::ChangeType;
int32_t CloudMediaDownloadService::GetDownloadThmNum(const int32_t type, int32_t &totalNum)
{
    return this->dao_.GetDownloadThmNum(type, totalNum);
}

int32_t CloudMediaDownloadService::GetDownloadThms(
    const DownloadThumbnailQueryDto &queryDto, std::vector<PhotosDto> &photosDtos)
{
    std::vector<PhotosPo> photosPos;
    int32_t ret = this->dao_.GetDownloadThms(queryDto, photosPos);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "GetDownloadThms failed, ret:%{public}d", ret);
    photosDtos = this->processor_.GetPhotosDto(photosPos);
    return ret;
}

std::vector<PhotosDto> CloudMediaDownloadService::GetDownloadThmsByUri(
    const std::vector<int32_t> &fileIds, const int32_t type)
{
    MEDIA_INFO_LOG("enter CloudMediaDownloadService::GetDownloadThmsByUri type:%{public}d", type);
    std::vector<PhotosDto> photosDtoVec;
    std::vector<PhotosPo> photosPos;
    int32_t ret = this->dao_.GetDownloadAsset(fileIds, photosPos);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, photosDtoVec, "GetDownloadAsset failed, ret:%{public}d", ret);
    std::vector<DownloadAssetData> downloadAssetDataVec;
    this->processor_.GetDownloadAssetData(photosPos, downloadAssetDataVec);
    MEDIA_INFO_LOG("GetDownloadThmsByUri size of downloadAssetDataVec: %{public}zu", downloadAssetDataVec.size());
    CHECK_AND_RETURN_RET_LOG(
        !downloadAssetDataVec.empty(), photosDtoVec, "GetDownloadThmsByUri Failed to get downloadAssetDataVec.");
    for (const auto &downloadAssetData : downloadAssetDataVec) {
        std::string filePath;
        std::string fileName;
        CHECK_AND_RETURN_RET_LOG(
            CloudMediaFileUtils::GetParentPathAndFilename(downloadAssetData.path, filePath, fileName),
            photosDtoVec,
            "GetDownloadThmsByUri failed to GetParentPathAndFilename");
        PhotosDto photosDto;
        photosDto.fileId = downloadAssetData.fileId;
        photosDto.cloudId = downloadAssetData.cloudId;
        photosDto.data = filePath;
        photosDto.mediaType = downloadAssetData.mediaType;
        photosDto.size = downloadAssetData.fileSize;
        photosDto.path = downloadAssetData.path;
        photosDto.modifiedTime = downloadAssetData.editTime;
        photosDto.fileName = fileName;
        photosDto.originalCloudId = downloadAssetData.originalCloudId;
        int32_t retThm = E_OK;
        int32_t retLcd = E_OK;
        if (static_cast<uint32_t>(type) & TYPE_THM_MASK) {
            retThm = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadAssetData, photosDto);
            CHECK_AND_PRINT_LOG(retThm == E_OK, "GetDownloadThmsByUri GetAttachment thm fail");
        }
        if (static_cast<uint32_t>(type) & TYPE_LCD_MASK) {
            retLcd = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadAssetData, photosDto);
            CHECK_AND_PRINT_LOG(retLcd == E_OK, "GetDownloadThmsByUri GetAttachment lcd fail");
        }
        if ((retThm != E_OK) && (retLcd != E_OK)) {
            continue;
        }
        MEDIA_DEBUG_LOG("GetDownloadThmsByUri Photo: %{public}s", photosDto.ToString().c_str());
        photosDtoVec.push_back(photosDto);
    }
    return photosDtoVec;
}

int32_t CloudMediaDownloadService::OnDownloadThm(
    const std::vector<std::string> &thmVector, std::vector<MediaOperateResultDto> &result)
{
    CHECK_AND_RETURN_RET_LOG(!thmVector.empty(), E_OK, "thmVector is empty");
    MEDIA_INFO_LOG("size of thmVector is %{public}zu", thmVector.size());
    int32_t ret = this->dao_.UpdateDownloadThm(thmVector);
    CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to UpdateDownloadThms.");
    if (ret == E_OK && !thmVector.empty()) {
        CloudMediaDfxService::UpdateAttachmentStat(INDEX_THUMB_SUCCESS, thmVector.size());
    }
    /* 通知
     DataSyncNotifier::GetInstance().TryNotify(PHOTO_URI_PREFIX, ChangeType::INSERT, "");
     DataSyncNotifier::GetInstance().FinalNotify();
    */
    MediaGallerySyncNotify::GetInstance().TryNotify(PhotoColumn::PHOTO_CLOUD_URI_PREFIX, ChangeType::INSERT, "");
    MediaGallerySyncNotify::GetInstance().FinalNotify();
    for (auto &thm : thmVector) {  // collect results
        MediaOperateResultDto mediaResult;
        mediaResult.cloudId = thm;
        mediaResult.errorCode = ret;
        result.emplace_back(mediaResult);
    }
    return ret;
}

int32_t CloudMediaDownloadService::OnDownloadLcd(
    const std::vector<std::string> &lcdVector, std::vector<MediaOperateResultDto> &result)
{
    CHECK_AND_RETURN_RET_LOG(!lcdVector.empty(), E_OK, "lcdVector is empty");
    MEDIA_INFO_LOG("size of lcdVector is %{public}zu", lcdVector.size());
    int32_t ret = this->dao_.UpdateDownloadLcd(lcdVector);
    CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to UpdateDownloadLcd.");
    if (ret == E_OK && !lcdVector.empty()) {
        CloudMediaDfxService::UpdateAttachmentStat(INDEX_LCD_SUCCESS, lcdVector.size());
    }
    for (auto &thm : lcdVector) {  // collect results
        MediaOperateResultDto mediaResult;
        mediaResult.cloudId = thm;
        mediaResult.errorCode = ret;
        result.emplace_back(mediaResult);
    }
    return ret;
}

int32_t CloudMediaDownloadService::OnDownloadThmAndLcd(
    const std::vector<std::string> &bothVector, std::vector<MediaOperateResultDto> &result)
{
    CHECK_AND_RETURN_RET_LOG(!bothVector.empty(), E_OK, "bothVector is empty");
    MEDIA_INFO_LOG("size of bothVector is %{public}zu", bothVector.size());
    int32_t ret = this->dao_.UpdateDownloadThmAndLcd(bothVector);
    CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to UpdateDownloadThmAndLcd.");
    if (ret == E_OK && !bothVector.empty()) {
        CloudMediaDfxService::UpdateAttachmentStat(INDEX_THUMB_SUCCESS, bothVector.size());
        CloudMediaDfxService::UpdateAttachmentStat(INDEX_LCD_SUCCESS, bothVector.size());
    }
    for (auto &thm : bothVector) {  // collect results
        MediaOperateResultDto mediaResult;
        mediaResult.cloudId = thm;
        mediaResult.errorCode = ret;
        result.emplace_back(mediaResult);
    }
    return ret;
}

void CloudMediaDownloadService::NotifyDownloadLcd(const std::vector<std::string> &cloudIds)
{
    std::vector<std::string> fileIds;
    this->dao_.GetFileIdFromCloudId(cloudIds, fileIds);
    MEDIA_INFO_LOG("size of fileIds is %{public}zu", fileIds.size());
    for (auto &fileId : fileIds) {
        std::string uri = PhotoColumn::PHOTO_CLOUD_URI_PREFIX + fileId;
        MediaGallerySyncNotify::GetInstance().TryNotify(uri, ChangeType::INSERT, "");
    }
    MediaGallerySyncNotify::GetInstance().FinalNotify();
}

bool CloudMediaDownloadService::IsCloudInsertTaskPriorityHigh()
{
    int32_t cloudSyncStatus = static_cast<int32_t>(system::GetParameter(CLOUDSYNC_STATUS_KEY, "0").at(0) - '0');
    MEDIA_INFO_LOG("cloudSyncStatus: %{public}d", cloudSyncStatus);
    return cloudSyncStatus == CloudSyncStatus::FIRST_FIVE_HUNDRED ||
           cloudSyncStatus == CloudSyncStatus::INCREMENT_DOWNLOAD;
}

int32_t CloudMediaDownloadService::OnDownloadThms(
    const std::unordered_map<std::string, int32_t> &downloadThumbnailMap, std::vector<MediaOperateResultDto> &result)
{
    MEDIA_INFO_LOG("enter CloudMediaDownloadService::OnDownloadThms");
    std::vector<std::string> thmVector;
    std::vector<std::string> lcdVector;
    std::vector<std::string> bothVector;
    std::vector<std::string> astcVector;
    MEDIA_INFO_LOG("size of downloadThumbnailMap is %{public}zu", downloadThumbnailMap.size());
    for (auto &pair : downloadThumbnailMap) {
        //(key,value) => key : cloudId, value : 001-> thm, 010 -> lcd, 011 -> thm and lcd, 100 -> astc(端云不会下载astc)
        if (pair.second == TYPE_THM) {
            thmVector.emplace_back(pair.first);
        } else if (pair.second == TYPE_LCD) {
            lcdVector.emplace_back(pair.first);
        } else if (pair.second == TYPE_THM_AND_LCD) {
            bothVector.emplace_back(pair.first);
        }
    }

    int32_t ret = E_ERR;
    ret = this->OnDownloadThm(thmVector, result);
    ret = this->OnDownloadLcd(lcdVector, result);
    if (ret == E_OK) {
        astcVector.insert(astcVector.end(), lcdVector.begin(), lcdVector.end());
    }
    ret = this->OnDownloadThmAndLcd(bothVector, result);
    if (ret == E_OK) {
        astcVector.insert(astcVector.end(), bothVector.begin(), bothVector.end());
    }
    MEDIA_INFO_LOG("size of astcVector is %{public}zu", astcVector.size());
    this->NotifyDownloadLcd(astcVector);
    return E_OK;
}

std::vector<PhotosDto> CloudMediaDownloadService::GetDownloadAsset(const std::vector<int32_t> &fileIds)
{
    MEDIA_INFO_LOG("enter CloudMediaDownloadService::GetDownloadAsset");
    std::vector<PhotosDto> photosDtoVec;
    std::vector<PhotosPo> photosPos;
    int32_t ret = this->dao_.GetDownloadAsset(fileIds, photosPos);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, photosDtoVec, "GetDownloadAsset failed, ret:%{public}d", ret);
    std::vector<DownloadAssetData> downloadAssetDataVec;
    this->processor_.GetDownloadAssetData(photosPos, downloadAssetDataVec);
    MEDIA_INFO_LOG("GetDownloadAsset size of downloadAssetDataVec: %{public}zu", downloadAssetDataVec.size());
    CHECK_AND_RETURN_RET_LOG(
        !downloadAssetDataVec.empty(), photosDtoVec, "GetDownloadAsset Failed to get downloadAssetDataVec.");
    for (const auto &downloadAssetData : downloadAssetDataVec) {
        std::string filePath;
        std::string fileName;
        CHECK_AND_RETURN_RET_LOG(
            CloudMediaFileUtils::GetParentPathAndFilename(downloadAssetData.path, filePath, fileName),
            photosDtoVec,
            "GetDownloadAsset failed to GetParentPathAndFilename");
        PhotosDto photosDto;
        photosDto.fileId = downloadAssetData.fileId;
        photosDto.cloudId = downloadAssetData.cloudId;
        photosDto.data = filePath;
        photosDto.mediaType = downloadAssetData.mediaType;
        photosDto.size = downloadAssetData.fileSize;
        photosDto.path = downloadAssetData.path;
        photosDto.modifiedTime = downloadAssetData.editTime;
        photosDto.fileName = fileName;
        photosDto.originalCloudId = downloadAssetData.originalCloudId;

        CHECK_AND_RETURN_RET_LOG(
            CloudMediaAttachmentUtils::GetAttachment("content", downloadAssetData, photosDto) == E_OK,
            photosDtoVec,
            "failed to GetAttachment");
        MEDIA_DEBUG_LOG("GetDownloadAsset Photo: %{public}s", photosDto.ToString().c_str());

        photosDtoVec.push_back(photosDto);
    }
    return photosDtoVec;
}

CloudMediaDownloadService::OnDownloadAssetData CloudMediaDownloadService::GetOnDownloadAssetData(PhotosPo &photosPo)
{
    CloudMediaDownloadService::OnDownloadAssetData assetData;
    assetData.err = E_OK;
    assetData.errorMsg = "";
    bool isMovingPhoto = CloudMediaSyncUtils::IsMovingPhoto(photosPo);
    bool isGraffiti = CloudMediaSyncUtils::IsGraffiti(photosPo);
    bool isLivePhoto = CloudMediaSyncUtils::IsLivePhoto(photosPo);
    bool isInvalidCover = photosPo.coverPosition.value_or(0) == 0 && photosPo.isRectificationCover.value_or(0) == 0;
    MEDIA_INFO_LOG("GetOnDownloadAssetData %{public}d,%{public}d,%{public}d", isMovingPhoto, isGraffiti, isLivePhoto);
    assetData.fixFileType = isMovingPhoto && !isGraffiti && !isLivePhoto;
    assetData.needSliceContent = (isMovingPhoto && !isGraffiti) && isLivePhoto;
    assetData.needParseCover = isMovingPhoto && isInvalidCover;
    assetData.needSliceRaw = isMovingPhoto;
    assetData.path = photosPo.data.value_or("");
    assetData.localPath = CloudMediaSyncUtils::GetLocalPath(assetData.path);
    assetData.dateModified = photosPo.dateModified.value_or(0);
    std::string extraUri = MediaFileUtils::GetExtraUri(photosPo.displayName.value_or(""), photosPo.data.value_or(""));
    assetData.fileUri = MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX,
                                                               std::to_string(photosPo.fileId.value_or(0)), extraUri);
    return assetData;
}

void CloudMediaDownloadService::UnlinkAsset(OnDownloadAssetData &assetData)
{
    int32_t ret = unlink(assetData.localPath.c_str());
    if (ret != 0) {
        assetData.err = errno;  // err always -1, use errno.
        assetData.errorMsg = "unlink failed";
        MEDIA_WARN_LOG("DownloadAsset unlink %{public}s failed", assetData.localPath.c_str());
    }
}

void CloudMediaDownloadService::ResetAssetModifyTime(OnDownloadAssetData &assetData)
{
    MEDIA_INFO_LOG("UpdateModifyTime: %{public}s,%{public}d",
        assetData.localPath.c_str(),
        access(assetData.localPath.c_str(), F_OK) == 0);
    if (access(assetData.localPath.c_str(), F_OK) != 0) {
        MEDIA_ERR_LOG("ResetAssetModifyTime file not exist %{public}s", assetData.localPath.c_str());
        return;
    }
    int32_t err = CloudMediaSyncUtils::UpdateModifyTime(assetData.localPath, assetData.dateModified);
    if (err != E_OK) {
        assetData.err = err;
        assetData.errorMsg = "Update ModifyTime failed";
        MEDIA_WARN_LOG("DownloadAsset UpdateModifyTime %{public}s failed",
            MediaFileUtils::DesensitizePath(assetData.localPath).c_str());
    }
}

int32_t CloudMediaDownloadService::SliceAssetFile(const std::string &originalFile, const std::string &path,
    const std::string &videoPath, const std::string &extraDataPath)
{
    MEDIA_INFO_LOG("SliceAssetFile");
    if (access(originalFile.c_str(), F_OK) != F_OK) {
        MEDIA_ERR_LOG("SliceAssetFile Not exist %{public}s", originalFile.c_str());
        return E_PATH;
    }
    std::string temp = originalFile + ".slicetemp";
    if (rename(originalFile.c_str(), temp.c_str()) == 0) {
        MEDIA_INFO_LOG("SliceAssetFile originalFile:%{public}s, path:%{public}s, videoPath:%{public}s, "
                       "extraDataPath:%{public}s, temp:%{public}s",
            originalFile.c_str(),
            path.c_str(),
            videoPath.c_str(),
            extraDataPath.c_str(),
            temp.c_str());
        if (MovingPhotoFileUtils::ConvertToMovingPhoto(temp, path, videoPath, extraDataPath) != 0) {
            MEDIA_INFO_LOG("SliceAssetFile convert to moving photo fail %{public}s", originalFile.c_str());
            if (unlink(temp.c_str()) != 0) {
                MEDIA_WARN_LOG("SliceAssetFile convert failed delete temp");
            }
            return E_PATH;
        }
        if (unlink(temp.c_str()) != 0) {
            MEDIA_WARN_LOG("SliceAssetFile convert success delete temp");
        }
    } else {
        MEDIA_ERR_LOG("SliceAssetFile rename failed path:%{public}s, to temp:%{public}s", path.c_str(), temp.c_str());
        return E_PATH;
    }
    return E_OK;
}

int32_t CloudMediaDownloadService::SliceAsset(const OnDownloadAssetData &assetData, const PhotosPo &photo)
{
    MEDIA_INFO_LOG("SliceAsset enter");
    if (assetData.needSliceRaw) {
        std::string rawFilePath = PhotoFileUtils::GetEditDataSourcePath(assetData.path);
        bool isLivePhoto = MovingPhotoFileUtils::IsLivePhoto(rawFilePath);
        if (isLivePhoto) {
            std::string sourceImage = CloudMediaSyncUtils::GetSourceMovingPhotoImagePath(assetData.path);
            std::string sourceVideo = CloudMediaSyncUtils::GetSourceMovingPhotoVideoPath(assetData.path);
            int32_t ret = SliceAssetFile(rawFilePath, sourceImage, sourceVideo, "");
            CHECK_AND_PRINT_LOG(ret == E_OK,
                "SliceRawFile Failed. rawFilePath: %{public}s, sourceImage: %{public}s, sourceVideo: %{public}s",
                rawFilePath.c_str(), sourceImage.c_str(), sourceVideo.c_str());
        } else {
            MEDIA_WARN_LOG("OnDownloadAsset need slice raw, but file is not live photo");
        }
    }
    if (assetData.needSliceContent) {
        bool isGraffiti = CloudMediaSyncUtils::IsGraffiti(photo);
        std::string videoPath = CloudMediaSyncUtils::GetMovingPhotoVideoPath(assetData.path);
        std::string extraDir = CloudMediaSyncUtils::GetMovingPhotoExtraDataDir(assetData.path);
        std::string extraDataPath = isGraffiti ? "" : CloudMediaSyncUtils::GetMovingPhotoExtraDataPath(assetData.path);
        if (!ForceCreateDirectory(extraDir)) {
            MEDIA_ERR_LOG("HandleAssetFile %{public}s error %{public}d", extraDir.c_str(), errno);
            return E_PATH;
        }
        int32_t ret = SliceAssetFile(assetData.localPath, assetData.localPath, videoPath, extraDataPath);
        if (ret == E_OK && assetData.needParseCover) {
            MEDIA_DEBUG_LOG("cover position is invalid, parse cover position from file");
            CoverPositionParser::GetInstance().AddTask(assetData.path, assetData.fileUri);
        }
        return ret;
    }
    return E_OK;
}

std::string CloudMediaDownloadService::PrintOnDownloadAssetData(const OnDownloadAssetData &assetData)
{
    std::stringstream ss;
    ss << "{"
       << "\"fixFileType\": " << std::to_string(assetData.fixFileType) << ","
       << "\"needSliceContent\": " << std::to_string(assetData.needSliceContent) << ","
       << "\"needSliceRaw\": " << std::to_string(assetData.needSliceRaw) << ","
       << "\"err\": " << assetData.err << ","
       << "\"dateModified\": " << assetData.dateModified << ","
       << "\"path\": \"" << assetData.path << "\","
       << "\"localPath\": \"" << assetData.localPath << "\","
       << "\"errorMsg\": \"" << assetData.errorMsg << "\"}";
    return ss.str();
}

int32_t CloudMediaDownloadService::OnDownloadAsset(
    const std::vector<std::string> &cloudIds, std::vector<MediaOperateResultDto> &result)
{
    MEDIA_INFO_LOG("enter CloudMediaDownloadService::OnDownloadAsset, %{public}zu", cloudIds.size());
    // get downloadAssetDataVec
    std::vector<PhotosPo> photosPoVec;
    int32_t ret = this->dao_.QueryDownloadAssetByCloudIds(cloudIds, photosPoVec);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "QueryDownloadAssetByCloudIds failed, ret:%{public}d", ret);
    // Requirement: If any asset is not in the database, return error. Caller should check the result.
    CHECK_AND_RETURN_RET_LOG(photosPoVec.size() == cloudIds.size(),
        E_CLOUDSYNC_INVAL_ARG,
        "QueryDownloadAssetByCloudIds failed, cloudIds size:%{public}zu, photosPoVec size:%{public}zu",
        cloudIds.size(),
        photosPoVec.size());
    // Update
    OnDownloadAssetData assetData;
    for (auto &photosPo : photosPoVec) {
        assetData = this->GetOnDownloadAssetData(photosPo);
        MEDIA_DEBUG_LOG("OnDownloadAsset %{public}s, %{public}s",
            photosPo.ToString().c_str(),
            PrintOnDownloadAssetData(assetData).c_str());
        HandlePhoto(photosPo, assetData);
        // record result
        MediaOperateResultDto mediaResult;
        mediaResult.cloudId = photosPo.cloudId.value_or("");
        mediaResult.errorCode = assetData.err;
        mediaResult.errorMsg = assetData.errorMsg;
        result.emplace_back(mediaResult);
    }
    return E_OK;
}

void CloudMediaDownloadService::HandlePhoto(const ORM::PhotosPo &photo, OnDownloadAssetData &assetData)
{
    int32_t ret = SliceAsset(assetData, photo);
    if (ret != E_OK) {
        MEDIA_INFO_LOG("HandlePhoto Failed to Slice %{public}s", assetData.localPath.c_str());
        assetData.errorMsg = "Slice Moving File Failed";
        assetData.err = ret;
        return;
    }
    ret = this->dao_.UpdateDownloadAsset(assetData.fixFileType, assetData.path);
    if (ret != E_OK) {
        MEDIA_INFO_LOG("Failed to Handle HandlePhoto %{public}s", assetData.localPath.c_str());
        assetData.errorMsg = "UpdateDownloadAsset failed";
        assetData.err = ret;
        this->UnlinkAsset(assetData);
    } else if (assetData.dateModified > 0 && (assetData.needSliceContent || assetData.needSliceRaw)) {
        this->ResetAssetModifyTime(assetData);
    }
}
}  // namespace OHOS::Media::CloudSync