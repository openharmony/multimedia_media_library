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

#include "parameters.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "cloud_media_file_utils.h"
#include "cloud_media_attachment_utils.h"
#include "cloud_media_sync_utils.h"
#include "cloud_sync_notify_handler.h"
#include "thumbnail_const.h"
#include "thumbnail_service.h"
#include "cloud_media_asset_manager.h"
#include "cloud_media_asset_types.h"

namespace OHOS::Media::CloudSync {
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
    CHECK_AND_RETURN_RET_LOG(
        !downloadAssetDataVec.empty(), photosDtoVec, "GetDownloadThmsByUri Failed to get downloadAssetDataVec.");
    MEDIA_INFO_LOG("GetDownloadThmsByUri size of downloadAssetDataVec: %{public}zu", downloadAssetDataVec.size());
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
        if (type & TYPE_THM) {
            retThm = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadAssetData, photosDto);
            CHECK_AND_PRINT_LOG(retThm == E_OK, "GetDownloadThmsByUri GetAttachment thm fail");
        }
        if (type & TYPE_LCD) {
            retLcd = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadAssetData, photosDto);
            CHECK_AND_PRINT_LOG(retLcd == E_OK, "GetDownloadThmsByUri GetAttachment lcd fail");
        }
        if ((retThm != E_OK) && (retLcd != E_OK)) {
            continue;
        }
        MEDIA_INFO_LOG("GetDownloadThmsByUri Photo: %{public}s", photosDto.ToString().c_str());
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
    /* 通知
     DataSyncNotifier::GetInstance().TryNotify(PHOTO_URI_PREFIX, ChangeType::INSERT, "");
     DataSyncNotifier::GetInstance().FinalNotify();
    */
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
    for (auto &thm : bothVector) {  // collect results
        MediaOperateResultDto mediaResult;
        mediaResult.cloudId = thm;
        mediaResult.errorCode = ret;
        result.emplace_back(mediaResult);
    }
    return ret;
}

bool CloudMediaDownloadService::IsCloudInsertTaskPriorityHigh()
{
    int32_t cloudSyncStatus = static_cast<int32_t>(system::GetParameter(CLOUDSYNC_STATUS_KEY, "0").at(0) - '0');
    MEDIA_INFO_LOG("cloudSyncStatus: %{public}d", cloudSyncStatus);
    return cloudSyncStatus == CloudSyncStatus::FIRST_FIVE_HUNDRED ||
           cloudSyncStatus == CloudSyncStatus::INCREMENT_DOWNLOAD;
}

void CloudMediaDownloadService::CreateAstcCloudDownload(const std::vector<std::string> &cloudIds)
{
    MEDIA_INFO_LOG("enter CreateAstcCloudDownload");
    CHECK_AND_RETURN_LOG(!cloudIds.empty(), "cloudIds is empty");
    std::vector<std::string> fileIds;
    int32_t ret = this->dao_.GetFileIdFromCloudId(cloudIds, fileIds);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to get fileIds");

    // 缩略图纹理
    bool isCloudInsertTaskPriorityHigh = this->IsCloudInsertTaskPriorityHigh();
    if (!isCloudInsertTaskPriorityHigh && !ThumbnailService::GetInstance()->GetCurrentStatusForTask()) {
        MEDIA_INFO_LOG("current status is not suitable for task");
        return;
    }
    for (auto &fileId : fileIds) {
        MEDIA_INFO_LOG("CreateAstcCloudDownload, fileId: %{public}s", fileId.c_str());
        ThumbnailService::GetInstance()->CreateAstcCloudDownload(fileId, isCloudInsertTaskPriorityHigh);
    }
    // 原图低优先级下载
    CloudMediaAssetManager::GetInstance().SetIsThumbnailUpdate();
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
    this->CreateAstcCloudDownload(astcVector);
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
    CHECK_AND_RETURN_RET_LOG(
        !downloadAssetDataVec.empty(), photosDtoVec, "GetDownloadAsset Failed to get downloadAssetDataVec.");
    MEDIA_INFO_LOG("GetDownloadAsset size of downloadAssetDataVec: %{public}zu", downloadAssetDataVec.size());
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
        MEDIA_INFO_LOG("GetDownloadAsset Photo: %{public}s", photosDto.ToString().c_str());

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
    assetData.fixFileType = isMovingPhoto && !isGraffiti && !isLivePhoto;
    assetData.needSlice = (isMovingPhoto && !isGraffiti) || isLivePhoto;
    assetData.path = photosPo.data.value_or("");
    assetData.localPath = CloudMediaSyncUtils::GetLocalPath(assetData.path);
    assetData.dateModified = photosPo.dateModified.value_or(0);
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
    return;
}

void CloudMediaDownloadService::ResetAssetModifyTime(OnDownloadAssetData &assetData)
{
    MEDIA_INFO_LOG("UpdateModifyTime: %{public}s,%{public}d, %{public}s,%{public}d",
        assetData.path.c_str(),
        access(assetData.path.c_str(), F_OK),
        assetData.localPath.c_str(),
        access(assetData.localPath.c_str(), F_OK));
    int32_t err = CloudMediaSyncUtils::UpdateModifyTime(
        assetData.needSlice ? assetData.path : assetData.localPath, assetData.dateModified);
    if (err != E_OK) {
        assetData.err = err;
        assetData.errorMsg = "Update ModifyTime failed";
        MEDIA_WARN_LOG("DownloadAsset UpdateModifyTime %{public}s failed",
            MediaFileUtils::DesensitizePath(assetData.localPath).c_str());
    }
    return;
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
        MEDIA_INFO_LOG("OnDownloadAsset %{public}s", photosPo.ToString().c_str());
        assetData = this->GetOnDownloadAssetData(photosPo);
        ret = this->dao_.UpdateDownloadAsset(assetData.fixFileType, assetData.needSlice, assetData.path);
        if (ret != E_OK) {
            MEDIA_INFO_LOG("Failed to Handle DownloadAsset %{public}s", assetData.localPath.c_str());
            assetData.errorMsg = "UpdateDownloadAsset failed";
            assetData.err = ret;
            this->UnlinkAsset(assetData);
        } else if (assetData.dateModified > 0) {
            this->ResetAssetModifyTime(assetData);
        }
        // record result
        MediaOperateResultDto mediaResult;
        mediaResult.cloudId = photosPo.cloudId.value_or("");
        mediaResult.errorCode = assetData.err;
        mediaResult.errorMsg = assetData.errorMsg;
        result.emplace_back(mediaResult);
    }
    return E_OK;
}
}  // namespace OHOS::Media::CloudSync