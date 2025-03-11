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

#define MLOG_TAG "PhotoAssetProxy"

#include <cstdint>
#include <string>
#include <sstream>

#include "media_photo_asset_proxy.h"

#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "fetch_result.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "image_packer.h"
#include "media_column.h"
#include "datashare_values_bucket.h"
#include "media_file_uri.h"
#include "medialibrary_tracer.h"
#include "userfilemgr_uri.h"
#include "datashare_helper.h"
#include "media_exif.h"

using namespace std;

namespace OHOS {
namespace Media {
const string API_VERSION = "api_version";
const string SAVE_PICTURE = "save_picture";
const double TIMER_MULTIPLIER = 60.0;
const std::unordered_map<CameraShotType, PhotoSubType> CAMERASHOT_TO_SUBTYPE_MAP = {
    {CameraShotType::MOVING_PHOTO, PhotoSubType::MOVING_PHOTO},
    {CameraShotType::BURST, PhotoSubType::BURST},
    {CameraShotType::IMAGE, PhotoSubType::CAMERA},
    {CameraShotType::VIDEO, PhotoSubType::CAMERA},
};
PhotoAssetProxy::PhotoAssetProxy() {}

PhotoAssetProxy::PhotoAssetProxy(shared_ptr<DataShare::DataShareHelper> dataShareHelper, CameraShotType cameraShotType,
    uint32_t callingUid, int32_t userId)
{
    dataShareHelper_ = dataShareHelper;
    cameraShotType_ = cameraShotType;
    callingUid_ = callingUid;
    userId_ = userId;
    auto itr = CAMERASHOT_TO_SUBTYPE_MAP.find(cameraShotType);
    if (itr == CAMERASHOT_TO_SUBTYPE_MAP.end()) {
        subType_ = PhotoSubType::CAMERA;
    } else {
        subType_ = itr->second;
    }
    MEDIA_INFO_LOG("init success, shottype: %{public}d, callingUid: %{public}d, userid: %{public}d",
        static_cast<int32_t>(cameraShotType), callingUid, userId);
}

PhotoAssetProxy::~PhotoAssetProxy()
{
    if (cameraShotType_ == CameraShotType::MOVING_PHOTO && !isMovingPhotoVideoSaved_) {
        if (dataShareHelper_ == nullptr) {
            MEDIA_WARN_LOG("datashareHelper is nullptr");
            return;
        }
        string uri = PAH_DEGENERATE_MOVING_PHOTO;
        MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri updateUri(uri);
        DataShare::DataSharePredicates predicates;
        DataShare::DataShareValuesBucket valuesBucket;
        string fileId = MediaFileUtils::GetIdFromUri(uri_);
        predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
        valuesBucket.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::DEFAULT));
        int32_t changeRows = dataShareHelper_->Update(updateUri, predicates, valuesBucket);
        MEDIA_WARN_LOG("Degenerate moving photo: %{public}s, ret: %{public}d", fileId.c_str(), changeRows);
    }
}

// 调用之前，必须先AddPhotoProxy，否则无法获取FileAsset对象
unique_ptr<FileAsset> PhotoAssetProxy::GetFileAsset()
{
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, nullptr,
        "Failed to create Asset, datashareHelper is nullptr");
    string uri = PAH_QUERY_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri queryUri(uri);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId_);
    DataShare::DatashareBusinessError businessError;
    vector<string> columns;

    auto resultSet = dataShareHelper_->Query(queryUri, predicates, columns, &businessError);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "Failed to query asset, fileId_: %{public}d", fileId_);
    auto fetchResult = make_unique<FetchResult<FileAsset>>(resultSet);
    CHECK_AND_RETURN_RET_LOG(fetchResult != nullptr, nullptr, "fetchResult is nullptr, %{public}d", fileId_);

    unique_ptr<FileAsset> fileAsset = fetchResult->GetFirstObject();
    if (fileAsset != nullptr) {
        fileAsset->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    }
    return fileAsset;
}

string PhotoAssetProxy::GetPhotoAssetUri()
{
    return uri_;
}

DataShare::DataShareValuesBucket PhotoAssetProxy::HandleAssetValues(const sptr<PhotoProxy> &photoProxy,
    const string &displayName, const MediaType &mediaType)
{
    DataShare::DataShareValuesBucket values;
    values.Put(MediaColumn::MEDIA_NAME, displayName);
    values.Put(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(mediaType));
    if (cameraShotType_ == CameraShotType::MOVING_PHOTO) {
        values.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
        values.Put(PhotoColumn::STAGE_VIDEO_TASK_STATUS, static_cast<int32_t>(StageVideoTaskStatus::NEED_TO_STAGE));
    }
    if (cameraShotType_ == CameraShotType::BURST) {
        values.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::BURST));
        values.Put(PhotoColumn::PHOTO_BURST_KEY, photoProxy->GetBurstKey());
        values.Put(PhotoColumn::PHOTO_BURST_COVER_LEVEL,
            photoProxy->IsCoverPhoto() ? static_cast<int32_t>(BurstCoverLevelType::COVER)
                                       : static_cast<int32_t>(BurstCoverLevelType::MEMBER));
        values.Put(PhotoColumn::PHOTO_DIRTY, -1);
    }
    values.Put(MEDIA_DATA_CALLING_UID, static_cast<int32_t>(callingUid_));
    values.Put(PhotoColumn::PHOTO_IS_TEMP, true);

    if (photoProxy->GetPhotoQuality() == PhotoQuality::LOW ||
        (photoProxy->GetFormat() == PhotoFormat::YUV && subType_ != PhotoSubType::BURST)) {
        values.Put(PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, static_cast<int32_t>(photoProxy->GetDeferredProcType()));
        values.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(cameraShotType_));
        values.Put(PhotoColumn::PHOTO_QUALITY, static_cast<int32_t>(photoProxy->GetPhotoQuality()));
        SetPhotoIdForAsset(photoProxy, values);
    }
    return values;
}

void PhotoAssetProxy::CreatePhotoAsset(const sptr<PhotoProxy> &photoProxy)
{
    CHECK_AND_RETURN_LOG(dataShareHelper_ != nullptr, "Failed to create Asset, datashareHelper is nullptr");
    CHECK_AND_RETURN_LOG(!(photoProxy->GetTitle().empty()), "Failed to create Asset, displayName is empty");
    bool cond = (cameraShotType_ == CameraShotType::BURST && photoProxy->GetBurstKey().empty());
    CHECK_AND_RETURN_LOG(!cond, "Failed to create Asset, burstKey is empty when CameraShotType::BURST");

    string displayName = photoProxy->GetTitle() + "." + photoProxy->GetExtension();
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    cond = ((mediaType != MEDIA_TYPE_IMAGE) && (mediaType != MEDIA_TYPE_VIDEO));
    CHECK_AND_RETURN_LOG(!cond,
        "Failed to create Asset, invalid file type %{public}d", static_cast<int32_t>(mediaType));
    DataShare::DataShareValuesBucket values = HandleAssetValues(photoProxy, displayName, mediaType);
    string uri = PAH_CREATE_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri createUri(uri);
    fileId_ = dataShareHelper_->InsertExt(createUri, values, uri_);
    CHECK_AND_RETURN_LOG(fileId_ >= 0, "Failed to create Asset, insert database error!");
    MEDIA_INFO_LOG(
        "MultistagesCapture Success, photoId: %{public}s, fileId: %{public}d, uri: %{public}s, burstKey: %{public}s",
        photoProxy->GetPhotoId().c_str(), fileId_, uri_.c_str(), photoProxy->GetBurstKey().c_str());
}

static bool isHighQualityPhotoExist(string uri)
{
    string filePath = MediaFileUri::GetPathFromUri(uri, true);
    string filePathTemp = filePath + ".high";
    return MediaFileUtils::IsFileExists(filePathTemp) || MediaFileUtils::IsFileExists(filePath);
}

void PhotoAssetProxy::SetPhotoIdForAsset(const sptr<PhotoProxy> &photoProxy, DataShare::DataShareValuesBucket &values)
{
    if (photoProxy->GetPhotoId() == "") {
        stringstream result;
        string displayName = photoProxy->GetTitle();
        for (size_t i = 0; i < displayName.length(); i++) {
            if (isdigit(displayName[i])) {
                result << displayName[i];
            }
        }
        values.Put(PhotoColumn::PHOTO_ID, result.str());
    } else {
        values.Put(PhotoColumn::PHOTO_ID, photoProxy->GetPhotoId());
    }
}

int32_t CloseFd(const shared_ptr<DataShare::DataShareHelper> &dataShareHelper, const string &uri, const int32_t fd)
{
    MediaLibraryTracer tracer;
    tracer.Start("CloseFd");

    int32_t retVal = E_FAIL;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, uri);

    if (dataShareHelper != nullptr) {
        string uriStr = PAH_SCAN_WITHOUT_ALBUM_UPDATE;
        MediaFileUtils::UriAppendKeyValue(uriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri closeAssetUri(uriStr);

        if (close(fd) == E_SUCCESS) {
            retVal = dataShareHelper->Insert(closeAssetUri, valuesBucket);
        }
        CHECK_AND_PRINT_LOG(retVal != E_FAIL, "Failed to close the file");
    }

    return retVal;
}

int PhotoAssetProxy::SaveImage(int fd, const string &uri, const string &photoId, void *output, size_t writeSize)
{
    MediaLibraryTracer tracer;
    tracer.Start("SaveImage");
    CHECK_AND_RETURN_RET_LOG(fd > 0, E_ERR, "invalid fd");
    if (isHighQualityPhotoExist(uri)) {
        MEDIA_INFO_LOG("high quality photo exists, discard low quality photo. photoId: %{public}s", photoId.c_str());
        return E_OK;
    }

    int ret = write(fd, output, writeSize);
    CHECK_AND_RETURN_RET_LOG(ret >= 0, ret, "write err %{public}d", errno);
    MEDIA_INFO_LOG("Save Low Quality file Success, photoId: %{public}s, size: %{public}zu, ret: %{public}d",
        photoId.c_str(), writeSize, ret);
    return E_OK;
}

int PhotoAssetProxy::PackAndSaveImage(int fd, const string &uri, const sptr<PhotoProxy> &photoProxy)
{
    MediaLibraryTracer tracer;
    tracer.Start("PackAndSaveImage");

    void *imageAddr = photoProxy->GetFileDataAddr();
    size_t imageSize = photoProxy->GetFileSize();
    bool cond = (imageAddr == nullptr || imageSize == 0);
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "imageAddr is nullptr or imageSize(%{public}zu)==0", imageSize);

    MEDIA_DEBUG_LOG("start pack PixelMap");
    Media::InitializationOptions opts;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.size = {
        .width = photoProxy->GetWidth(),
        .height = photoProxy->GetHeight()
    };

    auto pixelMap = Media::PixelMap::Create(opts);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, E_ERR, "Create pixelMap failed.");
    pixelMap->SetPixelsAddr(imageAddr, nullptr, imageSize, Media::AllocatorType::SHARE_MEM_ALLOC, nullptr);
    auto pixelSize = static_cast<uint32_t>(pixelMap->GetByteCount());
    CHECK_AND_RETURN_RET_LOG(pixelSize != 0, E_ERR, "pixel size is 0.");

    // encode rgba to jpeg
    auto buffer = new (std::nothrow) uint8_t[pixelSize];
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, E_ERR, "Failed to new buffer");
    int64_t packedSize = 0L;
    Media::ImagePacker imagePacker;
    Media::PackOption packOption;
    packOption.format = "image/jpeg";
    imagePacker.StartPacking(buffer, pixelSize, packOption);
    imagePacker.AddImage(*pixelMap);
    uint32_t packResult = imagePacker.FinalizePacking(packedSize);
    if (packResult != E_OK || buffer == nullptr) {
        MEDIA_ERR_LOG("packet pixelMap failed packResult: %{public}d", packResult);
        delete[] buffer;
        return E_ERR;
    }
    MEDIA_INFO_LOG("pack pixelMap success, packedSize: %{public}" PRId64, packedSize);

    auto ret = SaveImage(fd, uri, photoProxy->GetPhotoId(), buffer, packedSize);
    SetShootingModeAndGpsInfo(buffer, packedSize, photoProxy, fd);
    delete[] buffer;
    return ret;
}

void PhotoAssetProxy::SetShootingModeAndGpsInfo(const uint8_t *data, uint32_t size,
    const sptr<PhotoProxy> &photoProxy, int fd)
{
    MediaLibraryTracer tracer;
    tracer.Start("SetShootingModeAndGpsInfo");
    int32_t shootingMode = photoProxy->GetShootingMode();
    double latitude = photoProxy->GetLatitude();
    double longitude = photoProxy->GetLongitude();
    uint32_t errorCode = 0;
    SourceOptions opts;
    tracer.Start("CreateImageSource");
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    tracer.Finish();

    CHECK_AND_RETURN_LOG(imageSource != nullptr, "imageSource is nullptr");
    uint32_t index = 0;
    uint32_t ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_ISO_SPEED_LATITUDE_ZZZ,
        to_string(shootingMode));
    CHECK_AND_PRINT_LOG(ret == E_OK, "modify image property shooting mode fail %{public}d", ret);

    ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_LONGITUDE, LocationValueToString(longitude));
    CHECK_AND_PRINT_LOG(ret == E_OK, "modify image property longitude fail %{public}d", ret);

    ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_LONGITUDE_REF, longitude > 0.0 ? "E" : "W");
    CHECK_AND_PRINT_LOG(ret == E_OK, "modify image property longitude ref fail %{public}d", ret);

    ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_LATITUDE, LocationValueToString(latitude));
    CHECK_AND_PRINT_LOG(ret == E_OK, "modify image property latitude fail %{public}d", ret);

    tracer.Start("ModifyImageProperty");
    ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_LATITUDE_REF, latitude > 0.0 ? "N" : "S", fd);
    tracer.Finish();
    CHECK_AND_PRINT_LOG(ret == E_OK, "modify image property latitude ref fail %{public}d", ret);
    MEDIA_INFO_LOG("Success.");
}
 
std::string PhotoAssetProxy::LocationValueToString(double value)
{
    string result = "";
    double stringValue = value;
    if (value < 0.0) {
        stringValue = 0.0 - value;
    }

    int degrees = static_cast<int32_t>(stringValue);
    result = result + to_string(degrees) + ", ";
    stringValue -= (double)degrees;
    stringValue *= TIMER_MULTIPLIER;
    int minutes = (int)stringValue;
    result = result + to_string(minutes) + ", ";
    stringValue -= (double)minutes;
    stringValue *= TIMER_MULTIPLIER;
    result = result + to_string(stringValue);
    return result;
}

int32_t PhotoAssetProxy::AddProcessImage(shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    const sptr<PhotoProxy> &photoProxy, int32_t fileId, int32_t subType)
{
    string uri = PAH_ADD_IMAGE;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    if (photoProxy->GetFormat() == PhotoFormat::YUV) {
        MediaFileUtils::UriAppendKeyValue(uri, SAVE_PICTURE, OPRN_ADD_LOWQUALITY_IMAGE);
    }
    Uri updateAssetUri(uri);
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MediaColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ to_string(fileId) });

    DataShare::DataShareValuesBucket valuesBucket;
    SetPhotoIdForAsset(photoProxy, valuesBucket);
    valuesBucket.Put(PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, static_cast<int32_t>(photoProxy->GetDeferredProcType()));
    valuesBucket.Put(MediaColumn::MEDIA_ID, fileId);
    valuesBucket.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(subType));
    valuesBucket.Put(PhotoColumn::PHOTO_QUALITY, static_cast<int32_t>(photoProxy->GetPhotoQuality()));

    int32_t changeRows = dataShareHelper->Update(updateAssetUri, predicates, valuesBucket);
    CHECK_AND_PRINT_LOG(changeRows >= 0, "update fail, error: %{public}d", changeRows);
    MEDIA_INFO_LOG("MultistagesCapture photoId: %{public}s, fileId: %{public}d",
        photoProxy->GetPhotoId().c_str(), fileId);
    return changeRows;
}

int PhotoAssetProxy::SaveLowQualityPhoto(std::shared_ptr<DataShare::DataShareHelper>  &dataShareHelper,
    const sptr<PhotoProxy> &photoProxy, int32_t fileId, int32_t subType)
{
    MediaLibraryTracer tracer;
    tracer.Start("SaveLowQualityPhoto");
    string uri = PAH_ADD_LOWQUALITY_IMAGE;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(MediaColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ to_string(fileId) });

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_ID, photoProxy->GetPhotoId());
    valuesBucket.Put(PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, static_cast<int32_t>(photoProxy->GetDeferredProcType()));
    valuesBucket.Put(MediaColumn::MEDIA_ID, fileId);
    valuesBucket.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(subType));
    valuesBucket.Put(PhotoColumn::PHOTO_LATITUDE, photoProxy->GetLatitude());
    valuesBucket.Put(PhotoColumn::PHOTO_LONGITUDE, photoProxy->GetLongitude());

    int32_t changeRows = dataShareHelper->Update(updateAssetUri, predicates, valuesBucket);
    CHECK_AND_PRINT_LOG(changeRows >= 0, "update fail, error: %{public}d", changeRows);
    MEDIA_INFO_LOG("photoId: %{public}s,", photoProxy->GetPhotoId().c_str());
    photoProxy->Release();
    return E_OK;
}

void PhotoAssetProxy::DealWithLowQualityPhoto(shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    int fd, const string &uri, const sptr<PhotoProxy> &photoProxy)
{
    MediaLibraryTracer tracer;
    tracer.Start("DealWithLowQualityPhoto");
    MEDIA_INFO_LOG("start photoId: %{public}s format: %{public}d, quality: %{public}d",
        photoProxy->GetPhotoId().c_str(), photoProxy->GetFormat(), photoProxy->GetPhotoQuality());

    PhotoFormat photoFormat = photoProxy->GetFormat();
    if (photoFormat == PhotoFormat::RGBA) {
        PackAndSaveImage(fd, uri, photoProxy);
    } else if (photoFormat == PhotoFormat::DNG) {
        auto ret = SaveImage(fd, uri, photoProxy->GetPhotoId(), photoProxy->GetFileDataAddr(),
            photoProxy->GetFileSize());
        MEDIA_INFO_LOG("direct save dng file, ret: %{public}d", ret);
    } else {
        SaveImage(fd, uri, photoProxy->GetPhotoId(), photoProxy->GetFileDataAddr(), photoProxy->GetFileSize());
    }
    photoProxy->Release();
    CloseFd(dataShareHelper, uri, fd);
    MEDIA_INFO_LOG("end");
}

void PhotoAssetProxy::AddPhotoProxy(const sptr<PhotoProxy> &photoProxy)
{
    bool cond = (photoProxy == nullptr || dataShareHelper_ == nullptr);
    CHECK_AND_RETURN_LOG(!cond, "input param invalid, photo proxy is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAssetProxy::AddPhotoProxy " + photoProxy->GetPhotoId());
    MEDIA_INFO_LOG("MultistagesCapture, photoId: %{public}s", photoProxy->GetPhotoId().c_str());
    tracer.Start("PhotoAssetProxy CreatePhotoAsset");
    CreatePhotoAsset(photoProxy);
    CHECK_AND_RETURN_INFO_LOG(cameraShotType_ != CameraShotType::VIDEO, "MultistagesCapture exit for VIDEO");

    if (photoProxy->GetPhotoQuality() == PhotoQuality::LOW ||
        (photoProxy->GetFormat() == PhotoFormat::YUV && subType_ != PhotoSubType::BURST)) {
        AddProcessImage(dataShareHelper_, photoProxy, fileId_, static_cast<int32_t>(cameraShotType_));
    }
    if (photoProxy->GetFormat() == PhotoFormat::YUV) {
        photoProxy->Release();
        MEDIA_INFO_LOG("MultistagesCapture exit for YUV");
        tracer.Finish();
        return;
    }
    tracer.Finish();

    Uri openUri(uri_);
    int fd = dataShareHelper_->OpenFile(openUri, MEDIA_FILEMODE_READWRITE);
    CHECK_AND_RETURN_LOG(fd >= 0, "fd.Get() < 0 fd %{public}d status %{public}d", fd, errno);
    DealWithLowQualityPhoto(dataShareHelper_, fd, uri_, photoProxy);
    MEDIA_INFO_LOG("MultistagesCapture exit");
}

int32_t PhotoAssetProxy::GetVideoFd()
{
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR,
        "Failed to read video of moving photo, datashareHelper is nullptr");
    string videoUri = uri_;
    MediaFileUtils::UriAppendKeyValue(videoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, CREATE_MOVING_PHOTO_VIDEO);
    Uri openVideoUri(videoUri);
    int32_t fd = dataShareHelper_->OpenFile(openVideoUri, MEDIA_FILEMODE_READWRITE);
    MEDIA_INFO_LOG("GetVideoFd enter, video path: %{public}s, fd: %{public}d", videoUri.c_str(), fd);
    return fd;
}

void PhotoAssetProxy::NotifyVideoSaveFinished()
{
    isMovingPhotoVideoSaved_ = true;
    CHECK_AND_RETURN_LOG(dataShareHelper_ != nullptr, "datashareHelper is nullptr");
    string uriStr = PAH_ADD_FILTERS;
    Uri uri(uriStr);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::MEDIA_ID, fileId_);
    valuesBucket.Put(NOTIFY_VIDEO_SAVE_FINISHED, uri_);
    dataShareHelper_->Insert(uri, valuesBucket);
    MEDIA_INFO_LOG("video save finished %{public}s", uri_.c_str());
}
} // Media
} // OHOS