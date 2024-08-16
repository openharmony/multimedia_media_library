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
const double TIMER_MULTIPLIER = 60.0;
const int32_t BURST_COVER = 1;
const int32_t BURST_MEMBER = 2;

PhotoAssetProxy::PhotoAssetProxy() {}

PhotoAssetProxy::PhotoAssetProxy(shared_ptr<DataShare::DataShareHelper> dataShareHelper, CameraShotType cameraShotType,
    uint32_t callingUid, int32_t userId)
{
    dataShareHelper_ = dataShareHelper;
    cameraShotType_ = cameraShotType;
    callingUid_ = callingUid;
    userId_ = userId;
    subType_ = cameraShotType == CameraShotType::MOVING_PHOTO ? PhotoSubType::MOVING_PHOTO : PhotoSubType::CAMERA;
    MEDIA_INFO_LOG("init success, shottype: %{public}d, callingUid: %{public}d, userid: %{public}d",
        static_cast<int32_t>(cameraShotType), callingUid, userId);
}

PhotoAssetProxy::~PhotoAssetProxy() {}

// 调用之前，必须先AddPhotoProxy，否则无法获取FileAsset对象
unique_ptr<FileAsset> PhotoAssetProxy::GetFileAsset()
{
    if (dataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Failed to create Asset, datashareHelper is nullptr");
        return nullptr;
    }

    string uri = PAH_QUERY_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri queryUri(uri);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId_);
    DataShare::DatashareBusinessError businessError;
    vector<string> columns;

    auto resultSet = dataShareHelper_->Query(queryUri, predicates, columns, &businessError);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query asset, fileId_: %{public}d", fileId_);
        return nullptr;
    }
    auto fetchResult = make_unique<FetchResult<FileAsset>>(resultSet);
    if (fetchResult == nullptr) {
        MEDIA_ERR_LOG("fetchResult is nullptr, %{public}d", fileId_);
        return nullptr;
    }
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

void PhotoAssetProxy::CreatePhotoAsset(const sptr<PhotoProxy> &photoProxy)
{
    if (dataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Failed to create Asset, datashareHelper is nullptr");
        return;
    }
    if (photoProxy->GetTitle().empty()) {
        MEDIA_ERR_LOG("Failed to create Asset, displayName is empty");
        return;
    }
    if (cameraShotType_ == CameraShotType::BURST && photoProxy->GetBurstKey().empty()) {
        MEDIA_ERR_LOG("Failed to create Asset, burstKey is empty when CameraShotType::BURST");
        return;
    }
    string displayName = photoProxy->GetTitle() + "." + photoProxy->GetExtension();
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    if ((mediaType != MEDIA_TYPE_IMAGE) && (mediaType != MEDIA_TYPE_VIDEO)) {
        MEDIA_ERR_LOG("Failed to create Asset, invalid file type %{public}d", static_cast<int32_t>(mediaType));
        return;
    }
    DataShare::DataShareValuesBucket values;
    values.Put(MediaColumn::MEDIA_NAME, displayName);
    values.Put(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(mediaType));
    if (cameraShotType_ == CameraShotType::MOVING_PHOTO) {
        values.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    }
    if (cameraShotType_ == CameraShotType::BURST) {
        values.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::BURST));
        values.Put(PhotoColumn::PHOTO_BURST_KEY, photoProxy->GetBurstKey());
        if (photoProxy->IsCoverPhoto()) {
            values.Put(PhotoColumn::PHOTO_BURST_COVER_LEVEL, BURST_COVER);
        } else {
            values.Put(PhotoColumn::PHOTO_BURST_COVER_LEVEL, BURST_MEMBER);
        }
    }
    values.Put(MEDIA_DATA_CALLING_UID, static_cast<int32_t>(callingUid_));
    values.Put(PhotoColumn::PHOTO_IS_TEMP, true);
    string uri = PAH_CREATE_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri createUri(uri);
    fileId_ = dataShareHelper_->InsertExt(createUri, values, uri_);
    if (fileId_ < 0) {
        MEDIA_ERR_LOG("Failed to create Asset, insert database error!");
        return;
    }
    MEDIA_INFO_LOG(
        "CreatePhotoAsset Success, photoId: %{public}s, fileId: %{public}d, uri: %{public}s, burstKey: %{public}s",
        photoProxy->GetPhotoId().c_str(), fileId_, uri_.c_str(), photoProxy->GetBurstKey().c_str());
}

static bool isHighQualityPhotoExist(string uri)
{
    string filePath = MediaFileUri::GetPathFromUri(uri, true);
    string filePathTemp = filePath + ".high";
    return MediaFileUtils::IsFileExists(filePathTemp) || MediaFileUtils::IsFileExists(filePath);
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

        if (retVal == E_FAIL) {
            MEDIA_ERR_LOG("Failed to close the file");
        }
    }

    return retVal;
}

int PhotoAssetProxy::SaveImage(int fd, const string &uri, const string &photoId, void *output, size_t writeSize)
{
    MediaLibraryTracer tracer;
    tracer.Start("SaveImage");

    if (fd <= 0) {
        MEDIA_ERR_LOG("invalid fd");
        return E_ERR;
    }

    if (isHighQualityPhotoExist(uri)) {
        MEDIA_INFO_LOG("high quality photo exists, discard low quality photo. photoId: %{public}s", photoId.c_str());
        return E_OK;
    }

    int ret = write(fd, output, writeSize);
    if (ret < 0) {
        MEDIA_ERR_LOG("write err %{public}d", errno);
        return ret;
    }
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
    if (imageAddr == nullptr || imageSize == 0) {
        MEDIA_ERR_LOG("imageAddr is nullptr or imageSize(%{public}zu)==0", imageSize);
        return E_ERR;
    }

    MEDIA_DEBUG_LOG("start pack PixelMap");
    Media::InitializationOptions opts;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.size = {
        .width = photoProxy->GetWidth(),
        .height = photoProxy->GetHeight()
    };
    auto pixelMap = Media::PixelMap::Create(opts);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("Create pixelMap failed.");
        return E_ERR;
    }
    pixelMap->SetPixelsAddr(imageAddr, nullptr, imageSize, Media::AllocatorType::SHARE_MEM_ALLOC, nullptr);
    auto pixelSize = static_cast<uint32_t>(pixelMap->GetByteCount());
    if (pixelSize == 0) {
        MEDIA_ERR_LOG("pixel size is 0.");
        return E_ERR;
    }

    // encode rgba to jpeg
    auto buffer = new (std::nothrow) uint8_t[pixelSize];
    if (buffer == nullptr) {
        MEDIA_ERR_LOG("Failed to new buffer");
        return E_ERR;
    }
    int64_t packedSize = 0L;
    Media::ImagePacker imagePacker;
    Media::PackOption packOption;
    packOption.format = "image/jpeg";
    imagePacker.StartPacking(buffer, pixelSize, packOption);
    imagePacker.AddImage(*pixelMap);
    uint32_t packResult = imagePacker.FinalizePacking(packedSize);
    if (packResult != E_OK || buffer == nullptr) {
        MEDIA_ERR_LOG("packet pixelMap failed packResult: %{public}d", packResult);
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
    if (imageSource == nullptr) {
        MEDIA_ERR_LOG("imageSource is nullptr");
        return;
    }
    uint32_t index = 0;
    uint32_t ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_ISO_SPEED_LATITUDE_ZZZ,
        to_string(shootingMode));
    if (ret != E_OK) {
        MEDIA_ERR_LOG("modify image property shooting mode fail %{public}d", ret);
    }

    ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_LONGITUDE, LocationValueToString(longitude));
    if (ret != E_OK) {
        MEDIA_ERR_LOG("modify image property longitude fail %{public}d", ret);
    }

    ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_LONGITUDE_REF, longitude > 0.0 ? "E" : "W");
    if (ret != E_OK) {
        MEDIA_ERR_LOG("modify image property longitude ref fail %{public}d", ret);
    }

    ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_LATITUDE, LocationValueToString(latitude));
    if (ret != E_OK) {
        MEDIA_ERR_LOG("modify image property latitude fail %{public}d", ret);
    }

    tracer.Start("ModifyImageProperty");
    ret = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_LATITUDE_REF, latitude > 0.0 ? "N" : "S", fd);
    tracer.Finish();
    if (ret != E_OK) {
        MEDIA_ERR_LOG("modify image property latitude ref fail %{public}d", ret);
    }
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

int32_t PhotoAssetProxy::UpdatePhotoQuality(shared_ptr<DataShare::DataShareHelper> &dataShareHelper,
    const sptr<PhotoProxy> &photoProxy, int32_t fileId, int32_t subType)
{
    string uri = PAH_ADD_IMAGE;
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

    int32_t changeRows = dataShareHelper->Update(updateAssetUri, predicates, valuesBucket);
    if (changeRows < 0) {
        MEDIA_ERR_LOG("update fail, error: %{public}d", changeRows);
    }
    MEDIA_INFO_LOG("photoId: %{public}s, fileId: %{public}d", photoProxy->GetPhotoId().c_str(), fileId);
    return changeRows;
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
    } else {
        SaveImage(fd, uri, photoProxy->GetPhotoId(), photoProxy->GetFileDataAddr(), photoProxy->GetFileSize());
    }
    photoProxy->Release();
    CloseFd(dataShareHelper, uri, fd);
    MEDIA_INFO_LOG("end");
}

void PhotoAssetProxy::AddPhotoProxy(const sptr<PhotoProxy> &photoProxy)
{
    if (photoProxy == nullptr || dataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("input param invalid, photo proxy is nullptr");
        return;
    }

    MediaLibraryTracer tracer;
    tracer.Start("PhotoAssetProxy::AddPhotoProxy " + photoProxy->GetPhotoId());
    MEDIA_INFO_LOG("photoId: %{public}s", photoProxy->GetPhotoId().c_str());
    tracer.Start("PhotoAssetProxy CreatePhotoAsset");
    CreatePhotoAsset(photoProxy);
    if (cameraShotType_ == CameraShotType::VIDEO) {
        return;
    }
    if (photoProxy->GetPhotoQuality() == PhotoQuality::LOW) {
        UpdatePhotoQuality(dataShareHelper_, photoProxy, fileId_, static_cast<int32_t>(subType_));
    }
    tracer.Finish();

    Uri openUri(uri_);
    int fd = dataShareHelper_->OpenFile(openUri, MEDIA_FILEMODE_READWRITE);
    if (fd < 0) {
        MEDIA_ERR_LOG("fd.Get() < 0 fd %{public}d status %{public}d", fd, errno);
        return;
    }
    DealWithLowQualityPhoto(dataShareHelper_, fd, uri_, photoProxy);
    MEDIA_INFO_LOG("exit");
}

int32_t PhotoAssetProxy::GetVideoFd()
{
    if (dataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Failed to read video of moving photo, datashareHelper is nullptr");
        return E_ERR;
    }

    string videoUri = uri_;
    MediaFileUtils::UriAppendKeyValue(videoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, OPEN_MOVING_PHOTO_VIDEO);
    Uri openVideoUri(videoUri);
    int32_t fd = dataShareHelper_->OpenFile(openVideoUri, MEDIA_FILEMODE_READWRITE);
    MEDIA_INFO_LOG("GetVideoFd enter, video path: %{public}s, fd: %{public}d", videoUri.c_str(), fd);
    return fd;
}

void PhotoAssetProxy::NotifyVideoSaveFinished()
{
    string uriStr = PAH_MOVING_PHOTO_SCAN;
    MediaFileUtils::UriAppendKeyValue(uriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(uriStr);
    DataShare::DataSharePredicates predicates;
    DataShare::DatashareBusinessError businessError;
    std::vector<std::string> columns { uri_ };
    dataShareHelper_->Query(uri, predicates, columns, &businessError);
    MEDIA_INFO_LOG("video save finished %{public}s", uri_.c_str());
}
} // Media
} // OHOS